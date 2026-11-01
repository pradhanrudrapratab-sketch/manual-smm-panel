require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, "db.sqlite");
fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer',
 permissions TEXT NOT NULL DEFAULT '{}', is_active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services (
 id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, name TEXT NOT NULL,
 description TEXT DEFAULT '', link_label TEXT NOT NULL DEFAULT 'Target URL',
 price_per_1000 REAL NOT NULL, min_quantity INTEGER NOT NULL DEFAULT 100,
 max_quantity INTEGER NOT NULL DEFAULT 100000, active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
 service_id INTEGER NOT NULL REFERENCES services(id), service_name TEXT NOT NULL,
 target_link TEXT NOT NULL, quantity INTEGER NOT NULL, amount REAL NOT NULL,
 payment_amount INTEGER NOT NULL, payment_order_id TEXT UNIQUE, payment_status TEXT NOT NULL DEFAULT 'pending',
 payment_utr TEXT, status TEXT NOT NULL DEFAULT 'awaiting_payment',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
`);

// Safe, repeatable migrations for existing databases.
for (const sql of [
  "ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}'",
  "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"
]) {
  try { db.exec(sql); }
  catch (e) {
    if (!String(e.message).includes("duplicate column")) throw e;
  }
}

const DEFAULT_PERMISSIONS = {
  customer: [],
  admin: ["orders.manage", "services.manage"],
  semi_super_admin: ["users.view", "orders.manage", "services.manage"],
  super_admin: ["*"]
};

function parsePermissions(value) {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

// Environment credentials establish the one protected Super Admin.
const superEmail = String(process.env.SUPER_ADMIN_EMAIL || process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const superPassword = process.env.SUPER_ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || "";

if (superEmail && superPassword) {
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(superEmail);
  const hash = bcrypt.hashSync(superPassword, 12);
  if (existing) {
    db.prepare("UPDATE users SET role='super_admin',password_hash=?,is_active=1,permissions=? WHERE id=?")
      .run(hash, JSON.stringify(DEFAULT_PERMISSIONS.super_admin), existing.id);
  } else {
    db.prepare("INSERT INTO users(name,email,password_hash,role,permissions) VALUES(?,?,?,'super_admin',?)")
      .run("Super Administrator", superEmail, hash, JSON.stringify(DEFAULT_PERMISSIONS.super_admin));
  }
} else {
  console.warn("WARNING: Set SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD in Render environment variables.");
}

const count = db.prepare("SELECT COUNT(*) n FROM users WHERE role IN ('admin','super_admin')").get().n;
if (!count && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT OR IGNORE INTO users(name,email,password_hash,role,permissions) VALUES(?,?,?,'admin',?)")
    .run("Administrator", process.env.ADMIN_EMAIL.toLowerCase(), hash, JSON.stringify(DEFAULT_PERMISSIONS.admin));
}
if (db.prepare("SELECT COUNT(*) n FROM services").get().n === 0) {
  const seed = db.prepare(`INSERT INTO services(category,name,description,link_label,price_per_1000,min_quantity,max_quantity)
    VALUES(?,?,?,?,?,?,?)`);
  seed.run("Instagram", "Instagram Reel Views", "Views for a public Instagram Reel or post.", "Instagram Reel / Post URL", 35, 100, 100000);
  seed.run("Instagram", "Instagram Likes", "Likes for a public Instagram post or Reel.", "Instagram Post / Reel URL", 80, 50, 50000);
  seed.run("Instagram", "Instagram Followers", "Followers for an Instagram profile.", "Instagram Profile URL", 450, 100, 10000);
}

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false }));
if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be set in production.");
}
app.use(session({
  name: "sf.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: path.dirname(path.resolve(DB_PATH)) }),
  secret: process.env.SESSION_SECRET || "local-development-secret-change-this",
  resave: false, saveUninitialized: false, rolling: true,
  cookie: {
    httpOnly: true, sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/", maxAge: 30*24*60*60*1000
  }
}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60*1000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const safeUser = u => ({
  id: u.id, name: u.name, email: u.email, role: u.role,
  permissions: u.role === "super_admin" ? ["*"] : parsePermissions(u.permissions)
});
function auth(req,res,next) {
  if (!req.session.user) return res.status(401).json({error:"Please log in."});
  const u = db.prepare("SELECT id,name,email,role,permissions,is_active FROM users WHERE id=?").get(req.session.user.id);
  if (!u || !u.is_active) {
    return req.session.destroy(() => res.status(401).json({error:"Your account is disabled. Contact the administrator."}));
  }
  req.session.user = safeUser(u);
  next();
}
function permit(permission) {
  return (req,res,next) => {
    if (!req.session.user) return res.status(401).json({error:"Please log in."});
    const permissions = req.session.user.permissions || [];
    if (req.session.user.role === "super_admin" || permissions.includes("*") || permissions.includes(permission)) return next();
    return res.status(403).json({error:"You do not have permission to perform this action."});
  };
}
const admin = permit("orders.manage");
const superAdmin = (req,res,next) => {
  if (req.session.user && req.session.user.role === "super_admin") return next();
  return res.status(403).json({error:"Super Admin access required."});
};
function validUrl(v){ try { const u=new URL(v); return ["http:","https:"].includes(u.protocol); } catch { return false; } }
function famapiHeaders(){ return { "Authorization":`Bearer ${process.env.FAMAPI_API_KEY || ""}`, "Content-Type":"application/json" }; }

app.get("/api/health",(req,res)=>res.json({ok:true}));
app.get("/api/me",(req,res)=>res.json({user:req.session.user || null}));
app.post("/api/register", async (req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password || password.length<8)
    return res.status(400).json({error:"Enter a name, valid email and password of at least 8 characters."});
  try{
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),email.trim().toLowerCase(),hash);
    const u=db.prepare("SELECT id,name,email,role,permissions FROM users WHERE id=?").get(info.lastInsertRowid);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({error:"Could not start session."});
      req.session.user=safeUser(u);
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({error:"Could not save session."});
        res.json({user:req.session.user});
      });
    });
  }catch(e){res.status(409).json({error:"That email may already be registered."});}
});
app.post("/api/login", async (req,res)=>{
  const {email,password}=req.body||{};
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(String(email||"").toLowerCase().trim());
  if(!u || !u.is_active || !(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"Invalid email or password."});
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:"Could not start session."});
    req.session.user = safeUser(u);
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({error:"Could not save session."});
      res.json({user:req.session.user});
    });
  });
});
app.post("/api/logout",(req,res)=>{
  req.session.destroy(err => {
    res.clearCookie("sf.sid", {
      httpOnly:true, sameSite:"lax",
      secure:process.env.NODE_ENV === "production", path:"/"
    });
    if (err) return res.status(500).json({error:"Could not log out."});
    res.json({ok:true});
  });
});

app.get("/api/services",(req,res)=>{
  const rows=db.prepare("SELECT id,category,name,description,link_label,price_per_1000,min_quantity,max_quantity FROM services WHERE active=1 ORDER BY category,name").all();
  res.json({services:rows});
});
app.post("/api/orders",auth,async(req,res)=>{
  const {serviceId,targetLink,quantity}=req.body||{};
  const service=db.prepare("SELECT * FROM services WHERE id=? AND active=1").get(Number(serviceId));
  const qty=Number(quantity);
  if(!service) return res.status(404).json({error:"Service not found."});
  if(!validUrl(String(targetLink||""))) return res.status(400).json({error:"A valid target link is required before payment."});
  if(!Number.isInteger(qty)||qty<service.min_quantity||qty>service.max_quantity) return res.status(400).json({error:`Quantity must be between ${service.min_quantity} and ${service.max_quantity}.`});
  if(!process.env.FAMAPI_API_KEY) return res.status(503).json({error:"Payments are not configured yet. Please contact the administrator."});
  const amount=Math.round((qty/1000)*service.price_per_1000*100)/100;
  const multiplier=Number(process.env.FAMAPI_AMOUNT_MULTIPLIER||100);
  const paymentAmount=Math.round(amount*multiplier);
  if(!Number.isFinite(paymentAmount)||paymentAmount<1) return res.status(400).json({error:"Order amount is invalid."});
  const tx=db.transaction(()=>{
    const info=db.prepare(`INSERT INTO orders(user_id,service_id,service_name,target_link,quantity,amount,payment_amount)
      VALUES(?,?,?,?,?,?,?)`).run(req.session.user.id,service.id,service.name,String(targetLink).trim(),qty,amount,paymentAmount);
    return Number(info.lastInsertRowid);
  });
  const orderId=tx();
  try{
    const response=await fetch(`${(process.env.FAMAPI_BASE_URL||"https://mrkrishna.site/api/v1").replace(/\/$/,"")}/create-order`,{
      method:"POST",headers:famapiHeaders(),body:JSON.stringify({amount:paymentAmount,note:`SMM Order #${orderId}`})
    });
    const data=await response.json();
    if(!response.ok || !data.id || !data.payment_link) throw new Error(data.message||"Payment provider rejected the request.");
    db.prepare("UPDATE orders SET payment_order_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(data.id,orderId);
    res.json({orderId,paymentLink:data.payment_link,qrUrl:data.qr_url||null,amount,order:data.id});
  }catch(e){
    db.prepare("UPDATE orders SET payment_status='failed',status='payment_failed',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(orderId);
    res.status(502).json({error:"Could not create payment. No order was submitted for fulfilment."});
  }
});
app.post("/api/orders/:id/verify",auth,async(req,res)=>{
  const order=db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(Number(req.params.id),req.session.user.id);
  if(!order)return res.status(404).json({error:"Order not found."});
  if(order.payment_status==="success")return res.json({verified:true,status:order.status});
  if(!order.payment_order_id)return res.status(400).json({error:"Payment order is not available."});
  try{
    const response=await fetch(`${(process.env.FAMAPI_BASE_URL||"https://mrkrishna.site/api/v1").replace(/\/$/,"")}/orders/${encodeURIComponent(order.payment_order_id)}`,{headers:famapiHeaders()});
    const payload=await response.json();
    const d=payload.data||{};
    const verified=response.ok && payload.status==="success" && d.status==="COMPLETED" &&
      String(d.order_id)===String(order.payment_order_id) && Number(d.amount)===Number(order.payment_amount);
    if(!verified)return res.json({verified:false,status:"pending",message:"Payment is not confirmed yet. Try again shortly."});
    db.prepare(`UPDATE orders SET payment_status='success',payment_utr=?,status='pending',updated_at=CURRENT_TIMESTAMP
      WHERE id=? AND payment_status!='success'`).run(d.utr||null,order.id);
    res.json({verified:true,status:"pending"});
  }catch(e){res.status(502).json({error:"Unable to verify payment right now. Please retry."});}
});
app.get("/api/orders",auth,(req,res)=>{
  const canManage = req.session.user.role === "super_admin" ||
    (req.session.user.permissions || []).includes("orders.manage");
  const rows = canManage
    ? db.prepare("SELECT o.*,u.name customer_name,u.email customer_email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 500").all()
    : db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id);
  res.json({orders:rows});
});
app.patch("/api/admin/orders/:id",admin,(req,res)=>{
  const allowed=["pending","processing","completed","partial","cancelled"];
  const status=String(req.body.status||"");
  if(!allowed.includes(status))return res.status(400).json({error:"Invalid order status."});
  const info=db.prepare("UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status='success'").run(status,Number(req.params.id));
  if(!info.changes)return res.status(404).json({error:"Paid order not found."});
  res.json({ok:true});
});
app.get("/api/admin/services",permit("services.manage"),(req,res)=>res.json({services:db.prepare("SELECT * FROM services ORDER BY id DESC").all()}));
app.post("/api/admin/services",permit("services.manage"),(req,res)=>{
  const b=req.body||{};
  if(!b.category||!b.name||!b.link_label||!Number.isFinite(Number(b.price_per_1000))||Number(b.price_per_1000)<=0)
    return res.status(400).json({error:"Category, service name, link label and valid price are required."});
  const info=db.prepare(`INSERT INTO services(category,name,description,link_label,price_per_1000,min_quantity,max_quantity,active)
    VALUES(?,?,?,?,?,?,?,1)`).run(b.category,b.name,b.description||"",b.link_label,Number(b.price_per_1000),Number(b.min_quantity)||1,Number(b.max_quantity)||100000);
  res.json({id:info.lastInsertRowid});
});
app.patch("/api/admin/services/:id",permit("services.manage"),(req,res)=>{
  const b=req.body||{};
  db.prepare(`UPDATE services SET category=?,name=?,description=?,link_label=?,price_per_1000=?,min_quantity=?,max_quantity=?,active=? WHERE id=?`)
    .run(b.category,b.name,b.description||"",b.link_label,Number(b.price_per_1000),Number(b.min_quantity),Number(b.max_quantity),b.active?1:0,Number(req.params.id));
  res.json({ok:true});
});
app.delete("/api/admin/services/:id",permit("services.manage"),(req,res)=>{
  db.prepare("UPDATE services SET active=0 WHERE id=?").run(Number(req.params.id)); res.json({ok:true});
});

// User management is restricted to the Super Admin.
app.get("/api/admin/users",auth,superAdmin,(req,res)=>{
  const users = db.prepare("SELECT id,name,email,role,permissions,is_active,created_at FROM users ORDER BY id DESC").all()
    .map(u => ({...u, permissions:parsePermissions(u.permissions), is_active:!!u.is_active}));
  res.json({users});
});

app.patch("/api/admin/users/:id/role",auth,superAdmin,(req,res)=>{
  const id = Number(req.params.id);
  const role = String(req.body.role || "");
  if (!Number.isInteger(id) || !["customer","admin","semi_super_admin"].includes(role))
    return res.status(400).json({error:"Invalid user or role."});
  const target = db.prepare("SELECT id,role FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({error:"User not found."});
  if (target.role === "super_admin") return res.status(403).json({error:"Super Admin accounts cannot be changed here."});
  db.prepare("UPDATE users SET role=?,permissions=? WHERE id=?")
    .run(role,JSON.stringify(DEFAULT_PERMISSIONS[role]),id);
  res.json({ok:true});
});

app.patch("/api/admin/users/:id/permissions",auth,superAdmin,(req,res)=>{
  const id = Number(req.params.id);
  const permissions = req.body.permissions;
  if (!Number.isInteger(id) || !Array.isArray(permissions) ||
      !permissions.every(x => ["orders.manage","services.manage","users.view"].includes(x)))
    return res.status(400).json({error:"Invalid permissions."});
  const target = db.prepare("SELECT role FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({error:"User not found."});
  if (target.role === "super_admin") return res.status(403).json({error:"Super Admin permissions are protected."});
  db.prepare("UPDATE users SET permissions=? WHERE id=?").run(JSON.stringify([...new Set(permissions)]),id);
  res.json({ok:true});
});

app.patch("/api/admin/users/:id/status",auth,superAdmin,(req,res)=>{
  const id = Number(req.params.id);
  const active = req.body.active;
  if (!Number.isInteger(id) || typeof active !== "boolean")
    return res.status(400).json({error:"Invalid account status."});
  const target = db.prepare("SELECT id,role FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({error:"User not found."});
  if (target.role === "super_admin") return res.status(403).json({error:"Super Admin accounts cannot be disabled here."});
  db.prepare("UPDATE users SET is_active=? WHERE id=?").run(active ? 1 : 0,id);
  res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Manual SMM panel running on port ${PORT}`));
