# Manual SMM Panel

A small, self-hostable SMM ordering website. Customers choose a service, submit the required target URL and quantity, pay through FAMAPI, and the admin fulfils orders manually.

## Features

- Customer registration, login and order history.
- Service catalogue with category, description, price per 1,000, min/max quantity and a **required target-link label**.
- Each service can specify the type of URL required (Reel/post/profile/etc.).
- FAMAPI payment-order creation and server-side payment verification.
- Admin order list with customer, target link, quantity, payment state, UTR and manual work-status updates.
- Admin can add services.
- SQLite database and SQLite-backed sessions.

## Deploy to Render

1. Push this folder to a new GitHub repository.
2. In Render, choose **New + → Blueprint** and select the repository. Render reads `render.yaml`.
3. Set these environment variables in the Render service:
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD` (strong password)
   - `FAMAPI_API_KEY` (your private FAMAPI live API key)
   - `PUBLIC_BASE_URL` (your deployed `https://...onrender.com` URL)
4. Deploy. The admin account is created on first boot if the admin environment variables are present.
5. Open `/` and log in using the admin email/password.

You can also create a Render Web Service manually:
- Build command: `npm install`
- Start command: `npm start`
- Add a persistent disk mounted at `/var/data`.
- Set `DATABASE_PATH=/var/data/db.sqlite`.

**Important:** The persistent disk is essential. Without it, SQLite data may disappear on redeploy/restart. Render persistent disks are available on paid web-service plans, not the free web-service plan.

## FAMAPI integration

Uses only the endpoints supplied in the project brief:

- `POST https://mrkrishna.site/api/v1/create-order`
- `GET https://mrkrishna.site/api/v1/orders/{order_id}`

The API key is read only by the server from `FAMAPI_API_KEY`; it is never sent to the browser. A payment is accepted only when the server receives `status: "success"`, `data.status: "COMPLETED"`, matching `data.order_id`, and matching amount. The customer redirect/payment link is not proof of payment.

### Amount unit — verify before accepting live payments

The supplied FAMAPI documentation shows an integer `amount` but does not say whether it represents rupees or paise. This project defaults `FAMAPI_AMOUNT_MULTIPLIER=100` (₹1.00 becomes 100). Confirm the expected unit with the FAMAPI provider before taking real payments. Set it to `1` if the API expects whole rupees. Do a small test payment first.

## Admin workflow

1. Customer registers and places an order with the required URL.
2. Customer pays and clicks **I have paid · Verify payment**.
3. Once FAMAPI confirms payment, the order appears as `pending` in the admin queue.
4. Admin opens the target link, fulfils the service manually outside this website, and updates status to `processing`, `completed`, `partial` or `cancelled`.

No SMM supplier API is integrated.

## SQLite and backups

The database is stored at `DATABASE_PATH`. On Render, keep it under the mounted persistent disk (for example `/var/data/db.sqlite`). Back up the SQLite file regularly. Do not delete or replace it while the service is running.

## Security notes

- Set a long random `SESSION_SECRET`.
- Use a strong admin password and do not commit `.env`.
- FAMAPI key must remain in Render environment variables.
- This is a starter implementation. Before taking substantial customer funds, add operational backups, CSRF protection, admin audit logs, refund handling, and a tested recovery procedure.
