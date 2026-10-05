# V33 — Scheduled Billing Jobs

V33 adds a safe one-shot scheduler for V31/V32 billing notifications.

## What changed
- `billing_cron.py` sends one authenticated `POST /internal/billing-notifications` request and exits.
- The application records billing-job runs in `billing_job_runs`.
- A 30-minute database-backed lock prevents overlapping scheduler invocations from running the billing job twice.
- A stale running job is automatically marked `stale` before a new run starts.
- Completed/failed runs retain a small result/error record for operational troubleshooting.
- Payment/subscription state is not changed by the scheduler itself.

## Railway setup
Use a **separate Railway service** for the scheduler so the web service continues to run Gunicorn normally.

Scheduler service environment variables:
- `BILLING_APP_URL=https://YOUR-RAILWAY-DOMAIN`
- `BILLING_NOTIFICATION_CRON_SECRET=<same long random secret used by the web service>`

Scheduler service start command:

```text
python billing_cron.py
```

Configure the Railway scheduler service with a daily cron schedule. The current reminder rules are day-based (14, 7, 3, 1 days before expiry and invoice due/overdue buckets), so one run per day is sufficient.

## Security
- Never put the cron secret in GitHub.
- The scheduler has no database credentials and does not access the SQLite file directly.
- The web endpoint rejects missing or incorrect secrets.
- Duplicate/overlapping requests are safely skipped while another billing job is running.

## Existing data
The migration is additive. Existing schools, subscriptions, invoices, payments, receipts, users, results, attendance, and billing notification history are preserved.
