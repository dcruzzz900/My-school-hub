# V31 — Automated Billing Notifications

V31 adds tenant-scoped in-app billing reminders for School Admin/Sub-Admin accounts.

## Notifications
- Trial/subscription expiry: 14, 7, 3 and 1 day reminders.
- Expired/suspended/cancelled status alert.
- Pending invoice due-soon, due-today and overdue reminders.
- Duplicate reminders are prevented with a unique billing notification event key.

## Security
- Notifications are written to the existing school-scoped `notifications` table with target role `admin`.
- Teachers, students and parents do not receive billing notifications.
- No browser-supplied school ID is used by the cron endpoint.
- The cron endpoint requires `BILLING_NOTIFICATION_CRON_SECRET` and the `X-Billing-Cron-Secret` header.
- The job does not activate, suspend, renew, delete or modify subscriptions.

## Railway configuration
Add a Railway environment variable:

`BILLING_NOTIFICATION_CRON_SECRET=<long-random-secret>`

Then invoke the endpoint periodically with an external scheduler or Railway-compatible cron service:

`POST /internal/billing-notifications`

Header:

`X-Billing-Cron-Secret: <same-secret>`

A daily run is sufficient for the current reminder schedule.

## Existing data
The migration is additive. Existing schools, subscriptions, invoices, payments, receipts, users, results and attendance are preserved.
