# V29 – Payment Gateway Integration Architecture

V29 prepares the school platform for secure Nigerian payment gateway integration without requiring live credentials.

## Supported webhook endpoints

- `POST /webhooks/paystack`
- `POST /webhooks/flutterwave`

## Required Railway environment variables

For Paystack:

- `PAYSTACK_WEBHOOK_SECRET` = the Paystack webhook secret configured in the Paystack dashboard.

For Flutterwave:

- `FLUTTERWAVE_WEBHOOK_SECRET` = the Flutterwave secret hash configured for the webhook.

Do **not** commit either value to GitHub or store it in the SQLite database.

## Secure processing flow

1. Provider sends webhook.
2. Signature/hash is verified against the raw request body.
3. Provider event ID is checked for idempotency.
4. Payment reference is matched to an invoice.
5. Currency must be NGN.
6. Amount must match the invoice amount.
7. The school and invoice relationship is checked.
8. A payment record is created or reused.
9. Successful payment is confirmed once only.
10. Subscription is activated/renewed.
11. A unique receipt is generated.
12. The webhook event is marked processed and audited.

Repeated webhook delivery does not renew the school twice.

## Important deployment rule

Do not enable a live webhook until the corresponding secret has been added to Railway and the provider dashboard is configured with the exact HTTPS webhook URL.

For example:

`https://YOUR-RAILWAY-DOMAIN/webhooks/paystack`

or

`https://YOUR-RAILWAY-DOMAIN/webhooks/flutterwave`

Replace `YOUR-RAILWAY-DOMAIN` with the actual production domain.

## Manual payments remain supported

Super Admin can still record and manually confirm a payment. The same amount validation and receipt generation are used.

## Data safety

V29 does not delete schools, students, teachers, results, attendance, or existing subscription records. Payment/webhook tables are additive migrations.
