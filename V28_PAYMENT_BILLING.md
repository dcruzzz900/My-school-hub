# V28 — Payment & Subscription Renewal Architecture

V28 adds a non-gateway billing layer. It does not process live card/mobile-money payments.

## Flow
1. Super Admin selects a school and creates an invoice from an active paid plan.
2. A payment reference can be recorded as `pending`.
3. Pending payments do not grant access.
4. Super Admin independently verifies the payment and confirms it.
5. Confirmation marks the invoice paid, records the confirmer, activates the invoice plan, extends the subscription for the invoice billing period, and stores the payment reference on the school.
6. All billing changes are audit logged.

## Safety
- No automatic activation from an unverified payment record.
- No database reset or school-data deletion.
- Existing subscription/trial logic remains available.
- Live Paystack/Flutterwave API keys and webhook verification are intentionally not configured in this stage.
