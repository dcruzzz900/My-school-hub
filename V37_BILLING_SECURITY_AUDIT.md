# V37 – Billing Security & Financial Audit Trail

## Purpose
V37 adds an append-only financial audit layer without changing subscription rules or deleting existing billing data.

## Controls
- Financial audit events are append-only and protected by SQLite UPDATE/DELETE triggers.
- Payment history is append-only and records creation/status/amount/reference changes.
- Report downloads are logged with actor, report, format, date range and row count.
- Confirmed payments create a financial audit event with receipt reference.
- Super Admin can view the read-only audit dashboard at `/platform/billing-audit`.
- Existing application audit logging remains in place.

## Separation of duties
Payment confirmation remains restricted to the existing Super Admin billing workflow and verified gateway webhooks. School Admins cannot confirm payments. V37 does not introduce a reversal/refund operation; any future reversal must be a separate, explicitly authorized workflow that creates a new audit event rather than modifying history.

## Deployment
No live payment credentials are added by this release. No existing school data is reset or replaced. The migration is additive.
