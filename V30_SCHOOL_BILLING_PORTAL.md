# V30 — School Admin Billing & Payment Portal

## Purpose
V30 gives each School Admin a school-scoped, read-only billing portal. It exposes billing information without allowing the school to alter payment confirmation or another school's records.

## School Admin portal
- `/billing`
- Current subscription/trial status
- Plan, expiry and days remaining
- School ID and Tenant ID
- Student/teacher plan usage
- Invoice history
- Payment status/history
- Confirmed receipts
- Renewal instructions

## Receipt access
- `/billing/receipt/<receipt_id>`
- Receipt lookup is restricted to the authenticated School Admin's own `school_id`.
- Printable receipt includes invoice, plan, amount, provider, reference, School ID and Tenant ID.

## Security
- Only `admin` role can access the portal.
- School ID is taken from the authenticated session; URL IDs are not used for authorization.
- School Admin cannot create, edit, confirm, cancel or refund payments from this portal.
- Super Admin remains responsible for manual billing actions and payment confirmation.
- Gateway-confirmed payments continue to use V29's webhook verification and idempotency controls.

## Data safety
- No destructive database migration was added.
- No school, student, teacher, result or attendance data is deleted or replaced.
