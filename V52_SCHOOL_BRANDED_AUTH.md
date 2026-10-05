# V52 — School-Branded Authentication

## Behavior

After a school is active and the School Admin uploads an official logo, that
logo is automatically used as the tenant's authentication branding for:

- Admin / Sub-Admin login
- Staff / Teacher login
- Student login
- Parent login
- Staff signup
- Student signup
- Parent signup
- School activation / account recovery screens where a school context is known

The public My School Hub welcome screen remains on system branding until a
school context is securely resolved by subdomain, session, School ID/Tenant ID,
or a valid school-issued signup code.

## Tenant security

The browser may submit a School ID/Tenant ID or signup code only as a lookup
selector. The server resolves the corresponding `schools` row and reads the
stored logo filename and branding settings from that record. A client cannot
choose an arbitrary image path or logo filename.

Once authenticated, `session.school_id` is authoritative and takes precedence
over editable form values.

## Logo fallback

No active logo = default My School Hub branding.

Uploading or replacing the logo requires no code change. The same tenant logo
URL is served with `Cache-Control: no-store` so replacement is visible promptly.

## Branding controls

School Admin can configure:

- Enable/disable authentication branding
- Background logo opacity (0.03–0.35)
- Logo position (left / center / right)
- Background style (watermark / soft / plain)
- School-name visibility

These settings are stored on the `schools` tenant record.

## Dynamic signup branding

Staff and Student signup codes dynamically resolve the school branding as the
user enters a valid active code. Parent signup resolves branding from School
ID/Tenant ID. Student login accepts an optional School ID/Tenant ID and checks
it against the student's actual school before authentication succeeds.
