# My School Hub V52 — Integrated Authentication, Signup, Linking & Audit Changes

This build integrates the latest authentication, registration, student-claim, parent-linking, tenant-isolation and audit specification into the V52 production candidate.

## Integrated changes

- Public Welcome screen exposes Admin, Staff, Student and Parent only.
- Public signup labels use New School Signup, Staff Signup, Student Signup and Parent Signup.
- Platform/Super Admin remains an internal role and is not exposed on public authentication screens.
- Staff signup is controlled by a school-issued signup code; school and role are never user-selectable.
- Staff first-login onboarding remains separate from initial signup.
- Student signup now claims an existing official student record rather than creating a duplicate academic record.
- Student claim requires a valid class signup code plus admission/register number and server-side tenant/class validation.
- Already-claimed student records are rejected without revealing account details.
- Parent signup creates the parent account separately; child linking is performed through the verified parent-child workflow.
- Parent signup accepts a School ID/Tenant ID or a school-hosted portal context.
- Parent accounts may log in before child verification, but no student data is exposed until a verified relationship exists.
- Signup codes carry school/tenant context, expiration, usage limits and class/session information.
- Added structured signup, activation-attempt, status-history and security-event tables.
- Added request/transaction correlation fields for security/audit tracing.
- Added account/signup/activation status fields without collapsing them into a single state.
- Added student account ownership marker so one official student record can have one active claimed account.
- Tenant identifiers are backfilled and stamped on relevant records.
- Existing Parent Portal and Railway `parent_students` migration repair remain intact.

## Security principle

Client-provided role, school, tenant, class, arm and permission values are not trusted as authorization decisions. The server resolves authoritative scope from authenticated accounts, verified signup codes and school records.

AI, results, attendance and official academic records remain outside the registration/account-claim authority path and are not modified by this integration.

## Validation

- Python compilation: passed
- Full contract test suite: **26 passed**
- Fresh database migration using a stubbed password-hash dependency: passed
- Signup-code generation and validation: passed
