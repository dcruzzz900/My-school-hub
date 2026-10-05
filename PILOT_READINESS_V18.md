# V18 — Multi-School Pilot Readiness

## Purpose
V18 prepares the School Result Management System for a controlled multi-school pilot without changing or deleting existing production school data.

## Onboarding sequence
1. Super Admin signs in at `/platform/login`.
2. Open **Schools → Onboard a School**.
3. Enter the school's legal/display name, registered email, first School Admin name and unique admin username.
4. The platform creates a permanent `school_code` (School ID) and `tenant_id`.
5. The School Admin account is created in a pending activation state with no usable password.
6. A one-time activation code is generated. Share it only with the intended school administrator.
7. The administrator activates the school, sets a real password, and completes school setup.
8. Verify that the School Admin can see only the assigned school's data.
9. Create teachers/sub-admins and assign role + school level + class/subject/department scope.
10. Activate devices only after the user's online login succeeds.

## Pilot acceptance tests
- [ ] School A has a unique School ID.
- [ ] School A has a unique permanent Tenant ID.
- [ ] School B has different identifiers.
- [ ] School A users cannot access School B by changing URL/form IDs.
- [ ] A teacher can access only the classes/subjects granted by scope.
- [ ] A revoked/expired role loses protected permissions.
- [ ] A suspended school cannot authenticate normal school users.
- [ ] Offline device bootstrap records the correct Tenant ID.
- [ ] Offline sync rejects a mismatched tenant/device identity.
- [ ] Result finalization/publishing remains server-authorized.
- [ ] A verified database backup exists before production rollout.
- [ ] `/healthz` and `/readyz` respond successfully after deployment.

## First-week pilot
Use one school, one School Admin and 2–3 teachers. Test on Android Chrome and iPhone Safari if available. Record device model, browser, first-sync time, offline duration, sync conflicts, result-printing behavior and any failed workflows.

## Production safety
- Never delete the Railway Volume during an upgrade.
- Never replace `school.db` with a blank database.
- Keep `SKIP_DEMO_SEED=1` in production.
- Back up before migrations and before major configuration changes.
- Keep production `SECRET_KEY` stable across deployments.
- Do not expose Tenant IDs as secrets; authorization must still come from the authenticated session/device identity.
- Treat activation codes as one-time credentials and do not publish them in screenshots or public messages.

## Rollout stages
**Stage 1:** one pilot school → **Stage 2:** 3–5 schools → **Stage 3:** 10+ schools after reviewing sync, database load, backups and support incidents.

## Important architecture checkpoint
SQLite can be retained for the pilot if measured concurrency remains acceptable. Before a large rollout, perform load testing and plan PostgreSQL migration rather than assuming SQLite will scale indefinitely.
