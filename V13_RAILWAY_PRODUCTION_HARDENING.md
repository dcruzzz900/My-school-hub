# V13 — Railway Production Hardening

This release is designed to update the existing deployment without deleting the existing SQLite database.

## Railway variables

Set these on the existing service:

- `DATA_DIR=/data` — required when using a Railway Volume mounted at `/data`.
- `SECRET_KEY=<existing secret>` — keep the existing value when upgrading an existing installation; changing it logs out existing sessions and can invalidate device credentials.
- `SKIP_DEMO_SEED=1` — prevents creation of the demo school on a fresh public deployment.
- `SESSION_COOKIE_SECURE=1` — enables HTTPS-only session cookies.

## Volume

The existing SQLite database must remain on the persistent Railway Volume. Do not remove or recreate the Volume during an application update.

## Update procedure

1. Confirm the Railway Volume is still mounted at `/data`.
2. Confirm the variables above are present.
3. Before deploying, make a database backup using `python backup_db.py` or your existing backup process.
4. Deploy this ZIP/repository version normally.
5. The application runs idempotent migrations on startup; it does not call `init_db(reset=True)`.
6. Check `/healthz` after deployment.
7. Log in and verify one existing school, one existing user, and one existing result before doing broader testing.

## Important V13 repair

V13 fixes the historical `NameError: name 'migration_role_scope_compat' is not defined` startup failure. The compatibility migration is idempotent and backfills missing role-assignment tenant IDs from the corresponding school. It does not delete role assignments or permissions.

## Super Admin

The supported server-side command remains:

`python create_super_admin.py`

Run it in the Railway service environment so it uses the same `DATA_DIR=/data` database as the web service. Do not create a second database in a temporary shell or local filesystem.
