# V14 — Database Migration & Backup Safety

V14 protects production database upgrades without deleting existing school data.

## What changed

- Startup migrations are serialized with a process lock so multiple Gunicorn workers do not run schema changes simultaneously.
- Before a pending migration, SQLite creates an online backup under `<DATA_DIR>/backups/`.
- The backup is checked with `PRAGMA integrity_check` before the migration continues.
- Up to 10 `pre-migration-*.db` snapshots are retained.
- The existing `backup_db.py` remains available for scheduled full backups.
- The migration process remains idempotent and continues to use the existing `schema_version`/`schema_steps` mechanism.
- No migration automatically deletes or resets the production database.

## Railway requirements

Keep the Railway Volume mounted at the application's persistent data directory. Do not delete/recreate the Volume during deployment.

Recommended environment variables:

```text
DATA_DIR=/data
SKIP_DEMO_SEED=1
SECRET_KEY=<your-existing-secret-key>
```

## Safe update sequence

1. Deploy the new application code.
2. Keep the existing Railway Volume attached.
3. On startup, one worker acquires the migration lock.
4. If schema changes are pending, a verified SQLite snapshot is created first.
5. Migrations run once; waiting workers re-check the schema after the lock is released.
6. If a migration fails, do not delete the database. Keep the pre-migration backup and inspect the deployment logs before retrying.

## Manual backup

```bash
python backup_db.py --keep 30
```

Backups are integrity-checked before being retained.

## Recovery principle

Never solve a migration error by deleting `school.db` or the Railway Volume. Preserve the backup, diagnose the failing migration, and restore only after confirming which snapshot is appropriate.
