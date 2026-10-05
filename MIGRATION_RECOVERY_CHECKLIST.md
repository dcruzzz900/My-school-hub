# Production Migration Recovery Checklist

- [ ] Do not delete the Railway Volume.
- [ ] Do not run `reset=True` against production.
- [ ] Check deployment logs for the first migration error.
- [ ] Confirm the newest `backups/pre-migration-*.db` exists.
- [ ] Verify the backup with SQLite `PRAGMA integrity_check` before using it.
- [ ] Fix the migration code first when possible.
- [ ] Restart/redeploy and allow the idempotent migration to retry.
- [ ] Restore a backup only when the database itself must be rolled back and after taking a fresh copy of the current database.
- [ ] After recovery, run the platform Security Audit and review school/user counts.
