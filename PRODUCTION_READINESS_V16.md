# V16 — Production Readiness & Railway Go-Live

## Safe deployment sequence
1. Keep the existing Railway Volume attached. **Do not delete/recreate it.**
2. Confirm the existing database path and `DATA_DIR` still point to the persistent volume.
3. Set a stable `SECRET_KEY` in Railway Variables. Do not commit it to GitHub.
4. Set `SKIP_DEMO_SEED=1` for the live system.
5. Deploy the V16 repository/ZIP through the normal Railway deployment flow.
6. Wait for the deployment health check to become healthy.
7. Run `python production_smoke_test.py https://YOUR-RAILWAY-DOMAIN` from a machine with internet access.
8. Log in as Super Admin and confirm the school count and a sample school are unchanged.
9. Create a verified backup before making the next schema-changing deployment.

## Health endpoints
- `/healthz` — lightweight liveness check.
- `/readyz` — database readiness/integrity check; returns no school/student records.

## Backup policy
Use `python backup_db.py --keep 14` before planned upgrades and on a daily schedule using a scheduler/cron service. SQLite backups are verified with `PRAGMA integrity_check` before being retained.

Back up the database **and** uploaded files/materials if they are stored on the same persistent volume. A database backup alone does not restore uploaded documents.

## Rollback rule
Never roll back by deleting the production database. Preserve the current database first. If a migration has changed the schema, follow `MIGRATION_RECOVERY_CHECKLIST.md` and `RESTORE_PROCEDURE.md`.

## Final go-live checks
- [ ] Existing schools visible and counts unchanged.
- [ ] Super Admin login works.
- [ ] School Admin login works.
- [ ] Suspended school remains blocked.
- [ ] School A cannot access School B by changing IDs.
- [ ] Teacher class/subject scope is enforced.
- [ ] Offline sync rejects tenant mismatch.
- [ ] Results/score permissions remain enforced.
- [ ] Backup creation succeeds and integrity is `ok`.
- [ ] `/healthz` and `/readyz` return healthy responses.
- [ ] Railway Volume remains attached and persistent.
