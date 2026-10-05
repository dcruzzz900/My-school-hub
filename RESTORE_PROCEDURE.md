# Production Database Restore Procedure

1. Put the Railway service in maintenance/stop it so no application process is writing to SQLite.
2. Preserve the current `/data/instance/school.db` as a separate rollback copy before replacing anything.
3. Select a backup whose integrity status is `OK` in the Super Admin Backup dashboard.
4. Replace the production database with the verified backup file only while the service is stopped.
5. Start the service and allow the normal migration lock/startup checks to run.
6. Confirm `/healthz`, Super Admin login, school login, tenant isolation, and recent audit entries.
7. If verification fails, stop the service and restore the preserved rollback copy.

Never delete the Railway Volume as part of a database restore.
