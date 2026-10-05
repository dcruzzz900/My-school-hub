# Railway Production Checklist

## Required environment variables
- `SECRET_KEY`: stable, long random secret. Never commit it.
- `DATA_DIR`: mount your Railway persistent volume path (for example `/data`).
- `SKIP_DEMO_SEED=1`: prevents demo seeding in production.
- `PORT`: supplied by Railway.

## Database and uploads
The application stores SQLite and uploaded/generated files under `DATA_DIR` when configured. Use a persistent Railway volume; do not rely on the container filesystem for production data.

## AI
Keep AI disabled until the school has completed the privacy/consent configuration. Store provider credentials only as server environment variables.

## First deployment
1. Create/attach the Railway persistent volume.
2. Set `DATA_DIR` to its mount path.
3. Set `SECRET_KEY` and `SKIP_DEMO_SEED=1`.
4. Deploy.
5. Open `/healthz`.
6. Confirm the database migration completes without errors.
7. Log in and verify the tenant/school context.
8. Verify a parent account and `parent_students` relationship before enabling the parent portal.
9. Enable AI only after reviewing AI & Privacy settings.

## Recovery
Before schema changes, take a database backup. If a stale migration marker exists while a Parent Portal table is missing, the startup migration repair recreates the missing Parent Portal tables/indexes without dropping existing data.
