# Deploying on Railway

This app keeps its central multi-school database in one SQLite file. That is
fine for a school platform of this size, but it has two hard rules on Railway:

1. **The database must live on a Volume.** Railway's normal disk is wiped on
   every deploy. Without a Volume you will lose every school's data.
2. **Run exactly one worker process** (the included `Procfile` /
   `railway.json` already do: `--workers 1 --threads 8`). SQLite allows one
   writer at a time; several worker processes fight over it.

## Steps

1. Create a new Railway project from this folder (GitHub repo, or `railway up`).
2. In the service, add a **Volume** and mount it at `/data`.
3. Set these **Variables**:

   | Variable | Value |
   |---|---|
   | `DATA_DIR` | `/data` (database, logos, uploaded materials and the generated secret key all live here) |
   | `SECRET_KEY` | a long random string (`python -c "import secrets; print(secrets.token_hex(32))"`) |
   | `SKIP_DEMO_SEED` | `1` — **important**: otherwise a brand-new database is created with a demo school whose admin password is `admin123` |
   | `SESSION_COOKIE_SECURE` | `1` (Railway serves you over HTTPS) |

4. Deploy. Railway checks `/healthz` before switching traffic to the new version.
5. Create your first Super Admin (this is deliberately not possible from a web
   page). With the Railway CLI linked to the project:

   ```
   railway run python create_super_admin.py
   ```

   (Or open a shell on the service and run `python create_super_admin.py`.)
   Make sure `DATA_DIR=/data` is set in the shell you run it from so it opens the
   same database the web service uses.
6. Log in as Super Admin, create your schools, then create each school's admin.

## Backups

Run `python backup_db.py` daily (Railway cron service, or `railway run python backup_db.py`). It makes a
verified, consistent copy safe to take while the site is busy, into `/data/backups/`, and keeps the newest 14.

Manual alternatives:

Copy `/data/school.db` regularly (Railway volume backups, or a scheduled
`sqlite3 /data/school.db ".backup '/data/backup.db'"` followed by downloading
that file). A copy of the `materials/` folder and the logo files in `/data`
completes the picture.

## Moving from PythonAnywhere

Copy `instance/` from your PythonAnywhere app (it holds `school.db`, `secret_key.txt`,
`materials/` and logos) into the volume at `/data`. Keep the same `secret_key.txt`
(or set `SECRET_KEY` to its contents) so existing sessions and offline device
credentials keep working. The database upgrades itself to the latest version on first start.

## When you outgrow one SQLite file

Hundreds of schools writing at once, or a need to run more than one server
process, is the point to move the central database to PostgreSQL. This codebase
uses SQLite directly (raw SQL, triggers), so that is a real porting project, not a setting.
