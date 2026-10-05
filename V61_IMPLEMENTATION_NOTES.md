# V61 — notes

## Install (same as before)
1. Back up your database (`instance/school.db` or your DATA_DIR copy).
2. Unzip over the project folder (leave `instance/` alone) and reload the web app. The database upgrades itself on first start.
3. Check `select * from migration_notes;` — if it lists a skipped unique index, old data has duplicates to clean up.

## Root causes found
* **School Setup 500** — `/admin/setup-wizard` called a helper (`count`) that did not exist, and `table_exists` was never imported. Both fixed.
* **Multi-School Control Centre 500** — same missing import; the page is also hardened so one bad school row cannot break it.
* **Timetable "Day" empty** — schools created before the timetable existed had no school-day rows. Days are now created for every school and re-checked on each visit. The slot form also stored the "teachable" flag inverted (breaks were teachable, lessons were not); fixed and repaired by the migration.
* **Score Change History empty** — the old log was never written by the save path and the page read the wrong term. Replaced by an append-only `score_audit` table written in the same transaction as every score change (form and CSV).
* **Dashboard search** — the bar was static markup. Now a real, tenant- and RBAC-scoped search (`/api/search`, `/search`).
* **Print** — a dedicated `/result/<id>/print` page contains only the result sheet (A4, shared CSS). PDF uses the same settings.

## New
Student login (identifier + first-login class code), class code management, student account page, staff name history + admin notice,
auto next term / session, educational domains, overall/subject position toggles, 4 result templates + branding, passport in header,
analytics charts (SVG, no CDN), Super Admin subscriptions with history, simplified Super Admin menu.

## Tests
`python tests/v61_scenarios.py` (289 checks) and `python tests/v60_scenarios.py` (213 checks), plus the original suite (46).
