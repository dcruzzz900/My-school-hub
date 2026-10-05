# V60 — Profiles, custom fields, RBAC roles, online-only

## Install (PythonAnywhere Bash console or Railway redeploy)
1. Back up first: copy `instance/school.db` (or your DATA_DIR database) somewhere safe.
2. Unzip over the existing project folder (keeps `instance/` untouched) and reload the web app.
3. The database migrates itself on first start (schema version +1). Nothing to run by hand.
4. Check the migration notes: `sqlite3 instance/school.db "select * from migration_notes;"`
   If it lists a skipped unique index, your old data already contains duplicates (e.g. the same
   admission number in two classes of one school). New duplicates are still blocked by database
   triggers; fix the old rows and restart to create the index.

## What changed
* Student login crash: the login query referenced `students.email`, a column that did not exist. Added by migration;
  login now also refuses ambiguous identifiers, logs technical errors server-side and re-checks tenant on every request.
* Profiles: `/student/profile` (student self-service), `/students/<id>/profile/edit` (admin / form teacher / registrar),
  `/staff/<id>/edit` (own profile, or School Admin). One validation + audit engine in `profile_core.py`,
  routes in `profile_routes.py`.
* Uniqueness: DB triggers + indexes (tenant-aware, case-insensitive) for admission no., staff username, email, staff ID,
  and unique custom-field values.
* Custom fields: Administration -> Custom Fields (overview, add, edit, details, reorder, activate, archive, delete-if-unused).
* Audit: `rbac_audit_log` plus triggers making it, `audit_log`, `role_assignment_audit` and `security_events` append-only.
* Roles added: Registrar / Admissions Officer, Attendance Officer, Front Desk / Reception Officer, and standard names for
  Vice Principal / Deputy Principal, HOD, Examination Officer, Guidance/Counselling Officer, Bursar / Accountant,
  ICT / System Support Officer. Old names keep working for existing accounts.
* Online-only: offline app, sync API, queue, conflict screen, device credentials and offline JS removed. The old service
  worker is replaced by a self-removing one; `online-only.js` shows a connection error and blocks submits when offline.

## Tests
`python tests/v60_scenarios.py` (213 checks, real HTTP requests on a fresh DB) and the existing suite.
