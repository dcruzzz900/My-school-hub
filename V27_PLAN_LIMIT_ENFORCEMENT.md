# V27 — Automated Plan-Limit Enforcement & Usage Alerts

## Purpose
V27 adds safe, server-side subscription-limit enforcement for student and teacher creation. It does not delete or modify existing records when a limit is reached.

## Enforcement
- Active/trial/grace schools may create records only within configured plan limits.
- Expired, suspended, or cancelled subscriptions cannot create new students/teachers.
- Legacy schools remain unlimited.
- Single-student creation and CSV student import enforce the student limit.
- Teacher creation enforces the teacher limit.
- Offline requests receive a structured error instead of silently creating over-limit records.

## Alerts
- 80%+ usage: warning.
- 100% usage: limit reached.
- Subscription/trial with 14 days or less: warning.
- `/api/subscription-status` exposes only non-sensitive plan/usage information to authorized school admins/sub-admins.

## Data safety
No migration resets the database. Existing records are preserved.
