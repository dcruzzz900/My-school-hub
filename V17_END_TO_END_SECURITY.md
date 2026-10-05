# V17 — End-to-End Security & Tenant Isolation

V17 is the final security regression layer before production pilot deployment.
It tests the complete trust boundary:

`User → School → Tenant → Role → Scope → Permission → Data → Offline Device → Sync`

## Security invariants

1. A school user's tenant is derived from the authenticated account/session.
2. `tenant_id` and `school_id` supplied by a browser, URL, form, or offline payload are never treated as authorization.
3. School A cannot read or mutate School B records by changing IDs.
4. Offline device credentials remain bound to their enrolled tenant.
5. Sync rejects cross-tenant record mutation.
6. School Admin/Sub-Admin cannot enter platform/Super Admin routes.
7. Suspended schools cannot authenticate through the normal school login.
8. Failed attack attempts must not mutate the target school's records.
9. Platform-level administration is separate from school-level administration.
10. Existing production data must never be reset as part of testing or deployment.

## Running the V17 tests

Run inside a development/test environment, never against the production database:

```bash
python -m pytest tests/test_v17_end_to_end_isolation.py -q
```

If the project's dependencies are not installed, install the pinned dependencies from `requirements.txt` first.

## Railway safety

- Do not delete or recreate the Railway Volume.
- Do not delete `school.db`.
- Keep the production `SECRET_KEY` unchanged during an update.
- Deploy to a staging/test service first when possible.
- Run migrations using the application's migration mechanism; do not manually drop tables.
- Take a verified database backup before a production deployment.

## Interpretation

A passing V17 suite means the tested attack paths were rejected in the isolated test database. It does not replace a professional penetration test or a review of newly added application code.
