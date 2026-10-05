# School Results — Final Production Candidate Checklist

This package is the consolidated UI/UX + functionality baseline for the School Results Flask application.

## Release gates

- [x] Core school result functionality retained
- [x] Multi-school tenant isolation retained
- [x] RBAC retained
- [x] Parent portal and My Children workflow included
- [x] AI layer integrated as an optional service layer
- [x] AI privacy/consent controls included
- [x] AI outputs remain drafts until authorized approval where required
- [x] AI cannot directly modify official marks, grades, attendance or finalized results
- [x] Offline/synchronization architecture retained
- [x] Railway migration recovery for missing parent tables included
- [x] Health endpoint included
- [x] Production configuration checker included
- [x] UI/UX route references audited
- [x] 108 Jinja templates parse successfully
- [x] Automated contract/regression tests pass in the build environment

## Railway deployment gates

Set these before production:

```text
SECRET_KEY=<stable-secret>
SKIP_DEMO_SEED=1
DATA_DIR=<persistent-volume-path>
```

Then verify:

1. Deploy the package without deleting the existing persistent database.
2. Run/allow application migrations.
3. Confirm `/healthz` returns healthy.
4. Confirm the Parent Portal tables exist.
5. Log in as each role and verify RBAC.
6. Verify School A cannot access School B data.
7. Confirm AI remains disabled until the school administrator activates it.
8. Configure an AI provider only on the server; never expose its credentials in frontend code.

## Final QA flows

### School administrator
Login → Dashboard → School Setup → Theme & Branding → Students → Staff → Parents → Results → Reports → AI & Privacy.

### Teacher
Login → Dashboard → Classes → Attendance → Results → AI Comments → Parent Messages → Reports.

### Student
Login → Dashboard → Results → Learning Materials → AI Tutor → Notifications.

### Parent
Login → Dashboard → My Children → Child Result → Attendance → Timetable → Messages → AI Consent.

### Super Admin
Login → Platform Dashboard → Schools → Tenant/RBAC → Billing → Backups → Security/Audit → System Health.

## Important production note

The build environment used for packaging does not contain the full production Flask dependency stack. Automated contract tests and static template/Python checks are therefore not a substitute for the final live Railway/browser QA. Perform the runtime smoke test after deployment.
