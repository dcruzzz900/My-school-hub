# V20 — School Setup Wizard

V20 adds a non-destructive setup wizard for authenticated School Admin/Sub-Admin users.

## Sequence

1. School profile
2. School logo (optional)
3. School level
4. Academic session
5. Academic term
6. Classes and arms
7. Subjects
8. Class-subject assignments
9. Teachers
10. Roles and scopes
11. Students
12. School administrator verification
13. Grading/result configuration review
14. Result design/signature review

The wizard is a checklist and navigation layer. It does not automatically delete, reset, or replace existing school data.

## Production safety

- Do not delete the Railway Volume.
- Do not replace the production database with a blank database.
- Take a verified backup before major setup changes.
- Verify School ID and Tenant ID before inviting staff.
- Verify role scopes before allowing score entry.
