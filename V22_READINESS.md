# V22 — School Configuration & Readiness Gate

V22 adds a non-destructive readiness state to each school. A School Admin must complete the required configuration checks and explicitly mark the school **READY FOR LIVE DATA**.

Required checks include school identity, activation, academic session/term, classes, subjects, class-subject assignments, active teachers, active roles/scopes, students, active administrator and grading bands.

Result term publication is blocked until the school is marked ready. Existing records are not deleted or reset.

## Existing production data
Do not delete or recreate the Railway volume or `school.db`. Deploy normally and allow the migration framework to add the readiness columns.
