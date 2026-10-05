# Timetable replacement — v2

Replaced the active legacy timetable UI/model with the supplied Automated Timetable Generator specification.

## Active online timetable
- Tenant/school scoped automated timetable setup.
- Unified `ScheduleSlot` timing model for teaching, breaks, assembly, activities and other slots.
- Class/arm, subject, teacher assignment, teacher availability, workload and room entities.
- Weekly/daily subject requirements.
- Draft/version lifecycle with validation, submission, review, approval, rejection, revision and publication.
- Published timetable protection: published versions are not directly edited.
- Manual draft editing with revalidation.
- Conflict detection for teacher, class, room, availability, slot type, assignment eligibility and requirement coverage.
- Double/triple-period continuity checks.
- PDF, Excel and CSV export.
- Parent/student timetable views use the published v2 version.

## Offline preservation
The existing legacy timetable tables are retained for compatibility with older offline clients. The new timetable tables are sync-enabled for the future offline/synchronization phase and the existing offline architecture is not removed.
