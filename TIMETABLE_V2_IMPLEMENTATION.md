# Automated Timetable Generator v2

The legacy period/entry timetable is no longer the active timetable implementation.
The active model follows the supplied automated timetable specification:

- `ScheduleSlot = WHEN`: one chronological school-day timeline containing TEACHING, BREAK, ASSEMBLY, ACTIVITY and OTHER slots.
- `TimetableEntry = WHAT + WHO + WHERE`: class/arm, subject, teacher and room reference a schedule slot instead of duplicating times.
- Tenant/school scoping is applied to all active timetable queries and writes.
- Academic session/term, school days, schedule templates, subject requirements, teacher assignments, availability, workload profiles, rooms, versions, conflicts, approvals and audit tables are present.
- Generation creates a new draft/version and never silently overwrites a published timetable.
- Validation blocks teacher/class/room collisions, unavailable teachers, invalid teacher assignments, non-teaching slots and unmet weekly/daily requirements.
- Double/triple-period requirements are checked for consecutive teaching slots and cannot cross breaks.
- Manual draft editing revalidates after every saved change.
- Version lifecycle supports DRAFT, SAVED, VALIDATED, SUBMITTED, UNDER_REVIEW, CHANGES_REQUESTED, REJECTED, APPROVED, PENDING_PUBLICATION, PUBLISHED, SUPERSEDED and ARCHIVED states through the available workflow actions.
- Rejected/published versions require a new revision.
- Parent/student-facing timetable views use the published v2 timetable only.
- PDF, Excel and CSV export are available with role checks.
- New timetable entities are marked syncable so the existing offline/synchronization architecture remains intact.

Legacy `timetable_periods` / `timetable_entries` tables are retained only as compatibility storage for older databases and offline clients; they are not used by the new online timetable UI.
