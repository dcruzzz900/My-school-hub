# V52 System Enhancements

Integrated required fixes and enhancements:

- Strict upload limits: passport/staff photo 500 KB, signatures 500 KB, learning materials 1 MB, with frontend and backend validation.
- Pending school activation workflow: registration creates a permanent School ID/Tenant ID and admin account but does not issue an activation code. Platform reviewers receive activation notifications and explicitly approve before a secure single-use code is generated and delivered through the configured channel.
- School Dashboard and School Setup aliases resolve through the authenticated tenant context.
- Fixed Add Student POST workflow, validation, tenant stamping, immediate list visibility and clear errors.
- Teacher form now uses centralized RBAC roles and creates/updates scoped role assignments and permissions.
- Reports & Analytics dashboard with academic, grade, attendance and result-status insights plus school-scoped filters.
- Learning materials remain tenant/class/session scoped and are visible to authorized students/staff; 1 MB file limit enforced.
- School Admin notifications for staff signup, student account activation, parent signup, parent-child link requests, result submissions and publication.
- School profile controls remain under Theme & Branding; school name/logo are shown in the authenticated application shell.
- Automatic timetable generator with class/teacher conflict avoidance, configurable period counts and horizontal/vertical teacher views.
- Result-sheet independent toggles for Form Teacher name/signature and Principal name/signature across online result and PDF generation.
- Tenant isolation retained for all new records and queries.
