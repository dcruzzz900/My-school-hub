# School Results UI/UX Functionality Map — v45

The existing Flask functionality is retained and rearranged into the approved navigation architecture.

## Admin / Sub-admin
- Dashboard: school overview, AI entry point, setup and branding
- Academic: Students, Teachers, Classes, Subjects, Results, Attendance, Timetable, Learning Materials, Reports
- School Management: Parents, Grading, Sessions & Terms, Promotion
- Intelligence: AI Assistant, Parent Messages, Notifications
- Administration: Theme & Branding, School Setup, Billing, Settings

## Teacher / Staff
- Dashboard
- My Classes / score entry
- Results and broadsheets
- Attendance
- Timetable
- Learning Materials
- Reports
- Parent Messages
- AI Assistant
- Notifications
- Settings / offline access

## Student
- Dashboard
- Published Results
- Learning Materials
- AI Tutor
- Notifications
- Profile and account functionality remain available through existing screens

## Parent
- Parent Dashboard
- My Children
- Child Result / Result PDF
- Attendance
- Timetable
- Notifications
- Parent/Teacher messaging from the child context
- AI consent from the child context

## Platform Admin
- Dashboard
- Schools / Provisioning / Verification
- Users
- Roles
- Billing / Subscriptions
- Backups
- Security Audit
- Audit
- Notifications

## AI
The AI Command Center is the common intelligence entry point. Feature screens remain role/permission scoped:
Result Analysis, Teacher Comments, Principal Comments, Performance Alerts, AI Tutor, Learning Materials, Result Assistant, AI Privacy & Consent.

## Preservation rule
This pass changes navigation and information architecture only; existing routes, models, database logic, RBAC, tenant isolation, offline/sync endpoints and result calculations are preserved.
