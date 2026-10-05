# AI-Powered School Results — UI/UX & Architecture

This release integrates the AI layer into the existing Flask School Results application. It does not replace the core results, attendance, RBAC, multi-school, billing or offline systems.

## UI structure

- **AI Command Center**: Result Analysis, Teacher Comments, Principal Comments, Performance Alerts, AI Tutor, Learning Materials and Result Assistant.
- **AI Privacy & Consent**: school-level activation, per-feature switches, student consent, retention and audit activity.
- **AI Draft Review**: generated comments/analysis are explicitly labelled as drafts and require authorized human review.
- **Theme & Branding**: school-specific dashboard color tokens and theme presets with preview.
- **Login/Onboarding**: role-oriented login UI, School ID/Tenant ID field, school registration and staff registration where only names are required and other profile fields are optional.

## Security flow

`Authentication -> RBAC -> Tenant check -> AI enabled -> Feature enabled -> Required consent -> Data minimization -> AI service -> Output validation -> Human review`

AI queries are always constrained to the authenticated school. The AI provider never receives direct database access.

## Offline / online

The existing offline app remains the operational data-entry layer. AI-generated outputs can be stored server-side and surfaced through the same portal; the optional external provider is server-configured and never exposed to the browser. Normal results, attendance and calculations continue to work without AI.

## Provider configuration

AI is provider-independent. For a production external provider, configure server environment variables such as:

- `AI_API_URL`
- `AI_API_KEY`
- `AI_MODEL`

If these are absent, the application still provides deterministic local analysis, comments, alerts and learning-material scaffolding. No API key is required in the frontend.

## Human control

The AI layer never directly changes marks, grades, attendance, promotion status or finalized results. AI comments and recommendations are stored as drafts until an authorized staff member reviews and approves them.

## v41 Parent Portal consolidation
The AI layer now sits alongside a dedicated tenant-scoped Parent Portal. Parent accounts are separate from staff RBAC; parent-child links, published results, attendance, timetable and parent/teacher conversations are scoped by school. Parent login is available through the unified login screen.
