# v52 Production Candidate

This release freezes the current architecture and consolidates the UI/UX and functionality work rather than adding another feature branch.

Highlights:
- Screen-by-screen UI/UX architecture aligned with existing Flask functionality.
- Admin, staff, student and parent navigation organized around their actual workflows.
- Parent dashboard/My Children and parent-teacher messaging integrated.
- AI Command Center, tutor, learning materials, result analysis, comments, alerts and result assistant integrated behind privacy/RBAC checks.
- School theme/branding and result-sheet customization retained.
- Offline/sync and Railway migration hardening retained.
- Production health/readiness tooling and release checklist included.

Validation performed in the packaging environment:
- pytest: 19 passed
- Python compilation: passed
- Jinja templates: 108 parsed, 0 errors
- ZIP integrity: passed

The final live deployment still requires runtime/browser QA against the project's actual dependency environment.

## V52 School-Branded Authentication

Added tenant-aware authentication branding with school logo watermarking,
per-school opacity/position/style controls, secure school lookup, dynamic
signup-code branding, student school-code validation, cache-safe logo updates,
and branded recovery/activation screens.
