# V63 — consolidated requirements (second round)

Tests: `python tests/v62_scenarios.py` → 622 checks, 0 failed (it is the cumulative scenario suite; name kept for continuity).
`python tests/v60_scenarios.py` → 213 passed. The 47 pytest-style files in `tests/test_*.py` pass.
Also checked in headless Chromium: result PDFs for all 5 templates (one page each), Super Admin header at 1366 px and 375 px (hamburger opens/closes).

## Done (requirement → what changed)
| # | Requirement | Status |
|---|---|---|
| 1 | Super Admin menu/header | Taller header (72 px) with search, notification bell (red count) and avatar; hamburger on phones; active item highlighted; every menu link tested (200); header search filters schools. |
| 2, 30 | No duplicate settings | Auth branding only in Theme & Branding; result colours/alignment/header only in Result Display Settings; School Profile keeps school information only (and says where the others live). A scan of all settings templates found no remaining duplicate controls except signup forms and Super Admin billing/subscription pages (see "Not done"). |
| 3 | Multiple roles | A staff member can hold any number of roles. Permissions combine; adding/removing a role is immediate and audited; all roles show on the staff dashboard and staff list. |
| 4 | School Admin | Not an assignable role anywhere (form and server both refuse). |
| 5 | Subject-based score entry | Score entry/CSV upload depend only on the class+subject assignment (and the school admin). A Discipline Master without an assignment cannot; with one, can. Other roles don't block entry. |
| 6 | Score audit | Every entered/edited/cleared/deleted/after-publication change records staff name, staff ID, all roles, subject, class, arm, student, previous/new score, action, date and time. School Admin sees it in Audit History; append-only. |
| 7 | Registrar / Admissions Officer | Dashboard, registration with generated admission and register numbers, class/arm, admission details, statuses (Active, Suspended, Transferred, Withdrawn, Graduated, Expelled + school-defined), transfers (date, destination, history kept), append-only status history, unique numbers per school. |
| 8 | Class Teacher / Form Teacher | Own class only: register (view/number), attendance, history, results, individual sheets, broadsheet (view/print). No score entry unless assigned the subject; no settings access. |
| 9–13 | Attendance | Server date/time in the school's timezone; future and backdated dates rejected with the exact messages; no date picker or time inputs; one record per student/staff per day; corrections need a reason and keep the original record/timestamp; the original timestamp/date are protected by database triggers; audit log of records, corrections and rejected attempts; statuses Present/Absent/Late/Excused. |
| 14, 15 | Notifications, date/time | Dashboard + menu show the unread count (red); unread items green, read neutral; mark one/all read updates every counter at once (staff, student, parent, Super Admin). Dashboard shows "Friday, 03/10/2026 — 7:02 PM" from the server clock in the school timezone (the device clock is not used). |
| 17 | Comments | Subject-teacher, Class-teacher and Principal comments are separate fields with separate auto-comment rules (carried over from V62). |
| 18–25 | Result sheet | Preview now renders the real result sheet (same template/settings/data) — the old mock preview is gone. Logo and text alignment are independent. Logo/passport/signature images over 600 KB used to vanish silently; they are now scaled instead (this was why the logo did not appear). Principal signature/date work before or after the class teacher saves. Passport is fitted without stretching or cropping. Every display toggle is tested for the sheet and the PDF. |
| 26 | Broadsheet styling | Screen, print and PDF broadsheets inherit the result sheet's colours, font, logo (same on/off switch) and alignments. |
| 27 | Student login | Username, Admission No. or Register No. + password. No class code. Account status is checked after the credentials (Suspended/Withdrawn/Transferred etc. get a clear message). Students with a missing class link get a clear message instead of "Invalid login details". |
| 28, 29 | Custom result fields | Admin adds/edits/enables/deletes fields (text, number, date, choice, yes/no; per-term or fixed); choose result sheet and/or student profile; values entered in the result editor; tenant-specific; a field holding data can only be switched off, not deleted. |
| 31 | Tenant isolation | Each new route/table is scoped by the session's school; cross-school attempts are tested for registrar, status, registers, attendance, custom fields, notifications, score audit, broadsheet. |

## Bugs found and fixed along the way
* Parent login crashed (database connection closed then reused).
* Three parent-message routes were accidentally removed during editing and were restored; a new test now fails if any template links to a route that does not exist.
* The CSRF check now also accepts the `X-CSRF-Token` header (needed by the new fetch() calls).

## Behaviour changes
* Roles now stack (V62 replaced the old role); score entry no longer looks at job titles.
* Class codes are no longer used for sign-in. The class-code pages still exist but nothing reads them (see below).
* Manual check-in/out times were removed from the staff attendance page (the self check-in button stamps server time).
* Result Display Settings URL: `/admin/result-display`. New pages: `/admin/result-fields`, `/registrar`, `/my-class/<id>/register`.
* Migrations (run automatically): `v63_attendance_integrity`, `v63_score_audit_fields`, `v63_custom_result_fields`, `v63_registrar`, `v63_notification_reads`.
* Admission and register number uniqueness is enforced per school by new database indexes; if an existing database already contains duplicates, the index is skipped (the registrar form still blocks duplicates).

## Not done / not verified
* Class Login Codes: kept as-is but now unused. The requirement says they are for "enrollment/linking"; no enrolment flow uses them yet — decide what they should do.
* Offline/device sync: the attendance and role changes were tested online only. If devices sync attendance offline, the sync code needs the same date rule.
* Super Admin billing vs subscription pages both set a plan/days; I did not merge them.
* The acceptance matrix was not run on real phones/tablets. Browser checks were headless Chromium only (result printing, Super Admin header). Safari/Firefox print was not tested.
* Result PDF is drawn by ReportLab, the on-screen sheet by HTML/CSS: the same data and settings feed both and tests compare their content, but they are not pixel-identical.
* Not exercised: Sub-Admin and Principal against every new page; staff signup page layout.
