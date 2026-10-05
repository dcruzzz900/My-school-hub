# V52 Enhancements Release Notes

This package is based on `school-results-v52-school-branded-auth.zip` and integrates the requested system enhancements.

## Validation performed
- Python AST/compile checks: passed for `app.py`, `db.py`, and `pdf_utils.py`.
- Template `url_for()` static endpoint audit: 197 references checked; no missing application endpoints (excluding the expected `static` helper).
- New migration is idempotent and adds V52 enhancement tables/columns through the existing `schema_steps` migration framework.
- Oversized upload rejection occurs before the application saves the file.

## Runtime limitation
The current build environment does not contain the project's Flask/Werkzeug runtime dependencies, so a live browser/HTTP test and live database migration could not be executed here. Deploy and run the included production dependencies on Railway for the final runtime gate.
