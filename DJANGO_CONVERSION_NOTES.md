# Django conversion — status

## The constraint this was built under

**This sandbox has no internet access and Django is not installed, and I was not able to install it.**
I could not run `manage.py`, Django's test client, or any actual Django request through this code. Everything
below marked "Verified" was run for real, in this environment. Everything marked "Not verified" is code I wrote
carefully and checked for syntax and consistency, but have never executed. Please install Django and run the test
commands near the bottom before trusting this in production.

## The approach

Rewriting ~17,000 lines, 300 routes and 150 templates directly into Django views/urls/Django-template-language would
have meant a blind rewrite with nothing to check it against. Instead:

1. **`school/core.py`** — a small, framework-neutral re-implementation of exactly the slice of Flask this
   application uses (`@app.route`, `request`, `session`, `g`, `flash`, `url_for`, `render_template` on the existing
   Jinja2 environment, `redirect`, `jsonify`, `send_file`, CSRF/before/after hooks, error handlers, blueprints). It
   has **no dependency on Flask or Django** — just Jinja2, MarkupSafe and the standard library.
2. **`app.py`, `v61_routes.py`, `profile_routes.py`, `registrar.py`, `billing_finalization.py`** now import from
   `school.core` instead of `flask`. Every view function, every route, every template is **completely unchanged**.
3. **`school/django_glue.py`** adapts a real Django `HttpRequest` into the small request surface `school.core`
   expects, and turns the `Response` the dispatcher returns into a Django `HttpResponse`/`FileResponse`. Django's own
   session middleware (`SESSION_ENGINE`) backs `session[...]` directly.
4. **`config/`** — a minimal Django project (`settings.py`, `urls.py`, `wsgi.py`, `manage.py`) whose URLconf is a
   single catch-all that hands every request to `school.django_glue.handle()`.
5. **`school/testing_werkzeug.py`** — a second backend for the exact same `school.core.dispatch()` function, built on
   Werkzeug instead of Django. This is what let me **prove the core dispatcher, CSRF, sessions, routing, templates,
   and all 300 views are correct**, without having Django available.

Your application's database layer (`db.py`, raw `sqlite3`, 101 tables, 154 triggers) is untouched — it still talks to
the same SQLite file the same way. Converting that to the Django ORM is a separate, much larger project; see
"Not done" below.

## Verified (really run, in this sandbox, today)

```
python tests/v62_scenarios.py   → 622 checks, 0 failed
python tests/v60_scenarios.py   → 213 checks, 0 failed
the 47 tests/test_*.py files    → all pass
```

These exercise the full request cycle through `school.core.dispatch()` — routing, the before/after hooks, CSRF,
sessions, file uploads, PDF generation, every permission check, every template — for every one of the 300 routes
touched by the suites. This is the same dispatcher Django will call; only the outer Django/WSGI skin is unverified.

## Not verified (written, not run)

- `config/settings.py`, `config/urls.py`, `config/wsgi.py`, `manage.py`
- `school/django_glue.py` (the Django ↔ `school.core` adapter)
- `school/testing.py`'s `DjangoTestClient` (a Flask-test-client-shaped wrapper over `django.test.Client`, meant to
  let the *same* `tests/v62_scenarios.py` run against real Django once it's installed — see below)
- Static file serving through `django.contrib.staticfiles` (the app currently serves `/static/<path>` itself via
  `school.core`, which also works stand-alone; I didn't switch to Django's static handling, deliberately, so nothing
  here depends on it being right)
- `Procfile` (now `gunicorn config.wsgi:application`) and `requirements.txt` (now lists `Django>=5.0` instead of
  `Flask>=3.0`, plus `itsdangerous`/Jinja2/MarkupSafe pinned explicitly since Django doesn't pull them in)

## What to do once Django is available

```bash
pip install -r requirements.txt
python manage.py check                         # catches settings/import mistakes immediately
python manage.py runserver 0.0.0.0:5050         # manual smoke test — this now serves the whole app
SCHOOL_TEST_BACKEND=django python tests/v62_scenarios.py   # same 622-check suite, through real Django this time
SCHOOL_TEST_BACKEND=django python tests/v60_scenarios.py
```

If `SCHOOL_TEST_BACKEND=django` run reveals bugs in `django_glue.py` or `settings.py`, the Werkzeug-backed run
(`SCHOOL_TEST_BACKEND=werkzeug`, or just unset — it's the default) still passes, which narrows the bug to the
Django-specific ~250 lines rather than the application itself.

## Known rough edges to expect

- **File uploads in `DjangoTestClient._prepare`**: I handle plain dicts, lists of pairs and Werkzeug `MultiDict`s,
  and file tuples `(BytesIO, filename)`. The existing suite's patterns are covered, but I have not run it, so a
  subtly different shape could surface a bug there specifically (not in the application).
- **`send_file` / `FileResponse`**: PDF/CSV/XLSX downloads go through Django's `FileResponse` when streamed from a
  real file path, and a plain `HttpResponse` for in-memory buffers (`io.BytesIO`) — both paths exist in the app
  (e.g. result PDFs are in-memory; some document downloads are from disk). Only the in-memory path is exercised by
  the Werkzeug-backed suite; the on-disk path (`send_file(path, ...)`, `send_from_directory`) needs a real check.
- **Cookie flags**: Django's `set_cookie`/`delete_cookie` signatures differ slightly from Werkzeug's; I mapped the
  kwargs the app actually uses (`max_age`, `path`), but an edge case (e.g. `domain=`) isn't exercised anywhere in
  the current code, so it's untested rather than unsupported.
- **`DATABASES` in `settings.py`** points at a throwaway SQLite file Django itself never reads from or writes to —
  it exists only because some `manage.py` subcommands assume `DATABASES` is configured. The application's real data
  continues to live in `instance/school.db` / `DATA_DIR`, read through `db.py` exactly as before.

## Not done (separate, larger project if you want it)

- **Django ORM models for the 101 tables.** Everything still runs on raw `sqlite3` through `db.py`. Moving to the
  ORM means writing/generating 101 models, replacing 1,061 raw SQL calls, and — this is the part that needs care —
  re-expressing the 154 database triggers (append-only audit tables, the permanent School ID, immutable attendance
  timestamps) as Django-level enforcement, since triggers don't travel through `inspectdb`.
- **Django template language.** The 150 templates still render through the original Jinja2 environment
  (`school.core.render_template`), not `django.template`. This is why none of the ~565 Jinja calls-with-arguments,
  97 `.get()` filters, or 156 inline `if/else` expressions needed rewriting — but it also means Django's template
  tooling (admin, debug toolbar's template panel) won't see these templates as Django templates.
- **Django admin.** Not wired up (it needs ORM models to be useful).
