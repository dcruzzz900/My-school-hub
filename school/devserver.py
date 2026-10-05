"""Tiny standalone dev server (``python app.py``) for manual testing without Django or gunicorn.
Not used in production (see Procfile / config/wsgi.py) and not exercised by the test suites, which use the test
clients in school.testing instead. Thin wrapper now that SchoolApp is itself a real WSGI callable (see school/core.py).
"""
from werkzeug.serving import run_simple


def run_dev_server(app, host="0.0.0.0", port=5050, debug=False):
    run_simple(host, port, app, use_reloader=debug, use_debugger=debug)
