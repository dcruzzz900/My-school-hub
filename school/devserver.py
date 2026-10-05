"""Tiny standalone dev server (``python app.py``) for manual testing without Django or gunicorn.

Not used in production (see Procfile / wsgi) and not exercised by the test suites, which use the test clients in
school.testing instead.
"""
from werkzeug.serving import run_simple
from werkzeug.wrappers import Request

from school.core import dispatch
from itsdangerous import URLSafeSerializer, BadSignature
import json


def run_dev_server(app, host="0.0.0.0", port=5050, debug=False):
    ser = URLSafeSerializer(app.secret_key, salt="school-session")

    def wsgi_app(environ, start_response):
        req = Request(environ)
        raw = req.cookies.get("sessionid")
        try:
            sess = dict(ser.loads(raw)) if raw else {}
        except BadSignature:
            sess = {}
        before = json.dumps(sess, sort_keys=True)
        resp = dispatch(app, req, sess)
        headers = list(resp.headers.items())
        if json.dumps(sess, sort_keys=True) != before:
            if sess:
                headers.append(("Set-Cookie", f"sessionid={ser.dumps(sess)}; Path=/; HttpOnly"))
            else:
                headers.append(("Set-Cookie", "sessionid=; Path=/; Max-Age=0"))
        status = f"{resp.status_code} {resp.headers.get('X-Status-Text', '')}".strip()
        start_response(f"{resp.status_code} OK", headers)
        return [resp.data]

    run_simple(host, port, wsgi_app, use_reloader=debug, use_debugger=debug)
