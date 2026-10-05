"""Test harness that runs the application's real dispatcher without Django.

It builds a WSGI environ with Werkzeug, parses it with Werkzeug's request object (which has exactly the Flask-style
``form`` / ``args`` / ``files`` / ``headers`` surface the dispatcher expects), keeps the session in a signed cookie and
hands the resulting ``Response`` back. Everything the application does between "request arrives" and "response leaves"
is therefore exercised for real; only Django's own HTTP glue (see ``school.django_glue``) is not.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from urllib.parse import urljoin, urlsplit

from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.datastructures import MultiDict
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from school.core import dispatch
from school.testing import TestResponse, _Hdr


class WerkzeugClient:
    SESSION_COOKIE = "sessionid"

    def __init__(self, app):
        self.app = app
        self.cookies: dict[str, str] = {}
        self._ser = URLSafeSerializer((app.secret_key or "test-secret"), salt="school-session")

    # -- session cookie
    def _load(self):
        raw = self.cookies.get(self.SESSION_COOKIE)
        if not raw:
            return {}
        try:
            return dict(self._ser.loads(raw))
        except BadSignature:
            return {}

    def _store(self, sess):
        if sess:
            self.cookies[self.SESSION_COOKIE] = self._ser.dumps(sess)      # raises if something is not JSON-serialisable
        else:
            self.cookies.pop(self.SESSION_COOKIE, None)

    @contextmanager
    def session_transaction(self):
        sess = self._load()
        yield sess
        self._store(sess)

    # -- requests
    def open(self, path, method="GET", data=None, headers=None, follow_redirects=False, content_type=None, query_string=None, **kw):
        history = []
        for _ in range(20):
            resp = self._once(path, method, data, headers, content_type, query_string)
            if follow_redirects and resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                history.append(resp)
                path = urljoin(path, resp.headers.get("Location"))
                parts = urlsplit(path)
                path = parts.path + (("?" + parts.query) if parts.query else "")
                if resp.status_code in (301, 302, 303):
                    method, data, content_type = "GET", None, None
                query_string = None
                continue
            resp.history = history
            return resp
        raise RuntimeError("Too many redirects")

    def _once(self, path, method, data, headers, content_type, query_string):
        if isinstance(data, list):
            data = MultiDict(data)
        builder = EnvironBuilder(path=path, method=method.upper(), data=data, headers=headers, content_type=content_type,
                                 query_string=query_string, environ_base={"REMOTE_ADDR": "127.0.0.1"})
        environ = builder.get_environ()
        if self.cookies:
            environ["HTTP_COOKIE"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        req = Request(environ)
        sess = self._load()
        before = json.dumps(sess, sort_keys=True)
        resp = dispatch(self.app, req, sess)
        if json.dumps(sess, sort_keys=True) != before:
            self._store(sess)
        for key, value, kwargs in resp.cookies:
            if value == "" or kwargs.get("max_age") == 0:
                self.cookies.pop(key, None)
            else:
                self.cookies[key] = value
        return TestResponse(resp.status_code, _Hdr({k: v for k, v in resp.headers.items()}), resp.data)

    def get(self, path, **kw):
        return self.open(path, "GET", **kw)

    def post(self, path, **kw):
        return self.open(path, "POST", **kw)

    def put(self, path, **kw):
        return self.open(path, "PUT", **kw)

    def delete(self, path, **kw):
        return self.open(path, "DELETE", **kw)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
