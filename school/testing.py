"""Flask-style test clients for the application (so the existing scenario suites run unchanged).

* ``make_test_client(app)`` returns a Django-backed client when Django is configured, otherwise the Werkzeug-backed
  harness from ``school.testing_werkzeug`` (which runs the very same dispatcher without Django).
* Set ``SCHOOL_TEST_BACKEND=werkzeug`` or ``=django`` to force one.
"""
from __future__ import annotations

import io
import json
import os
from contextlib import contextmanager


class TestResponse:
    """Minimal response wrapper offering the attributes the suites use: status_code, headers, data, get_data, get_json."""

    def __init__(self, status_code, headers, data, history=()):
        self.status_code = status_code
        self.headers = headers
        self._data = data
        self.history = list(history)

    @property
    def data(self):
        return self._data

    @property
    def text(self):
        return self._data.decode("utf-8", "replace")

    def get_data(self, as_text=False):
        return self.text if as_text else self._data

    def get_json(self, silent=False):
        try:
            return json.loads(self.text)
        except ValueError:
            if silent:
                return None
            raise

    @property
    def location(self):
        return self.headers.get("Location")


def make_test_client(app, *args, **kwargs):
    backend = os.environ.get("SCHOOL_TEST_BACKEND")
    if backend is None:
        try:
            from django.conf import settings
            backend = "django" if settings.configured else "werkzeug"
        except ImportError:
            backend = "werkzeug"
    if backend == "django":
        return DjangoTestClient(app)
    from school.testing_werkzeug import WerkzeugClient
    return WerkzeugClient(app)


class DjangoTestClient:
    """Flask-test-client lookalike on top of ``django.test.Client`` (real Django request/response cycle)."""

    def __init__(self, app):
        from django.test import Client
        self.app = app
        self._c = Client(enforce_csrf_checks=False, raise_request_exception=False)

    # -- helpers
    @staticmethod
    def _prepare(data):
        """Flask-style form data (dict, list of pairs, MultiDict, (file, name) tuples) -> Django test client payload."""
        from django.core.files.uploadedfile import SimpleUploadedFile
        if data is None:
            return {}
        pairs = data.items(multi=True) if hasattr(data, "items") and "multi" in getattr(data.items, "__code__", type("x", (), {"co_varnames": ()})).co_varnames else (
            data.items() if hasattr(data, "items") else list(data))
        out: dict = {}
        for k, v in pairs:
            if isinstance(v, tuple) and len(v) >= 2 and hasattr(v[0], "read"):
                content = v[0].read()
                v = SimpleUploadedFile(v[1], content if isinstance(content, bytes) else content.encode())
            elif hasattr(v, "read") and hasattr(v, "name"):
                v = SimpleUploadedFile(os.path.basename(v.name), v.read())
            elif isinstance(v, io.BytesIO):
                v = SimpleUploadedFile("upload.bin", v.getvalue())
            out.setdefault(k, []).append(v)
        return {k: (vs[0] if len(vs) == 1 else vs) for k, vs in out.items()}

    @staticmethod
    def _extra(headers):
        extra = {}
        for k, v in (headers or {}).items():
            key = "CONTENT_TYPE" if k.lower() == "content-type" else "HTTP_" + k.upper().replace("-", "_")
            extra[key] = v
        return extra

    def open(self, path, method="GET", data=None, headers=None, follow_redirects=False, content_type=None, query_string=None, **kw):
        extra = self._extra(headers)
        if query_string:
            path += ("&" if "?" in path else "?") + (query_string if isinstance(query_string, str) else "&".join(f"{k}={v}" for k, v in query_string.items()))
        m = method.upper()
        if m in ("GET", "HEAD", "OPTIONS", "DELETE") and data is None:
            resp = self._c.generic(m, path, follow=follow_redirects, **extra)
        else:
            payload = self._prepare(data)
            from django.test.client import MULTIPART_CONTENT
            resp = self._c.generic(m, path, data=self._c._encode_data(payload, content_type or MULTIPART_CONTENT) if hasattr(self._c, "_encode_data") else payload,
                                   content_type=content_type or MULTIPART_CONTENT, follow=follow_redirects, **extra)
        hdrs = {k: v for k, v in resp.headers.items()}
        return TestResponse(resp.status_code, _Hdr(hdrs), resp.content, getattr(resp, "redirect_chain", []))

    def get(self, path, **kw):
        return self.open(path, "GET", **kw)

    def post(self, path, **kw):
        return self.open(path, "POST", **kw)

    def put(self, path, **kw):
        return self.open(path, "PUT", **kw)

    def delete(self, path, **kw):
        return self.open(path, "DELETE", **kw)

    @contextmanager
    def session_transaction(self):
        from django.conf import settings
        session = self._c.session
        yield session
        session.save()
        self._c.cookies[settings.SESSION_COOKIE_NAME] = session.session_key

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Hdr(dict):
    """Case-insensitive read access for response headers."""

    def get(self, k, default=None):
        for key, v in self.items():
            if key.lower() == k.lower():
                return v
        return default

    def __getitem__(self, k):
        for key, v in dict.items(self):
            if key.lower() == k.lower():
                return v
        raise KeyError(k)

    def __contains__(self, k):
        return any(key.lower() == k.lower() for key in dict.keys(self))
