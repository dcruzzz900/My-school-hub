"""Bridges a real Django HttpRequest to ``school.core.dispatch()``.

The application's 300 routes, request hooks, CSRF check, Jinja templates and every view function are unchanged from
``app.py`` / ``v61_routes.py`` / ``profile_routes.py`` / ``registrar.py`` / ``billing_finalization.py`` - this module's
only job is translation at the edges:

* Django's ``HttpRequest`` is wrapped in ``_ReqAdapter`` so it exposes the small Flask-style surface
  (``request.form``, ``request.args``, ``request.files``, ``request.headers`` ...) that the application code reads.
* Django's ``request.session`` (itself backed by ``SESSION_ENGINE`` in settings.py) is handed to ``dispatch()`` as the
  session backend, so ``session["x"] = y`` in application code writes straight into Django's real session store.
* The ``school.core.Response`` the dispatcher returns is converted to a Django ``HttpResponse``/``FileResponse``.
"""
from __future__ import annotations

import mimetypes

from django.http import FileResponse, HttpResponse, HttpResponseNotFound

from school.core import current_app_obj, dispatch


class _HeaderAdapter:
    """Case-insensitive read access over a Django ``HttpHeaders`` object, with the Flask-style ``.get()`` default."""

    def __init__(self, django_headers):
        self._h = django_headers

    def get(self, key, default=None):
        return self._h.get(key, default)

    def __getitem__(self, key):
        return self._h[key]

    def __contains__(self, key):
        return key in self._h


class _FileAdapter:
    """Flask's ``FileStorage``-shaped wrapper over a Django ``UploadedFile``."""

    def __init__(self, f):
        self._f = f
        self.filename = f.name
        self.content_type = f.content_type
        self.stream = f

    def save(self, dst):
        with open(dst, "wb") as out:
            for chunk in self._f.chunks():
                out.write(chunk)

    def read(self, *a):
        return self._f.read(*a)

    def seek(self, *a):
        return self._f.seek(*a)

    def tell(self):
        return self._f.tell()


class _FilesAdapter:
    def __init__(self, django_files):
        self._files = django_files

    def get(self, key, default=None):
        f = self._files.get(key)
        return _FileAdapter(f) if f else default

    def getlist(self, key):
        return [_FileAdapter(f) for f in self._files.getlist(key)]

    def __contains__(self, key):
        return key in self._files


class _ReqAdapter:
    """Flask-style ``request`` built from a Django ``HttpRequest``."""

    def __init__(self, django_request):
        self._r = django_request
        self.method = django_request.method
        self.path = django_request.path
        self.full_path = django_request.get_full_path()
        self.query_string = django_request.META.get("QUERY_STRING", "")
        self.headers = _HeaderAdapter(django_request.headers)
        self.remote_addr = django_request.META.get("REMOTE_ADDR")
        self.host = django_request.get_host()
        self.is_secure = django_request.is_secure()
        self.scheme = "https" if self.is_secure else "http"
        self.url = django_request.build_absolute_uri()
        self.referrer = django_request.META.get("HTTP_REFERER")
        self.content_length = django_request.META.get("CONTENT_LENGTH")
        self.cookies = django_request.COOKIES
        self.files = _FilesAdapter(django_request.FILES)
        ctype = (django_request.content_type or "").split(";")[0].strip()
        self.is_json = ctype == "application/json"
        if self.method in ("POST", "PUT", "PATCH", "DELETE") and not self.is_json:
            self.form = django_request.POST
        else:
            from werkzeug.datastructures import MultiDict
            self.form = MultiDict()
        self.args = django_request.GET
        from werkzeug.datastructures import CombinedMultiDict
        self.values = CombinedMultiDict([self.args, self.form])

    def get_data(self, cache=True, as_text=False):
        data = self._r.body
        return data.decode("utf-8", "replace") if as_text else data

    def get_json(self, silent=False, force=False):
        import json
        try:
            return json.loads(self._r.body.decode("utf-8"))
        except ValueError:
            if silent:
                return None
            raise


def handle(django_request):
    app = current_app_obj()
    req = _ReqAdapter(django_request)
    resp = dispatch(app, req, django_request.session)
    if resp.file_path:
        f = open(resp.file_path, "rb")
        django_resp = FileResponse(f, status=resp.status_code)
    else:
        django_resp = HttpResponse(resp.data, status=resp.status_code)
    for key, value in resp.headers.items():
        if key.lower() == "content-length" and resp.file_path:
            continue   # FileResponse sets this itself by streaming the file
        django_resp[key] = value
    for key, value, kwargs in resp.cookies:
        if value == "" or kwargs.get("max_age") == 0:
            django_resp.delete_cookie(key, path=kwargs.get("path", "/"))
        else:
            django_resp.set_cookie(key, value, **{k: v for k, v in kwargs.items() if k != "max_age"} | (
                {"max_age": kwargs["max_age"]} if "max_age" in kwargs else {}))
    return django_resp
