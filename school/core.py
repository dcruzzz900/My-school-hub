"""Framework-neutral core of the School Results application.

This module contains everything the application code needs that used to come from Flask, written so that it can sit on
top of Django (see ``school.django_glue``) *or* on a plain WSGI/Werkzeug test harness (``school.testing_werkzeug``):

* ``SchoolApp``   - route registry (``@app.route``), request hooks, error handlers, Jinja environment, config
* ``request`` / ``session`` / ``g``  - per-request proxies with the same behaviour the application already relies on
* ``flash``, ``redirect``, ``url_for``, ``render_template``, ``jsonify``, ``send_file``, ``send_from_directory``, ``abort``
* ``dispatch()``  - runs one request: route match -> before hooks -> view -> response -> after hooks -> error handlers

It imports neither Django nor Flask. The Django layer only has to provide a request object with the small Flask-style
surface documented in ``RequestLike`` and a session object that behaves like a dict.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
import datetime
import decimal
import io
import json
import logging
import mimetypes
import os
import re
import uuid
from urllib.parse import quote, urlencode, urljoin

import jinja2
from markupsafe import Markup, escape  # noqa: F401  (re-exported for application modules)

# --------------------------------------------------------------------------------------------------------------------
# HTTP errors
# --------------------------------------------------------------------------------------------------------------------

_STATUS_NAMES = {
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 409: "Conflict", 410: "Gone", 413: "Payload Too Large", 415: "Unsupported Media Type",
    422: "Unprocessable Entity", 429: "Too Many Requests", 500: "Internal Server Error", 503: "Service Unavailable",
}


class HTTPException(Exception):
    """Raised by ``abort()``; turned into a response by the matching error handler (or a plain default page)."""

    def __init__(self, code=500, description=None, response=None):
        super().__init__(f"{code} {_STATUS_NAMES.get(code, 'Error')}")
        self.code = int(code)
        self.description = description
        self.response = response

    @property
    def name(self):
        return _STATUS_NAMES.get(self.code, "Error")


def abort(code, description=None):
    raise HTTPException(code, description)


class BuildError(LookupError):
    """``url_for`` was asked for an endpoint (or arguments) that does not exist."""


# --------------------------------------------------------------------------------------------------------------------
# Headers / Response
# --------------------------------------------------------------------------------------------------------------------

class Headers:
    """Case-insensitive header mapping (``response.headers['X'] = ...``, ``.setdefault``, ``.get``, ``.add``)."""

    def __init__(self, initial=None):
        self._items: list[tuple[str, str]] = []
        if initial:
            for k, v in (initial.items() if hasattr(initial, "items") else initial):
                self.add(k, v)

    def _find(self, key):
        k = key.lower()
        return [i for i, (n, _v) in enumerate(self._items) if n.lower() == k]

    def __getitem__(self, key):
        idx = self._find(key)
        if not idx:
            raise KeyError(key)
        return self._items[idx[0]][1]

    def get(self, key, default=None):
        idx = self._find(key)
        return self._items[idx[0]][1] if idx else default

    def __setitem__(self, key, value):
        idx = self._find(key)
        if idx:
            self._items[idx[0]] = (key, str(value))
            for i in reversed(idx[1:]):
                del self._items[i]
        else:
            self._items.append((key, str(value)))

    def add(self, key, value):
        self._items.append((key, str(value)))

    def setdefault(self, key, value):
        idx = self._find(key)
        if idx:
            return self._items[idx[0]][1]
        self._items.append((key, str(value)))
        return str(value)

    def pop(self, key, *default):
        idx = self._find(key)
        if not idx:
            if default:
                return default[0]
            raise KeyError(key)
        v = self._items[idx[0]][1]
        for i in reversed(idx):
            del self._items[i]
        return v

    def __delitem__(self, key):
        self.pop(key)

    def __contains__(self, key):
        return bool(self._find(key))

    def getlist(self, key):
        return [v for n, v in self._items if n.lower() == key.lower()]

    def items(self):
        return list(self._items)

    def keys(self):
        return [n for n, _ in self._items]

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)


class Response:
    """A response the application builds. Converted to a real HTTP response by the Django glue / test harness."""

    default_mimetype = "text/html"

    def __init__(self, response=b"", status=200, headers=None, mimetype=None, content_type=None, file_path=None):
        self.status_code = int(status)
        self.headers = Headers(headers)
        self.cookies: list[tuple[str, str, dict]] = []
        self.file_path = file_path          # when set, the body is streamed from this path
        self._data = b""
        if isinstance(response, str):
            self._data = response.encode("utf-8")
        elif isinstance(response, (bytes, bytearray)):
            self._data = bytes(response)
        elif response is not None and not file_path:
            self._data = str(response).encode("utf-8")
        if content_type:
            self.headers["Content-Type"] = content_type
        elif "Content-Type" not in self.headers:
            mt = mimetype or self.default_mimetype
            if mt.startswith("text/") or mt in ("application/json", "application/javascript"):
                mt += "; charset=utf-8"
            self.headers["Content-Type"] = mt

    # -- body
    @property
    def data(self):
        if self.file_path and not self._data:
            with open(self.file_path, "rb") as f:
                return f.read()
        return self._data

    def get_data(self, as_text=False):
        d = self.data
        return d.decode("utf-8", "replace") if as_text else d

    def set_data(self, value):
        self._data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        self.file_path = None
        self.headers["Content-Length"] = str(len(self._data))

    @property
    def mimetype(self):
        return (self.headers.get("Content-Type") or "").split(";")[0].strip()

    @property
    def location(self):
        return self.headers.get("Location")

    def get_json(self, silent=False):
        try:
            return json.loads(self.get_data(as_text=True))
        except ValueError:
            if silent:
                return None
            raise

    # -- cookies
    def set_cookie(self, key, value="", **kwargs):
        self.cookies.append((key, value, kwargs))

    def delete_cookie(self, key, **kwargs):
        self.cookies.append((key, "", dict(kwargs, max_age=0)))


def _json_default(o):
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, decimal.Decimal):
        return str(o)
    if isinstance(o, uuid.UUID):
        return str(o)
    if hasattr(o, "keys") and hasattr(o, "__getitem__"):          # sqlite3.Row
        return {k: o[k] for k in o.keys()}
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def jsonify(*args, **kwargs):
    if args and kwargs:
        raise TypeError("jsonify() accepts positional or keyword arguments, not both")
    payload = args[0] if len(args) == 1 else (list(args) if args else dict(kwargs))
    return Response(json.dumps(payload, default=_json_default, separators=(",", ":")) + "\n", mimetype="application/json")


def redirect(location, code=302):
    body = f'<!doctype html><title>Redirecting...</title><p>Redirecting to <a href="{escape(location)}">{escape(location)}</a>.</p>'
    r = Response(body, status=code)
    r.headers["Location"] = str(location)
    return r


def make_response(*args):
    if not args:
        return Response()
    return _to_response(args if len(args) > 1 else args[0])


def _to_response(rv):
    status = headers = None
    if isinstance(rv, tuple):
        if len(rv) == 3:
            rv, status, headers = rv
        elif len(rv) == 2:
            rv, x = rv
            if isinstance(x, (dict, list, Headers)):
                headers = x
            else:
                status = x
        else:
            raise TypeError("A view returned a tuple of unsupported length.")
    if isinstance(rv, Response):
        resp = rv
    elif isinstance(rv, (str, bytes, bytearray)):
        resp = Response(rv)
    elif isinstance(rv, (dict, list)):
        resp = jsonify(rv)
    elif rv is None:
        raise TypeError("The view function did not return a valid response (it returned None).")
    else:
        raise TypeError(f"The view function returned an unsupported type: {type(rv).__name__}")
    if status is not None:
        resp.status_code = int(status)
    if headers:
        for k, v in (headers.items() if hasattr(headers, "items") else headers):
            resp.headers[k] = v
    return resp


def _content_disposition(disposition, filename):
    try:
        filename.encode("ascii")
        return f'{disposition}; filename="{filename}"'
    except UnicodeEncodeError:
        return f"{disposition}; filename*=UTF-8''{quote(filename)}"


def send_file(path_or_file, mimetype=None, as_attachment=False, download_name=None, max_age=None, **_ignored):
    """Send a file from disk or an in-memory file object."""
    if isinstance(path_or_file, (str, os.PathLike)):
        path = os.fspath(path_or_file)
        if not os.path.isfile(path):
            abort(404)
        name = download_name or os.path.basename(path)
        mt = mimetype or mimetypes.guess_type(name)[0] or "application/octet-stream"
        resp = Response(b"", mimetype=mt, file_path=path)
        resp.headers["Content-Length"] = str(os.path.getsize(path))
    else:
        f = path_or_file
        data = f.getvalue() if isinstance(f, io.BytesIO) else f.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        name = download_name
        mt = mimetype or (mimetypes.guess_type(name)[0] if name else None) or "application/octet-stream"
        resp = Response(data, mimetype=mt)
        resp.headers["Content-Length"] = str(len(data))
    if as_attachment:
        resp.headers["Content-Disposition"] = _content_disposition("attachment", name or "download")
    elif name:
        resp.headers["Content-Disposition"] = _content_disposition("inline", name)
    if max_age is not None:
        resp.headers["Cache-Control"] = f"public, max-age={int(max_age)}"
    return resp


def safe_join(directory, *parts):
    base = os.path.abspath(directory)
    path = os.path.abspath(os.path.join(base, *[p for p in parts if p]))
    if path != base and not path.startswith(base + os.sep):
        return None
    return path


def send_from_directory(directory, path, **kwargs):
    full = safe_join(directory, path)
    if full is None or not os.path.isfile(full):
        abort(404)
    kwargs.setdefault("max_age", None)
    return send_file(full, **kwargs)


# --------------------------------------------------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------------------------------------------------

_VAR = re.compile(r"<(?:(?P<conv>[a-zA-Z_]+)(?:\((?P<args>[^)]*)\))?:)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)>")
_CONVERTERS = {
    "string": (r"[^/]+", str), "int": (r"\d+", int), "float": (r"\d+\.\d+", float),
    "path": (r".+", str), "uuid": (r"[0-9a-fA-F-]{36}", str),
}


class Rule:
    """One URL rule, e.g. ``/students/<int:student_id>/photo``."""

    def __init__(self, rule, endpoint, view, methods=None, defaults=None, strict_slashes=True):
        self.rule = rule
        self.endpoint = endpoint
        self.view = view
        m = {x.upper() for x in (methods or ["GET"])}
        if "GET" in m:
            m.add("HEAD")
        m.add("OPTIONS")
        self.methods = m
        self.defaults = dict(defaults or {})
        self.strict_slashes = strict_slashes
        self._parts = []                # ("s", text) | ("v", name, conv)
        regex = ""
        pos = 0
        self.arguments = set()
        for mo in _VAR.finditer(rule):
            lit = rule[pos:mo.start()]
            if lit:
                self._parts.append(("s", lit)); regex += re.escape(lit)
            conv = mo.group("conv") or "string"
            if conv not in _CONVERTERS:
                raise ValueError(f"unknown converter {conv!r} in rule {rule!r}")
            self._parts.append(("v", mo.group("name"), conv))
            self.arguments.add(mo.group("name"))
            regex += f"(?P<{mo.group('name')}>{_CONVERTERS[conv][0]})"
            pos = mo.end()
        tail = rule[pos:]
        if tail:
            self._parts.append(("s", tail)); regex += re.escape(tail)
        self.is_static = not self.arguments
        self.has_path = any(p[0] == "v" and p[2] == "path" for p in self._parts)
        self.static_len = sum(len(p[1]) for p in self._parts if p[0] == "s")
        self.slash_redirect = rule.endswith("/") and len(rule) > 1 and strict_slashes
        body = regex.rstrip("/") if self.slash_redirect else regex
        self._re = re.compile("^" + body + ("/?" if self.slash_redirect else "") + "$")

    def match(self, path):
        mo = self._re.match(path)
        if not mo:
            return None
        values = {}
        for k, v in mo.groupdict().items():
            conv = next(p[2] for p in self._parts if p[0] == "v" and p[1] == k)
            values[k] = _CONVERTERS[conv][1](v)
        for k, v in self.defaults.items():
            values.setdefault(k, v)
        return values

    def build(self, values):
        """Return (path, unused_values). Raises BuildError if a required variable is missing."""
        out, used = "", set()
        for p in self._parts:
            if p[0] == "s":
                out += p[1]
            else:
                _, name, conv = p
                if name not in values or values[name] is None:
                    raise BuildError(f"missing value for '{name}' in rule {self.rule!r}")
                s = str(values[name])
                out += quote(s, safe="/") if conv == "path" else quote(s, safe="")
                used.add(name)
        return out, {k: v for k, v in values.items() if k not in used}


class Blueprint:
    """Group of routes registered later with ``app.register_blueprint`` (endpoints become ``<name>.<function>``)."""

    def __init__(self, name, import_name=None, url_prefix=""):
        self.name = name
        self.url_prefix = url_prefix
        self._routes = []

    def route(self, rule, **options):
        def deco(fn):
            self._routes.append((rule, options, fn))
            return fn
        return deco


class _UrlMap:
    def __init__(self, app):
        self._app = app

    def iter_rules(self, endpoint=None):
        return iter([r for r in self._app.rules if endpoint is None or r.endpoint == endpoint])


class SchoolApp:
    """Application object: the same decorators the code base already uses, plus a Jinja environment."""

    def __init__(self, import_name=None, root_path=None, template_folder="templates", static_folder="static"):
        self.import_name = import_name
        self.root_path = os.path.abspath(root_path or os.getcwd())
        self.template_folder = os.path.join(self.root_path, template_folder)
        self.static_folder = os.path.join(self.root_path, static_folder)
        self.config = {"PROPAGATE_EXCEPTIONS": None, "MAX_CONTENT_LENGTH": None, "TESTING": False,
                       "PERMANENT_SESSION_LIFETIME": datetime.timedelta(days=31)}
        self.secret_key = None
        self.logger = logging.getLogger("school")
        self.rules: list[Rule] = []
        self.view_functions: dict[str, callable] = {}
        self.before_request_funcs: list = []
        self.after_request_funcs: list = []
        self.teardown_request_funcs: list = []
        self.context_processors: list = []
        self.error_handlers: dict = {}
        self.url_map = _UrlMap(self)
        self._static: dict[str, list] = {}
        self._dynamic: list[Rule] = []
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_folder),
            autoescape=jinja2.select_autoescape(["html", "htm", "xml"]),
            auto_reload=False,
        )
        self.jinja_env.globals.update(url_for=url_for, get_flashed_messages=get_flashed_messages, config=self.config)
        # Flask serves /static/<path>; so do we (works the same under gunicorn, no extra package needed).
        self.add_url_rule("/static/<path:filename>", endpoint="static", view_func=self._send_static)
        self.wsgi_app = None   # kept only so `app.wsgi_app = ProxyFix(app.wsgi_app, ...)` is a harmless no-op; real request/response plumbing is `school.core.dispatch`, driven by the Django/Werkzeug glue, which already reads X-Forwarded-For/-Proto.
        global _app
        _app = self

    # -- registration -------------------------------------------------------------------------------------------
    def _send_static(self, filename):
        return send_from_directory(self.static_folder, filename, max_age=3600)

    def add_url_rule(self, rule, endpoint=None, view_func=None, methods=None, **options):
        endpoint = endpoint or view_func.__name__
        if endpoint in self.view_functions and self.view_functions[endpoint] is not view_func:
            raise AssertionError(f"View function mapping is overwriting an existing endpoint function: {endpoint}")
        r = Rule(rule, endpoint, view_func, methods, options.get("defaults"), options.get("strict_slashes", True))
        self.rules.append(r)
        self.view_functions[endpoint] = view_func
        if r.is_static:
            self._static.setdefault(rule, []).append(r)
        else:
            self._dynamic.append(r)
        self._dynamic.sort(key=lambda x: (x.has_path, -x.static_len, len(x.arguments)))
        return view_func

    def route(self, rule, **options):
        def deco(fn):
            self.add_url_rule(rule, options.pop("endpoint", None), fn, options.pop("methods", None), **options)
            return fn
        return deco

    def register_blueprint(self, bp):
        for rule, options, fn in bp._routes:
            ep = f"{bp.name}.{options.get('endpoint') or fn.__name__}"
            self.add_url_rule(bp.url_prefix + rule, ep, fn, options.get("methods"),
                              **{k: v for k, v in options.items() if k in ("defaults", "strict_slashes")})

    def before_request(self, fn):
        self.before_request_funcs.append(fn)
        return fn

    def after_request(self, fn):
        self.after_request_funcs.append(fn)
        return fn

    def teardown_request(self, fn):
        self.teardown_request_funcs.append(fn)
        return fn

    def context_processor(self, fn):
        self.context_processors.append(fn)
        return fn

    def template_filter(self, name=None):
        def deco(fn):
            self.jinja_env.filters[name or fn.__name__] = fn
            return fn
        return deco

    def errorhandler(self, code_or_exception):
        def deco(fn):
            self.error_handlers[code_or_exception] = fn
            return fn
        return deco

    # -- matching / url building --------------------------------------------------------------------------------
    def match(self, path, method):
        """Return (rule, values); raise HTTPException(404/405) or _SlashRedirect."""
        allowed = set()
        candidates = list(self._static.get(path, []))
        if not candidates and not path.endswith("/"):
            # a rule declared with a trailing slash also answers without it (redirecting to the canonical form)
            candidates = [r for r in self._static.get(path + "/", []) if r.slash_redirect]
        for rule in candidates + self._dynamic:
            values = {} if rule.is_static else rule.match(path)
            if values is None:
                continue
            if method.upper() in rule.methods:
                if rule.slash_redirect and not path.endswith("/"):
                    raise _SlashRedirect(path + "/")
                return rule, values
            allowed |= rule.methods
        if allowed:
            e = HTTPException(405)
            e.allowed = sorted(allowed)
            raise e
        raise HTTPException(404)

    def build_url(self, endpoint, values):
        rules = [r for r in self.rules if r.endpoint == endpoint]
        if not rules:
            raise BuildError(f"Could not build url for endpoint '{endpoint}'.")
        last = None
        for rule in sorted(rules, key=lambda r: -len(r.arguments & set(values))):
            try:
                path, rest = rule.build(values)
                return path, rest
            except BuildError as e:
                last = e
        raise BuildError(f"Could not build url for endpoint '{endpoint}' with values {sorted(values)}. {last}")

    # -- misc ---------------------------------------------------------------------------------------------------
    test_client_class = None

    def test_client(self, *args, **kwargs):
        if self.test_client_class is not None:
            return self.test_client_class(self)
        from school.testing import make_test_client
        return make_test_client(self, *args, **kwargs)

    @contextmanager
    def test_request_context(self, path="/", method="GET", **kwargs):
        """Minimal stand-in: real Flask lets you push a fake request to call code that needs `request`/`session`
        outside of an actual request; the test suite only uses this as a context-manager no-op around opening a
        `test_client()`, so this provides the same shape without re-implementing Werkzeug request construction."""
        from werkzeug.test import EnvironBuilder
        from werkzeug.wrappers import Request as _WReq
        environ = EnvironBuilder(path=path, method=method, **kwargs).get_environ()
        req = _WReq(environ)
        ctx = _Ctx(self, req, {})
        token = _current.set(ctx)
        try:
            yield ctx
        finally:
            _current.reset(token)


class _SlashRedirect(Exception):
    def __init__(self, location):
        self.location = location


_app: SchoolApp | None = None


def current_app_obj() -> SchoolApp:
    if _app is None:
        raise RuntimeError("No SchoolApp has been created yet.")
    return _app


# --------------------------------------------------------------------------------------------------------------------
# Request context + proxies
# --------------------------------------------------------------------------------------------------------------------

class _Ctx:
    __slots__ = ("app", "request", "session_backend", "endpoint", "view_args", "g", "flashes", "permanent", "rule")

    def __init__(self, app, request, session_backend):
        self.app = app
        self.request = request
        self.session_backend = session_backend
        self.endpoint = None
        self.view_args = {}
        self.g = _G()
        self.flashes = None
        self.permanent = False
        self.rule = None


_current: contextvars.ContextVar = contextvars.ContextVar("school_request_ctx", default=None)


def _ctx() -> _Ctx:
    c = _current.get()
    if c is None:
        raise RuntimeError("Working outside of request context.")
    return c


class _G:
    """Per-request scratch space (``g.portal_school = ...``)."""

    def get(self, name, default=None):
        return self.__dict__.get(name, default)

    def pop(self, name, *default):
        return self.__dict__.pop(name, *default)

    def setdefault(self, name, value):
        return self.__dict__.setdefault(name, value)

    def __contains__(self, name):
        return name in self.__dict__

    def __iter__(self):
        return iter(self.__dict__)


class _RequestView:
    """The Flask-style request: delegates to the backend request, adding ``endpoint`` / ``view_args``."""

    def __getattr__(self, name):
        c = _ctx()
        if name == "endpoint":
            return c.endpoint
        if name == "view_args":
            return c.view_args
        if name == "blueprint":
            return c.endpoint.rpartition(".")[0] if c.endpoint and "." in c.endpoint else None
        if name == "url_rule":
            return c.rule
        return getattr(c.request, name)

    def __bool__(self):
        return _current.get() is not None


class _SessionView:
    """dict-like session. ``session.permanent = True`` keeps the cookie for PERMANENT_SESSION_LIFETIME."""

    def _b(self):
        return _ctx().session_backend

    def __getitem__(self, k):
        return self._b()[k]

    def __setitem__(self, k, v):
        self._b()[k] = v

    def __delitem__(self, k):
        del self._b()[k]

    def __contains__(self, k):
        return k in self._b()

    def __iter__(self):
        return iter(list(self._b().keys()))

    def __len__(self):
        return len(list(self._b().keys()))

    def __bool__(self):
        return len(self) > 0

    def get(self, k, default=None):
        b = self._b()
        return b[k] if k in b else default

    def pop(self, k, *default):
        b = self._b()
        if k in b:
            v = b[k]
            del b[k]
            return v
        if default:
            return default[0]
        raise KeyError(k)

    def setdefault(self, k, default=None):
        b = self._b()
        if k not in b:
            b[k] = default
        return b[k]

    def update(self, *a, **kw):
        for k, v in dict(*a, **kw).items():
            self._b()[k] = v

    def clear(self):
        b = self._b()
        for k in list(b.keys()):
            del b[k]

    def keys(self):
        return list(self._b().keys())

    def items(self):
        b = self._b()
        return [(k, b[k]) for k in b.keys()]

    def values(self):
        b = self._b()
        return [b[k] for k in b.keys()]

    @property
    def permanent(self):
        return _ctx().permanent

    @permanent.setter
    def permanent(self, value):
        _ctx().permanent = bool(value)

    @property
    def modified(self):
        return True


class _GView:
    def __getattr__(self, name):
        try:
            return getattr(_ctx().g, name)
        except AttributeError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        setattr(_ctx().g, name, value)

    def __delattr__(self, name):
        delattr(_ctx().g, name)

    def get(self, name, default=None):
        return _ctx().g.get(name, default)

    def pop(self, name, *default):
        return _ctx().g.pop(name, *default)

    def __contains__(self, name):
        return name in _ctx().g


class _AppView:
    def __getattr__(self, name):
        return getattr(current_app_obj(), name)


request = _RequestView()
session = _SessionView()
g = _GView()
current_app = _AppView()


# --------------------------------------------------------------------------------------------------------------------
# Helpers that need the request context
# --------------------------------------------------------------------------------------------------------------------

def flash(message, category="message"):
    flashes = list(session.get("_flashes", []))
    flashes.append([category, str(message)])
    session["_flashes"] = flashes


def get_flashed_messages(with_categories=False, category_filter=()):
    c = _ctx()
    if c.flashes is None:
        c.flashes = session.pop("_flashes", []) if "_flashes" in session else []
    flashes = c.flashes
    if category_filter:
        flashes = [f for f in flashes if f[0] in category_filter]
    return [tuple(f) for f in flashes] if with_categories else [f[1] for f in flashes]


def url_for(endpoint, **values):
    app = current_app_obj()
    anchor = values.pop("_anchor", None)
    external = values.pop("_external", False)
    scheme = values.pop("_scheme", None)
    values.pop("_method", None)
    if endpoint.startswith(".") and _current.get() is not None:
        bp = _ctx().endpoint.rpartition(".")[0]
        endpoint = f"{bp}{endpoint}" if bp else endpoint[1:]
    path, rest = app.build_url(endpoint, values)
    rest = {k: v for k, v in rest.items() if v is not None}
    url = path
    if rest:
        url += "?" + urlencode(rest, doseq=True)
    if anchor:
        url += "#" + quote(str(anchor))
    if external:
        req = _ctx().request
        url = f"{scheme or ('https' if req.is_secure else 'http')}://{req.host}{url}"
    return url


def render_template(template_name, **context):
    app = current_app_obj()
    ctx = {"request": request, "session": session, "g": g}
    for fn in app.context_processors:
        ctx.update(fn() or {})
    ctx.update(context)
    return app.jinja_env.get_template(template_name).render(ctx)


def render_template_string(source, **context):
    app = current_app_obj()
    ctx = {"request": request, "session": session, "g": g}
    for fn in app.context_processors:
        ctx.update(fn() or {})
    ctx.update(context)
    return app.jinja_env.from_string(source).render(ctx)


# --------------------------------------------------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------------------------------------------------

def _default_error_response(code, description=None):
    name = _STATUS_NAMES.get(code, "Error")
    return Response(f"<!doctype html>\n<title>{code} {name}</title>\n<h1>{name}</h1>\n<p>{escape(description or name)}</p>\n",
                    status=code)


def _handle_http_error(app, exc: HTTPException):
    if exc.response is not None:
        return _to_response(exc.response)
    handler = app.error_handlers.get(exc.code) or app.error_handlers.get(HTTPException)
    if handler:
        return _to_response(handler(exc))
    resp = _default_error_response(exc.code, exc.description)
    if exc.code == 405 and getattr(exc, "allowed", None):
        resp.headers["Allow"] = ", ".join(exc.allowed)
    return resp


def _handle_exception(app, exc: Exception):
    propagate = app.config.get("PROPAGATE_EXCEPTIONS")
    if propagate is None:
        propagate = bool(app.config.get("TESTING") or app.config.get("DEBUG"))
    if propagate:
        raise exc
    app.logger.error("Unhandled exception on request", exc_info=exc)
    for kind, handler in app.error_handlers.items():
        if isinstance(kind, type) and issubclass(kind, BaseException) and isinstance(exc, kind) and kind is not HTTPException:
            return _to_response(handler(exc))
    handler = app.error_handlers.get(500)
    if handler:
        try:
            return _to_response(handler(exc))
        except Exception:
            app.logger.exception("Error handler failed")
    return _default_error_response(500)


def dispatch(app: SchoolApp, req, session_backend) -> Response:
    """Run one request through the application.

    ``req`` needs the small Flask-style surface (method, path, full_path, url, host, is_secure, remote_addr, headers, form,
    args, values, files, cookies, referrer, is_json, get_json(), get_data(), content_length).
    ``session_backend`` is any dict-like object; its changes are persisted by the caller.
    """
    ctx = _Ctx(app, req, session_backend)
    token = _current.set(ctx)
    try:
        resp = None
        method = req.method.upper()
        try:
            try:
                rule, values = app.match(req.path, method)
            except _SlashRedirect as sr:
                return _finish(app, redirect(sr.location + (("?" + req.query_string) if getattr(req, "query_string", "") else ""), 308))
            ctx.rule, ctx.endpoint, ctx.view_args = rule, rule.endpoint, dict(values)
            limit = app.config.get("MAX_CONTENT_LENGTH")
            clen = getattr(req, "content_length", None)
            if limit and clen and int(clen) > int(limit):
                raise HTTPException(413)
            for fn in app.before_request_funcs:
                rv = fn()
                if rv is not None:
                    resp = _to_response(rv)
                    break
            if resp is None:
                if method == "OPTIONS":
                    resp = Response("", headers={"Allow": ", ".join(sorted(rule.methods))})
                else:
                    resp = _to_response(rule.view(**values))
        except HTTPException as e:
            resp = _handle_http_error(app, e)
        except Exception as e:                      # noqa: BLE001 - mapped to the 500 handler
            resp = _handle_exception(app, e)
        return _finish(app, resp)
    finally:
        for fn in app.teardown_request_funcs:
            try:
                fn(None)
            except Exception:
                app.logger.exception("teardown_request failed")
        _current.reset(token)


def _finish(app, resp):
    for fn in reversed(app.after_request_funcs):
        resp = _to_response(fn(resp))
    return resp


def session_is_permanent() -> bool:
    c = _current.get()
    return bool(c and c.permanent)
