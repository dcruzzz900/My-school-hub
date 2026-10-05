"""Django settings. The application's own logic (routes, views, templates, CSRF, sessions) lives in school.core /
app.py and is unaffected by anything here - Django is providing WSGI serving, the session/cookie middleware stack,
static files and (optionally later) the ORM. See school/django_glue.py for how a Django request becomes a call into
school.core.dispatch().
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "*").split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "school",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

# The application's own data lives in its existing SQLite database, read/written with the application's own sqlite3
# code (see db.py) exactly as before. Django's DATABASES is only used for the one thing Django itself needs a
# database for by default (none, currently - see below) - this entry exists purely so `manage.py` subcommands that
# expect DATABASES to be present do not error out.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(os.environ.get("DATA_DIR") or os.path.join(BASE_DIR, "instance"), "django_meta.db"),
    }
}

# Sessions: Django's own signed-cookie session store. school.core's `session` proxy is backed directly by Django's
# request.session (see school/django_glue.py), so `session["x"] = y` writes through to the real Django session.
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_COOKIE_NAME = "sessionid"
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 60 * 60 * 24 * 31
SESSION_SAVE_EVERY_REQUEST = False
if os.environ.get("SESSION_COOKIE_SECURE") == "1" or os.environ.get("DJANGO_ENV") == "production":
    SESSION_COOKIE_SECURE = True

SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-secret-key-not-for-production"

STATIC_URL = "/static/"
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

DATA_UPLOAD_MAX_MEMORY_SIZE = 20 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 20 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = None

USE_TZ = False   # the application manages its own timezone handling (school_now/school_tz in app.py)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
