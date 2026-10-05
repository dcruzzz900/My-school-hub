import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Import the application module so its ~300 @app.route registrations (and init_db()) run once at process start,
# before any request arrives - exactly like Flask's `app.py` did under gunicorn before this conversion.
import app  # noqa: E402,F401

application = get_wsgi_application()
