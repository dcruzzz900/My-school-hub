"""Small Werkzeug-backed shims kept at their original import names (security hashing, filename sanitising, proxy
header handling) so the application code is unchanged. These have nothing to do with Flask routing/requests, so they
work identically under Django or the plain Werkzeug test harness.
"""
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: F401
from werkzeug.utils import secure_filename  # noqa: F401
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: F401
