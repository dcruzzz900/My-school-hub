from school.core import (
    SchoolApp as Flask, render_template, request, redirect, url_for, session, flash,
    send_file, send_from_directory, g, jsonify, abort, Response, HTTPException,
)
from school.compat import check_password_hash, generate_password_hash, secure_filename, ProxyFix
from functools import wraps
import os
import sqlite3
import io
import csv as csv_module
import secrets
import time
import re
import threading
import hmac
import hashlib
from collections import defaultdict, deque

from db import (generate_school_code, 
    get_db, init_db, grade_for, get_school, INSTANCE_DIR, table_exists, ensure_school_v61_defaults,
    POSITION_LABELS, FULL_ACCESS_POSITIONS, form_teacher_class_ids,
    can_view_all_results, can_view_class_results, student_full_name,
    seed_school_defaults, upsert_enrollment, log_audit,
    get_visible_notifications, get_unread_notification_count,
    recompute_attendance, attendance_percentage, grading_problems, grade_band_problems, parse_arms,
    generate_teacher_comment, generate_principal_comment,
    CLASS_CATEGORIES, MATERIAL_KINDS, format_dmy, STAFF_ATTENDANCE_STATUSES,
    PDF_FONT_CHOICES, WEB_FONTS, generate_activation_code, current_activation_code_status,
    verify_activation_code,
    generate_signup_code, verify_signup_code,
    TIMEZONE_CHOICES, RESULT_HEADER_LAYOUTS,
)
import datetime
import json
from pdf_utils import build_broadsheet_pdf, build_result_pdf, build_class_results_pdf, build_cumulative_result_pdf, build_generic_table_pdf
from email_utils import send_email, send_platform_email
from reports import build_csv, build_xlsx
from security_audit import run_security_audit
from ai.provider import generate as ai_provider_generate, configured as ai_provider_configured
from ai.result_analysis import analyze_student, compare as compare_analysis
from ai.comments import teacher_comment as ai_teacher_comment, principal_comment as ai_principal_comment
from ai.tutor import local_tutor_answer

ALLOWED_LOGO_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Learning Materials: extension -> the broad type shown to teachers/students.
# Anything not in this map (e.g. a full video file) should be linked via
# external_url instead of uploaded — see MATERIALS_DIR below.
MATERIAL_EXTENSIONS = {
    "pdf": "PDF", "doc": "Word", "docx": "Word", "ppt": "PowerPoint", "pptx": "PowerPoint",
    "jpg": "Image", "jpeg": "Image", "png": "Image", "gif": "Image",
}
MATERIALS_DIR = os.path.join(INSTANCE_DIR, "materials")
STUDENT_PHOTOS_DIR = os.path.join(INSTANCE_DIR, "student_photos")
STAFF_PHOTOS_DIR = os.path.join(INSTANCE_DIR, "staff_photos")
PARENT_PHOTOS_DIR = os.path.join(INSTANCE_DIR, "parent_photos")
SIGNATURES_DIR = os.path.join(INSTANCE_DIR, "signatures")
STAFF_DOCUMENTS_DIR = os.path.join(INSTANCE_DIR, "staff_documents")
CUSTOM_FILES_DIR = os.path.join(INSTANCE_DIR, "custom_field_files")
STAFF_DOCUMENT_EXTENSIONS = {"pdf","doc","docx","jpg","jpeg","png"}

app = Flask(__name__, root_path=os.path.dirname(os.path.abspath(__file__)))
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # hard request ceiling; individual upload limits are enforced below

# Trust one reverse-proxy hop for the real client IP (X-Forwarded-For),
# since PythonAnywhere — and most hosts — put the app behind a proxy.
# Without this, every visitor would appear to share the proxy's own IP,
# which would make the rate limiter below block everyone at once instead
# of just whoever is actually hammering a route.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Cookie hardening. SameSite=Lax is safe for this app everywhere. "Secure"
# (send the cookie only over HTTPS) is opt-in so a plain-http local test still
# works: set SESSION_COOKIE_SECURE=1 on any real HTTPS deployment.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
# Railway/production should set SESSION_COOKIE_SECURE=1 because the public
# application is served over HTTPS. Keep an explicit opt-out for local HTTP
# development so the development server remains usable.
if os.environ.get("SESSION_COOKIE_SECURE") == "1" or os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True


def _get_or_create_secret_key():
    key_path = os.path.join(INSTANCE_DIR, "secret_key.txt")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if not os.path.exists(key_path):
        with open(key_path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(key_path) as f:
        return f.read().strip()


app.secret_key = os.environ.get("SECRET_KEY") or _get_or_create_secret_key()

# Keep staff signed in across a working week (session.permanent is set at login).
# The school server is always required: there is no offline mode.
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=30)

# Make sure the database exists and is migrated, whether this file is run
# directly (python app.py) or imported by a production server (e.g. the
# WSGI file on PythonAnywhere, or gunicorn).
init_db()
from billing_finalization import billing_finalization_bp
app.register_blueprint(billing_finalization_bp)


# ---------- CSRF protection ----------
# Every form in this app posts data with a browser session cookie, which is
# exactly what CSRF exploits — a malicious page elsewhere can make the
# browser submit a form to us using the person's own logged-in cookie. A
# random per-session token, embedded as a hidden field in every POST form
# and checked against the session on every state-changing request, means a
# request that didn't originate from a page we actually rendered is
# rejected, since an attacker's page has no way to know that token.

CSRF_UNSAFE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def _check_csrf():
    if request.method not in CSRF_UNSAFE_METHODS:
        return None
    if request.path.startswith("/api/"):
        # JSON endpoints authenticate with the session cookie, so they must carry the
        # CSRF token in a header (a cross-site page cannot set custom headers).
        if "user_id" in session or "student_id" in session or "platform_admin_id" in session:
            submitted = request.headers.get("X-CSRF-Token", "")
            expected = session.get("_csrf_token", "")
            if expected and secrets.compare_digest(submitted, expected):
                return None
        return jsonify({"error": "csrf_check_failed"}), 403
    submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")   # fetch() calls send the header
    expected = session.get("_csrf_token", "")
    if not expected or not secrets.compare_digest(submitted, expected):
        app.logger.warning(
            "CSRF/session check failed: path=%s method=%s user_id=%s has_session_token=%s form_token_present=%s",
            request.path, request.method, session.get("user_id"), bool(expected), bool(submitted))
        flash("Your session timed out or that page was open too long — please try again.", "error")
        return redirect(request.referrer or "/")
    return None


app.jinja_env.filters["dmy"] = format_dmy


# ---------- production security headers ----------
# Keep this deliberately conservative: the application contains existing
# inline scripts/styles, so a restrictive CSP would need a full nonce/hash
# migration first. These headers add browser-side protections without
# changing the application's rendering behaviour.
@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure or os.environ.get("SESSION_COOKIE_SECURE") == "1" or os.environ.get("FLASK_ENV") == "production":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# ---------- strict per-file upload limits ----------
UPLOAD_LIMITS = {"passport": 500 * 1024, "signature": 500 * 1024, "staff_document": 1 * 1024 * 1024, "learning_material": 1 * 1024 * 1024}

def _file_size_bytes(file_storage):
    if not file_storage or not getattr(file_storage, "filename", ""):
        return 0
    try:
        pos = file_storage.stream.tell(); file_storage.stream.seek(0, os.SEEK_END); size = file_storage.stream.tell(); file_storage.stream.seek(pos); return int(size)
    except Exception:
        return 0

def _verify_image(file_storage, limit, label):
    """Server-side check that an upload really is an image of acceptable size (not just a file name)."""
    import profile_core
    data, _ext, err = profile_core.read_image_upload(file_storage, limit, label)
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass
    return err

def _reject_oversize(file_storage, kind):
    limit = UPLOAD_LIMITS[kind]; size = _file_size_bytes(file_storage)
    if size > limit:
        label = {"passport":"Passport image", "signature":"Signature", "staff_document":"Staff document", "learning_material":"Learning material"}[kind]
        return f"{label} must not exceed {'500 KB' if limit == 500 * 1024 else '1 MB'}."
    return None

# ---------- safe production error responses ----------
@app.errorhandler(413)
def _payload_too_large(_error):
    return "Uploaded file is too large. Maximum size is 20 MB.", 413


@app.errorhandler(500)
def _internal_server_error(_error):
    # Do not expose stack traces, SQL details, filesystem paths, or secrets
    # to end users. Flask still logs the underlying exception server-side.
    return "An internal server error occurred. Please try again.", 500


# ---------- Role & permission helpers ----------
ROLE_CATALOG = {
    # Legacy label "Form Teacher" is normalized to the single current "Class Teacher / Form Teacher" role.
    "School Admin": ["view","create","edit","delete","approve","verify","finalize","lock","publish","import","export","manage_users","manage_branding","manage_attendance","manage_reports"],
    "Sub-Admin": ["view","create","edit","delete","approve","verify","publish","import","export","manage_users","manage_attendance","manage_reports"],
    "Class Teacher / Form Teacher": ["view","create","edit","import","export","manage_attendance"],
    "Subject Teacher": ["view","create","edit","import"],
    "Discipline Master": ["view","create","edit","export","manage_attendance"],
    "Guidance/Counselor": ["view","create","edit"],
    "Librarian": ["view","create","edit","delete","export"],
    "Labour Master": ["view","create","edit","export","manage_attendance"],
    "Non-Teaching Staff": ["view","manage_attendance"],
    # Legacy/approved administrative roles remain available for existing accounts.
    "Principal": ["view","create","edit","approve","verify","finalize","lock","publish","import","export","manage_users","manage_branding","manage_attendance","manage_reports"],
    "Head Teacher": ["view","create","edit","approve","verify","finalize","publish","import","export","manage_users","manage_branding","manage_attendance","manage_reports"],
    "Vice Principal": ["view","create","edit","approve","verify","finalize","publish","export","manage_attendance","manage_reports"],
    "Deputy Head": ["view","create","edit","approve","verify","publish","export"],
    "HOD": ["view","create","edit","approve","verify","export"],
    "Examination/Result Officer": ["view","create","edit","verify","finalize","lock","publish","import","export"],
    "ICT Officer": ["view","create","edit","import","export"],
    "Finance/Bursar": ["view","create","edit","export"],
    "Teacher": ["view","create","edit","import"],
    "Other Staff": ["view"],
    # Standardised role names (V60). Default-deny: each role starts with only the permissions below.
    "Vice Principal / Deputy Principal": ["view","create","edit","approve","verify","finalize","publish","export","manage_attendance","manage_reports"],
    "HOD / Head of Department": ["view","create","edit","approve","verify","export"],
    "Examination Officer": ["view","create","edit","verify","finalize","lock","publish","import","export"],
    "Guidance/Counselling Officer": ["view","create","edit"],
    "Bursar / Accountant": ["view","create","edit","export"],
    "Registrar / Admissions Officer": ["view","create","edit","import","export"],
    "Attendance Officer": ["view","manage_attendance","export"],
    "ICT / System Support Officer": ["view"],
    "Front Desk / Reception Officer": ["view","create"],
}

# Legacy role names stay valid for existing accounts, but new assignments use the standardised names.
LEGACY_ROLE_ALIASES = {
    "Vice Principal": "Vice Principal / Deputy Principal", "Deputy Head": "Vice Principal / Deputy Principal",
    "HOD": "HOD / Head of Department", "Examination/Result Officer": "Examination Officer",
    "Guidance/Counselor": "Guidance/Counselling Officer", "Finance/Bursar": "Bursar / Accountant",
    "ICT Officer": "ICT / System Support Officer",
}


ROLE_TO_POSITION = {"Principal":"principal","Vice Principal":"vice_principal","Head Teacher":"principal",
    "Class Teacher / Form Teacher":"form_teacher","Form Teacher":"form_teacher","Class Teacher":"form_teacher",
    "Examination/Result Officer":"exam_officer","Examination Officer":"exam_officer",
    "Vice Principal / Deputy Principal":"vice_principal","Subject Teacher":"subject_teacher"}


def user_roles(conn, user_id, school_id):
    """All of a staff member's CURRENT roles (canonical names, primary first). Active assignments are the source of
    truth; users.rbac_role is only the fallback for accounts that predate role assignments."""
    names = []
    for ra in active_role_assignments(conn, user_id, school_id):
        r = canonical_rbac_role(ra["role"])
        if r and r not in names:
            names.append(r)
    if not names:
        row = conn.execute("SELECT rbac_role FROM users WHERE id=? AND school_id=?", (user_id, school_id)).fetchone()
        if row and row["rbac_role"]:
            names.append(canonical_rbac_role(row["rbac_role"]))
    return names


def session_roles():
    """The signed-in staff member's roles as of this request (refreshed from the database on every request)."""
    roles = session.get("rbac_roles")
    if roles is None:
        roles = [session["rbac_role"]] if session.get("rbac_role") else []
    return [canonical_rbac_role(r) for r in roles]


def _sync_primary_role(conn, user_id, school_id, roles):
    primary = roles[0] if roles else "Teacher"
    position = next((ROLE_TO_POSITION[r] for r in roles if r in ROLE_TO_POSITION and r != "Subject Teacher"), None)
    if position is None and "Subject Teacher" in roles:
        position = "subject_teacher"
    conn.execute("UPDATE users SET rbac_role=?, position=? WHERE id=? AND school_id=?", (primary, position, user_id, school_id))


def _role_audit(conn, aid, user_id, school_id, actor_id, actor_name, action, previous, new, reason):
    conn.execute(
        "INSERT INTO role_assignment_audit (assignment_id,user_id,school_id,actor_user_id,actor_name,action,previous_role,new_role,approval_status,reason) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)", (aid, user_id, school_id, actor_id, actor_name, action, previous, new, "approved", reason))


def _materialize_legacy_role(conn, user_id, school_id):
    """Accounts created before role assignments existed only have users.rbac_role. Turn it into a real active assignment
    (with its permissions) the first time anyone edits that person's roles, so add/remove behave identically for everyone."""
    if conn.execute("SELECT 1 FROM role_assignments WHERE user_id=? AND school_id=? AND status='active'", (user_id, school_id)).fetchone():
        return
    row = conn.execute("SELECT rbac_role, role FROM users WHERE id=? AND school_id=?", (user_id, school_id)).fetchone()
    if not row or row["role"] == "admin":
        return
    role = canonical_rbac_role(row["rbac_role"]) or "Teacher"
    if role not in ROLE_CATALOG or role in ADMIN_ONLY_ROLES:
        role = "Teacher"
    school = conn.execute("SELECT tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()
    aid = conn.execute("INSERT INTO role_assignments (user_id,school_id,tenant_id,school_level,role,status,approved_at,reason) "
                       "VALUES (?,?,?,'All',?,'active',CURRENT_TIMESTAMP,'Existing role recorded')",
                       (user_id, school_id, school["tenant_id"] if school else None, role)).lastrowid
    for perm in ROLE_CATALOG.get(role, []):
        conn.execute("INSERT INTO role_assignment_permissions (assignment_id,permission,granted) VALUES (?,?,1)", (aid, perm))


def add_staff_role(conn, user_id, school_id, role, actor_id, actor_name, school_level="All", reason=None):
    """Give a staff member one more role. Active at once; permissions of all active roles are combined.
    Tenant isolation: the user must belong to `school_id` (never a client-supplied id). Caller commits."""
    role = canonical_rbac_role(role)
    user = conn.execute("SELECT id, role FROM users WHERE id=? AND school_id=?", (user_id, school_id)).fetchone()
    if not user or user["role"] == "admin" or role not in ROLE_CATALOG or role in ADMIN_ONLY_ROLES:
        return None
    _materialize_legacy_role(conn, user_id, school_id)
    existing = [r for r in user_roles(conn, user_id, school_id)]
    if role in existing and conn.execute("SELECT 1 FROM role_assignments WHERE user_id=? AND school_id=? AND role=? AND status='active'", (user_id, school_id, role)).fetchone():
        return "exists"
    school = conn.execute("SELECT tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()
    aid = conn.execute(
        "INSERT INTO role_assignments (user_id,school_id,tenant_id,school_level,role,status,requested_by,approved_by,approved_at,reason) "
        "VALUES (?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP,?)",
        (user_id, school_id, school["tenant_id"] if school else None, school_level, role, actor_id, actor_id,
         reason or "Role added by School Admin")).lastrowid
    for perm in ROLE_CATALOG.get(role, []):
        conn.execute("INSERT INTO role_assignment_permissions (assignment_id,permission,granted) VALUES (?,?,1)", (aid, perm))
    _role_audit(conn, aid, user_id, school_id, actor_id, actor_name, "role_added", None, role, reason or "Role added; active immediately")
    _sync_primary_role(conn, user_id, school_id, user_roles(conn, user_id, school_id))
    return aid


def remove_staff_role(conn, user_id, school_id, role, actor_id, actor_name, reason=None):
    """Take one role away. Its permissions disappear on the very next request. A staff member always keeps at least
    the default 'Teacher' role so the account is never left without a role."""
    role = canonical_rbac_role(role)
    user = conn.execute("SELECT id, role FROM users WHERE id=? AND school_id=?", (user_id, school_id)).fetchone()
    if not user:
        return False
    _materialize_legacy_role(conn, user_id, school_id)
    rows = conn.execute("SELECT id, role FROM role_assignments WHERE user_id=? AND school_id=? AND status='active'", (user_id, school_id)).fetchall()
    hit = [r for r in rows if canonical_rbac_role(r["role"]) == role]
    if not hit:
        return False
    for r in hit:
        conn.execute("UPDATE role_assignments SET status='revoked', updated_at=CURRENT_TIMESTAMP WHERE id=?", (r["id"],))
        _role_audit(conn, r["id"], user_id, school_id, actor_id, actor_name, "role_removed", role, None, reason or "Role removed; permissions removed immediately")
    remaining = user_roles(conn, user_id, school_id)
    if not [x for x in remaining if x]:
        add_staff_role(conn, user_id, school_id, "Teacher", actor_id, actor_name, reason="Default role restored")
    _sync_primary_role(conn, user_id, school_id, user_roles(conn, user_id, school_id))
    return True


def set_staff_roles(conn, user_id, school_id, roles, actor_id, actor_name, reason=None):
    """Make `roles` the staff member's complete set of roles (add what is missing, remove what is no longer ticked)."""
    roles = [canonical_rbac_role(r) for r in roles if canonical_rbac_role(r) in ROLE_CATALOG and r not in ADMIN_ONLY_ROLES]
    user = conn.execute("SELECT id, role FROM users WHERE id=? AND school_id=?", (user_id, school_id)).fetchone()
    if not user or user["role"] == "admin":
        return None
    if not roles:
        roles = ["Teacher"]
    _materialize_legacy_role(conn, user_id, school_id)
    current = user_roles(conn, user_id, school_id)
    for r in roles:                      # add first, so removing the old roles can never leave the account role-less
        add_staff_role(conn, user_id, school_id, r, actor_id, actor_name, reason=reason)
    for r in current:
        if r not in roles:
            remove_staff_role(conn, user_id, school_id, r, actor_id, actor_name, reason)
    # primary = first ticked role
    conn.execute("UPDATE users SET rbac_role=? WHERE id=? AND school_id=?", (roles[0], user_id, school_id))
    return roles


def change_staff_role(conn, user_id, school_id, new_role, actor_id, actor_name, school_level="All", reason=None):
    """Replace ALL of a staff member's roles with `new_role` (kept for single-role callers)."""
    if set_staff_roles(conn, user_id, school_id, [new_role], actor_id, actor_name, reason) is None:
        return None
    row = conn.execute("SELECT id FROM role_assignments WHERE user_id=? AND school_id=? AND status='active' ORDER BY id DESC", (user_id, school_id)).fetchone()
    return row["id"] if row else None



ADMIN_ONLY_ROLES = {"School Admin"}   # created automatically at school signup/activation; never an ordinary staff role


def assignable_roles():
    return sorted(r for r in ROLE_CATALOG if r not in LEGACY_ROLE_ALIASES and r not in ADMIN_ONLY_ROLES)

SCHOOL_LEVELS = ("All","Nursery","Primary","Secondary")

def canonical_rbac_role(value):
    """Return the single current class/form teacher role name. Historical
    databases may still contain the old labels; they are read compatibly but
    are never exposed as separate assignable roles."""
    if value in ("Form Teacher", "Class Teacher"):
        return "Class Teacher / Form Teacher"
    return value


def active_role_assignments(conn, user_id, school_id):
    today = datetime.date.today().isoformat()
    return conn.execute("""
        SELECT ra.*, u.name AS user_name, s.name AS school_name
        FROM role_assignments ra
        JOIN users u ON u.id=ra.user_id
        JOIN schools s ON s.id=ra.school_id
        WHERE ra.user_id=? AND ra.school_id=?
          AND ra.status='active'
          AND (ra.start_date IS NULL OR ra.start_date<=?)
          AND (ra.end_date IS NULL OR ra.end_date>=?)
        ORDER BY ra.id DESC
    """, (user_id, school_id, today, today)).fetchall()

def user_has_permission(conn, user_id, school_id, permission, school_level=None, class_id=None, subject_id=None):
    rows = active_role_assignments(conn, user_id, school_id)
    matched=[]
    for ra in rows:
        if school_level and ra["school_level"] not in ("All", school_level): continue
        if class_id and ra["class_id"] and int(ra["class_id"]) != int(class_id): continue
        if subject_id and ra["subject_id"] and int(ra["subject_id"]) != int(subject_id): continue
        matched.append(ra)
    # Explicit DENY always overrides ALLOW.
    for ra in matched:
        if conn.execute("SELECT 1 FROM role_assignment_permissions WHERE assignment_id=? AND permission=? AND granted=0 LIMIT 1",(ra["id"],permission)).fetchone(): return False
    for ra in matched:
        if conn.execute("SELECT 1 FROM role_assignment_permissions WHERE assignment_id=? AND permission=? AND granted=1 LIMIT 1",(ra["id"],permission)).fetchone(): return True
    if permission == "view" and session.get("role") in ("admin","sub_admin","teacher"): return True
    return session.get("role") == "admin"

def role_scope_label(row):
    parts = [row["school_level"]]
    if row["department"]: parts.append(row["department"])
    if row["class_id"]: parts.append(f"class #{row['class_id']}")
    if row["class_arm"]: parts.append(f"arm {row['class_arm']}")
    if row["subject_id"]: parts.append(f"subject #{row['subject_id']}")
    return " · ".join(parts)



# ---------- Scoped authorization helpers ----------
CLASS_BOUND_ROLES = {"Teacher", "Subject Teacher", "Class Teacher / Form Teacher"}
# Roles that may read every class's results (leadership / examinations). Everyone else sees only their own class.
RESULT_VIEW_ROLES = {"Principal", "Head Teacher", "Vice Principal", "Vice Principal / Deputy Principal", "Deputy Head",
                     "Examination Officer", "Examination/Result Officer", "Sub-Admin"}


def can_enter_scores(conn, class_id, subject_id):
    """Score entry/editing follows the ACTUAL class+subject assignment, not the job title.
    * School Admin / Sub-Admin: yes (their own school only).
    * Any staff member (whatever their other roles - Discipline Master, Librarian, Class Teacher...): yes only for a
      class+subject pair they are assigned to in THIS school. A Discipline Master with no subject assignment cannot."""
    role = session.get("role")
    school_id = current_school_id()
    if role in ("admin", "sub_admin"):
        return bool(conn.execute("SELECT 1 FROM classes WHERE id=? AND school_id=?", (class_id, school_id)).fetchone())
    if role != "teacher":
        return False
    row = conn.execute(
        "SELECT cs.id FROM class_subjects cs JOIN classes c ON c.id=cs.class_id JOIN subjects s ON s.id=cs.subject_id "
        "WHERE cs.class_id=? AND cs.subject_id=? AND cs.teacher_id=? AND c.school_id=? AND s.school_id=? LIMIT 1",
        (class_id, subject_id, session.get("user_id"), school_id, school_id)).fetchone()
    return bool(row)


def can_access_scope(user_id, school_id, permission, school_level=None, department=None, class_id=None, class_arm=None, subject_id=None):
    """Server-side scope check; tenant/client IDs are never trusted."""
    conn=get_db()
    if school_id != current_school_id() and session.get("role") != "admin": conn.close(); return False
    assignments=active_role_assignments(conn,user_id,school_id)
    # Teaching staff whose roles are ALL class-bound (Teacher / Subject Teacher / Class Teacher-Form Teacher) are limited to
    # what the records say: the class they are form teacher of, and the class+subject pairs they are assigned. A staff member who
    # also holds a school-wide role (Librarian, Registrar, Principal...) gets that role's permissions on top, never less.
    if session.get("role") == "teacher":
        roles = session_roles()
        if all(r in CLASS_BOUND_ROLES for r in roles):
            ft_classes = set(form_teacher_class_ids(conn, user_id)) if "Class Teacher / Form Teacher" in roles else set()
            if class_id is not None and subject_id is not None:
                assigned = conn.execute(
                    "SELECT 1 FROM class_subjects cs JOIN classes c ON c.id=cs.class_id JOIN subjects s ON s.id=cs.subject_id "
                    "WHERE cs.class_id=? AND cs.subject_id=? AND cs.teacher_id=? AND c.school_id=? AND s.school_id=? LIMIT 1",
                    (class_id, subject_id, user_id, school_id, school_id)).fetchone()
                if not assigned and not (permission == "view" and int(class_id) in ft_classes):
                    conn.close(); return False
            elif class_id is not None:
                in_asg = conn.execute("SELECT 1 FROM class_subjects cs JOIN classes c ON c.id=cs.class_id WHERE cs.class_id=? AND cs.teacher_id=? AND c.school_id=? LIMIT 1",
                                      (class_id, user_id, school_id)).fetchone()
                if int(class_id) not in ft_classes and not in_asg:
                    conn.close(); return False
            elif "Class Teacher / Form Teacher" in roles and not ft_classes and len(roles) == 1:
                conn.close(); return False
    for a in assignments:
        if school_level and a["school_level"] not in ("All",school_level): continue
        if department and a["department"] and a["department"] != department: continue
        if class_id and a["class_id"] and int(a["class_id"]) != int(class_id): continue
        if class_arm and a["class_arm"] and a["class_arm"] != class_arm: continue
        if subject_id and a["subject_id"] and int(a["subject_id"]) != int(subject_id): continue
        if conn.execute("SELECT 1 FROM role_assignment_permissions WHERE assignment_id=? AND permission=? AND granted=0 LIMIT 1",(a["id"],permission)).fetchone(): conn.close(); return False
    if session.get("role") in ("admin", "sub_admin") and not assignments: conn.close(); return True
    for a in assignments:
        if school_level and a["school_level"] not in ("All",school_level): continue
        if department and a["department"] and a["department"] != department: continue
        if class_id and a["class_id"] and int(a["class_id"]) != int(class_id): continue
        if class_arm and a["class_arm"] and a["class_arm"] != class_arm: continue
        if subject_id and a["subject_id"] and int(a["subject_id"]) != int(subject_id): continue
        if conn.execute("SELECT 1 FROM role_assignment_permissions WHERE assignment_id=? AND permission=? AND granted=1 LIMIT 1",(a["id"],permission)).fetchone(): conn.close(); return True
    conn.close(); return False

def require_scoped_permission(permission, school_level=None, department=None, class_id=None, class_arm=None, subject_id=None):
    uid=session.get("user_id"); sid=current_school_id()
    return bool(uid and sid and can_access_scope(uid,sid,permission,school_level,department,class_id,class_arm,subject_id))

@app.route("/healthz")
def healthz():
    """Cheap liveness probe for hosts like Railway (no login, no data)."""
    conn = get_db()
    conn.execute("SELECT 1").fetchone()
    conn.close()
    resp = jsonify({"status": "ok"})
    resp.headers["Cache-Control"] = "no-store"     # the connectivity monitor needs a LIVE answer
    return resp


@app.route("/readyz")
def readyz():
    """Readiness probe: verifies that the configured SQLite database is usable."""
    try:
        conn = get_db()
        row = conn.execute("PRAGMA integrity_check").fetchone()
        verdict = row[0] if row else "unknown"
        conn.close()
        if verdict != "ok":
            return jsonify({"status": "not_ready", "database": "integrity_check_failed"}), 503
        resp = jsonify({"status": "ready", "database": "ok"})
        resp.headers["Cache-Control"] = "no-store"
        return resp
    except Exception:
        # Do not expose database paths or SQL details to unauthenticated probes.
        return jsonify({"status": "not_ready", "database": "unavailable"}), 503


# ---------- rate limiting ----------
# In-memory sliding-window counter per (route, client IP). This is a
# single-process store — fine for the size of deployment this app targets
# (one PythonAnywhere web worker), but it resets if the process restarts
# and isn't shared across multiple workers. That trade-off is consistent
# with the rest of the app's approach (e.g. the secret key is a local
# file, not an external service) — if this ever runs behind several
# worker processes, this should move to a shared store like Redis instead.

_rate_limit_lock = threading.Lock()
_rate_limit_store = defaultdict(deque)


def _is_rate_limited(key, max_attempts, window_seconds):
    now = time.time()
    with _rate_limit_lock:
        bucket = _rate_limit_store[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= max_attempts:
            return True
        bucket.append(now)
        return False


def rate_limit(max_attempts, window_seconds):
    """Caps how many POSTs a single IP can make to the decorated route
    within a trailing time window — every submission counts, not just
    failed ones, so a script can't dodge the limit by mixing in the
    occasional well-formed request. GET requests (just viewing the page)
    are never limited. On rejection, redirects back to the same page with
    a flash message rather than a bare error, so it fits the app's normal
    error handling."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.method == "POST":
                key = f"{request.endpoint}:{request.remote_addr}"
                if _is_rate_limited(key, max_attempts, window_seconds):
                    flash("Too many attempts from this connection. Please wait a few minutes and try again.", "error")
                    return redirect(request.path)
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ---------- custom subdomains ----------
# A school's chosen subdomain (e.g. "greenwood") only means something once
# the *hosting* is set up to route greenwood.<your-domain> to this same
# Flask app — a database column can't make DNS point anywhere. BASE_DOMAIN
# is the one thing the app needs told about that setup: the domain schools'
# subdomains sit under. Leave it unset and this feature quietly does
# nothing (every visitor just sees the normal, unbranded login page).
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "").strip().lower().rstrip(".")

RESERVED_SUBDOMAINS = {"www", "app", "api", "admin", "mail", "portal", "static", "assets"}


def _resolve_subdomain_from_host():
    if not BASE_DOMAIN:
        return None
    host = request.host.split(":")[0].lower()
    suffix = "." + BASE_DOMAIN
    if not host.endswith(suffix):
        return None
    label = host[: -len(suffix)]
    if not label or "." in label:  # only a single subdomain label, not a deeper one
        return None
    return label


@app.before_request
def _load_portal_school():
    g.portal_school = None
    label = _resolve_subdomain_from_host()
    if label and label not in RESERVED_SUBDOMAINS:
        conn = get_db()
        g.portal_school = conn.execute("SELECT * FROM schools WHERE subdomain=?", (label,)).fetchone()
        conn.close()


def _public_auth_school(conn=None):
    """Resolve the school used for public authentication branding.

    The browser may supply a School ID/Tenant ID or a school-issued signup
    code only as a selector. The actual branding record is always loaded from
    the server-side schools table. A hostname/subdomain takes precedence.
    Once authenticated, the session's school_id is the authoritative source.
    """
    if g.get("portal_school") is not None:
        return g.portal_school
    own_conn = conn is None
    conn = conn or get_db()
    try:
        sid = session.get("school_id")
        if sid:
            school = conn.execute("SELECT * FROM schools WHERE id=?", (sid,)).fetchone()
            if school:
                return school

        school_code = (request.values.get("school_code") or "").strip()
        if school_code:
            return conn.execute(
                "SELECT * FROM schools WHERE LOWER(school_code)=LOWER(?) OR LOWER(tenant_id)=LOWER(?) OR LOWER(school_id_public)=LOWER(?) LIMIT 1",
                (school_code, school_code, school_code),
            ).fetchone()

        signup_code = (request.values.get("signup_code") or "").strip()
        if signup_code and _table_exists_safe(conn, "signup_codes"):
            row = conn.execute(
                "SELECT sc.school_id FROM signup_codes sc JOIN schools s ON s.id=sc.school_id "
                "WHERE sc.code=? AND sc.status='active' AND s.activation_status='active' "
                "AND (sc.expires_at IS NULL OR sc.expires_at>CURRENT_TIMESTAMP) "
                "AND COALESCE(sc.usage_count,0)<COALESCE(sc.max_usage,1) LIMIT 1",
                (signup_code,),
            ).fetchone()
            if row:
                return conn.execute("SELECT * FROM schools WHERE id=?", (row["school_id"],)).fetchone()

        recovery_user_id = session.get("recovery_user_id") or session.get("recovery_verified_user_id")
        if recovery_user_id and _table_exists_safe(conn, "users"):
            row = conn.execute("SELECT school_id FROM users WHERE id=?", (recovery_user_id,)).fetchone()
            if row:
                return conn.execute("SELECT * FROM schools WHERE id=?", (row["school_id"],)).fetchone()

        username = (request.values.get("username") or "").strip()
        if username and _table_exists_safe(conn, "users"):
            row = conn.execute("SELECT school_id FROM users WHERE LOWER(username)=LOWER(?) LIMIT 1", (username,)).fetchone()
            if row:
                return conn.execute("SELECT * FROM schools WHERE id=?", (row["school_id"],)).fetchone()
        return None
    finally:
        if own_conn:
            conn.close()


def _auth_branding_payload(school):
    if not school:
        return {
            "school_name": "My School Hub", "logo_url": None, "branding": False,
            "opacity": 0.0, "position": "center", "background_style": "plain",
            "show_name": True,
        }
    logo = school["logo_filename"] if "logo_filename" in school.keys() else None
    enabled = bool(school["auth_branding_enabled"] if "auth_branding_enabled" in school.keys() else 1)
    active = str(school["activation_status"] or "").lower() == "active"
    branding = bool(enabled and active and logo)
    return {
        "school_id": school["id"],
        "school_name": school["name"],
        "logo_url": url_for("portal_logo", school_id=school["id"]) if branding else None,
        "branding": branding,
        "opacity": float(school["auth_logo_opacity"] if "auth_logo_opacity" in school.keys() and school["auth_logo_opacity"] is not None else 0.10),
        "position": school["auth_logo_position"] if "auth_logo_position" in school.keys() else "center",
        "background_style": school["auth_background_style"] if "auth_background_style" in school.keys() else "watermark",
        "show_name": bool(school["auth_show_school_name"] if "auth_show_school_name" in school.keys() else 1),
    }


@app.route("/auth/branding")
def auth_branding():
    conn = get_db()
    school = _public_auth_school(conn)
    payload = _auth_branding_payload(school)
    conn.close()
    return jsonify(payload)


@app.context_processor
def inject_portal_school():
    return dict(portal_school=g.get("portal_school"))


@app.context_processor
def inject_auth_branding():
    # Keep public auth pages school-aware without making school branding global.
    try:
        school = _public_auth_school()
        payload = _auth_branding_payload(school)
        return dict(
            auth_school=school,
            auth_school_name=payload.get("school_name"),
            auth_logo_url=payload.get("logo_url"),
            auth_branding=payload.get("branding", False),
            auth_logo_opacity=payload.get("opacity", 0.0),
            auth_logo_position=payload.get("position", "center"),
            auth_background_style=payload.get("background_style", "plain"),
            auth_show_school_name=payload.get("show_name", True),
        )
    except Exception:
        return dict(auth_school=None, auth_school_name="My School Hub", auth_logo_url=None,
                    auth_branding=False, auth_logo_opacity=0.0, auth_logo_position="center",
                    auth_background_style="plain", auth_show_school_name=True)


@app.before_request
def _check_force_logout():
    school_id = session.get("school_id")
    login_time = session.get("login_time")
    if school_id and login_time and ("user_id" in session or "student_id" in session):
        conn = get_db()
        row = conn.execute("SELECT force_logout_at FROM schools WHERE id=?", (school_id,)).fetchone()
        conn.close()
        if row and row["force_logout_at"] and login_time <= row["force_logout_at"]:
            session.clear()
            flash("You've been signed out by your school administrator. Please log in again.", "error")
            return redirect(url_for("login"))
    return None


@app.route("/portal-logo/<int:school_id>")
def portal_logo(school_id):
    """Publicly serves a school's logo so its subdomain's login page can
    show it before anyone has signed in — a school's own logo isn't
    sensitive, so this is intentionally not session-gated."""
    conn = get_db()
    school = get_school(conn, school_id)
    conn.close()
    if (not school or not school["logo_filename"] or
        str(school["activation_status"] or "").lower() != "active" or
        bool(school["is_archived"] if "is_archived" in school.keys() else 0)):
        return "", 404
    response = send_from_directory(INSTANCE_DIR, school["logo_filename"])
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# ---------- helpers ----------

def _table_exists_safe(conn, name):
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())

def parent_login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "parent_id" not in session:
            return redirect(url_for("login"))
        conn = get_db()
        parent = conn.execute("SELECT * FROM parent_accounts WHERE id=? AND school_id=?", (session["parent_id"], session.get("school_id"))).fetchone()
        conn.close()
        if not parent or not parent["is_active"]:
            session.clear(); flash("This parent account is no longer active.", "error"); return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

def parent_child(conn, parent_id, student_id):
    return conn.execute(
        "SELECT s.*, c.name AS class_name, c.school_id FROM parent_students ps "
        "JOIN students s ON s.id=ps.student_id JOIN classes c ON c.id=s.class_id "
        "WHERE ps.parent_id=? AND ps.school_id=? AND ps.status='verified' AND s.id=? AND s.is_active=1",
        (parent_id, current_school_id(), student_id),
    ).fetchone()

def parent_children(conn, parent_id):
    return conn.execute(
        "SELECT s.*, c.name AS class_name FROM parent_students ps "
        "JOIN students s ON s.id=ps.student_id JOIN classes c ON c.id=s.class_id "
        "WHERE ps.parent_id=? AND ps.school_id=? AND ps.status='verified' AND s.is_active=1 ORDER BY s.first_name, s.last_name",
        (parent_id, current_school_id()),
    ).fetchall()

def login_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            # A session must not outlive its account: if an admin deactivated
            # or deleted this user since they logged in, end it now.
            _conn = get_db()
            _u = _conn.execute("SELECT is_active,school_id,tenant_id,rbac_role,position FROM users WHERE id=?",(session["user_id"],)).fetchone()
            _roles = user_roles(_conn, session["user_id"], _u["school_id"]) if _u is not None else []
            _school=_conn.execute("SELECT id,tenant_id,activation_status,is_suspended,is_archived FROM schools WHERE id=?",(session.get("school_id"),)).fetchone()
            tenant_ok=bool(_u and _school and _u["school_id"]==_school["id"] and _u["tenant_id"]==_school["tenant_id"] and session.get("tenant_id")==_school["tenant_id"])
            _conn.close()
            if _u is not None and _u["is_active"]:
                # The CURRENT active role in the database always wins over whatever was cached at login,
                # so a role change by the School Admin takes effect on the very next request.
                session["rbac_role"] = _u["rbac_role"]
                session["rbac_roles"] = _roles
                session["position"] = _u["position"]
            if _u is None or not _u["is_active"]:
                session.clear()
                flash("This account is no longer active. Contact your school admin.", "error")
                return redirect(url_for("login"))
            if not tenant_ok: session.clear(); flash("Your tenant session is invalid. Please sign in again.","error"); return redirect(url_for("login"))
            if not _school or _school["activation_status"]!="active" or _school["is_suspended"] or _school["is_archived"]: session.clear(); flash("This school is not currently available.","error"); return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                flash("You don't have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return decorator


def current_school_id():
    return session.get("school_id")

def current_tenant_id():
    return session.get("tenant_id")


def request_id():
    rid = request.headers.get("X-Request-ID") or session.get("request_id") or secrets.token_hex(12)
    session["request_id"] = rid
    return rid

def security_event(conn, event_name, decision="allowed", details=None, resource_type=None, resource_id=None, school_id=None, tenant_id=None):
    """Append a structured security event without exposing secrets."""
    conn.execute("INSERT INTO security_events(event_name,actor_user_id,actor_role,actor_name,school_id,tenant_id,resource_type,resource_id,decision,details,request_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (event_name, session.get("user_id"), session.get("role"), session.get("name"), school_id or session.get("school_id"), tenant_id or session.get("tenant_id"), resource_type, resource_id, decision, (details or "")[:1000], request_id()))

def audit_status_change(conn, entity_type, entity_id, status_type, previous_status, new_status, reason=""):
    conn.execute("INSERT INTO status_history(entity_type,entity_id,status_type,previous_status,new_status,changed_by,reason,school_id,tenant_id,request_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (entity_type,entity_id,status_type,previous_status,new_status,session.get("user_id"),reason,current_school_id(),current_tenant_id(),request_id()))

def validate_password_policy(password, username=None):
    errors=[]
    if not password or len(password)<8 or len(password)>128: errors.append("Password must be 8–128 characters.")
    if password and not re.search(r"[A-Z]", password): errors.append("Password must contain an uppercase letter.")
    if password and not re.search(r"[a-z]", password): errors.append("Password must contain a lowercase letter.")
    if password and not re.search(r"\d", password): errors.append("Password must contain a number.")
    if password and not re.search(r"[^A-Za-z0-9]", password): errors.append("Password must contain a special character.")
    if username and password and username.lower() in password.lower(): errors.append("Password must not contain your username.")
    return errors

def _security_audit_event(conn, action, details, school_id=None):
    try: log_audit(conn, session.get("role", "system"), session.get("name", "System"), action, details=details, school_id=school_id)
    except Exception: pass


def current_term(conn):
    return conn.execute(
        "SELECT terms.*, sessions.name as session_name FROM terms "
        "JOIN sessions ON sessions.id = terms.session_id "
        "WHERE terms.is_active=1 AND sessions.school_id=? LIMIT 1",
        (current_school_id(),),
    ).fetchone()


def resolve_term(conn, requested_term_id=None):
    """Returns the requested term (if it belongs to this school) or the
    currently active term otherwise — used so broadsheets/results can show
    a past term's data, not just whatever's active right now."""
    if requested_term_id:
        term = conn.execute(
            "SELECT terms.*, sessions.name as session_name FROM terms "
            "JOIN sessions ON sessions.id = terms.session_id "
            "WHERE terms.id=? AND sessions.school_id=?",
            (requested_term_id, current_school_id()),
        ).fetchone()
        if term:
            return term
    return current_term(conn)


def resolve_session(conn, requested_session_id=None):
    """Same idea as resolve_term, but for a whole academic session — used
    by the cumulative/annual result, which spans every term in a session
    rather than just one."""
    if requested_session_id:
        s = conn.execute(
            "SELECT * FROM sessions WHERE id=? AND school_id=?",
            (requested_session_id, current_school_id()),
        ).fetchone()
        if s:
            return s
    return conn.execute(
        "SELECT * FROM sessions WHERE school_id=? AND is_active=1 LIMIT 1", (current_school_id(),)
    ).fetchone()


# Terms are always named "1st Term" / "2nd Term" / "3rd Term" from the
# fixed dropdown on Setup → Terms, so cumulative results can order them
# chronologically by name — any other name (very old/custom data) just
# sorts after these three, in creation order.
_TERM_ORDER = {"1st Term": 1, "2nd Term": 2, "3rd Term": 3}


def term_sort_key(t):
    return (_TERM_ORDER.get(t["name"], 99), t["id"])


def terms_for_session(conn, session_id):
    rows = conn.execute("SELECT * FROM terms WHERE session_id=?", (session_id,)).fetchall()
    return sorted(rows, key=term_sort_key)


def student_class_for_session(conn, student_id, session_id):
    """Which class this student was in during a given session — mirrors
    student_class_for_term, but keyed directly by session."""
    row = conn.execute(
        "SELECT class_id FROM enrollments WHERE student_id=? AND session_id=?",
        (student_id, session_id),
    ).fetchone()
    if row:
        return row["class_id"]
    current = conn.execute("SELECT class_id FROM students WHERE id=?", (student_id,)).fetchone()
    return current["class_id"] if current else None


def all_terms_for_school(conn):
    return conn.execute(
        "SELECT terms.*, sessions.name as session_name FROM terms "
        "JOIN sessions ON sessions.id = terms.session_id "
        "WHERE sessions.school_id=? ORDER BY sessions.id DESC, terms.id DESC",
        (current_school_id(),),
    ).fetchall()


def student_class_for_term(conn, student_id, term_id):
    """Which class this student was actually in during the given term's
    session — falls back to their current class if no enrollment record
    exists for that session (e.g. very old data predating this feature)."""
    row = conn.execute(
        "SELECT e.class_id FROM enrollments e JOIN terms t ON t.session_id = e.session_id "
        "WHERE e.student_id=? AND t.id=?", (student_id, term_id),
    ).fetchone()
    if row:
        return row["class_id"]
    current = conn.execute("SELECT class_id FROM students WHERE id=?", (student_id,)).fetchone()
    return current["class_id"] if current else None


def get_grading_config(conn):
    return conn.execute(
        "SELECT * FROM grading_config WHERE school_id=? LIMIT 1", (current_school_id(),)
    ).fetchone()


def compute_total(ca1, ca2, exam, ca3=0):
    return round((ca1 or 0) + (ca2 or 0) + (ca3 or 0) + (exam or 0), 2)


def ca3_enabled(config):
    """CA3 is optional: a school switches it on by giving it a maximum above 0.
    Every existing school keeps it off (ca3_max = 0) until an admin opts in."""
    try:
        return bool(config and (config["ca3_max"] or 0) > 0)
    except (KeyError, IndexError):
        return False


class ScoreChangeError(ValueError):
    """Raised when a score write is refused (cross-school reference, missing reason, ...)."""


def _actor_role_label():
    if session.get("rbac_role"):
        return session["rbac_role"]
    pos = session.get("position")
    if pos and pos in POSITION_LABELS:
        return POSITION_LABELS[pos]
    return (session.get("role") or "user").replace("_", " ").title()


def save_score(conn, student_id, subject_id, term_id, ca1, ca2, ca3, exam, user_id, reason=None, source="score_entry"):
    """The one place an online score row is written (form save and CSV import both come through here).
    Every real change is written to the append-only score_audit log in the SAME transaction as the score,
    so a score can never change without a history row (and vice versa)."""
    ctx = conn.execute(
        "SELECT st.first_name, st.last_name, st.other_names, st.admission_no, st.class_id, c.name AS class_name, c.arm AS class_arm, c.school_id, "
        "sc.tenant_id, sub.name AS subject_name, t.name AS term_name, t.session_id, se.name AS session_name, t.is_published "
        "FROM students st JOIN classes c ON c.id=st.class_id JOIN schools sc ON sc.id=c.school_id "
        "JOIN subjects sub ON sub.id=? AND sub.school_id=c.school_id "
        "JOIN terms t ON t.id=? JOIN sessions se ON se.id=t.session_id AND se.school_id=c.school_id "
        "WHERE st.id=?", (subject_id, term_id, student_id)).fetchone()
    if not ctx or ctx["school_id"] != current_school_id():
        raise ScoreChangeError("That student, subject or term does not belong to your school.")
    existing = conn.execute(
        "SELECT * FROM scores WHERE student_id=? AND subject_id=? AND term_id=?",
        (student_id, subject_id, term_id),
    ).fetchone()
    old_vals = (existing["ca1"], existing["ca2"], existing["ca3"], existing["exam"]) if existing else (None, None, None, None)
    changed = (existing is None and any((ca1, ca2, ca3, exam))) or (
        existing is not None and (existing["ca1"] != ca1 or existing["ca2"] != ca2 or (existing["ca3"] or 0) != ca3 or existing["exam"] != exam))
    reason = (reason or "").strip()[:300] or None
    if changed and ctx["is_published"] and not reason:
        raise ScoreChangeError("This term's results are published. Enter a reason for the score change.")
    if changed:
        old_total = compute_total(old_vals[0], old_vals[1], old_vals[3], old_vals[2]) if existing else None
        new_total = compute_total(ca1, ca2, exam, ca3)
        conn.execute(
            "INSERT INTO score_history (student_id, subject_id, term_id, old_ca1, old_ca2, old_ca3, old_exam, "
            "new_ca1, new_ca2, new_ca3, new_exam, changed_by, tenant_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (student_id, subject_id, term_id, *(old_vals[0], old_vals[1], old_vals[2], old_vals[3]), ca1, ca2, ca3, exam, user_id, ctx["tenant_id"]),
        )
        full_name = " ".join(x for x in (ctx["last_name"], ctx["first_name"], ctx["other_names"]) if x)
        if existing is None:
            action = "Score entered"
        elif ctx["is_published"]:
            action = "Previously submitted score changed"
        elif not any((ca1, ca2, ca3, exam)):
            action = "Score cleared"
        else:
            action = "Score edited"
        conn.execute(
            "INSERT INTO score_audit(school_id,tenant_id,student_id,student_name,admission_no,subject_id,subject_name,class_id,class_name,"
            "session_id,session_name,term_id,term_name,old_ca1,old_ca2,old_ca3,old_exam,old_total,new_ca1,new_ca2,new_ca3,new_exam,new_total,"
            "difference,changed_by,changed_by_name,changed_by_role,result_status,reason,source,class_arm,action) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ctx["school_id"], ctx["tenant_id"], student_id, full_name, ctx["admission_no"], subject_id, ctx["subject_name"],
             ctx["class_id"], ctx["class_name"], ctx["session_id"], ctx["session_name"], term_id, ctx["term_name"],
             old_vals[0], old_vals[1], old_vals[2], old_vals[3], old_total, ca1, ca2, ca3, exam, new_total,
             round(new_total - (old_total or 0), 2), user_id, session.get("name"), recorder_role_label(),
             "Published" if ctx["is_published"] else "Draft", reason, source, ctx["class_arm"], action),
        )
    conn.execute(
        "INSERT INTO scores (student_id, subject_id, term_id, ca1, ca2, ca3, exam) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(student_id, subject_id, term_id) DO UPDATE SET "
        "ca1=excluded.ca1, ca2=excluded.ca2, ca3=excluded.ca3, exam=excluded.exam",
        (student_id, subject_id, term_id, ca1, ca2, ca3, exam),
    )


def audit_scores_deleted(conn, student_ids, reason="Student record deleted"):
    """Deleting a student removes their scores; each removed score is first written to the append-only score audit
    (who, when, which subject/class/arm, the values that were deleted)."""
    if not student_ids:
        return
    sp = ",".join("?" * len(student_ids))
    rows = conn.execute(
        "SELECT sc.*, st.first_name, st.last_name, st.other_names, st.admission_no, st.class_id, c.name AS class_name, c.arm AS class_arm, "
        "c.school_id, sch.tenant_id, sub.name AS subject_name, t.name AS term_name, t.session_id, se.name AS session_name, t.is_published "
        "FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id JOIN schools sch ON sch.id=c.school_id "
        "JOIN subjects sub ON sub.id=sc.subject_id JOIN terms t ON t.id=sc.term_id JOIN sessions se ON se.id=t.session_id "
        f"WHERE sc.student_id IN ({sp})", list(student_ids)).fetchall()
    for r in rows:
        old_total = compute_total(r["ca1"], r["ca2"], r["exam"], r["ca3"])
        conn.execute(
            "INSERT INTO score_audit(school_id,tenant_id,student_id,student_name,admission_no,subject_id,subject_name,class_id,class_name,"
            "session_id,session_name,term_id,term_name,old_ca1,old_ca2,old_ca3,old_exam,old_total,new_ca1,new_ca2,new_ca3,new_exam,new_total,"
            "difference,changed_by,changed_by_name,changed_by_role,result_status,reason,source,class_arm,action) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,0,?,?,?,?,?,?,'student_deleted',?,'Score deleted')",
            (r["school_id"], r["tenant_id"], r["student_id"], " ".join(x for x in (r["last_name"], r["first_name"], r["other_names"]) if x),
             r["admission_no"], r["subject_id"], r["subject_name"], r["class_id"], r["class_name"], r["session_id"], r["session_name"],
             r["term_id"], r["term_name"], r["ca1"], r["ca2"], r["ca3"], r["exam"], old_total,
             -(old_total or 0), session.get("user_id"), session.get("name"), recorder_role_label(),
             "Published" if r["is_published"] else "Draft", reason, r["class_arm"]))


def score_range_errors(config, ca1, ca2, ca3, exam):
    errs = []
    for label, value, limit in (("CA1", ca1, config["ca1_max"]), ("CA2", ca2, config["ca2_max"]),
                                ("CA3", ca3, config["ca3_max"] or 0), ("Exam", exam, config["exam_max"])):
        if value < 0 or value > limit:
            errs.append(f"{label} {value:g} is outside 0–{limit:g}")
    return errs


def class_in_school(conn, class_id):
    return conn.execute(
        "SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, current_school_id())
    ).fetchone()


def subject_in_school(conn, subject_id):
    return conn.execute(
        "SELECT * FROM subjects WHERE id=? AND school_id=?", (subject_id, current_school_id())
    ).fetchone()


def student_in_school(conn, student_id):
    row = conn.execute(
        "SELECT s.* FROM students s JOIN classes c ON c.id=s.class_id "
        "WHERE s.id=? AND c.school_id=?", (student_id, current_school_id())
    ).fetchone()
    return row


def teacher_in_school(conn, teacher_id):
    return conn.execute(
        "SELECT * FROM users WHERE id=? AND school_id=? AND role='teacher'",
        (teacher_id, current_school_id()),
    ).fetchone()


def require_class_result_access(conn, class_id, permission="view"):
    """Authorize a class using the authenticated user's scoped assignment first,
    then retain the legacy form-teacher/result rule for older accounts."""
    class_row = class_in_school(conn, class_id)
    if not class_row:
        flash("That class doesn't exist.", "error")
        return redirect(url_for("dashboard"))
    level = class_row["level"] if "level" in class_row.keys() else None
    if session.get("role") == "teacher" and not can_view_all_results(session.get("role"), session.get("position")):
        # Results and broadsheets: only a Class Teacher / Form Teacher of THIS class (or a role allowed school-wide).
        roles = session_roles()
        ft_here = "Class Teacher / Form Teacher" in roles and int(class_id) in set(form_teacher_class_ids(conn, session.get("user_id")))
        school_wide = any(r in RESULT_VIEW_ROLES for r in roles)
        if not ft_here and not school_wide:
            flash("You can view results and the broadsheet only for the class you are Class Teacher / Form Teacher of.", "error")
            return redirect(url_for("dashboard"))
        return None
    if can_access_scope(session.get("user_id"), current_school_id(), permission,
                        school_level=level, class_id=class_id):
        return None
    if not can_view_class_results(conn, session.get("role"), session.get("position"), session.get("user_id"), class_id):
        flash(
            "You don't have access to view results for this class. Only the principal, "
            "vice principal, exam officer, and this class's form teacher can view its results.",
            "error",
        )
        return redirect(url_for("dashboard"))
    return None


def get_accessible_class_ids(conn, role, position, user_id):
    if can_view_all_results(role, position) or (role == "teacher" and any(r in RESULT_VIEW_ROLES for r in session_roles())):
        return "all"
    if role == "teacher" and "Class Teacher / Form Teacher" not in session_roles():
        return []          # a class record alone grants nothing once the Class Teacher / Form Teacher role is removed
    return form_teacher_class_ids(conn, user_id)


def require_cumulative_enabled(conn):
    """Returns None if this school has Cumulative Result turned on, or a
    redirect response otherwise."""
    school = get_school(conn, current_school_id())
    if not school or not school["cumulative_enabled"]:
        flash("Cumulative/Annual results are turned off for this school. Enable it under Setup → Terms.", "error")
        return redirect(url_for("dashboard"))
    return None


# ---------- PWA: manifest & service worker (served at root scope) ----------

@app.route("/service-worker.js")
def service_worker():
    """Online-only: this worker caches nothing. Devices that installed an older
    offline-capable worker fetch this file on their next visit, and it removes
    itself and every cache the old worker created."""
    resp = send_from_directory("static", "service-worker.js", mimetype="application/javascript")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/manifest.json")
def manifest():
    return send_from_directory("static", "manifest.json", mimetype="application/manifest+json")


@app.route("/school-logo")
def school_logo():
    if "school_id" not in session:
        return "", 404
    conn = get_db()
    school = get_school(conn, session["school_id"])
    conn.close()
    if not school or not school["logo_filename"]:
        return "", 404
    return send_from_directory(INSTANCE_DIR, school["logo_filename"])


@app.context_processor
def inject_me_avatar():
    """The signed-in user's passport (if any) for the dashboard header; clicking it opens their profile."""
    try:
        if session.get("student_id") and session.get("role") == "student":
            conn = get_db()
            try:
                r = conn.execute("SELECT first_name, last_name, photo_filename FROM students WHERE id=? AND school_id=?", (session["student_id"], session.get("school_id"))).fetchone()
            finally:
                conn.close()
            if r:
                return {"me_avatar": {"name": r["first_name"] or "Student", "initial": (r["first_name"] or "S")[0].upper(),
                                      "photo_url": url_for("student_self_photo") if r["photo_filename"] else None,
                                      "profile_url": url_for("student_self_profile")}}
        elif session.get("user_id") and session.get("school_id"):
            conn = get_db()
            try:
                r = conn.execute("SELECT name, photo_filename FROM users WHERE id=? AND school_id=?", (session["user_id"], session.get("school_id"))).fetchone()
            finally:
                conn.close()
            if r:
                return {"me_avatar": {"name": r["name"], "initial": (r["name"] or "U")[0].upper(),
                                      "photo_url": url_for("staff_photo", user_id=session["user_id"]) if r["photo_filename"] else None,
                                      "profile_url": url_for("staff_profile", user_id=session["user_id"])}}
    except Exception:
        app.logger.exception("Could not build the header avatar")
    return {}


@app.context_processor
def inject_school_settings():
    if "school_id" in session:
        conn = get_db()
        school = get_school(conn, session["school_id"])
        conn.close()
        if school:
            logo_url = url_for("school_logo") if school["logo_filename"] else None
            font = WEB_FONTS.get(school["web_font"] or "system", WEB_FONTS["system"])
            return dict(
                school_name=school["name"], school_logo_url=logo_url,
                school_logo_align=school["logo_align"],
                school_name_align=school["name_align"] or "center",
                cumulative_enabled=bool(school["cumulative_enabled"]),
                web_font_css=font["css"], web_font_google=font["google"],
                school_timezone=school["timezone"] or "Africa/Lagos",
                school_date_format=school["date_format"] or "dmy",
                result_accent_color=school["result_accent_color"] or "#1f3a5f",
                result_header_layout=school["result_header_layout"] or "logo-left",
                theme_preset=school["theme_preset"] or "default",
                dashboard_primary_color=school["dashboard_primary_color"] or "#1f6feb",
                dashboard_secondary_color=school["dashboard_secondary_color"] or "#0b3b75",
                dashboard_accent_color=school["dashboard_accent_color"] or "#7c4dff",
                dashboard_sidebar_style=school["dashboard_sidebar_style"] or "dark",
                dashboard_header_style=school["dashboard_header_style"] or "solid",
                school_tagline=school["school_tagline"] or "Better Data. Brighter Futures.",
            )
    return dict(school_name="School Result System", school_logo_url=None, school_logo_align="center",
                school_name_align="center",
                cumulative_enabled=False, web_font_css=WEB_FONTS["system"]["css"], web_font_google=None,
                school_timezone="Africa/Lagos", school_date_format="dmy",
                result_accent_color="#1f3a5f", result_header_layout="logo-left",
                theme_preset="default", dashboard_primary_color="#1f6feb",
                dashboard_secondary_color="#0b3b75", dashboard_accent_color="#7c4dff",
                dashboard_sidebar_style="dark", dashboard_header_style="solid",
                school_tagline="Better Data. Brighter Futures.")


def notification_reader():
    """(reader_type, reader_id, table, role, school_id) for whoever is signed in, or None."""
    if "user_id" in session:
        return ("user", session["user_id"], "users", session.get("role"), session.get("school_id"))
    if "student_id" in session:
        return ("student", session["student_id"], "students", "student", session.get("school_id"))
    if "parent_id" in session:
        return ("parent", session["parent_id"], "parent_accounts", "parent", session.get("school_id"))
    return None


def notification_rows(conn, reader, limit=50):
    """The reader's visible notifications, each with `is_read`. Read = at or before the reader's old 'seen up to' mark,
    or individually marked read. Everything is limited to the reader's own school (or platform-wide notices)."""
    rtype, rid, table, role, school_id = reader
    seen = conn.execute(f"SELECT last_notification_seen_id FROM {table} WHERE id=?", (rid,)).fetchone()
    seen_id = (seen["last_notification_seen_id"] if seen else 0) or 0
    rows = get_visible_notifications(conn, role, school_id, limit)
    done = {r["notification_id"] for r in conn.execute("SELECT notification_id FROM notification_reads WHERE reader_type=? AND reader_id=?", (rtype, rid)).fetchall()}
    return [dict(r) | {"is_read": (r["id"] <= seen_id) or (r["id"] in done)} for r in rows]


@app.context_processor
def inject_school_clock():
    """Server time for the live clock (the device clock is never used): epoch seconds + the school's timezone name."""
    if "school_id" not in session and "platform_admin_id" not in session:
        return {}
    try:
        conn = get_db()
        tz, name = school_tz(conn, session.get("school_id")) if session.get("school_id") else (ZoneInfo("Africa/Lagos"), "Africa/Lagos")
        text = school_clock_text(conn, session.get("school_id")) if session.get("school_id") else ""
        conn.close()
    except Exception:
        name, text = "Africa/Lagos", ""
    return dict(server_epoch=int(datetime.datetime.now(datetime.timezone.utc).timestamp()), clock_tz=name, dash_clock=text)


@app.context_processor
def inject_platform_unread():
    if "platform_admin_id" not in session:
        return {}
    conn = get_db()
    try:
        n = conn.execute("SELECT COUNT(*) c FROM platform_notifications WHERE read_at IS NULL").fetchone()["c"]
    finally:
        conn.close()
    return dict(platform_unread=n)


@app.context_processor
def inject_unread_notifications():
    reader = notification_reader()
    count = 0
    if reader:
        conn = get_db()
        try:
            count = sum(1 for n in notification_rows(conn, reader, 500) if not n["is_read"])
        finally:
            conn.close()
    return dict(unread_notifications=count)


def _iso_utc(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") if dt else None


def subscription_state(school, now=None):
    """Return effective subscription state without mutating the database."""
    now = now or datetime.datetime.utcnow()
    status = (school["subscription_status"] if "subscription_status" in school.keys() else "legacy") or "legacy"
    if status == "legacy":
        return {"status": "legacy", "active": True, "label": "Legacy / Existing", "days_left": None}
    if status in ("suspended", "cancelled"):
        return {"status": status, "active": False, "label": status.title(), "days_left": None}
    end_key = "trial_ends_at" if status == "trial" else "subscription_ends_at"
    end_raw = school[end_key] if end_key in school.keys() else None
    end = None
    if end_raw:
        try:
            end = datetime.datetime.fromisoformat(end_raw.replace("Z", ""))
        except ValueError:
            end = None
    grace_raw = school["grace_ends_at"] if "grace_ends_at" in school.keys() else None
    grace = None
    if grace_raw:
        try:
            grace = datetime.datetime.fromisoformat(grace_raw.replace("Z", ""))
        except ValueError:
            grace = None
    if end and now > end:
        if grace and now <= grace:
            days = max(0, (grace.date() - now.date()).days)
            return {"status": "grace", "active": True, "label": "Grace period", "days_left": days}
        return {"status": "expired", "active": False, "label": "Expired", "days_left": 0}
    days = max(0, (end.date() - now.date()).days) if end else None
    return {"status": status, "active": True, "label": status.replace("_", " ").title(), "days_left": days}



def subscription_plan_for_school(conn, school):
    code = (school["subscription_plan"] if "subscription_plan" in school.keys() else "legacy") or "legacy"
    return conn.execute("SELECT * FROM subscription_plans WHERE code=? AND is_active=1", (code,)).fetchone()

def school_plan_usage(conn, school_id):
    students = conn.execute("SELECT COUNT(*) AS n FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1", (school_id,)).fetchone()["n"]
    teachers = conn.execute("SELECT COUNT(*) AS n FROM users WHERE school_id=? AND role='teacher' AND COALESCE(is_active,1)=1", (school_id,)).fetchone()["n"]
    return {"students": students, "teachers": teachers}

def plan_limit_state(plan, usage):
    out = {}
    for key, col in (("students", "max_students"), ("teachers", "max_teachers")):
        limit = plan[col] if plan else None
        used = usage[key]
        out[key] = {"used": used, "limit": limit, "percent": round((used / limit) * 100, 1) if limit else 0, "exceeded": bool(limit and used >= limit)}
    return out

def subscription_login_allowed(school):
    return subscription_state(school)["active"]


def plan_limit_check(conn, school_id, resource, additional=1):
    """Check whether a school may create additional records under its plan.
    Legacy schools remain unlimited. Existing records are never deleted or
    modified when a limit is reached.
    """
    school = get_school(conn, school_id)
    if not school:
        return False, "School not found.", None
    state = subscription_state(school)
    if not state["active"]:
        return False, f"This school's {state['label'].lower()} does not allow new records. Contact the platform administrator.", state
    plan = subscription_plan_for_school(conn, school)
    if not plan or resource not in ("students", "teachers"):
        return True, None, state
    usage = school_plan_usage(conn, school_id)
    limit = plan[f"max_{resource}"] if f"max_{resource}" in plan.keys() else None
    used = usage[resource]
    if limit is not None and used + additional > limit:
        return False, f"{resource.title()} limit reached ({used}/{limit}) on the {plan['name']} plan. Contact the platform administrator to upgrade or extend the plan.", state
    return True, None, state


def plan_usage_alerts(conn, school_id):
    """Return non-blocking usage warnings for the School Admin dashboard."""
    school = get_school(conn, school_id)
    if not school:
        return []
    plan = subscription_plan_for_school(conn, school)
    if not plan:
        return []
    usage = school_plan_usage(conn, school_id)
    alerts = []
    for resource in ("students", "teachers"):
        limit = plan[f"max_{resource}"] if f"max_{resource}" in plan.keys() else None
        used = usage[resource]
        if not limit:
            continue
        pct = (used / limit) * 100
        if used >= limit:
            alerts.append({"resource": resource.title(), "level": "danger", "used": used, "limit": limit, "percent": 100})
        elif pct >= 80:
            alerts.append({"resource": resource.title(), "level": "warning", "used": used, "limit": limit, "percent": round(pct)})
    state = subscription_state(school)
    if state["status"] in ("trial", "active", "grace") and state["days_left"] is not None and state["days_left"] <= 14:
        alerts.append({"resource": "Subscription", "level": "warning", "used": state["days_left"], "limit": None, "percent": None})
    return alerts


# ---------- auth ----------

@app.route("/", methods=["GET"])
def index():
    if "parent_id" in session:
        return redirect(url_for("parent_dashboard"))
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/admin/login")
def admin_login(): return render_template("login.html", selected_portal="admin")
@app.route("/staff/login")
def staff_login(): return render_template("login.html", selected_portal="staff")
@app.route("/parent/login")
def parent_login(): return render_template("login.html", selected_portal="parent")

@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_attempts=10, window_seconds=300)
def login():
    if request.method == "POST":
        identifier = request.form["username"].strip()
        password = request.form["password"]
        requested_school_code = request.form.get("school_code", "").strip()
        conn = get_db()
        parent = conn.execute(
            "SELECT * FROM parent_accounts WHERE (username=? OR (email IS NOT NULL AND LOWER(email)=LOWER(?)) OR (phone IS NOT NULL AND phone=?))",
            (identifier, identifier, identifier),
        ).fetchone() if _table_exists_safe(conn, "parent_accounts") else None
        if parent and check_password_hash(parent["password_hash"], password):
            school = get_school(conn, parent["school_id"])
            if not parent["is_active"] or ("account_status" in parent.keys() and parent["account_status"] != "active"):
                conn.close()
                flash("This parent account has been deactivated. Contact the school administrator.", "error")
                return render_template("login.html")
            if requested_school_code and school and requested_school_code.lower() not in {str(school["school_code"] or "").lower(), str(school["tenant_id"] or "").lower()}:
                conn.close(); flash("That School ID / Tenant ID does not match this account.", "error"); return render_template("login.html")
            if school and school["activation_status"] != "active":
                conn.close(); flash("This school hasn't been activated yet.", "error"); return render_template("login.html")
            if school and school["is_archived"]:
                conn.close(); flash("This school's account has been archived.", "error"); return render_template("login.html")
            if school and school["is_suspended"]:
                conn.close(); flash("This school's account has been suspended.", "error"); return render_template("login.html")
            if school and not subscription_login_allowed(school):
                conn.close(); flash("This school's subscription or trial has expired.", "error"); return render_template("login.html")
            if g.portal_school and (not school or school["id"] != g.portal_school["id"]):
                conn.close(); flash(f"That account isn't registered under {g.portal_school['name']}'s portal.", "error"); return render_template("login.html")
            verified_count=conn.execute("SELECT COUNT(*) AS n FROM parent_students WHERE parent_id=? AND school_id=? AND status='verified'",(parent["id"],parent["school_id"])).fetchone()["n"]
            conn.close()
            # Parent may sign in before a child is verified; student data remains inaccessible until a verified link exists.
            session.clear(); session.permanent=True
            session["parent_id"] = parent["id"]; session["name"] = parent["name"]; session["role"] = "parent"
            session["school_id"] = parent["school_id"]; session["tenant_id"] = school["tenant_id"] if school and "tenant_id" in school.keys() else None
            session["school_code"] = school["school_code"] if school and "school_code" in school.keys() else None
            session["login_time"] = datetime.datetime.utcnow().isoformat(timespec="seconds")
            session["account_status"] = "active"
            session["permissions"] = []
            session["scope"] = "school"
            return redirect(url_for("parent_dashboard"))
        user = conn.execute(
            "SELECT * FROM users WHERE LOWER(username)=LOWER(?) "
            "OR (email IS NOT NULL AND LOWER(email)=LOWER(?)) "
            "OR (phone IS NOT NULL AND phone=?)",
            (identifier, identifier, identifier),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            if not user["is_active"]:
                conn.close()
                flash("This account has been deactivated. Contact your school admin.", "error")
                return render_template("login.html")
            school = get_school(conn, user["school_id"])
            if requested_school_code and school and requested_school_code.lower() not in {str(school["school_code"] or "").lower(), str(school["tenant_id"] or "").lower()}:
                conn.close()
                flash("That School ID / Tenant ID does not match this account.", "error")
                return render_template("login.html")
            conn.close()
            if school and school["activation_status"] != "active":
                flash("This school hasn't been activated yet. Enter your activation code on the Activate School page.", "error")
                return render_template("login.html")
            if school and school["is_archived"]:
                flash("This school's account has been archived. Contact the platform administrator.", "error")
                return render_template("login.html")
            if school and school["is_suspended"]:
                flash("This school's account has been suspended. Contact the platform administrator.", "error")
                return render_template("login.html")
            if school and not subscription_login_allowed(school):
                flash("This school's subscription or trial has expired. Contact the platform administrator.", "error")
                return render_template("login.html")
            if g.portal_school and (not school or school["id"] != g.portal_school["id"]):
                flash(f"That account isn't registered under {g.portal_school['name']}'s portal.", "error")
                return render_template("login.html")
            session.permanent = True
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            session["position"] = user["position"]
            session["rbac_role"] = user["rbac_role"] if "rbac_role" in user.keys() else None
            session["rbac_roles"] = [user["rbac_role"]] if "rbac_role" in user.keys() and user["rbac_role"] else []
            session["school_id"] = user["school_id"]
            session["tenant_id"] = school["tenant_id"] if school and "tenant_id" in school.keys() else None
            session["school_code"] = school["school_code"] if school and "school_code" in school.keys() else None
            session["login_time"] = datetime.datetime.utcnow().isoformat(timespec="seconds")
            if user["role"] == "admin" and "first_login_required" in user.keys() and user["first_login_required"]:
                return redirect(url_for("admin_first_login"))
            if user["role"] == "teacher" and "first_login_required" in user.keys() and user["first_login_required"]:
                return redirect(url_for("staff_onboarding"))
            return redirect(url_for("dashboard"))
        conn.close()
        flash("Invalid username/email/phone or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required()
def change_password():
    if request.method == "POST":
        current = request.form["current_password"]
        new = request.form["new_password"]
        confirm = request.form["confirm_password"]
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=? AND school_id=? AND tenant_id=?", (session["user_id"], current_school_id(), current_tenant_id())).fetchone()
        if not check_password_hash(user["password_hash"], current):
            flash("Your current password is incorrect.", "error")
        elif len(new) < 6:
            flash("New password must be at least 6 characters.", "error")
        elif new != confirm:
            flash("New password and confirmation don't match.", "error")
        else:
            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (generate_password_hash(new), session["user_id"]),
            )
            conn.commit()
            conn.close()
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
        conn.close()
    return render_template("change_password.html")


SECURITY_QUESTIONS = [
    "What was the name of your first school?",
    "What is your mother's maiden name?",
    "What is the name of your favorite teacher?",
    "What was the name of your first pet?",
    "What town were you born in?",
]

POSITION_CHOICES = [
    ("principal", "Principal"),
    ("vice_principal", "Vice Principal"),
    ("exam_officer", "Exam Officer"),
    ("form_teacher", "Class Teacher / Form Teacher"),
    ("subject_teacher", "Subject Teacher"),
]


@app.route("/register-school", methods=["GET", "POST"])
@rate_limit(max_attempts=5, window_seconds=3600)
def register_school():
    if request.method=="POST":
        school_name=request.form.get("school_name","").strip(); email=request.form.get("registered_email","").strip(); phone=request.form.get("registered_phone","").strip(); admin_name=request.form.get("admin_name","").strip(); username=request.form.get("admin_username","").strip()
        errors=[]
        if not school_name: errors.append("School name is required.")
        if not email or "@" not in email: errors.append("Enter a valid school email address.")
        if not admin_name: errors.append("Administrator name is required.")
        if len(username)<4 or len(username)>30 or not re.fullmatch(r"[A-Za-z0-9_.]+",username): errors.append("Username must be 4–30 characters using letters, numbers, underscore or period.")
        if errors:
            for e in errors: flash(e,"error")
            return render_template("register_school.html")
        conn=get_db()
        try:
            tenant="TEN-"+secrets.token_hex(6).upper(); code=generate_school_code(conn, school_name)
            while conn.execute("SELECT 1 FROM schools WHERE tenant_id=?",(tenant,)).fetchone(): tenant="TEN-"+secrets.token_hex(6).upper()
            sid=conn.execute("INSERT INTO schools(name,registered_email,registered_phone,activation_status,tenant_id,school_code) VALUES(?,?,?,?,?,?)",(school_name,email,phone or None,"pending",tenant,code)).lastrowid
            conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,first_login_required) VALUES(?,?,?,?,?,'admin',1)",(sid,tenant,admin_name,username,generate_password_hash(secrets.token_urlsafe(24))))
            conn.execute("INSERT INTO platform_activation_requests(school_id,status) VALUES (?, 'pending')",(sid,))
            conn.execute("INSERT INTO platform_notifications(title,message,school_id) VALUES (?,?,?)",("New school activation request",f"{school_name} registered. School ID: {code}. Tenant ID: {tenant}. Email: {email}. Phone: {phone or 'Not provided'}.",sid))
            seed_school_defaults(conn,sid); _security_audit_event(conn,"school_activation_request",f"Requested school activation for {school_name}",sid); conn.commit(); conn.close(); flash("School registration submitted. Your school is pending activation. You will be notified when an authorized reviewer approves it and sends the activation code.","success"); return redirect(url_for("activate_school"))
        except sqlite3.IntegrityError:
            conn.rollback(); conn.close(); flash("That administrator username is already in use.","error")
    return render_template("register_school.html")


@app.route("/register", methods=["GET", "POST"])
@rate_limit(max_attempts=5, window_seconds=3600)
def register():
    """Staff Signup. School and role are derived from the secure signup code."""
    conn=get_db()
    if request.method=="POST":
        username=request.form.get("username","").strip(); code=request.form.get("signup_code","").strip()
        first=request.form.get("first_name","").strip(); last=request.form.get("surname","").strip(); other=request.form.get("other_names","").strip()
        password=request.form.get("password",""); confirm=request.form.get("confirm_password","")
        errors=[]
        if not re.fullmatch(r"[A-Za-z0-9_.]{4,30}",username): errors.append("Username must be 4–30 characters using letters, numbers, underscore or period.")
        if len(first)<2 or len(first)>50 or not re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ' -]+",first): errors.append("First name is required.")
        if len(last)<2 or len(last)>50 or not re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ' -]+",last): errors.append("Surname is required.")
        if other and len(other)>100: errors.append("Other names must not exceed 100 characters.")
        errors += validate_password_policy(password,username)
        if password!=confirm: errors.append("Password and confirmation don't match.")
        row,msg=verify_signup_code(conn,code,"staff",consume=False)
        if not row: errors.append(msg)
        elif conn.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)",(username,)).fetchone(): errors.append("This username is already in use.")
        if errors:
            for e in errors: flash(e,"error")
            conn.close(); return render_template("register.html")
        try:
            full=" ".join(x for x in (first,last,other) if x)
            cur=conn.execute("INSERT INTO users(school_id,tenant_id,name,first_name,surname,other_names,username,password_hash,role,first_login_required,account_status,signup_status,activation_status) VALUES(?,?,?,?,?,?,?, ?,'teacher',1,'active','approved','active')",(row["school_id"],row["tenant_id"],full,first,last,other or None,username,generate_password_hash(password)))
            uid=cur.lastrowid
            conn.execute("UPDATE users SET rbac_role='Teacher' WHERE id=?",(uid,))
            _ra=conn.execute("INSERT INTO role_assignments(user_id,school_id,tenant_id,school_level,role,status,reason) VALUES(?,?,?,'All','Teacher','active','Default role on staff signup')",(uid,row["school_id"],row["tenant_id"])).lastrowid
            for _perm in ROLE_CATALOG.get("Teacher",[]): conn.execute("INSERT INTO role_assignment_permissions(assignment_id,permission,granted) VALUES(?,?,1)",(_ra,_perm))
            conn.execute("INSERT INTO signups(user_id,signup_type,signup_status,verified_at,approved_at,school_id,tenant_id,request_id) VALUES(?,?,?,?,?,?,?,?)",(uid,"staff","approved",datetime.datetime.utcnow().isoformat(),datetime.datetime.utcnow().isoformat(),row["school_id"],row["tenant_id"],request_id()))
            verify_signup_code(conn,code,"staff",school_id=row["school_id"],consume=True)
            security_event(conn,"STAFF_SIGNUP_COMPLETED",details="Staff account created using school-issued signup code",resource_type="user",resource_id=uid,school_id=row["school_id"],tenant_id=row["tenant_id"])
            conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",("System",row["school_id"],"admin","New staff signup",f"{full} created a staff account and completed signup."))
            conn.commit(); conn.close(); flash("Staff account created. Complete your staff profile after signing in.","success"); return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.rollback(); conn.close(); flash("We could not complete your registration. Please try again.","error")
    conn.close(); return render_template("register.html")

@app.route("/register/parent", methods=["GET","POST"])
@rate_limit(max_attempts=5, window_seconds=3600)
def register_parent():
    """Create a parent account; child linking is a separate verified action."""
    conn=get_db()
    if request.method=="POST":
        first=request.form.get("first_name","").strip(); last=request.form.get("surname","").strip(); phone=request.form.get("phone","").strip(); email=request.form.get("email","").strip() or None; username=request.form.get("username","").strip() or None; school_code=request.form.get("school_code","").strip()
        password=request.form.get("password",""); confirm=request.form.get("confirm_password","")
        errors=[]
        if len(first)<2: errors.append("First name is required.")
        if len(last)<2: errors.append("Surname is required.")
        if not phone: errors.append("Phone is required.")
        if not email and not username: errors.append("Email or username is required.")
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): errors.append("Enter a valid email address.")
        ident=username or email or "parent"
        errors += validate_password_policy(password,ident)
        if password!=confirm: errors.append("Password and confirmation don't match.")
        if email and conn.execute("SELECT 1 FROM parent_accounts WHERE LOWER(email)=LOWER(?)",(email,)).fetchone(): errors.append("This email is already in use.")
        if username and conn.execute("SELECT 1 FROM parent_accounts WHERE LOWER(username)=LOWER(?)",(username,)).fetchone(): errors.append("This username is already in use.")
        if errors:
            for e in errors: flash(e,"error")
            conn.close(); return render_template("register_parent.html")
        # Parent signup is intentionally school-neutral until a verified child link establishes school scope.
        school_id = None; tenant_id = None
        if g.portal_school:
            school_id=g.portal_school["id"]; tenant_id=g.portal_school["tenant_id"]
        elif school_code:
            school = conn.execute("SELECT id,tenant_id,activation_status,is_suspended,is_archived FROM schools WHERE LOWER(school_code)=LOWER(?) OR LOWER(tenant_id)=LOWER(?)",(school_code,school_code)).fetchone()
            if school and school["activation_status"]=="active" and not school["is_suspended"] and not school["is_archived"]:
                school_id=school["id"]; tenant_id=school["tenant_id"]
            else:
                errors.append("Enter a valid active School ID or Tenant ID.")
        else:
            errors.append("School ID or Tenant ID is required for parent signup.")
        if errors:
            for e in errors: flash(e,"error")
            conn.close(); return render_template("register_parent.html")
        try:
            ident=username or email
            cur=conn.execute("INSERT INTO parent_accounts(school_id,tenant_id,name,username,email,phone,password_hash,is_active,account_status,signup_status) VALUES(?,?,?,?,?,?,?,1,'active','pending')",(school_id,tenant_id,f"{first} {last}",ident,email,phone,generate_password_hash(password)))
            conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",("System",school_id,"admin","New parent signup",f"{first} {last} submitted a parent signup request."))
            pid=cur.lastrowid
            conn.execute("INSERT INTO signups(user_id,signup_type,signup_status,school_id,tenant_id,request_id,notes) VALUES(NULL,'parent','pending',?,?,?,?)",(school_id,tenant_id,request_id(),f"Parent account {pid} awaiting child verification"))
            security_event(conn,"PARENT_ACCOUNT_CREATED",details="Parent account created; no child data exposed until verified link exists",resource_type="parent",resource_id=pid,school_id=school_id,tenant_id=tenant_id)
            conn.commit(); conn.close(); flash("Parent account created. Please verify and link your child before accessing student information.","success"); return redirect(url_for("parent_login"))
        except Exception as exc:
            conn.rollback(); conn.close(); flash(str(exc) if str(exc).startswith("Please") else "We could not complete your registration. Please try again.","error")
    conn.close(); return render_template("register_parent.html")


@app.route("/signup/school", methods=["GET","POST"])
def signup_school_alias(): return register_school()

@app.route("/signup/staff", methods=["GET","POST"])
def signup_staff_alias(): return register()


@app.route("/signup/parent", methods=["GET","POST"])
def signup_parent_alias(): return register_parent()

@app.route("/recover", methods=["GET", "POST"])
@rate_limit(max_attempts=5, window_seconds=600)
def recover():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (username,)).fetchone()
        conn.close()
        if not user or not user["security_question"]:
            flash("We couldn't find a recoverable account with that username. Ask your admin for help resetting it.", "error")
            return redirect(url_for("recover"))
        session["recovery_user_id"] = user["id"]
        return redirect(url_for("recover_answer"))
    return render_template("recover.html")


@app.route("/recover/answer", methods=["GET", "POST"])
@rate_limit(max_attempts=5, window_seconds=600)
def recover_answer():
    user_id = session.get("recovery_user_id")
    if not user_id:
        return redirect(url_for("recover"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if request.method == "POST":
        answer = request.form.get("security_answer", "").strip().lower()
        if user and check_password_hash(user["security_answer_hash"], answer):
            session["recovery_verified_user_id"] = user_id
            conn.close()
            return redirect(url_for("recover_reset"))
        conn.close()
        flash("That answer doesn't match. Please try again.", "error")
        return redirect(url_for("recover_answer"))

    conn.close()
    if not user:
        return redirect(url_for("recover"))
    return render_template("recover_answer.html", question=user["security_question"])


@app.route("/recover/reset", methods=["GET", "POST"])
@rate_limit(max_attempts=5, window_seconds=600)
def recover_reset():
    user_id = session.get("recovery_verified_user_id")
    if not user_id:
        return redirect(url_for("recover"))

    if request.method == "POST":
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(new) < 6:
            flash("New password must be at least 6 characters.", "error")
        elif new != confirm:
            flash("New password and confirmation don't match.", "error")
        else:
            conn = get_db()
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), user_id))
            conn.commit()
            conn.close()
            session.pop("recovery_user_id", None)
            session.pop("recovery_verified_user_id", None)
            flash("Password reset. You can now log in with your new password.", "success")
            return redirect(url_for("login"))
    return render_template("recover_reset.html")


# ---------- dashboard ----------

@app.route("/dashboard")
@login_required()
def dashboard():
    # One UI: staff work in the app (/app), which reads and writes the copy of the
    # school's data on the device and syncs it automatically — the same screens
    # whether the connection is up or down. The server-rendered dashboard below is
    # kept only as a fallback: /dashboard?classic=1
    conn = get_db()
    term = current_term(conn)
    school_id = current_school_id()
    if session["role"] in ("admin", "sub_admin"):
        stats = {
            "students": conn.execute(
                "SELECT COUNT(*) c FROM students s JOIN classes c ON c.id=s.class_id "
                "WHERE c.school_id=? AND s.is_active=1", (school_id,)
            ).fetchone()["c"],
            "classes": conn.execute("SELECT COUNT(*) c FROM classes WHERE school_id=?", (school_id,)).fetchone()["c"],
            "teachers": conn.execute(
                "SELECT COUNT(*) c FROM users WHERE role='teacher' AND school_id=?", (school_id,)
            ).fetchone()["c"],
            "subjects": conn.execute("SELECT COUNT(*) c FROM subjects WHERE school_id=?", (school_id,)).fetchone()["c"],
        }
        alerts = plan_usage_alerts(conn, school_id)
        school = get_school(conn, school_id)
        plan = subscription_plan_for_school(conn, school)
        conn.close()
        return render_template("admin_dashboard.html", term=term, stats=stats, plan=plan, plan_alerts=alerts)
    else:
        assignments = conn.execute(
            "SELECT cs.*, c.name as class_name, s.name as subject_name FROM class_subjects cs "
            "JOIN classes c ON c.id=cs.class_id JOIN subjects s ON s.id=cs.subject_id "
            "WHERE cs.teacher_id=? AND c.school_id=?", (session["user_id"], school_id)
        ).fetchall()
        accessible = get_accessible_class_ids(conn, session.get("role"), session.get("position"), session["user_id"])
        if accessible == "all":
            result_classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (school_id,)).fetchall()
        elif accessible:
            placeholders = ",".join("?" * len(accessible))
            result_classes = conn.execute(
                f"SELECT * FROM classes WHERE id IN ({placeholders}) AND school_id=? ORDER BY name",
                tuple(accessible) + (school_id,),
            ).fetchall()
        else:
            result_classes = []
        is_form_teacher = bool(form_teacher_class_ids(conn, session["user_id"]))
        conn.close()
        return render_template(
            "teacher_dashboard.html", term=term, assignments=assignments,
            position_label=POSITION_LABELS.get(session.get("position")),
            result_classes=result_classes, is_form_teacher=is_form_teacher and "Class Teacher / Form Teacher" in session_roles(),
            my_roles=session_roles(),
        )


@app.route("/api/subscription-status")
@login_required("admin", "sub_admin")
def api_subscription_status():
    """Small non-sensitive subscription payload for the admin UI."""
    conn = get_db()
    school_id = current_school_id()
    school = get_school(conn, school_id)
    plan = subscription_plan_for_school(conn, school) if school else None
    usage = school_plan_usage(conn, school_id) if school else {"students": 0, "teachers": 0}
    state = subscription_state(school) if school else {"status": "unknown", "active": False, "label": "Unknown", "days_left": None}
    alerts = plan_usage_alerts(conn, school_id) if school else []
    limits = plan_limit_state(plan, usage) if plan else {}
    conn.close()
    return {"ok": True, "state": state, "plan": {"name": plan["name"], "code": plan["code"]} if plan else None, "usage": usage, "limits": limits, "alerts": alerts}


# ---------- admin: school profile ----------

@app.route("/admin/school", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_school():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST":
        name = request.form.get("school_name", "").strip()
        registered_email = request.form.get("registered_email", "").strip() or None
        registered_phone = request.form.get("registered_phone", "").strip() or None
        timezone = request.form.get("timezone", "Africa/Lagos").strip() or "Africa/Lagos"
        if timezone not in TIMEZONE_CHOICES:
            timezone = "Africa/Lagos"
        date_format = request.form.get("date_format", "dmy")
        if date_format not in ("dmy", "mdy", "ymd"):
            date_format = "dmy"
        auto_teacher_comment = 1 if request.form.get("auto_teacher_comment") else 0
        auto_principal_comment = 1 if request.form.get("auto_principal_comment") else 0
        web_font = request.form.get("web_font", "system")
        if web_font not in WEB_FONTS:
            web_font = "system"
        pdf_font = request.form.get("pdf_font", "Helvetica")
        if pdf_font not in PDF_FONT_CHOICES:
            pdf_font = "Helvetica"
        if not name:
            flash("School name cannot be empty.", "error")
        else:
            conn.execute(
                "UPDATE schools SET name=?, registered_email=?, registered_phone=?, timezone=?, date_format=?, "
                "auto_teacher_comment=?, auto_principal_comment=?, web_font=?, pdf_font=? WHERE id=?",
                (name, registered_email, registered_phone, timezone, date_format,
                 auto_teacher_comment, auto_principal_comment, web_font, pdf_font, school_id),
            )
            conn.commit()
            flash("School profile updated.", "success")

        file = request.files.get("logo")
        if file and file.filename:
            ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
            if ext not in ALLOWED_LOGO_EXTENSIONS:
                flash("Logo must be a PNG, JPG, or GIF image.", "error")
            else:
                old = get_school(conn, school_id)
                if old and old["logo_filename"]:
                    old_path = os.path.join(INSTANCE_DIR, old["logo_filename"])
                    if os.path.exists(old_path):
                        os.remove(old_path)
                new_filename = f"school_logo_{school_id}.{ext}"
                os.makedirs(INSTANCE_DIR, exist_ok=True)
                file.save(os.path.join(INSTANCE_DIR, new_filename))
                conn.execute("UPDATE schools SET logo_filename=? WHERE id=?", (new_filename, school_id))
                conn.commit()
                flash("Logo updated.", "success")

    settings = get_school(conn, school_id)
    conn.close()
    return render_template("admin_school.html", settings=settings, web_fonts=WEB_FONTS, pdf_fonts=PDF_FONT_CHOICES,
                            base_domain=BASE_DOMAIN, timezones=TIMEZONE_CHOICES, header_layouts=RESULT_HEADER_LAYOUTS)


@app.route("/admin/school/subdomain", methods=["POST"])
@login_required("admin", "sub_admin")
def set_school_subdomain():
    conn = get_db()
    school_id = current_school_id()
    raw = request.form.get("subdomain", "").strip().lower()
    if not raw:
        conn.execute("UPDATE schools SET subdomain=NULL WHERE id=?", (school_id,))
        conn.commit()
        conn.close()
        flash("Custom subdomain removed.", "success")
        return redirect(url_for("admin_school"))

    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])?", raw):
        conn.close()
        flash("Subdomain must be 3-30 characters: lowercase letters, digits and hyphens only, and can't start or end with a hyphen.", "error")
        return redirect(url_for("admin_school"))
    if raw in RESERVED_SUBDOMAINS:
        conn.close()
        flash(f"'{raw}' is reserved and can't be used as a subdomain.", "error")
        return redirect(url_for("admin_school"))

    taken = conn.execute("SELECT id FROM schools WHERE subdomain=? AND id!=?", (raw, school_id)).fetchone()
    if taken:
        conn.close()
        flash(f"'{raw}' is already taken by another school. Please choose a different subdomain.", "error")
        return redirect(url_for("admin_school"))

    conn.execute("UPDATE schools SET subdomain=? WHERE id=?", (raw, school_id))
    conn.commit()
    conn.close()
    flash(f"Subdomain set to '{raw}'.", "success")
    return redirect(url_for("admin_school"))


@app.route("/admin/school/remove_logo", methods=["POST"])
@login_required("admin", "sub_admin")
def remove_school_logo():
    conn = get_db()
    school_id = current_school_id()
    settings = get_school(conn, school_id)
    if settings and settings["logo_filename"]:
        old_path = os.path.join(INSTANCE_DIR, settings["logo_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
        conn.execute("UPDATE schools SET logo_filename=NULL WHERE id=?", (school_id,))
        conn.commit()
        flash("Logo removed.", "success")
    conn.close()
    return redirect(url_for("admin_school"))


@app.route("/admin/school/signup_code", methods=["POST"])
@login_required("admin", "sub_admin")
def set_staff_signup_code():
    code = request.form.get("staff_signup_code", "").strip()
    conn = get_db()
    conn.execute("UPDATE schools SET staff_signup_code=? WHERE id=?", (code or None, current_school_id()))
    conn.commit()
    conn.close()
    if code:
        flash(f"Staff registration is now enabled with the code: {code}", "success")
    else:
        flash("Staff registration has been turned off.", "success")
    return redirect(url_for("admin_school"))


@app.route("/admin/email", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_email():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save":
            conn.execute(
                "UPDATE schools SET smtp_host=?, smtp_port=?, smtp_username=?, smtp_password=?, "
                "smtp_use_tls=?, smtp_from_email=?, smtp_from_name=? WHERE id=?",
                (
                    request.form.get("smtp_host", "").strip() or None,
                    int(request.form["smtp_port"]) if request.form.get("smtp_port") else None,
                    request.form.get("smtp_username", "").strip() or None,
                    request.form.get("smtp_password", "").strip() or None,
                    1 if request.form.get("smtp_use_tls") else 0,
                    request.form.get("smtp_from_email", "").strip() or None,
                    request.form.get("smtp_from_name", "").strip() or None,
                    school_id,
                ),
            )
            conn.commit()
            flash("Email settings saved.", "success")
        elif action == "test":
            test_to = request.form.get("test_email", "").strip()
            school = get_school(conn, school_id)
            if test_to:
                ok, msg = send_email(school, test_to, "Test email from your School Result System",
                                      "If you're reading this, your email settings are working correctly.")
                flash(msg, "success" if ok else "error")
    settings = get_school(conn, school_id)
    conn.close()
    return render_template("admin_email.html", settings=settings)


# ---------- settings hub ----------

@app.route("/admin/school/result-preview")
@login_required("admin", "sub_admin")
def result_design_preview():
    """Preview = the REAL result sheet. It renders the same template, with the same settings and the same data builder as the
    student report, print page and PDF - using a real student of this school (no dummy page that could drift out of date)."""
    conn = get_db()
    school_id = current_school_id()
    term = current_term(conn)
    sid_ = request.args.get("student_id", type=int)
    student_row = None
    if term:
        if sid_:
            student_row = conn.execute("SELECT st.id FROM students st JOIN classes c ON c.id=st.class_id WHERE st.id=? AND c.school_id=?", (sid_, school_id)).fetchone()
        if not student_row:
            student_row = conn.execute(
                "SELECT st.id FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1 "
                "ORDER BY (SELECT COUNT(*) FROM scores sc WHERE sc.student_id=st.id AND sc.term_id=?) DESC, st.id LIMIT 1", (school_id, term["id"])).fetchone()
    if not student_row:
        conn.close()
        flash("Add a student and enter some scores first - the preview shows a real student's result sheet.", "error")
        return redirect(url_for("result_settings"))
    data = build_result_data(conn, student_row["id"], term["id"])
    students = conn.execute("SELECT st.id, st.first_name, st.last_name, st.other_names FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1 ORDER BY st.last_name LIMIT 300", (school_id,)).fetchall()
    conn.close()
    return render_template("result_preview.html", term=term, student_full_name=student_full_name, students=students,
                           preview_student_id=student_row["id"], **data)


@app.route("/settings")
@login_required()
def settings_hub():
    conn = get_db()
    me = conn.execute("SELECT username, email, phone FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return render_template("settings_hub.html", me=me)


@app.route("/account/username", methods=["POST"])
@login_required()
def update_my_username():
    new_username = request.form.get("new_username", "").strip()
    current_password = request.form.get("current_password", "")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if not check_password_hash(user["password_hash"], current_password):
        conn.close()
        flash("Your current password is incorrect.", "error")
        return redirect(url_for("settings_hub"))
    if len(new_username) < 3:
        conn.close()
        flash("Username must be at least 3 characters.", "error")
        return redirect(url_for("settings_hub"))
    if " " in new_username:
        conn.close()
        flash("Username can't contain spaces.", "error")
        return redirect(url_for("settings_hub"))
    if new_username == user["username"]:
        conn.close()
        flash("That's already your username.", "error")
        return redirect(url_for("settings_hub"))
    if conn.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?) AND id!=?", (new_username, session["user_id"])).fetchone():
        conn.close()
        flash("That username is already taken — please choose another.", "error")
        return redirect(url_for("settings_hub"))

    old_username = user["username"]
    conn.execute("UPDATE users SET username=? WHERE id=?", (new_username, session["user_id"]))
    log_audit(conn, "user", user["name"], "username_changed",
              details=f"'{old_username}' -> '{new_username}'", school_id=user["school_id"] if "school_id" in user.keys() else None)
    conn.commit()
    conn.close()
    flash("Username updated. Use your new username next time you log in.", "success")
    return redirect(url_for("settings_hub"))


@app.route("/account/contact", methods=["POST"])
@login_required()
def update_my_contact():
    conn = get_db()
    email = request.form.get("email", "").strip() or None
    phone = request.form.get("phone", "").strip() or None
    if email and conn.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?) AND id!=?", (email, session["user_id"])).fetchone():
        conn.close()
        flash("That email is already in use by another account.", "error")
        return redirect(url_for("settings_hub"))
    if phone and conn.execute("SELECT 1 FROM users WHERE phone=? AND id!=?", (phone, session["user_id"])).fetchone():
        conn.close()
        flash("That phone number is already in use by another account.", "error")
        return redirect(url_for("settings_hub"))
    conn.execute("UPDATE users SET email=?, phone=? WHERE id=?", (email, phone, session["user_id"]))
    conn.commit()
    conn.close()
    flash("Contact info updated.", "success")
    return redirect(url_for("settings_hub"))


# ---------- staff profile, photo & digital signature ----------

@app.route("/my-profile")
@login_required()
def my_profile():
    return redirect(url_for("staff_profile", user_id=session["user_id"]))


@app.route("/staff/<int:user_id>")
@login_required()
def staff_profile(user_id):
    conn = get_db()
    school_id = current_school_id()
    staff = conn.execute("SELECT * FROM users WHERE id=? AND school_id=? AND tenant_id=?", (user_id, school_id, current_tenant_id())).fetchone()
    if not staff:
        conn.close()
        flash("Staff member not found.", "error")
        return redirect(url_for("dashboard"))
    is_self = user_id == session["user_id"]
    can_manage = session["role"] in ("admin", "sub_admin")
    if not is_self and not can_manage:
        conn.close()
        flash("You don't have access to that profile.", "error")
        return redirect(url_for("dashboard"))

    subjects_taught = conn.execute(
        "SELECT DISTINCT s.name FROM class_subjects cs JOIN subjects s ON s.id=cs.subject_id "
        "WHERE cs.teacher_id=? ORDER BY s.name", (user_id,)
    ).fetchall()
    classes_taught = conn.execute(
        "SELECT DISTINCT c.name FROM class_subjects cs JOIN classes c ON c.id=cs.class_id "
        "WHERE cs.teacher_id=? ORDER BY c.name", (user_id,)
    ).fetchall()
    form_classes = conn.execute(
        "SELECT name FROM classes WHERE form_teacher_id=? AND school_id=? ORDER BY name", (user_id, school_id)
    ).fetchall()
    recent_attendance = conn.execute(
        "SELECT * FROM staff_attendance WHERE user_id=? AND school_id=? ORDER BY date DESC, id DESC LIMIT 20", (user_id, school_id)
    ).fetchall()
    documents = conn.execute("SELECT * FROM staff_documents WHERE user_id=? AND school_id=? AND tenant_id=? ORDER BY uploaded_at DESC", (user_id, school_id, current_tenant_id())).fetchall() if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='staff_documents'").fetchone() else []
    conn.close()
    return render_template(
        "staff_profile.html", staff=staff, is_self=is_self, can_manage=can_manage,
        subjects_taught=subjects_taught, classes_taught=classes_taught, form_classes=form_classes,
        recent_attendance=recent_attendance, documents=documents, position_labels=POSITION_LABELS,
    )


@app.route("/staff/<int:user_id>/photo")
@login_required()
def staff_photo(user_id):
    conn = get_db()
    staff = conn.execute("SELECT photo_filename, school_id FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not staff or staff["school_id"] != current_school_id() or not staff["photo_filename"]:
        return "", 404
    # A staff passport is personal data: only School Admin / Sub-Admin (and the person themself) may see it.
    if session.get("role") not in ("admin", "sub_admin") and user_id != session.get("user_id"):
        return "", 404
    return send_from_directory(STAFF_PHOTOS_DIR, staff["photo_filename"])


@app.route("/staff/<int:user_id>/signature")
def staff_signature(user_id):
    # Used as an <img src> straight from result pages (viewed by staff AND
    # by logged-in students/parents), so this accepts either session kind —
    # same rule school_logo() already uses — rather than @login_required(),
    # which only recognises staff sessions.
    if "school_id" not in session:
        return "", 404
    conn = get_db()
    staff = conn.execute("SELECT signature_filename, school_id FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not staff or staff["school_id"] != session["school_id"] or not staff["signature_filename"]:
        return "", 404
    return send_from_directory(SIGNATURES_DIR, staff["signature_filename"])


@app.route("/account/photo/upload", methods=["POST"])
@login_required()
def upload_my_photo():
    conn = get_db()
    user_id = session["user_id"]
    file = request.files.get("photo")
    if not file or not file.filename:
        conn.close()
        flash("Please choose an image file to upload.", "error")
        return redirect(url_for("staff_profile", user_id=user_id))
    size_error = _reject_oversize(file, "passport") or _verify_image(file, 500 * 1024, "Passport photograph")
    if size_error:
        conn.close(); flash(size_error, "error"); return redirect(url_for("staff_profile", user_id=user_id))
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_LOGO_EXTENSIONS:
        conn.close()
        flash("Photo must be a PNG, JPG, or GIF image.", "error")
        return redirect(url_for("staff_profile", user_id=user_id))
    old = conn.execute("SELECT photo_filename FROM users WHERE id=?", (user_id,)).fetchone()
    if old and old["photo_filename"]:
        old_path = os.path.join(STAFF_PHOTOS_DIR, old["photo_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
    new_filename = f"staff_{user_id}.{ext}"
    os.makedirs(STAFF_PHOTOS_DIR, exist_ok=True)
    file.save(os.path.join(STAFF_PHOTOS_DIR, new_filename))
    conn.execute("UPDATE users SET photo_filename=? WHERE id=?", (new_filename, user_id))
    conn.commit()
    conn.close()
    flash("Photo updated.", "success")
    return redirect(url_for("staff_profile", user_id=user_id))


@app.route("/account/signature/upload", methods=["POST"])
@login_required()
def upload_my_signature():
    conn = get_db()
    user_id = session["user_id"]
    file = request.files.get("signature")
    if not file or not file.filename:
        conn.close()
        flash("Please choose an image file to upload.", "error")
        return redirect(url_for("staff_profile", user_id=user_id))
    size_error = _reject_oversize(file, "signature") or _verify_image(file, 500 * 1024, "Signature")
    if size_error:
        conn.close(); flash(size_error, "error"); return redirect(url_for("staff_profile", user_id=user_id))
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_LOGO_EXTENSIONS:
        conn.close()
        flash("Signature must be a PNG, JPG, or GIF image (ideally a transparent PNG).", "error")
        return redirect(url_for("staff_profile", user_id=user_id))
    old = conn.execute("SELECT signature_filename FROM users WHERE id=?", (user_id,)).fetchone()
    if old and old["signature_filename"]:
        old_path = os.path.join(SIGNATURES_DIR, old["signature_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
    new_filename = f"sig_{user_id}.{ext}"
    os.makedirs(SIGNATURES_DIR, exist_ok=True)
    file.save(os.path.join(SIGNATURES_DIR, new_filename))
    # Uploading a fresh signature doesn't silently turn it on — the person
    # may want to review it first, so `use_digital_signature` is left as-is
    # and toggled explicitly below.
    conn.execute("UPDATE users SET signature_filename=? WHERE id=?", (new_filename, user_id))
    conn.commit()
    conn.close()
    flash("Signature uploaded. Turn it on below to have it stamped on results automatically.", "success")
    return redirect(url_for("staff_profile", user_id=user_id))


@app.route("/account/signature/toggle", methods=["POST"])
@login_required()
def toggle_my_signature():
    conn = get_db()
    user_id = session["user_id"]
    use_it = 1 if request.form.get("use_digital_signature") else 0
    row = conn.execute("SELECT signature_filename FROM users WHERE id=?", (user_id,)).fetchone()
    if use_it and (not row or not row["signature_filename"]):
        conn.close()
        flash("Upload a signature image before turning this on.", "error")
        return redirect(url_for("staff_profile", user_id=user_id))
    conn.execute("UPDATE users SET use_digital_signature=? WHERE id=?", (use_it, user_id))
    conn.commit()
    conn.close()
    flash("Digital signature " + ("enabled." if use_it else "disabled — results will show a blank line for a manual signature."), "success")
    return redirect(url_for("staff_profile", user_id=user_id))


@app.route("/account/signature/remove", methods=["POST"])
@login_required()
def remove_my_signature():
    conn = get_db()
    user_id = session["user_id"]
    row = conn.execute("SELECT signature_filename FROM users WHERE id=?", (user_id,)).fetchone()
    if row and row["signature_filename"]:
        old_path = os.path.join(SIGNATURES_DIR, row["signature_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
        conn.execute("UPDATE users SET signature_filename=NULL, use_digital_signature=0 WHERE id=?", (user_id,))
        conn.commit()
        flash("Signature removed.", "success")
    conn.close()
    return redirect(url_for("staff_profile", user_id=user_id))


@app.route("/account/staff-document/upload", methods=["POST"])
@login_required()
def upload_staff_document():
    uid=session["user_id"]; conn=get_db(); staff=conn.execute("SELECT id FROM users WHERE id=? AND school_id=? AND tenant_id=?",(uid,current_school_id(),current_tenant_id())).fetchone()
    file=request.files.get("document")
    if not staff or not file or not file.filename:
        conn.close(); flash("Please choose a staff document to upload.","error"); return redirect(url_for("staff_profile",user_id=uid))
    size=_file_size_bytes(file)
    if size>UPLOAD_LIMITS["staff_document"]:
        conn.close(); flash("Staff document must not exceed 1 MB.","error"); return redirect(url_for("staff_profile",user_id=uid))
    ext=file.filename.rsplit(".",1)[-1].lower() if "." in file.filename else ""
    if ext not in STAFF_DOCUMENT_EXTENSIONS:
        conn.close(); flash("Staff document must be PDF, Word or an image file (JPG, PNG).","error"); return redirect(url_for("staff_profile",user_id=uid))
    os.makedirs(os.path.join(STAFF_DOCUMENTS_DIR,str(current_school_id()),str(uid)),exist_ok=True)
    stored=f"{secrets.token_hex(12)}.{ext}"; path=os.path.join(STAFF_DOCUMENTS_DIR,str(current_school_id()),str(uid),stored)
    file.save(path)
    conn.execute("INSERT INTO staff_documents(school_id,tenant_id,user_id,original_filename,stored_filename,mime_type,size_bytes) VALUES(?,?,?,?,?,?,?)",(current_school_id(),current_tenant_id(),uid,secure_filename(file.filename),stored,file.mimetype,size))
    conn.commit(); conn.close(); flash("Staff document uploaded successfully.","success"); return redirect(url_for("staff_profile",user_id=uid))

@app.route("/staff-document/<int:document_id>")
@login_required()
def staff_document(document_id):
    conn=get_db(); doc=conn.execute("SELECT * FROM staff_documents WHERE id=? AND school_id=? AND tenant_id=?",(document_id,current_school_id(),current_tenant_id())).fetchone()
    if not doc:
        conn.close(); return "",404
    allowed=doc["user_id"]==session.get("user_id") or session.get("role") in ("admin","sub_admin")
    if not allowed:
        conn.close(); return "",403
    path=os.path.join(STAFF_DOCUMENTS_DIR,str(doc["school_id"]),str(doc["user_id"]),doc["stored_filename"])
    conn.close()
    if not os.path.isfile(path): return "",404
    return send_file(path,download_name=doc["original_filename"],as_attachment=False,mimetype=doc["mime_type"] or None)

@app.route("/staff-document/<int:document_id>/delete",methods=["POST"])
@login_required()
def delete_staff_document(document_id):
    conn=get_db(); doc=conn.execute("SELECT * FROM staff_documents WHERE id=? AND school_id=? AND tenant_id=?",(document_id,current_school_id(),current_tenant_id())).fetchone()
    if not doc:
        conn.close(); flash("Document not found.","error"); return redirect(url_for("staff_profile",user_id=session.get("user_id")))
    if doc["user_id"]!=session.get("user_id") and session.get("role") not in ("admin","sub_admin"):
        conn.close(); flash("You are not authorized to remove that document.","error"); return redirect(url_for("staff_profile",user_id=session.get("user_id")))
    path=os.path.join(STAFF_DOCUMENTS_DIR,str(doc["school_id"]),str(doc["user_id"]),doc["stored_filename"])
    if os.path.isfile(path): os.remove(path)
    conn.execute("DELETE FROM staff_documents WHERE id=?",(document_id,)); conn.commit(); conn.close(); flash("Staff document removed.","success"); return redirect(url_for("staff_profile",user_id=session.get("user_id")))

# ---------- notifications (staff) ----------

@app.route("/notifications")
@login_required()
def notifications_inbox():
    conn = get_db()
    notifications = notification_rows(conn, notification_reader())
    conn.close()
    return render_template("notifications_inbox.html", notifications=notifications)


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
def notification_mark_read(notification_id):
    """Mark ONE notification read for the signed-in staff member / student / parent. Only notifications that reader may
    see (their school, their audience) can be marked; the unread count is returned so the page updates at once."""
    reader = notification_reader()
    if not reader:
        return jsonify({"ok": False}), 401
    conn = get_db()
    try:
        visible = {n["id"] for n in get_visible_notifications(conn, reader[3], reader[4], 500)}
        if notification_id not in visible:
            return jsonify({"ok": False}), 404
        conn.execute("INSERT OR IGNORE INTO notification_reads(reader_type,reader_id,notification_id) VALUES (?,?,?)", (reader[0], reader[1], notification_id))
        conn.commit()
        unread = sum(1 for n in notification_rows(conn, reader, 500) if not n["is_read"])
        return jsonify({"ok": True, "unread": unread})
    finally:
        conn.close()


@app.route("/notifications/read-all", methods=["POST"])
def notification_mark_all_read():
    reader = notification_reader()
    if not reader:
        return jsonify({"ok": False}), 401
    conn = get_db()
    try:
        for n in notification_rows(conn, reader, 500):
            if not n["is_read"]:
                conn.execute("INSERT OR IGNORE INTO notification_reads(reader_type,reader_id,notification_id) VALUES (?,?,?)", (reader[0], reader[1], n["id"]))
        conn.commit()
    finally:
        conn.close()
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": True, "unread": 0})
    return redirect(request.referrer or url_for("notifications_inbox"))


@app.route("/notifications/compose", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def notifications_compose():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()
        target_role = request.form.get("target_role", "all")
        if target_role not in ("all", "teacher", "student", "parent"):
            target_role = "all"
        if not title or not message:
            flash("Please fill in both a title and a message.", "error")
        else:
            conn = get_db()
            conn.execute(
                "INSERT INTO notifications (sender_label, school_id, target_role, title, message) VALUES (?,?,?,?,?)",
                (f"Admin: {session['name']}", current_school_id(), target_role, title, message),
            )
            conn.commit()
            conn.close()
            flash("Notification sent.", "success")
            return redirect(url_for("notifications_inbox"))
    return render_template("notifications_compose.html")


@app.route("/settings/delete_account", methods=["POST"])
@login_required("admin")
def delete_account():
    password = request.form.get("password", "")
    confirm_text = request.form.get("confirm_text", "").strip().upper()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if not check_password_hash(user["password_hash"], password):
        conn.close()
        flash("Your password was incorrect. Account not deleted.", "error")
        return redirect(url_for("settings_hub"))
    if confirm_text != "DELETE":
        conn.close()
        flash("You must type DELETE exactly to confirm. Account not deleted.", "error")
        return redirect(url_for("settings_hub"))

    school_id = current_school_id()
    class_ids = [r["id"] for r in conn.execute("SELECT id FROM classes WHERE school_id=?", (school_id,)).fetchall()]
    if class_ids:
        placeholders = ",".join("?" * len(class_ids))
        student_ids = [r["id"] for r in conn.execute(
            f"SELECT id FROM students WHERE class_id IN ({placeholders})", class_ids
        ).fetchall()]
        if student_ids:
            sp = ",".join("?" * len(student_ids))
            conn.execute(f"DELETE FROM student_skill_ratings WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM student_term_info WHERE student_id IN ({sp})", student_ids)
            audit_scores_deleted(conn, list(student_ids))
            conn.execute(f"DELETE FROM score_history WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM scores WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM enrollments WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM students WHERE id IN ({sp})", student_ids)
        conn.execute(f"DELETE FROM class_subjects WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM classes WHERE id IN ({placeholders})", class_ids)
    conn.execute("DELETE FROM subjects WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM skill_traits WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM grade_scale WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM grading_config WHERE school_id=?", (school_id,))
    term_ids = [r["id"] for r in conn.execute(
        "SELECT terms.id FROM terms JOIN sessions ON sessions.id=terms.session_id WHERE sessions.school_id=?",
        (school_id,),
    ).fetchall()]
    if term_ids:
        tp = ",".join("?" * len(term_ids))
        conn.execute(f"DELETE FROM terms WHERE id IN ({tp})", term_ids)
    conn.execute("DELETE FROM sessions WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM users WHERE school_id=?", (school_id,))
    school = get_school(conn, school_id)
    school_name = school["name"] if school else "Unknown"
    if school and school["logo_filename"]:
        old_path = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
    conn.execute("DELETE FROM schools WHERE id=?", (school_id,))
    log_audit(conn, "admin", user["name"], "self_delete_account",
              details=f"School admin permanently deleted their own school '{school_name}'", school_id=None)
    conn.commit()
    conn.close()
    session.clear()
    flash("Your school's account and all its data have been permanently deleted.", "success")
    return redirect(url_for("login"))


def school_readiness_checks(conn, school_id):
    """Return the authoritative pre-live readiness checks for one tenant."""
    school = get_school(conn, school_id)
    if not school:
        return [], False
    def count(sql, params=(school_id,)):
        # Setup must remain readable even when an older/partially migrated
        # production database is missing an optional readiness table.  Treat
        # that check as incomplete instead of allowing the whole setup page to
        # crash with a generic 500 error.
        try:
            row = conn.execute(sql, params).fetchone()
            return int(row["n"] or 0) if row else 0
        except Exception:
            return 0
    classes = count("SELECT COUNT(*) AS n FROM classes WHERE school_id=?")
    subjects = count("SELECT COUNT(*) AS n FROM subjects WHERE school_id=?")
    teachers = count("SELECT COUNT(*) AS n FROM users WHERE school_id=? AND role='teacher' AND COALESCE(is_active,1)=1")
    students = count("SELECT COUNT(*) AS n FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=?")
    sessions = count("SELECT COUNT(*) AS n FROM sessions WHERE school_id=?")
    terms = count("SELECT COUNT(*) AS n FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.school_id=?")
    class_subjects = count("SELECT COUNT(*) AS n FROM class_subjects cs JOIN classes c ON c.id=cs.class_id WHERE c.school_id=?")
    active_roles = count("SELECT COUNT(*) AS n FROM role_assignments WHERE school_id=? AND status='active'") if table_exists(conn, "role_assignments") else 0
    active_admins = count("SELECT COUNT(*) AS n FROM users WHERE school_id=? AND role='admin' AND COALESCE(is_active,1)=1")
    grade_bands = count("SELECT COUNT(*) AS n FROM grade_scale WHERE school_id=?")
    checks = [
        ("profile", bool((school["name"] or "").strip())),
        ("identity", bool((school["school_code"] or "").strip()) and bool((school["tenant_id"] or "").strip())),
        ("activation", (school["activation_status"] if "activation_status" in school.keys() else "active") == "active" and not bool(school["is_archived"] if "is_archived" in school.keys() else 0)),
        ("sessions", sessions > 0),
        ("terms", terms > 0),
        ("classes", classes > 0),
        ("subjects", subjects > 0),
        ("class_subjects", class_subjects > 0),
        ("teachers", teachers > 0),
        ("roles", active_roles > 0),
        ("students", students > 0),
        ("admin", active_admins > 0),
        ("grading", grade_bands > 0),
    ]
    return checks, all(done for _, done in checks)


@app.route("/staff/onboarding", methods=["GET","POST"])
@login_required("teacher")
def staff_onboarding():
    conn=get_db(); uid=session["user_id"]; user=conn.execute("SELECT * FROM users WHERE id=? AND school_id=? AND tenant_id=?",(uid,current_school_id(),current_tenant_id())).fetchone()
    if not user: conn.close(); session.clear(); return redirect(url_for("login"))
    if request.method=="POST":
        first=request.form.get("first_name","").strip(); last=request.form.get("surname","").strip(); other=request.form.get("other_names","").strip()
        if not first or not last: flash("First name and surname are required.","error")
        else:
            vals={"name":" ".join(x for x in (first,last,other) if x),"first_name":first,"surname":last,"other_names":other or None,"email":request.form.get("email","").strip() or None,"phone":request.form.get("phone","").strip() or None,"first_login_required":0,"first_login_completed_at":datetime.datetime.utcnow().isoformat(timespec="seconds")}
            for col in ("address","date_of_birth","gender","qualifications"):
                if col in user.keys(): vals[col]=request.form.get(col,"").strip() or None
            conn.execute(f"UPDATE users SET {', '.join(k+'=?' for k in vals)} WHERE id=?",list(vals.values())+[uid]); conn.commit(); conn.close(); flash("Staff profile saved.","success"); return redirect(url_for("dashboard"))
    conn.close(); return render_template("staff_onboarding.html",user=user)


@app.route("/admin/first-login", methods=["GET", "POST"])
@login_required("admin")
def admin_first_login():
    """First-login orientation for newly provisioned School Admins.

    This is deliberately a short gate before the existing non-destructive
    setup wizard. Existing schools are not forced through it.
    """
    conn = get_db()
    school_id = current_school_id()
    school = get_school(conn, school_id)
    user = conn.execute("SELECT * FROM users WHERE id=?", (session.get("user_id"),)).fetchone()
    if not school or not user:
        conn.close()
        session.clear()
        return redirect(url_for("login"))
    if not user["first_login_required"]:
        conn.close()
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        now = datetime.datetime.utcnow().isoformat(timespec="seconds")
        conn.execute("UPDATE users SET first_login_required=0, first_login_completed_at=? WHERE id=?", (now, user["id"]))
        conn.execute("UPDATE schools SET onboarding_started_at=COALESCE(onboarding_started_at, ?) WHERE id=?", (now, school_id))
        log_audit(conn, "admin", user["name"], "first_login_onboarding_started",
                  details=f"First-login onboarding started for '{school['name']}'", school_id=school_id)
        conn.commit(); conn.close()
        return redirect(url_for("admin_setup_wizard"))
    conn.close()
    return render_template("admin_first_login.html", school=school, user=user)


@app.route("/admin/setup-wizard", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_setup_wizard():
    """Authoritative school setup checklist and explicit live-readiness gate."""
    conn = get_db()
    school_id = current_school_id()
    school = get_school(conn, school_id)
    if not school:
        conn.close()
        flash("Your school could not be found.", "error")
        return redirect(url_for("login"))

    checks, ready = school_readiness_checks(conn, school_id)
    labels = {
        "profile":"School profile", "identity":"School/Tenant identity", "activation":"School activation",
        "sessions":"Academic session", "terms":"Academic term", "classes":"Classes and arms",
        "subjects":"Subjects", "class_subjects":"Class-subject assignments", "teachers":"Active teachers",
        "roles":"Roles and scopes", "students":"Students", "admin":"Active school administrator",
        "grading":"Grading configuration",
    }
    descriptions = {
        "profile":"School identity and contact details are configured.",
        "identity":"Permanent School ID and Tenant ID are present.",
        "activation":"The school is active and not archived.",
        "sessions":"At least one academic session exists.", "terms":"At least one academic term exists.",
        "classes":"At least one class/arm exists.", "subjects":"At least one subject exists.",
        "class_subjects":"At least one subject is assigned to a class.",
        "teachers":"At least one active teacher account exists.",
        "roles":"At least one active role assignment exists.",
        "students":"At least one student is enrolled.",
        "admin":"At least one active school administrator exists.",
        "grading":"At least one grading band exists.",
    }
    urls = {
        "profile":url_for("admin_school"), "identity":url_for("admin_school"), "activation":url_for("admin_school"),
        "sessions":url_for("admin_terms"), "terms":url_for("admin_terms"), "classes":url_for("admin_classes"),
        "subjects":url_for("admin_subjects"), "class_subjects":url_for("admin_class_subjects"),
        "teachers":url_for("admin_teachers"), "roles":url_for("admin_roles"), "students":url_for("admin_students"),
        "admin":url_for("admin_subadmins"), "grading":url_for("admin_grading"),
    }
    if request.method == "POST":
        if session.get("role") != "admin":
            conn.close(); flash("Only the School Admin can mark a school ready for live data.", "error")
            return redirect(url_for("admin_setup_wizard"))
        if not ready:
            conn.close(); flash("Complete every required readiness check before marking the school READY FOR LIVE DATA.", "error")
            return redirect(url_for("admin_setup_wizard"))
        now = datetime.datetime.utcnow().isoformat(timespec="seconds")
        conn.execute("UPDATE schools SET readiness_status='ready', ready_at=?, ready_by=?, readiness_version=1 WHERE id=?",
                     (now, session.get("user_id"), school_id))
        log_audit(conn, "admin", session.get("user_name") or "School Admin", "school_marked_ready",
                  details="School passed the required pre-live readiness checks.", school_id=school_id)
        conn.commit(); conn.close()
        flash("School marked READY FOR LIVE DATA. Future result publication now requires this readiness state.", "success")
        return redirect(url_for("admin_setup_wizard"))

    items=[]
    for key, done in checks:
        items.append({"key":key,"label":labels[key],"description":descriptions[key],"done":done,"url":urls[key]})
    completed=sum(1 for x in items if x["done"]); total=len(items); percent=round(completed*100/total) if total else 0
    status = (school["readiness_status"] if "readiness_status" in school.keys() else None) or "pending"
    # The wizard template displays these counters.  Supplying them explicitly
    # avoids undefined template state and keeps the page useful on older data.
    def count(sql, params=(school_id,)):
        row = conn.execute(sql, params).fetchone()
        return row["n"] if row else 0

    stats = {
        "classes": count("SELECT COUNT(*) AS n FROM classes WHERE school_id=?"),
        "subjects": count("SELECT COUNT(*) AS n FROM subjects WHERE school_id=?"),
        "teachers": count("SELECT COUNT(*) AS n FROM users WHERE school_id=? AND role='teacher' AND COALESCE(is_active,1)=1"),
        "students": count("SELECT COUNT(*) AS n FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=?"),
    }
    conn.close()
    return render_template("admin_setup_wizard.html", school=school, checks=items, completed=completed, total=total,
                           percent=percent, ready=ready, readiness_status=status, stats=stats)


# ---------- admin: setup ----------

@app.route("/admin/classes", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_classes():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST" and not require_scoped_permission("create"):
        flash("You do not have permission to create classes in your assigned scope.", "error")
        return redirect(url_for("admin_classes"))
    if request.method == "GET" and not require_scoped_permission("view"):
        flash("You do not have permission to view classes in your assigned scope.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form["name"].strip()
        category = request.form.get("category", "").strip() or None
        if category and category not in CLASS_CATEGORIES:
            category = None
        arms = parse_arms(request.form.get("arms", ""))
        if name and arms:
            # "JSS 1" + arms "A, B, C" -> three classes: "JSS 1 A", "JSS 1 B", "JSS 1 C"
            added, existed = [], []
            for arm in arms:
                full = f"{name} {arm}"
                try:
                    conn.execute("INSERT INTO classes (school_id, name, category, level, arm) VALUES (?,?,?,?,?)",
                                 (school_id, full, category, name, arm))
                    added.append(full)
                except Exception:
                    existed.append(full)
            conn.commit()
            if added:
                flash("Added: " + ", ".join(added) + ".", "success")
            if existed:
                flash("Already existed: " + ", ".join(existed) + ".", "error")
        elif name:
            try:
                conn.execute("INSERT INTO classes (school_id, name, category) VALUES (?,?,?)", (school_id, name, category))
                conn.commit()
                flash(f"Class '{name}' added.", "success")
            except sqlite3.IntegrityError:
                conn.rollback()
                flash("That class already exists.", "error")
    classes = conn.execute(
        "SELECT c.*, u.name as teacher_name FROM classes c LEFT JOIN users u ON u.id=c.form_teacher_id "
        "WHERE c.school_id=? ORDER BY c.name", (school_id,)
    ).fetchall()
    teachers = conn.execute("SELECT * FROM users WHERE role='teacher' AND school_id=? ORDER BY name", (school_id,)).fetchall()
    conn.close()
    return render_template("admin_classes.html", classes=classes, teachers=teachers, categories=CLASS_CATEGORIES)


@app.route("/admin/classes/<int:class_id>/set_category", methods=["POST"])
@login_required("admin", "sub_admin")
def set_class_category(class_id):
    if not require_scoped_permission("edit", class_id=class_id):
        flash("You do not have permission to edit this class.", "error")
        return redirect(url_for("admin_classes"))
    conn = get_db()
    class_row = class_in_school(conn, class_id)
    if not class_row:
        conn.close()
        flash("That class doesn't exist.", "error")
        return redirect(url_for("admin_classes"))
    category = request.form.get("category", "").strip() or None
    if category and category not in CLASS_CATEGORIES:
        conn.close()
        flash("Not a recognized category.", "error")
        return redirect(url_for("admin_classes"))
    conn.execute("UPDATE classes SET category=? WHERE id=?", (category, class_id))
    conn.commit()
    conn.close()
    flash(f"Category for '{class_row['name']}' updated.", "success")
    return redirect(url_for("admin_classes"))


@app.route("/admin/classes/<int:class_id>/set_form_teacher", methods=["POST"])
@login_required("admin", "sub_admin")
def set_form_teacher(class_id):
    if not require_scoped_permission("edit", class_id=class_id):
        flash("You do not have permission to edit this class.", "error")
        return redirect(url_for("admin_classes"))
    conn = get_db()
    if not class_in_school(conn, class_id):
        conn.close()
        flash("Class not found.", "error")
        return redirect(url_for("admin_classes"))
    teacher_id = request.form.get("teacher_id") or None
    if teacher_id and not teacher_in_school(conn, teacher_id):
        conn.close()
        flash("That teacher was not found.", "error")
        return redirect(url_for("admin_classes"))
    conn.execute("UPDATE classes SET form_teacher_id=? WHERE id=?", (teacher_id, class_id))
    if teacher_id:
        # Being the form teacher of a class makes this a Class Teacher / Form Teacher; the class record supplies the scope.
        add_staff_role(conn, int(teacher_id), current_school_id(), "Class Teacher / Form Teacher", session.get("user_id"), session.get("name"),
                       reason="Assigned as form teacher of a class")
    conn.commit()
    conn.close()
    flash("Form teacher updated.", "success")
    return redirect(url_for("admin_classes"))


@app.route("/admin/classes/<int:class_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_class(class_id):
    if not require_scoped_permission("delete", class_id=class_id):
        flash("You do not have permission to delete this class.", "error")
        return redirect(url_for("admin_classes"))
    conn = get_db()
    if not class_in_school(conn, class_id):
        conn.close()
        flash("Class not found.", "error")
        return redirect(url_for("admin_classes"))
    student_count = conn.execute(
        "SELECT COUNT(*) c FROM students WHERE class_id=?", (class_id,)
    ).fetchone()["c"]
    if student_count > 0:
        conn.close()
        flash(f"Can't delete this class — it still has {student_count} student(s) in it. Remove or reassign them first.", "error")
        return redirect(url_for("admin_classes"))
    conn.execute("DELETE FROM class_subjects WHERE class_id=?", (class_id,))
    conn.execute("DELETE FROM classes WHERE id=?", (class_id,))
    conn.commit()
    conn.close()
    flash("Class deleted.", "success")
    return redirect(url_for("admin_classes"))


@app.route("/admin/subjects", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_subjects():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST" and not require_scoped_permission("create"):
        conn.close()
        flash("You do not have permission to create subjects in your assigned scope.", "error")
        return redirect(url_for("admin_subjects"))
    if request.method == "GET" and not require_scoped_permission("view"):
        conn.close()
        flash("You do not have permission to view subjects in your assigned scope.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form["name"].strip()
        if name:
            try:
                conn.execute("INSERT INTO subjects (school_id, name) VALUES (?,?)", (school_id, name))
                conn.commit()
                flash(f"Subject '{name}' added.", "success")
            except sqlite3.IntegrityError:
                conn.rollback()
                flash("That subject already exists.", "error")
    subjects = conn.execute("SELECT * FROM subjects WHERE school_id=? ORDER BY name", (school_id,)).fetchall()
    conn.close()
    return render_template("admin_subjects.html", subjects=subjects)


@app.route("/admin/subjects/<int:subject_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_subject(subject_id):
    if not require_scoped_permission("delete", subject_id=subject_id):
        flash("You do not have permission to delete this subject.", "error")
        return redirect(url_for("admin_subjects"))
    conn = get_db()
    if not subject_in_school(conn, subject_id):
        conn.close()
        flash("Subject not found.", "error")
        return redirect(url_for("admin_subjects"))
    usage = conn.execute(
        "SELECT COUNT(*) c FROM class_subjects WHERE subject_id=?", (subject_id,)
    ).fetchone()["c"]
    if usage > 0:
        conn.close()
        flash("Can't delete this subject — it's still assigned to one or more classes. Unassign it first.", "error")
        return redirect(url_for("admin_subjects"))
    conn.execute("DELETE FROM subjects WHERE id=?", (subject_id,))
    conn.commit()
    conn.close()
    flash("Subject deleted.", "success")
    return redirect(url_for("admin_subjects"))


@app.route("/admin/class_subjects", methods=["GET", "POST"])
@app.route("/academics/assign-subjects", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_class_subjects():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST":
        try:
            class_id = int(request.form.get("class_id"))
            subject_id = int(request.form.get("subject_id"))
        except (TypeError, ValueError):
            class_id = subject_id = None
        teacher_id = request.form.get("teacher_id", type=int)
        if not class_id or not subject_id:
            conn.close(); flash("Please select both a class/arm and subject.", "error")
            return redirect(url_for("admin_class_subjects"))
        class_row = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, school_id)).fetchone()
        subject_row = conn.execute("SELECT * FROM subjects WHERE id=? AND school_id=?", (subject_id, school_id)).fetchone()
        if not class_row or not subject_row:
            conn.close(); flash("The selected class/arm or subject does not belong to this school.", "error")
            return redirect(url_for("admin_class_subjects"))
        if not require_scoped_permission("create", class_id=class_id, subject_id=subject_id):
            conn.close(); flash("You do not have permission to assign subjects in this scope.", "error")
            return redirect(url_for("admin_class_subjects"))
        if teacher_id:
            teacher = conn.execute("SELECT id FROM users WHERE id=? AND school_id=? AND role='teacher' AND COALESCE(is_active,1)=1", (teacher_id, school_id)).fetchone()
            if not teacher:
                conn.close(); flash("That teacher was not found in this school.", "error")
                return redirect(url_for("admin_class_subjects"))
        try:
            conn.execute("INSERT INTO class_subjects (class_id, subject_id, teacher_id) VALUES (?,?,?)", (class_id, subject_id, teacher_id))
            conn.commit()
            flash("Subject assigned to class/arm successfully.", "success")
        except sqlite3.IntegrityError:
            conn.rollback()
            existing = conn.execute("SELECT id, teacher_id FROM class_subjects WHERE class_id=? AND subject_id=?", (class_id, subject_id)).fetchone()
            if existing and teacher_id and not existing["teacher_id"]:
                conn.execute("UPDATE class_subjects SET teacher_id=? WHERE id=?", (teacher_id, existing["id"]))
                conn.commit(); flash("Subject was already assigned; the teacher assignment was updated.", "success")
            else:
                flash("That subject is already assigned to this class/arm. Use the assignment list to change its teacher.", "error")
    elif not require_scoped_permission("view"):
        conn.close(); flash("You do not have permission to view class-subject assignments.", "error")
        return redirect(url_for("dashboard"))
    classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY level, name, arm", (school_id,)).fetchall()
    subjects = conn.execute("SELECT * FROM subjects WHERE school_id=? ORDER BY name", (school_id,)).fetchall()
    teachers = conn.execute("SELECT * FROM users WHERE role='teacher' AND school_id=? AND COALESCE(is_active,1)=1 ORDER BY name", (school_id,)).fetchall()
    assignments = conn.execute(
        "SELECT cs.*, c.name as class_name, c.arm as class_arm, s.name as subject_name, u.name as teacher_name "
        "FROM class_subjects cs JOIN classes c ON c.id=cs.class_id JOIN subjects s ON s.id=cs.subject_id "
        "LEFT JOIN users u ON u.id=cs.teacher_id WHERE c.school_id=? AND s.school_id=? ORDER BY c.level, c.name, c.arm, s.name",
        (school_id, school_id),
    ).fetchall()
    conn.close()
    return render_template("admin_class_subjects.html", classes=classes, subjects=subjects, teachers=teachers, assignments=assignments)


@app.route("/admin/class_subjects/<int:cs_id>/assign_teacher", methods=["POST"])
@login_required("admin", "sub_admin")
def assign_teacher(cs_id):
    conn = get_db()
    cs_scope = conn.execute("SELECT * FROM class_subjects WHERE id=? AND class_id IN (SELECT id FROM classes WHERE school_id=?)", (cs_id, current_school_id())).fetchone()
    if not cs_scope or not require_scoped_permission("edit", class_id=cs_scope["class_id"], subject_id=cs_scope["subject_id"]):
        conn.close()
        flash("You do not have permission to edit this class-subject assignment.", "error")
        return redirect(url_for("admin_class_subjects"))
    teacher_id = request.form.get("teacher_id") or None
    if teacher_id and not teacher_in_school(conn, teacher_id):
        conn.close()
        flash("That teacher was not found.", "error")
        return redirect(url_for("admin_class_subjects"))
    conn.execute(
        "UPDATE class_subjects SET teacher_id=? WHERE id=? AND class_id IN (SELECT id FROM classes WHERE school_id=?)",
        (teacher_id, cs_id, current_school_id()),
    )
    conn.commit()
    conn.close()
    flash("Teacher assigned.", "success")
    return redirect(url_for("admin_class_subjects"))


@app.route("/admin/class_subjects/<int:cs_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_class_subject(cs_id):
    conn = get_db()
    cs_scope = conn.execute("SELECT * FROM class_subjects WHERE id=? AND class_id IN (SELECT id FROM classes WHERE school_id=?)", (cs_id, current_school_id())).fetchone()
    if not cs_scope or not require_scoped_permission("delete", class_id=cs_scope["class_id"], subject_id=cs_scope["subject_id"]):
        conn.close()
        flash("You do not have permission to delete this class-subject assignment.", "error")
        return redirect(url_for("admin_class_subjects"))
    conn.execute(
        "DELETE FROM class_subjects WHERE id=? AND class_id IN (SELECT id FROM classes WHERE school_id=?)",
        (cs_id, current_school_id()),
    )
    conn.commit()
    conn.close()
    flash("Assignment removed.", "success")
    return redirect(url_for("admin_class_subjects"))


@app.route("/admin/signup-codes",methods=["GET","POST"])
@login_required("admin","sub_admin","teacher")
def signup_codes():
    conn=get_db(); sid=current_school_id(); role=session.get("role")
    if request.method=="POST":
        typ=request.form.get("code_type"); class_id=request.form.get("class_id") or None; student_id=request.form.get("student_id") or None; allowed=typ in ("staff","student","parent_link")
        if typ in ("staff","parent_link") and role not in ("admin","sub_admin"): allowed=False
        if typ=="student" and role=="teacher" and (not class_id or int(class_id) not in form_teacher_class_ids(conn,session["user_id"])): allowed=False
        if not allowed: flash("You don't have permission to create that code.","error")
        else:
            try:
                code,expires=generate_signup_code(conn,typ,sid,session.get("user_id"),int(class_id) if class_id else None,int(student_id) if student_id else None,max_usage=int(request.form.get("max_usage",1) or 1)); conn.commit(); flash(f"Secure code created: {code} (expires {format_dmy(expires)}).","success")
            except Exception: conn.rollback(); flash("Could not create the signup code.","error")
    codes=conn.execute("SELECT sc.*,c.name class_name,s.first_name,s.last_name FROM signup_codes sc LEFT JOIN classes c ON c.id=sc.class_id LEFT JOIN students s ON s.id=sc.student_id WHERE sc.school_id=? ORDER BY sc.id DESC",(sid,)).fetchall(); classes=conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name",(sid,)).fetchall(); students=conn.execute("SELECT st.id,st.first_name,st.last_name,c.name class_name FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1 ORDER BY c.name,st.last_name",(sid,)).fetchall(); conn.close(); return render_template("admin_signup_codes.html",codes=codes,classes=classes,students=students)

@app.route("/admin/signup-codes/<int:code_id>/revoke",methods=["POST"])
@login_required("admin","sub_admin","teacher")
def revoke_signup_code(code_id):
    conn=get_db(); row=conn.execute("SELECT * FROM signup_codes WHERE id=? AND school_id=?",(code_id,current_school_id())).fetchone()
    if not row: conn.close(); flash("Signup code not found.","error"); return redirect(url_for("signup_codes"))
    if session.get("role") not in ("admin","sub_admin") and row["class_id"] not in form_teacher_class_ids(conn,session["user_id"]): conn.close(); flash("You don't have permission to revoke this code.","error"); return redirect(url_for("signup_codes"))
    conn.execute("UPDATE signup_codes SET status='revoked',revoked_at=CURRENT_TIMESTAMP,revoked_by=? WHERE id=?",(session.get("user_id"),code_id)); conn.commit(); conn.close(); flash("Signup code revoked.","success"); return redirect(url_for("signup_codes"))

@app.route("/admin/students", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_students():
    conn=get_db(); school_id=current_school_id()
    if request.method=="POST":
        try: class_id=int(request.form.get("class_id"))
        except (TypeError,ValueError): class_id=None
        if not class_id or not class_in_school(conn,class_id):
            conn.close(); flash("Please select a valid class/arm.","error"); return redirect(url_for("admin_students"))
        if not require_scoped_permission("create",class_id=class_id):
            conn.close(); flash("You do not have permission to create students in this class scope.","error"); return redirect(url_for("admin_students"))
        allowed,message,_=plan_limit_check(conn,school_id,"students",1)
        if not allowed:
            conn.close(); flash(message,"error"); return redirect(url_for("admin_students"))
        admission=request.form.get("admission_no","").strip(); first=request.form.get("first_name","").strip(); last=request.form.get("last_name","").strip(); errors=[]
        if not admission: errors.append("Admission No. / Register No. is required.")
        if not first: errors.append("First name is required.")
        if not last: errors.append("Last name is required.")
        if request.form.get("gender") not in ("M","F"): errors.append("Gender is required.")
        if conn.execute("SELECT 1 FROM students s JOIN classes c ON c.id=s.class_id WHERE c.school_id=? AND LOWER(TRIM(s.admission_no))=LOWER(TRIM(?))",(school_id,admission)).fetchone(): errors.append("That Admission No. / Register No. is already used by another student in this school.")
        if errors:
            for e in errors: flash(e,"error")
        else:
            try:
                school = conn.execute("SELECT id, tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()
                if not school or not school["tenant_id"]:
                    raise ValueError("School tenant information is incomplete. Please complete School Setup before adding students.")
                # Every class/arm and student write is resolved from the
                # authenticated tenant; no client-supplied tenant is trusted.
                class_row = conn.execute("SELECT id, school_id, tenant_id FROM classes WHERE id=? AND school_id=?", (class_id, school_id)).fetchone()
                if not class_row or class_row["tenant_id"] not in (None, school["tenant_id"]):
                    raise ValueError("The selected class/arm does not belong to the current school.")
                parent_email = request.form.get("parent_email", "").strip() or None
                if parent_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", parent_email):
                    raise ValueError("Parent/Guardian email address is not valid.")
                status = request.form.get("status", "Active")
                if status not in ("Active","Graduated","Transferred","Withdrawn","Suspended"):
                    status = "Active"
                tenant = school["tenant_id"]
                cur = conn.execute(
                    "INSERT INTO students (school_id,tenant_id,admission_no,first_name,last_name,other_names,gender,class_id,date_of_birth,religion,parent_name,parent_address,parent_email,parent_phone,parent_relationship,status,phone) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (school_id,tenant,admission,first,last,request.form.get("other_names","").strip() or None,
                     request.form.get("gender"),class_id,request.form.get("date_of_birth","").strip() or None,
                     request.form.get("religion","").strip() or None,request.form.get("parent_name","").strip() or None,
                     request.form.get("parent_address","").strip() or None,parent_email,
                     request.form.get("parent_phone","").strip() or None,request.form.get("parent_relationship","").strip() or None,
                     status,request.form.get("phone","").strip() or None),
                )
                student_id = cur.lastrowid
                upsert_enrollment(conn, student_id, class_id)
                # Optional passport upload (validated server-side).
                photo = request.files.get("photo")
                if photo and photo.filename:
                    size_error = _reject_oversize(photo, "passport") or _verify_image(photo, 500 * 1024, "Passport photograph")
                    if size_error:
                        raise ValueError(size_error)
                    ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
                    if ext not in ALLOWED_LOGO_EXTENSIONS:
                        raise ValueError("Passport photo must be a PNG, JPG, or GIF image.")
                    os.makedirs(STUDENT_PHOTOS_DIR, exist_ok=True)
                    filename = f"student_{student_id}.{ext}"
                    photo.save(os.path.join(STUDENT_PHOTOS_DIR, filename))
                    conn.execute("UPDATE students SET photo_filename=? WHERE id=? AND school_id=?", (filename, student_id, school_id))
                conn.commit()
                flash(f"Student '{first} {last}' added successfully.","success")
            except ValueError as exc:
                conn.rollback()
                flash(str(exc),"error")
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                app.logger.warning("Student creation rejected by database constraint: %s", exc)
                message = "That Admission No. / Register No. is already used by another student in this school." if "admission" in str(exc).lower() or "unique" in str(exc).lower() else "Student data conflicts with an existing record. Please check the admission/register number and class."
                flash(message,"error")
            except Exception:
                conn.rollback()
                app.logger.exception("Student creation failed")
                message = "Student could not be saved because the submitted data could not be processed. Check the required fields and try again."
                flash(message,"error")
    elif not require_scoped_permission("view"):
        conn.close(); flash("You do not have permission to view students.","error"); return redirect(url_for("dashboard"))
    classes=conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name",(school_id,)).fetchall(); class_filter=request.args.get("class_id",type=int)
    if class_filter: students=conn.execute("SELECT s.*,c.name class_name FROM students s JOIN classes c ON c.id=s.class_id WHERE s.class_id=? AND c.school_id=? AND s.is_active=1 ORDER BY s.last_name",(class_filter,school_id)).fetchall()
    else: students=conn.execute("SELECT s.*,c.name class_name FROM students s JOIN classes c ON c.id=s.class_id WHERE c.school_id=? AND s.is_active=1 ORDER BY c.name,s.last_name",(school_id,)).fetchall()
    conn.close(); return render_template("admin_students.html",classes=classes,students=students,class_filter=class_filter,student_full_name=student_full_name)


@app.route("/admin/students/<int:student_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_student(student_id):
    conn = get_db()
    student_scope = conn.execute("SELECT class_id FROM students WHERE id=? AND school_id=?", (student_id, current_school_id())).fetchone()
    if not student_scope or not require_scoped_permission("delete", class_id=student_scope["class_id"]):
        conn.close()
        flash("You do not have permission to delete this student.", "error")
        return redirect(url_for("admin_students"))
    if not student_in_school(conn, student_id):
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("admin_students"))
    conn.execute("DELETE FROM student_skill_ratings WHERE student_id=?", (student_id,))
    conn.execute("DELETE FROM student_term_info WHERE student_id=?", (student_id,))
    audit_scores_deleted(conn, [student_id])
    conn.execute("DELETE FROM score_history WHERE student_id=?", (student_id,))
    conn.execute("DELETE FROM scores WHERE student_id=?", (student_id,))
    conn.execute("DELETE FROM enrollments WHERE student_id=?", (student_id,))
    conn.execute("DELETE FROM students WHERE id=?", (student_id,))
    conn.commit()
    conn.close()
    flash("Student and their records deleted.", "success")
    return redirect(url_for("admin_students"))


@app.route("/students/<int:student_id>/parent")
@login_required()
def parent_profile(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    if session["role"] not in ("admin", "sub_admin") and student["class_id"] not in form_teacher_class_ids(conn, session["user_id"]):
        conn.close()
        flash("You don't have access to view this parent's profile.", "error")
        return redirect(url_for("dashboard"))
    if not student["parent_phone"] and not student["parent_email"]:
        conn.close()
        flash("No parent/guardian contact info has been recorded for this student yet.", "error")
        return redirect(url_for("student_profile", student_id=student_id))

    school_id = current_school_id()
    # A "parent profile" isn't its own login/account in this system yet —
    # it's assembled from the parent_* contact fields shared across every
    # student record that has the same guardian, matched by phone (or email
    # when no phone was given).
    if student["parent_phone"]:
        siblings = conn.execute(
            "SELECT s.*, c.name as class_name FROM students s JOIN classes c ON c.id=s.class_id "
            "WHERE c.school_id=? AND s.parent_phone=? AND s.is_active=1 ORDER BY s.first_name",
            (school_id, student["parent_phone"]),
        ).fetchall()
    else:
        siblings = conn.execute(
            "SELECT s.*, c.name as class_name FROM students s JOIN classes c ON c.id=s.class_id "
            "WHERE c.school_id=? AND s.parent_email=? AND s.is_active=1 ORDER BY s.first_name",
            (school_id, student["parent_email"]),
        ).fetchall()
    accounts = conn.execute(
        "SELECT pa.id, pa.name, pa.username, pa.email, pa.phone, pa.photo_filename FROM parent_accounts pa "
        "JOIN parent_students ps ON ps.parent_id=pa.id WHERE ps.student_id=? AND ps.school_id=? AND pa.school_id=? "
        "AND ps.status='verified' AND ps.revoked_at IS NULL", (student_id, school_id, school_id)).fetchall()
    conn.close()
    return render_template(
        "parent_profile.html", student=student, siblings=siblings, student_full_name=student_full_name,
        accounts=accounts, can_see_parent_photo=session["role"] in ("admin", "sub_admin"),
    )


@app.route("/admin/parents")
@login_required("admin", "sub_admin")
def admin_parents():
    conn = get_db()
    school_id = current_school_id()
    rows = conn.execute(
        "SELECT s.id, s.parent_name, s.parent_phone, s.parent_email, s.parent_relationship "
        "FROM students s JOIN classes c ON c.id=s.class_id "
        "WHERE c.school_id=? AND s.is_active=1 AND (s.parent_phone IS NOT NULL OR s.parent_email IS NOT NULL) "
        "ORDER BY s.parent_name", (school_id,)
    ).fetchall()
    # Group by the same key parent_profile() uses (phone, falling back to email),
    # and attach the dedicated portal account when one exists.
    seen = {}
    guardians = []
    for r in rows:
        key = r["parent_phone"] or r["parent_email"] or (r["parent_name"] or f"student-{r['id']}")
        if key in seen:
            continue
        seen[key] = True
        account = conn.execute("SELECT id,username,is_active FROM parent_accounts WHERE school_id=? AND ((phone IS NOT NULL AND phone=?) OR (email IS NOT NULL AND LOWER(email)=LOWER(?))) LIMIT 1", (school_id,r["parent_phone"],r["parent_email"])).fetchone()
        guardians.append(dict(r, account=account))
    conn.close()
    return render_template("admin_parents.html", guardians=guardians)



@app.route("/admin/parents/create", methods=["POST"])
@login_required("admin", "sub_admin")
def admin_parent_create():
    conn = get_db(); school_id = current_school_id()
    student_id = request.form.get("student_id", type=int)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip() or None
    phone = request.form.get("phone", "").strip() or None
    student = conn.execute("SELECT s.*, c.school_id FROM students s JOIN classes c ON c.id=s.class_id WHERE s.id=? AND c.school_id=? AND s.is_active=1", (student_id, school_id)).fetchone()
    if not student:
        conn.close(); flash("Student/guardian record not found.", "error"); return redirect(url_for("admin_parents"))
    name = name or student["parent_name"] or "Parent"
    username = username or ((phone or email or f"parent{student_id}").replace(" ", "").replace("+", ""))
    if not password or len(password) < 6:
        conn.close(); flash("Parent password must be at least 6 characters.", "error"); return redirect(url_for("admin_parents"))
    existing = conn.execute("SELECT id FROM parent_accounts WHERE school_id=? AND username=?", (school_id, username)).fetchone()
    if existing:
        conn.close(); flash("That parent username already exists in this school.", "error"); return redirect(url_for("admin_parents"))
    cur = conn.execute("INSERT INTO parent_accounts (school_id,tenant_id,name,username,email,phone,password_hash,account_status,signup_status) VALUES (?,?,?,?,?,?,?,'active','approved')", (school_id,current_tenant_id(),name,username,email,phone,generate_password_hash(password)))
    parent_id = cur.lastrowid
    # Link all active children that share this guardian's phone/email/name, without crossing tenants.
    if phone or email:
        rows = conn.execute("SELECT s.id FROM students s JOIN classes c ON c.id=s.class_id WHERE c.school_id=? AND s.is_active=1 AND ((? IS NOT NULL AND s.parent_phone=?) OR (? IS NOT NULL AND LOWER(s.parent_email)=LOWER(?)))", (school_id, phone, phone, email, email)).fetchall()
    else:
        rows = [(student_id,)]
    if not rows: rows = [(student_id,)]
    for r in rows:
        conn.execute("INSERT OR IGNORE INTO parent_students(parent_id,student_id,school_id,tenant_id,status) VALUES (?,?,?,? ,'verified')", (parent_id, r[0], school_id, current_tenant_id()))
    conn.commit(); conn.close()
    flash(f"Parent portal account created for {name}. Username: {username}", "success")
    return redirect(url_for("admin_parents"))

@app.route("/admin/parents/<int:parent_id>/reset", methods=["POST"])
@login_required("admin", "sub_admin")
def admin_parent_reset(parent_id):
    password = request.form.get("password", "")
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error"); return redirect(url_for("admin_parents"))
    conn = get_db(); row = conn.execute("SELECT id,name FROM parent_accounts WHERE id=? AND school_id=?", (parent_id,current_school_id())).fetchone()
    if not row:
        conn.close(); flash("Parent account not found.", "error"); return redirect(url_for("admin_parents"))
    conn.execute("UPDATE parent_accounts SET password_hash=? WHERE id=?", (generate_password_hash(password), parent_id)); conn.commit(); conn.close()
    flash(f"Password reset for {row['name']}.", "success"); return redirect(url_for("admin_parents"))

@app.route("/admin/parents/<int:parent_id>/toggle", methods=["POST"])
@login_required("admin", "sub_admin")
def admin_parent_toggle(parent_id):
    conn=get_db(); row=conn.execute("SELECT id,is_active,name FROM parent_accounts WHERE id=? AND school_id=?", (parent_id,current_school_id())).fetchone()
    if not row:
        conn.close(); flash("Parent account not found.","error"); return redirect(url_for("admin_parents"))
    conn.execute("UPDATE parent_accounts SET is_active=? WHERE id=?", (0 if row["is_active"] else 1,parent_id)); conn.commit(); conn.close()
    flash(f"Parent account {'activated' if not row['is_active'] else 'deactivated'}.","success"); return redirect(url_for("admin_parents"))

@app.route("/admin/parents/links")
@login_required("admin","sub_admin")
def admin_parent_links():
    conn=get_db(); rows=conn.execute("SELECT ps.*,p.name parent_name,p.username,s.first_name,s.last_name,c.name class_name FROM parent_students ps JOIN parent_accounts p ON p.id=ps.parent_id JOIN students s ON s.id=ps.student_id JOIN classes c ON c.id=s.class_id WHERE ps.school_id=? ORDER BY ps.status,p.name",(current_school_id(),)).fetchall(); conn.close(); return render_template("admin_parent_links.html",links=rows)

@app.route("/admin/parents/links/<int:link_id>/<action>",methods=["POST"])
@login_required("admin","sub_admin")
def admin_parent_link_action(link_id,action):
    if action not in ("verify","reject","suspend","revoke"): flash("Invalid relationship action.","error"); return redirect(url_for("admin_parent_links"))
    conn=get_db(); row=conn.execute("SELECT * FROM parent_students WHERE id=? AND school_id=?",(link_id,current_school_id())).fetchone()
    if not row: conn.close(); flash("Parent-child relationship not found.","error"); return redirect(url_for("admin_parent_links"))
    status={"verify":"verified","reject":"rejected","suspend":"suspended","revoke":"revoked"}[action]; conn.execute("UPDATE parent_students SET status=?,verified_at=CASE WHEN ?='verified' THEN CURRENT_TIMESTAMP ELSE verified_at END,verified_by=CASE WHEN ?='verified' THEN ? ELSE verified_by END,revoked_at=CASE WHEN ? IN ('revoke','suspend') THEN CURRENT_TIMESTAMP ELSE revoked_at END WHERE id=?",(status,status,status,session.get("user_id"),status,link_id)); _security_audit_event(conn,"parent_link_changed",f"Parent-child link {link_id}: {status}",current_school_id()); conn.commit(); conn.close(); flash(f"Parent-child relationship {status}.","success"); return redirect(url_for("admin_parent_links"))

@app.route("/parent/link-child",methods=["GET","POST"])
@parent_login_required
def parent_link_child():
    conn=get_db(); pid=session["parent_id"]
    if request.method=="POST":
        code=request.form.get("link_code","").strip(); row,msg=verify_signup_code(conn,code,"parent_link",school_id=current_school_id(),consume=False)
        if not row: flash(msg,"error")
        else:
            ex=conn.execute("SELECT id,status FROM parent_students WHERE parent_id=? AND student_id=? AND school_id=?",(pid,row["student_id"],current_school_id())).fetchone()
            if ex and ex["status"] in ("verified","pending"): flash("This student is already linked to your account.","info")
            else:
                conn.execute("INSERT INTO parent_students(parent_id,student_id,school_id,tenant_id,status) VALUES(?,?,?,?, 'pending') ON CONFLICT(parent_id,student_id) DO UPDATE SET status='pending',revoked_at=NULL",(pid,row["student_id"],current_school_id(),current_tenant_id())); conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",("System",current_school_id(),"admin","Parent-child linking request","A parent submitted a child-linking request that requires school verification.")); verify_signup_code(conn,code,"parent_link",school_id=current_school_id(),student_id=row["student_id"],consume=True); conn.commit(); flash("Child link submitted for school verification.","success")
    conn.close(); return render_template("parent_link_child.html")

@app.route("/parent/children/<int:student_id>/remove",methods=["POST"])
@parent_login_required
def parent_remove_child(student_id):
    conn=get_db(); row=conn.execute("SELECT id FROM parent_students WHERE parent_id=? AND student_id=? AND school_id=?",(session["parent_id"],student_id,current_school_id())).fetchone()
    if not row: conn.close(); flash("This child is not linked to your account.","error"); return redirect(url_for("parent_children_page"))
    conn.execute("UPDATE parent_students SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE id=?",(row["id"],)); conn.commit(); conn.close(); flash("Child relationship removed. Student records were preserved.","success"); return redirect(url_for("parent_children_page"))

@app.route("/parent/ai-consent/<int:student_id>",methods=["GET","POST"])
@parent_login_required
def parent_ai_consent(student_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    if not child:
        conn.close(); flash("You do not have access to this student.","error"); return redirect(url_for("parent_children_page"))
    settings=_ai_settings(conn,current_school_id())
    if request.method=="POST":
        action=request.form.get("action")
        if action in ("granted","withdrawn"):
            conn.execute("INSERT INTO student_ai_consent(student_id,school_id,status,granted_by_type,granted_by_id,policy_version,granted_at,withdrawn_at) VALUES (?,?,?,?,?,?,CASE WHEN ?='granted' THEN CURRENT_TIMESTAMP END,CASE WHEN ?='withdrawn' THEN CURRENT_TIMESTAMP END) ON CONFLICT(student_id) DO UPDATE SET status=excluded.status,granted_by_type=excluded.granted_by_type,granted_by_id=excluded.granted_by_id,policy_version=excluded.policy_version,granted_at=excluded.granted_at,withdrawn_at=excluded.withdrawn_at",(student_id,current_school_id(),action,"parent_guardian",session["parent_id"],settings["privacy_notice_version"],action,action))
            conn.execute("INSERT INTO parent_consent_events(school_id,parent_id,student_id,action,policy_version) VALUES (?,?,?,?,?)",(current_school_id(),session["parent_id"],student_id,action,settings["privacy_notice_version"]))
            _ai_log(conn,"privacy","parent_consent_changed",student_id,action,scope="student",request_summary=f"Parent {session['parent_id']} changed consent",output_summary="")
            conn.commit(); flash("AI consent updated.","success")
    row=conn.execute("SELECT status,policy_version,granted_at,withdrawn_at FROM student_ai_consent WHERE student_id=? AND school_id=?",(student_id,current_school_id())).fetchone(); conn.close()
    return render_template("parent_ai_consent.html",child=child,consent=row,policy_version=settings["privacy_notice_version"])

@app.route("/parent/logout")
def parent_logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/parent/dashboard")
@parent_login_required
def parent_dashboard():
    conn=get_db(); children=parent_children(conn,session["parent_id"])
    cards=[]
    for child in children:
        term=current_term(conn)
        analysis=None
        if term:
            try:
                analysis_rows=conn.execute("SELECT sc.ca1,sc.ca2,sc.exam,sc.ca3,sub.name subject_name FROM scores sc JOIN subjects sub ON sub.id=sc.subject_id WHERE sc.student_id=? AND sc.term_id=?",(child["id"],term["id"])).fetchall()
                analysis=analyze_student(analysis_rows)
            except Exception: analysis=None
        cards.append({"student":child,"analysis":analysis})
    conn.close(); return render_template("parent_dashboard.html",children=children,cards=cards)

@app.route("/parents/<int:parent_id>/photo")
def parent_photo(parent_id):
    """Parent passport: School Admin / Sub-Admin of the same school, or the parent themself."""
    if "school_id" not in session:
        return "", 404
    own = session.get("parent_id") == parent_id
    if not own and session.get("role") not in ("admin", "sub_admin"):
        return "", 404
    conn = get_db()
    row = conn.execute("SELECT photo_filename, school_id FROM parent_accounts WHERE id=?", (parent_id,)).fetchone()
    conn.close()
    if not row or row["school_id"] != session["school_id"] or not row["photo_filename"]:
        return "", 404
    return send_from_directory(PARENT_PHOTOS_DIR, row["photo_filename"])


@app.route("/parent/profile", methods=["GET", "POST"])
@parent_login_required
def parent_my_profile():
    conn = get_db()
    me = conn.execute("SELECT * FROM parent_accounts WHERE id=? AND school_id=?", (session["parent_id"], session.get("school_id"))).fetchone()
    if request.method == "POST":
        file = request.files.get("photo")
        if not file or not file.filename:
            flash("Please choose an image file to upload.", "error")
        else:
            err = _reject_oversize(file, "passport") or _verify_image(file, 500 * 1024, "Passport photograph")
            ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
            if not err and ext not in ALLOWED_LOGO_EXTENSIONS:
                err = "Photo must be a PNG, JPG, or GIF image."
            if err:
                flash(err, "error")
            else:
                if me["photo_filename"]:
                    old = os.path.join(PARENT_PHOTOS_DIR, me["photo_filename"])
                    if os.path.exists(old):
                        os.remove(old)
                os.makedirs(PARENT_PHOTOS_DIR, exist_ok=True)
                fn = f"parent_{me['id']}.{ext}"
                file.save(os.path.join(PARENT_PHOTOS_DIR, fn))
                conn.execute("UPDATE parent_accounts SET photo_filename=? WHERE id=? AND school_id=?", (fn, me["id"], me["school_id"]))
                conn.commit()
                flash("Passport photo updated.", "success")
        conn.close()
        return redirect(url_for("parent_my_profile"))
    conn.close()
    return render_template("parent_my_profile.html", me=me)


@app.route("/parent/children")
@parent_login_required
def parent_children_page():
    conn=get_db(); children=parent_children(conn,session["parent_id"]); conn.close()
    return render_template("parent_children.html",children=children)

@app.route("/parent/children/<int:student_id>")
@parent_login_required
def parent_child_detail(student_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    if not child:
        conn.close(); flash("You do not have access to this student.","error"); return redirect(url_for("parent_children_page"))
    terms=conn.execute("SELECT t.*, s.name session_name FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.school_id=? AND t.is_published=1 ORDER BY s.id DESC,t.id DESC",(current_school_id(),)).fetchall()
    teachers=conn.execute("SELECT DISTINCT u.id,u.name,u.email,u.phone FROM users u JOIN class_subjects cs ON cs.teacher_id=u.id WHERE cs.class_id=? AND u.school_id=? AND u.role='teacher' AND COALESCE(u.is_active,1)=1 UNION SELECT u.id,u.name,u.email,u.phone FROM users u JOIN classes c ON c.form_teacher_id=u.id WHERE c.id=? AND u.school_id=? AND u.role='teacher'",(child["class_id"],current_school_id(),child["class_id"],current_school_id())).fetchall()
    conn.close(); return render_template("parent_child_detail.html",child=child,terms=terms,teachers=teachers)

@app.route("/parent/children/<int:student_id>/result/<int:term_id>")
@parent_login_required
def parent_result(student_id,term_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    term=conn.execute("SELECT t.*,s.name session_name FROM terms t JOIN sessions s ON s.id=t.session_id WHERE t.id=? AND s.school_id=? AND t.is_published=1",(term_id,current_school_id())).fetchone()
    if not child or not term:
        conn.close(); flash("That published result is not available.","error"); return redirect(url_for("parent_children_page"))
    data=build_result_data(conn,student_id,term_id); conn.close()
    return render_template("parent_result.html",child=child,term=term,student_full_name=student_full_name,**data)

@app.route("/parent/children/<int:student_id>/result/<int:term_id>/pdf")
@parent_login_required
def parent_result_pdf(student_id,term_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    term=conn.execute("SELECT t.*,s.name session_name FROM terms t JOIN sessions s ON s.id=t.session_id WHERE t.id=? AND s.school_id=? AND t.is_published=1",(term_id,current_school_id())).fetchone()
    if not child or not term:
        conn.close(); flash("That published result is not available.","error"); return redirect(url_for("parent_children_page"))
    data=build_result_data(conn,student_id,term_id); school=get_school(conn,current_school_id()); logo_path=None
    if school and school["logo_filename"]:
        candidate=os.path.join(INSTANCE_DIR,school["logo_filename"])
        if os.path.exists(candidate): logo_path=candidate
    conn.close(); buf=build_result_pdf(data,term,school_name=school["name"],logo_path=logo_path,student_full_name=student_full_name,font_choice=school["pdf_font"],accent_color=school["result_accent_color"] or "#1f3a5f",name_align=school["name_align"])
    return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name=f"result_{child['admission_no']}_{term['name']}.pdf".replace(" ","_").replace("/","-"))

@app.route("/parent/children/<int:student_id>/attendance")
@parent_login_required
def parent_attendance(student_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    if not child: conn.close(); flash("You do not have access to this student.","error"); return redirect(url_for("parent_children_page"))
    rows=conn.execute("SELECT t.id,t.name,t.is_published, COUNT(ar.id) days_opened, SUM(CASE WHEN ar.status='present' THEN 1 ELSE 0 END) present, SUM(CASE WHEN ar.status='absent' THEN 1 ELSE 0 END) absent FROM terms t JOIN sessions se ON se.id=t.session_id LEFT JOIN attendance_records ar ON ar.term_id=t.id AND ar.student_id=? WHERE se.school_id=? GROUP BY t.id ORDER BY se.id DESC,t.id DESC",(student_id,current_school_id())).fetchall()
    conn.close(); return render_template("parent_attendance.html",child=child,rows=rows)

@app.route("/parent/children/<int:student_id>/timetable")
@parent_login_required
def parent_timetable(student_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    if not child: conn.close(); flash("You do not have access to this student.","error"); return redirect(url_for("parent_children_page"))
    school_id=current_school_id(); school=conn.execute("SELECT COALESCE(tenant_id,CAST(id AS TEXT)) tenant_id FROM schools WHERE id=?",(school_id,)).fetchone(); tenant=school["tenant_id"] if school else str(school_id)
    version=conn.execute("SELECT * FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=? AND status='PUBLISHED' ORDER BY id DESC LIMIT 1",(school_id,tenant)).fetchone()
    entries=[]
    if version:
        entries=conn.execute("SELECT te.*,ss.slot_name,ss.start_time,ss.end_time,s.name subject_name,u.name teacher_name,r.room_name,sd.day_name,sd.day_order FROM timetable_entries_v2 te JOIN schedule_slots ss ON ss.id=te.slot_id JOIN school_days_v2 sd ON sd.id=te.day_id JOIN subjects s ON s.id=te.subject_id LEFT JOIN users u ON u.id=te.teacher_id LEFT JOIN timetable_rooms_v2 r ON r.id=te.room_id WHERE te.timetable_version_id=? AND te.class_id=? AND te.school_id=? AND te.tenant_id=? ORDER BY sd.day_order,ss.slot_number",(version["id"],child["class_id"],school_id,tenant)).fetchall()
    conn.close(); return render_template("parent_timetable.html",child=child,entries=entries,version=version)

@app.route("/parent/notifications")
@parent_login_required
def parent_notifications():
    parent_id = session["parent_id"]      # only this parent's own notifications
    conn=get_db(); notifications=notification_rows(conn, ("parent", parent_id, "parent_accounts", "parent", session.get("school_id"))); conn.close()
    return render_template("parent_notifications.html",notifications=notifications)


@app.route("/students/<int:student_id>/profile")
@login_required()
def student_profile(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    if session["role"] not in ("admin", "sub_admin") and student["class_id"] not in form_teacher_class_ids(conn, session["user_id"]):
        conn.close()
        flash("You don't have access to view this student's profile.", "error")
        return redirect(url_for("dashboard"))
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (student["class_id"],)).fetchone()
    enrollment_history = conn.execute(
        "SELECT e.*, s.name as session_name, c.name as class_name FROM enrollments e "
        "JOIN sessions s ON s.id=e.session_id JOIN classes c ON c.id=e.class_id "
        "WHERE e.student_id=? ORDER BY s.id", (student_id,)
    ).fetchall()
    term_row = current_term(conn)
    custom_profile = [f for f in custom_field_rows(conn, current_school_id(), student_id, term_row["id"] if term_row else 0, "profile") if f["value"]]
    conn.close()
    return render_template(
        "student_profile.html", student=student, class_row=class_row,
        student_full_name=student_full_name, enrollment_history=enrollment_history, custom_profile=custom_profile,
    )


def _can_manage_student(conn, student):
    if session["role"] in ("admin", "sub_admin") or student["class_id"] in form_teacher_class_ids(conn, session["user_id"]):
        return True
    try:
        return any(r["role"] == "Registrar / Admissions Officer" for r in active_role_assignments(conn, session["user_id"], current_school_id()))
    except Exception:
        return False


@app.route("/students/<int:student_id>/photo")
@login_required()
def student_photo(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student or not _can_manage_student(conn, student):
        conn.close()
        return "", 404
    filename = student["photo_filename"]
    conn.close()
    if not filename:
        return "", 404
    return send_from_directory(STUDENT_PHOTOS_DIR, filename)


@app.route("/students/<int:student_id>/photo/upload", methods=["POST"])
@login_required()
def upload_student_photo(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student or not _can_manage_student(conn, student):
        conn.close()
        flash("You don't have access to manage this student's profile.", "error")
        return redirect(url_for("dashboard"))
    file = request.files.get("photo")
    if not file or not file.filename:
        conn.close()
        flash("Please choose an image file to upload.", "error")
        return redirect(url_for("student_profile", student_id=student_id))
    size_error = _reject_oversize(file, "passport") or _verify_image(file, 500 * 1024, "Passport photograph")
    if size_error:
        conn.close(); flash(size_error, "error"); return redirect(url_for("student_profile", student_id=student_id))
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_LOGO_EXTENSIONS:
        conn.close()
        flash("Passport photo must be a PNG, JPG, or GIF image.", "error")
        return redirect(url_for("student_profile", student_id=student_id))
    if student["photo_filename"]:
        old_path = os.path.join(STUDENT_PHOTOS_DIR, student["photo_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
    new_filename = f"student_{student_id}.{ext}"
    os.makedirs(STUDENT_PHOTOS_DIR, exist_ok=True)
    file.save(os.path.join(STUDENT_PHOTOS_DIR, new_filename))
    conn.execute("UPDATE students SET photo_filename=? WHERE id=?", (new_filename, student_id))
    conn.commit()
    conn.close()
    flash("Passport photo updated.", "success")
    return redirect(url_for("student_profile", student_id=student_id))


@app.route("/students/<int:student_id>/photo/remove", methods=["POST"])
@login_required()
def remove_student_photo(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student or not _can_manage_student(conn, student):
        conn.close()
        flash("You don't have access to manage this student's profile.", "error")
        return redirect(url_for("dashboard"))
    if student["photo_filename"]:
        old_path = os.path.join(STUDENT_PHOTOS_DIR, student["photo_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
        conn.execute("UPDATE students SET photo_filename=NULL WHERE id=?", (student_id,))
        conn.commit()
        flash("Passport photo removed.", "success")
    conn.close()
    return redirect(url_for("student_profile", student_id=student_id))


@app.route("/students/<int:student_id>/set_login", methods=["POST"])
@login_required()
def set_student_login(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student or not _can_manage_student(conn, student):
        conn.close()
        flash("You don't have access to manage this student's login.", "error")
        return redirect(url_for("dashboard"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username:
        conn.close()
        flash("Username is required.", "error")
        return redirect(url_for("student_profile", student_id=student_id))
    if password and len(password) < 6:
        conn.close()
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("student_profile", student_id=student_id))
    import profile_core as _pc
    username = username.lower()
    if not re.fullmatch(r"[a-z0-9._\-]{3,40}", username):
        conn.close()
        flash("Username must be 3-40 characters: letters, numbers, dot, underscore or hyphen.", "error")
        return redirect(url_for("student_profile", student_id=student_id))
    # A username must never look like another student's admission/register number in this school (login would be ambiguous).
    if conn.execute("SELECT 1 FROM students s JOIN classes c ON c.id=s.class_id WHERE c.school_id=? AND s.id<>? AND (LOWER(TRIM(s.admission_no))=? OR LOWER(TRIM(COALESCE(s.register_no,'')))=?)",
                    (current_school_id(), student_id, username, username)).fetchone():
        conn.close()
        flash("That username matches another student's Admission/Register No. Choose a different one.", "error")
        return redirect(url_for("student_profile", student_id=student_id))
    try:
        conn.execute("BEGIN IMMEDIATE")
        if password:
            conn.execute(
                "UPDATE students SET username=?, password_hash=?, failed_logins=0, locked_until=NULL WHERE id=?",
                (username, generate_password_hash(password), student_id),
            )
        else:
            conn.execute("UPDATE students SET username=? WHERE id=?", (username, student_id))
        _pc.audit(conn, {"type": "staff", "id": session.get("user_id"), "name": session.get("name"), "role": _actor_role_label(),
                         "school_id": current_school_id(), "tenant_id": session.get("tenant_id")},
                  "student_login_set" if password else "student_username_set", "student", student_id,
                  {"username": [student["username"], username], "password_reset": bool(password)}, ip=request.remote_addr)
        conn.commit()
        flash("Student login saved. The student signs in with the username, Admission No. or Register No. and this password.", "success")
    except sqlite3.IntegrityError:
        conn.rollback()
        flash("That username is already taken by another student.", "error")
    except Exception:
        conn.rollback()
        app.logger.exception("set_student_login failed")
        flash("The login could not be saved. Please try again.", "error")
    conn.close()
    return redirect(url_for("student_profile", student_id=student_id))


@app.route("/students/<int:student_id>/remove_login", methods=["POST"])
@login_required()
def remove_student_login(student_id):
    conn = get_db()
    student = student_in_school(conn, student_id)
    if not student or not _can_manage_student(conn, student):
        conn.close()
        flash("You don't have access to manage this student's login.", "error")
        return redirect(url_for("dashboard"))
    conn.execute("UPDATE students SET username=NULL, password_hash=NULL, first_login_completed_at=NULL WHERE id=?", (student_id,))
    import profile_core as _pc
    _pc.audit(conn, {"type": "staff", "id": session.get("user_id"), "name": session.get("name"), "role": _actor_role_label(),
                     "school_id": current_school_id(), "tenant_id": session.get("tenant_id")}, "student_login_removed", "student", student_id, {"username": student["username"]}, ip=request.remote_addr)
    conn.commit()
    conn.close()
    flash("Student login removed.", "success")
    return redirect(url_for("student_profile", student_id=student_id))


@app.route("/admin/students/csv_template")
@login_required("admin", "sub_admin")
def students_csv_template():
    content = (
        "admission_no,first_name,last_name,other_names,gender,class_name,date_of_birth,religion,parent_name,parent_address,parent_email,parent_phone,parent_relationship\n"
        "010,Fatima,Bello,Amina,F,JSS1A,2012-05-14,Christian,Mr Bello,12 Ahmadu Bello Way,parent@example.com,08012345678,Father\n"
    )
    buf = io.BytesIO(content.encode("utf-8"))
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name="students_template.csv")


@app.route("/admin/students/bulk_upload", methods=["POST"])
@login_required("admin", "sub_admin")
def students_bulk_upload():
    file = request.files.get("csv_file")
    if not file or file.filename == "":
        flash("Please choose a CSV file to upload.", "error")
        return redirect(url_for("admin_students"))

    conn = get_db()
    school_id = current_school_id()
    classes_by_name = {
        row["name"].strip().lower(): row["id"]
        for row in conn.execute("SELECT * FROM classes WHERE school_id=?", (school_id,)).fetchall()
    }

    try:
        text = file.read().decode("utf-8-sig")
    except Exception:
        conn.close()
        flash("Could not read that file — please upload a plain CSV file.", "error")
        return redirect(url_for("admin_students"))

    reader = csv_module.DictReader(io.StringIO(text))
    required_cols = {"admission_no", "first_name", "last_name", "class_name"}
    if not required_cols.issubset(set(c.strip() for c in (reader.fieldnames or []))):
        conn.close()
        flash(f"CSV must at least have these columns: {', '.join(sorted(required_cols))}. Download the template for reference.", "error")
        return redirect(url_for("admin_students"))

    added, skipped = 0, []
    allowed, message, _state = plan_limit_check(conn, school_id, "students", 0)
    if not allowed:
        conn.close()
        flash(message, "error")
        return redirect(url_for("admin_students"))
    school = get_school(conn, school_id)
    tenant_id = school["tenant_id"] if school else current_tenant_id()
    plan = subscription_plan_for_school(conn, school)
    current_usage = school_plan_usage(conn, school_id)["students"]
    student_limit = plan["max_students"] if plan and "max_students" in plan.keys() else None
    for i, row in enumerate(reader, start=2):
        if student_limit is not None and current_usage + added >= student_limit:
            skipped.append(f"Row {i}: student plan limit reached ({student_limit})")
            continue
        adm = (row.get("admission_no") or "").strip()
        fn = (row.get("first_name") or "").strip()
        ln = (row.get("last_name") or "").strip()
        other_names = (row.get("other_names") or "").strip() or None
        gender = (row.get("gender") or "").strip().upper()[:1]
        class_name = (row.get("class_name") or "").strip().lower()
        dob = (row.get("date_of_birth") or "").strip() or None
        religion = (row.get("religion") or "").strip() or None
        parent_name = (row.get("parent_name") or "").strip() or None
        parent_address = (row.get("parent_address") or "").strip() or None
        parent_email = (row.get("parent_email") or "").strip() or None
        parent_phone = (row.get("parent_phone") or "").strip() or None
        parent_relationship = (row.get("parent_relationship") or "").strip() or None

        if not (adm and fn and ln and class_name):
            skipped.append(f"Row {i}: missing required field(s)")
            continue
        class_id = classes_by_name.get(class_name)
        if not class_id:
            skipped.append(f"Row {i}: class '{row.get('class_name')}' doesn't exist — create it first")
            continue
        try:
            cur = conn.execute(
                "INSERT INTO students (school_id, tenant_id, admission_no, first_name, last_name, other_names, gender, "
                "class_id, date_of_birth, religion, parent_name, parent_address, parent_email, parent_phone, parent_relationship) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (school_id, tenant_id, adm, fn, ln, other_names, gender if gender in ("M", "F") else None,
                 class_id, dob, religion, parent_name, parent_address, parent_email, parent_phone, parent_relationship),
            )
            upsert_enrollment(conn, cur.lastrowid, class_id)
            added += 1
        except Exception:
            skipped.append(f"Row {i}: Admission No./Register No. '{adm}' is already used by another student in class '{row.get('class_name')}'")

    conn.commit()
    conn.close()

    if added:
        flash(f"Imported {added} student(s) successfully.", "success")
    if skipped:
        preview = "; ".join(skipped[:8]) + (f" (+{len(skipped)-8} more)" if len(skipped) > 8 else "")
        flash(f"Skipped {len(skipped)} row(s): {preview}", "error")
    if not added and not skipped:
        flash("No rows found in that file.", "error")

    return redirect(url_for("admin_students"))


@app.route("/admin/teachers", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_teachers():
    conn = get_db()
    school_id = current_school_id()
    if not require_scoped_permission("manage_users"):
        conn.close()
        flash("You do not have permission to manage teachers.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        allowed, message, _state = plan_limit_check(conn, school_id, "teachers", 1)
        if not allowed:
            conn.close()
            flash(message, "error")
            return redirect(url_for("admin_teachers"))
        name = request.form["name"].strip()
        username = " ".join(request.form["username"].strip().split())  # keep the case the admin typed; uniqueness is checked case-insensitively
        email = request.form.get("email", "").strip() or None
        phone = request.form.get("phone", "").strip() or None
        password = request.form["password"]
        picked = [r for r in (request.form.getlist("rbac_roles") or [request.form.get("rbac_role", "Teacher")]) if r in assignable_roles()]
        rbac_role = picked[0] if picked else "Teacher"
        position={"Principal":"principal","Vice Principal":"vice_principal","Head Teacher":"principal","Class Teacher / Form Teacher":"form_teacher","Form Teacher":"form_teacher","Class Teacher":"form_teacher","Examination/Result Officer":"exam_officer","Examination Officer":"exam_officer","Vice Principal / Deputy Principal":"vice_principal"}.get(rbac_role)
        if email and conn.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?)", (email,)).fetchone():
            flash("That email is already in use by another account.", "error")
        elif phone and conn.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
            flash("That phone number is already in use by another account.", "error")
        elif conn.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)", (username,)).fetchone():
            flash("That username is already taken.", "error")
        else:
            try:
                tenant=conn.execute("SELECT tenant_id FROM schools WHERE id=?",(school_id,)).fetchone()["tenant_id"]
                cur=conn.execute("INSERT INTO users (school_id,tenant_id,name,username,email,phone,password_hash,role,position,rbac_role) VALUES (?,?,?,?,?,?,?,?,?,?)",(school_id,tenant,name,username,email,phone,generate_password_hash(password),"teacher",position,rbac_role))
                set_staff_roles(conn, cur.lastrowid, school_id, picked or ["Teacher"], session.get("user_id"), session.get("name"), reason="Roles chosen at account creation")
                conn.commit()
                flash(f"Teacher '{name}' added.", "success")
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                app.logger.warning("Teacher creation rejected by database constraint: %s", exc)
                flash("That username, email or phone number is already in use.", "error")
            except Exception:
                conn.rollback()
                app.logger.exception("Teacher creation failed")
                flash("The teacher account could not be saved. Please check the details and try again.", "error")
    teachers = conn.execute("SELECT * FROM users WHERE role='teacher' AND school_id=? ORDER BY name", (school_id,)).fetchall()
    staff_roles = {t["id"]: user_roles(conn, t["id"], school_id) for t in teachers}
    conn.close()
    return render_template("admin_teachers.html", teachers=teachers, rbac_roles=assignable_roles(), position_labels=POSITION_LABELS, staff_roles=staff_roles)


@app.route("/admin/teachers/<int:teacher_id>/contact", methods=["POST"])
@login_required("admin", "sub_admin")
def update_teacher_contact(teacher_id):
    if not require_scoped_permission("manage_users"):
        flash("You do not have permission to manage this teacher.", "error")
        return redirect(url_for("admin_teachers"))
    conn = get_db()
    if not teacher_in_school(conn, teacher_id):
        conn.close()
        flash("Teacher not found.", "error")
        return redirect(url_for("admin_teachers"))
    email = request.form.get("email", "").strip() or None
    phone = request.form.get("phone", "").strip() or None
    if email and conn.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?) AND id!=?", (email, teacher_id)).fetchone():
        conn.close()
        flash("That email is already in use by another account.", "error")
        return redirect(url_for("admin_teachers"))
    if phone and conn.execute("SELECT 1 FROM users WHERE phone=? AND id!=?", (phone, teacher_id)).fetchone():
        conn.close()
        flash("That phone number is already in use by another account.", "error")
        return redirect(url_for("admin_teachers"))
    conn.execute("UPDATE users SET email=?, phone=? WHERE id=?", (email, phone, teacher_id))
    conn.commit()
    conn.close()
    flash("Contact info updated.", "success")
    return redirect(url_for("admin_teachers"))


@app.route("/admin/teachers/<int:teacher_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_teacher(teacher_id):
    if not require_scoped_permission("manage_users"):
        flash("You do not have permission to manage this teacher.", "error")
        return redirect(url_for("admin_teachers"))
    conn = get_db()
    if not teacher_in_school(conn, teacher_id):
        conn.close()
        flash("Teacher not found.", "error")
        return redirect(url_for("admin_teachers"))
    conn.execute("UPDATE classes SET form_teacher_id=NULL WHERE form_teacher_id=?", (teacher_id,))
    conn.execute("UPDATE class_subjects SET teacher_id=NULL WHERE teacher_id=?", (teacher_id,))
    conn.execute("DELETE FROM users WHERE id=? AND role='teacher'", (teacher_id,))
    conn.commit()
    conn.close()
    flash("Teacher removed. Any classes/subjects they were assigned to are now unassigned.", "success")
    return redirect(url_for("admin_teachers"))


@app.route("/admin/teachers/<int:teacher_id>/set_position", methods=["POST"])
@login_required("admin", "sub_admin")
def set_teacher_position(teacher_id):
    if not require_scoped_permission("manage_users"):
        flash("You do not have permission to manage this teacher.", "error")
        return redirect(url_for("admin_teachers"))
    conn = get_db()
    if not teacher_in_school(conn, teacher_id):
        conn.close()
        flash("Teacher not found.", "error")
        return redirect(url_for("admin_teachers"))
    picked = request.form.getlist("rbac_roles") or ([request.form.get("rbac_role")] if request.form.get("rbac_role") else [])
    picked = [r for r in picked if r in assignable_roles()]
    if not picked:
        conn.close(); flash("Choose at least one valid role.", "error"); return redirect(url_for("admin_teachers"))
    set_staff_roles(conn, teacher_id, current_school_id(), picked, session.get("user_id"), session.get("name"),
                    reason="Roles set on staff list; active immediately")
    conn.commit(); conn.close(); flash("Roles saved and active immediately.","success")
    return redirect(url_for("admin_teachers"))


@app.route("/admin/teachers/<int:teacher_id>/toggle_active", methods=["POST"])
@login_required("admin", "sub_admin")
def toggle_teacher_active(teacher_id):
    if not require_scoped_permission("manage_users"):
        flash("You do not have permission to manage this teacher.", "error")
        return redirect(url_for("admin_teachers"))
    conn = get_db()
    teacher = teacher_in_school(conn, teacher_id)
    if not teacher:
        conn.close()
        flash("Teacher not found.", "error")
        return redirect(url_for("admin_teachers"))
    new_status = 0 if teacher["is_active"] else 1
    conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, teacher_id))
    conn.commit()
    conn.close()
    flash("Account deactivated. They can no longer sign in." if not new_status else "Account reactivated.", "success")
    return redirect(url_for("admin_teachers"))


@app.route("/admin/teachers/<int:teacher_id>/reset_password", methods=["POST"])
@login_required("admin", "sub_admin")
def admin_reset_teacher_password(teacher_id):
    if not require_scoped_permission("manage_users"):
        flash("You do not have permission to manage this teacher.", "error")
        return redirect(url_for("admin_teachers"))
    conn = get_db()
    teacher = teacher_in_school(conn, teacher_id)
    if not teacher:
        conn.close()
        flash("Teacher not found.", "error")
        return redirect(url_for("admin_teachers"))
    new_password = secrets.token_urlsafe(6)
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_password), teacher_id))
    conn.commit()
    conn.close()
    flash(
        f"Password reset for {teacher['name']} (username: {teacher['username']}). "
        f"New temporary password: {new_password} — share this with them securely; "
        f"they can change it themselves afterward from Change Password.",
        "success",
    )
    return redirect(url_for("admin_teachers"))


# ---------- sub-admin management (main admin only) ----------

@app.route("/admin/subadmins", methods=["GET", "POST"])
@login_required("admin")
def admin_subadmins():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST":
        name = request.form["name"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        try:
            conn.execute(
                "INSERT INTO users (school_id, name, username, password_hash, role) VALUES (?,?,?,?, 'sub_admin')",
                (school_id, name, username, generate_password_hash(password)),
            )
            conn.commit()
            flash(f"Sub-Admin '{name}' added.", "success")
        except Exception:
            flash("That username is already taken.", "error")
    subadmins = conn.execute(
        "SELECT * FROM users WHERE role='sub_admin' AND school_id=? ORDER BY name", (school_id,)
    ).fetchall()
    conn.close()
    return render_template("admin_subadmins.html", subadmins=subadmins)


@app.route("/admin/subadmins/<int:user_id>/delete", methods=["POST"])
@login_required("admin")
def delete_subadmin(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=? AND role='sub_admin' AND school_id=?", (user_id, current_school_id()))
    conn.commit()
    conn.close()
    flash("Sub-Admin removed.", "success")
    return redirect(url_for("admin_subadmins"))


@app.route("/admin/subadmins/<int:user_id>/reset_password", methods=["POST"])
@login_required("admin")
def reset_subadmin_password(user_id):
    conn = get_db()
    sub = conn.execute(
        "SELECT * FROM users WHERE id=? AND role='sub_admin' AND school_id=?", (user_id, current_school_id())
    ).fetchone()
    if not sub:
        conn.close()
        flash("Sub-Admin not found.", "error")
        return redirect(url_for("admin_subadmins"))
    new_password = secrets.token_urlsafe(6)
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_password), user_id))
    conn.commit()
    conn.close()
    flash(
        f"Password reset for {sub['name']} (username: {sub['username']}). "
        f"New temporary password: {new_password} — share this with them securely.",
        "success",
    )
    return redirect(url_for("admin_subadmins"))


@app.route("/admin/grading", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_grading():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST":
        ca1 = float(request.form["ca1_max"])
        ca2 = float(request.form["ca2_max"])
        ca3 = float(request.form.get("ca3_max") or 0)   # 0 = CA3 not used
        exam = float(request.form["exam_max"])
        problems = grading_problems(conn, school_id, ca1, ca2, ca3, exam)
        if problems:
            flash(" ".join(problems), "error")
        else:
            conn.execute("UPDATE grading_config SET ca1_max=?, ca2_max=?, ca3_max=?, exam_max=? WHERE school_id=?",
                         (ca1, ca2, ca3, exam, school_id))
            conn.commit()
            if abs(ca1 + ca2 + ca3 + exam - 100) > 0.001:
                flash(f"Grading weights updated — note the maximums add up to {ca1 + ca2 + ca3 + exam:g}, not 100.", "success")
            else:
                flash("Grading weights updated.", "success")
    config = get_grading_config(conn)
    scale = conn.execute("SELECT * FROM grade_scale WHERE school_id=? ORDER BY min_score DESC", (school_id,)).fetchall()
    conn.close()
    return render_template("admin_grading.html", config=config, scale=scale)


@app.route("/admin/grading/scale/add", methods=["POST"])
@login_required("admin", "sub_admin")
def add_grade_scale():
    conn = get_db()
    try:
        lo, hi = float(request.form["min_score"]), float(request.form["max_score"])
        problems = grade_band_problems(conn, current_school_id(), request.form["grade"], lo, hi)
        if problems:
            flash(" ".join(problems), "error")
            conn.close()
            return redirect(url_for("admin_grading"))
        conn.execute(
            "INSERT INTO grade_scale (school_id, grade, min_score, max_score, remark) VALUES (?,?,?,?,?)",
            (current_school_id(), request.form["grade"].strip(), lo, hi, request.form.get("remark", "").strip()),
        )
        conn.commit()
        flash("Grade band added.", "success")
    except Exception:
        flash("Couldn't add that grade band — check the values entered.", "error")
    conn.close()
    return redirect(url_for("admin_grading"))


@app.route("/admin/grading/scale/<int:scale_id>/edit", methods=["POST"])
@login_required("admin", "sub_admin")
def edit_grade_scale(scale_id):
    conn = get_db()
    try:
        lo, hi = float(request.form["min_score"]), float(request.form["max_score"])
        problems = grade_band_problems(conn, current_school_id(), request.form["grade"], lo, hi, exclude_id=scale_id)
        if problems:
            flash(" ".join(problems), "error")
            conn.close()
            return redirect(url_for("admin_grading"))
        conn.execute(
            "UPDATE grade_scale SET grade=?, min_score=?, max_score=?, remark=? WHERE id=? AND school_id=?",
            (request.form["grade"].strip(), lo, hi, request.form.get("remark", "").strip(), scale_id, current_school_id()),
        )
        conn.commit()
        flash("Grade band updated.", "success")
    except Exception:
        flash("Couldn't update that grade band — check the values entered.", "error")
    conn.close()
    return redirect(url_for("admin_grading"))


@app.route("/admin/grading/scale/<int:scale_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_grade_scale(scale_id):
    conn = get_db()
    conn.execute("DELETE FROM grade_scale WHERE id=? AND school_id=?", (scale_id, current_school_id()))
    conn.commit()
    conn.close()
    flash("Grade band deleted.", "success")
    return redirect(url_for("admin_grading"))


@app.route("/admin/terms", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_terms():
    conn = get_db()
    school_id = current_school_id()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "new_session":
            name = request.form["session_name"].strip()
            try:
                conn.execute("INSERT INTO sessions (school_id, name, is_active, tenant_id) VALUES (?,?, 0, ?)", (school_id, name, session.get("tenant_id")))
                import profile_core as _pc
                _pc.audit(conn, {"type": "staff", "id": session.get("user_id"), "name": session.get("name"), "role": _actor_role_label(), "school_id": school_id, "tenant_id": session.get("tenant_id")}, "session_created", "session", name, {"name": name})
                conn.commit()
                flash("Session created.", "success")
            except Exception:
                flash("That session name already exists.", "error")
        elif action == "new_term":
            name = request.form["term_name"]
            session_id = request.form["session_id"]
            owner = conn.execute("SELECT * FROM sessions WHERE id=? AND school_id=?", (session_id, school_id)).fetchone()
            if owner:
                conn.execute("INSERT INTO terms (name, session_id, is_active) VALUES (?,?,0)", (name, session_id))
                import profile_core as _pc
                _pc.audit(conn, {"type": "staff", "id": session.get("user_id"), "name": session.get("name"), "role": _actor_role_label(), "school_id": school_id, "tenant_id": session.get("tenant_id")}, "term_created", "term", name, {"name": name, "session_id": session_id})
                conn.commit()
                flash("Term created.", "success")
        elif action in ("edit_term", "edit_session"):
            try:
                import profile_core as _pc
                _actor = {"type": "staff", "id": session.get("user_id"), "name": session.get("name"), "role": _actor_role_label(), "school_id": school_id, "tenant_id": session.get("tenant_id")}
                def _date(v, label):
                    v = (v or "").strip()
                    if not v:
                        return None
                    d = _pc.parse_date(v)
                    if not d:
                        raise ValueError(f"{label} is not a valid date.")
                    return d.isoformat()
                if action == "edit_term":
                    tid_ = request.form.get("term_id", type=int)
                    row = conn.execute("SELECT t.* FROM terms t JOIN sessions s ON s.id=t.session_id WHERE t.id=? AND s.school_id=?", (tid_, school_id)).fetchone()
                    if not row:
                        raise ValueError("Term not found.")
                    name = _pc.clean(request.form.get("name"))
                    if not 2 <= len(name) <= 40:
                        raise ValueError("Term name must be 2-40 characters.")
                    if conn.execute("SELECT 1 FROM terms WHERE session_id=? AND LOWER(name)=LOWER(?) AND id<>?", (row["session_id"], name, row["id"])).fetchone():
                        raise ValueError("That session already has a term with this name.")
                    sd, ed, nb = _date(request.form.get("start_date"), "Start date"), _date(request.form.get("end_date"), "End date"), _date(request.form.get("next_term_begins"), "Next term begins")
                    if sd and ed and ed < sd:
                        raise ValueError("The end date cannot be before the start date.")
                    conn.execute("UPDATE terms SET name=?, start_date=?, end_date=?, next_term_begins=? WHERE id=?", (name, sd, ed, nb, row["id"]))
                    _pc.audit(conn, _actor, "term_edited", "term", row["id"], _pc.diff(row, {"name": name, "start_date": sd, "end_date": ed, "next_term_begins": nb}, ["name", "start_date", "end_date", "next_term_begins"]))
                    flash("Term updated.", "success")
                else:
                    sid_ = request.form.get("session_id", type=int)
                    row = conn.execute("SELECT * FROM sessions WHERE id=? AND school_id=?", (sid_, school_id)).fetchone()
                    if not row:
                        raise ValueError("Session not found.")
                    name = _pc.clean(request.form.get("name"))
                    if not 4 <= len(name) <= 20:
                        raise ValueError("Session name must be 4-20 characters, for example 2026/2027.")
                    if conn.execute("SELECT 1 FROM sessions WHERE school_id=? AND LOWER(name)=LOWER(?) AND id<>?", (school_id, name, row["id"])).fetchone():
                        raise ValueError("A session with that name already exists.")
                    sd, ed = _date(request.form.get("start_date"), "Start date"), _date(request.form.get("end_date"), "End date")
                    if sd and ed and ed < sd:
                        raise ValueError("The end date cannot be before the start date.")
                    conn.execute("UPDATE sessions SET name=?, start_date=?, end_date=? WHERE id=?", (name, sd, ed, row["id"]))
                    _pc.audit(conn, _actor, "session_edited", "session", row["id"], _pc.diff(row, {"name": name, "start_date": sd, "end_date": ed}, ["name", "start_date", "end_date"]))
                    flash("Session updated.", "success")
                conn.commit()
            except ValueError as exc:
                conn.rollback()
                flash(str(exc), "error")
            except sqlite3.IntegrityError:
                conn.rollback()
                flash("That name is already in use.", "error")
        elif action == "activate_session":
            sid = request.form["session_id"]
            owner = conn.execute("SELECT * FROM sessions WHERE id=? AND school_id=?", (sid, school_id)).fetchone()
            if owner:
                conn.execute("UPDATE sessions SET is_active=0 WHERE school_id=?", (school_id,))
                conn.execute("UPDATE sessions SET is_active=1 WHERE id=?", (sid,))
                conn.commit()
                flash("Active session updated.", "success")
        elif action == "activate_term":
            tid = request.form["term_id"]
            owner = conn.execute(
                "SELECT terms.* FROM terms JOIN sessions ON sessions.id=terms.session_id "
                "WHERE terms.id=? AND sessions.school_id=?", (tid, school_id)
            ).fetchone()
            if owner:
                conn.execute(
                    "UPDATE terms SET is_active=0 WHERE session_id IN (SELECT id FROM sessions WHERE school_id=?)",
                    (school_id,),
                )
                conn.execute("UPDATE terms SET is_active=1 WHERE id=?", (tid,))
                conn.commit()
                flash("Active term updated.", "success")
        elif action == "publish_term":
            readiness = conn.execute("SELECT readiness_status FROM schools WHERE id=?", (school_id,)).fetchone()
            if not readiness or readiness["readiness_status"] != "ready":
                conn.close()
                flash("This school is not READY FOR LIVE DATA. Complete the Setup Wizard and have the School Admin mark it ready before publishing results.", "error")
                return redirect(url_for("admin_setup_wizard"))
            tid = request.form["term_id"]
            owner = conn.execute(
                "SELECT terms.* FROM terms JOIN sessions ON sessions.id=terms.session_id "
                "WHERE terms.id=? AND sessions.school_id=?", (tid, school_id)
            ).fetchone()
            if owner:
                already_published = bool(owner["is_published"])
                conn.execute("UPDATE terms SET is_published=1 WHERE id=?", (tid,))
                try:
                    pc_audit_actor = {"type": "staff", "id": session.get("user_id"), "name": session.get("name"), "role": _actor_role_label(), "school_id": school_id, "tenant_id": session.get("tenant_id")}
                    import profile_core as _pc
                    _pc.audit(conn, pc_audit_actor, "results_published" if not already_published else "results_republished", "term", tid,
                              {"term": owner["name"]}, ip=request.remote_addr)
                    # Automatic next term / session: runs once, only when this term was not already published.
                    if not already_published:
                        auto_msg = AUTO_ADVANCE(conn, int(tid))
                        if auto_msg:
                            flash(auto_msg, "success")
                except Exception:
                    app.logger.exception("Automatic next term/session creation failed")
                conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",(session.get("name","Administrator"),school_id,"admin","Result publication","A term's results were published and are now available to authorized users."))
                conn.commit()
                flash("Term published — results can now be emailed to parents.", "success")
        elif action == "unpublish_term":
            tid = request.form["term_id"]
            owner = conn.execute(
                "SELECT terms.* FROM terms JOIN sessions ON sessions.id=terms.session_id "
                "WHERE terms.id=? AND sessions.school_id=?", (tid, school_id)
            ).fetchone()
            if owner:
                conn.execute("UPDATE terms SET is_published=0 WHERE id=?", (tid,))
                conn.commit()
                flash("Term unpublished — emailing results is now paused for this term.", "success")
        elif action == "toggle_cumulative":
            enabled = 1 if request.form.get("cumulative_enabled") else 0
            conn.execute("UPDATE schools SET cumulative_enabled=? WHERE id=?", (enabled, school_id))
            conn.commit()
            flash(
                "Cumulative/Annual results are now " + ("enabled." if enabled else "disabled — terms operate independently again."),
                "success",
            )
    sessions_ = conn.execute("SELECT * FROM sessions WHERE school_id=? ORDER BY id DESC", (school_id,)).fetchall()
    terms = conn.execute(
        "SELECT terms.*, sessions.name as session_name FROM terms "
        "JOIN sessions ON sessions.id=terms.session_id WHERE sessions.school_id=? ORDER BY terms.id DESC", (school_id,)
    ).fetchall()
    school = get_school(conn, school_id)
    conn.close()
    return render_template("admin_terms.html", sessions=sessions_, terms=terms, school=school)


@app.route("/admin/reset_demo_data", methods=["POST"])
@login_required("admin", "sub_admin")
def reset_demo_data():
    if request.form.get("confirm_text", "").strip().upper() != "RESET":
        flash('You must type RESET exactly to confirm clearing demo data.', "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    school_id = current_school_id()
    class_ids = [r["id"] for r in conn.execute("SELECT id FROM classes WHERE school_id=?", (school_id,)).fetchall()]
    if class_ids:
        placeholders = ",".join("?" * len(class_ids))
        student_ids = [r["id"] for r in conn.execute(
            f"SELECT id FROM students WHERE class_id IN ({placeholders})", class_ids
        ).fetchall()]
        if student_ids:
            sp = ",".join("?" * len(student_ids))
            conn.execute(f"DELETE FROM student_skill_ratings WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM student_term_info WHERE student_id IN ({sp})", student_ids)
            audit_scores_deleted(conn, list(student_ids))
            conn.execute(f"DELETE FROM score_history WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM scores WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM enrollments WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM students WHERE id IN ({sp})", student_ids)
        conn.execute(f"DELETE FROM class_subjects WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM timetable_entries WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM timetable_entries_v2 WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM classes WHERE id IN ({placeholders})", class_ids)
    conn.execute("DELETE FROM subjects WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM users WHERE role='teacher' AND school_id=?", (school_id,))
    log_audit(conn, session["role"], session.get("name"), "clear_demo_data",
              details="Cleared demo/sample classes, subjects, students, and teachers", school_id=school_id)
    conn.commit()
    conn.close()
    flash("Demo data cleared. Sessions/terms, your admin login, the grading setup, and skill traits were kept. Start adding your real classes, subjects, teachers and students.", "success")
    return redirect(url_for("dashboard"))


# ---------- student promotion ----------

@app.route("/admin/promote", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def admin_promote():
    conn = get_db()
    school_id = current_school_id()
    classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (school_id,)).fetchall()

    from_class_id = request.values.get("from_class_id", type=int)
    students = []
    if from_class_id and class_in_school(conn, from_class_id):
        students = conn.execute(
            "SELECT * FROM students WHERE class_id=? AND is_active=1 ORDER BY admission_no, last_name",
            (from_class_id,),
        ).fetchall()

    if request.method == "POST":
        to_class_name = request.form.get("to_class_name", "").strip()
        to_class_id = request.form.get("to_class_id") or None
        student_ids = request.form.getlist("student_ids")

        if not class_in_school(conn, from_class_id):
            flash("Source class not found.", "error")
            return redirect(url_for("admin_promote"))

        if to_class_name:
            existing = conn.execute(
                "SELECT id FROM classes WHERE school_id=? AND name=?", (school_id, to_class_name)
            ).fetchone()
            if existing:
                to_class_id = existing["id"]
            else:
                cur = conn.execute("INSERT INTO classes (school_id, name) VALUES (?,?)", (school_id, to_class_name))
                to_class_id = cur.lastrowid
                conn.commit()
        elif to_class_id and not class_in_school(conn, to_class_id):
            flash("Destination class not found.", "error")
            return redirect(url_for("admin_promote", from_class_id=from_class_id))

        if not to_class_id:
            flash("Please choose or name a destination class.", "error")
            return redirect(url_for("admin_promote", from_class_id=from_class_id))
        if int(to_class_id) == from_class_id:
            flash("Destination class must be different from the source class.", "error")
            return redirect(url_for("admin_promote", from_class_id=from_class_id))
        if not student_ids:
            flash("Select at least one student to promote.", "error")
            return redirect(url_for("admin_promote", from_class_id=from_class_id))

        existing_admissions = {
            r["admission_no"]
            for r in conn.execute("SELECT admission_no FROM students WHERE class_id=?", (to_class_id,)).fetchall()
        }
        promoted, conflicts = 0, []
        for sid in student_ids:
            st = conn.execute("SELECT * FROM students WHERE id=? AND class_id=?", (sid, from_class_id)).fetchone()
            if not st:
                continue
            if st["admission_no"] in existing_admissions:
                conflicts.append(f"{student_full_name(st)} (Admission No./Register No. '{st['admission_no']}' already used in destination class)")
                continue
            conn.execute("UPDATE students SET class_id=? WHERE id=?", (to_class_id, sid))
            upsert_enrollment(conn, sid, to_class_id)
            existing_admissions.add(st["admission_no"])
            promoted += 1
        conn.commit()
        conn.close()

        if promoted:
            flash(f"Promoted {promoted} student(s) to their new class.", "success")
        if conflicts:
            preview = "; ".join(conflicts[:8]) + (f" (+{len(conflicts)-8} more)" if len(conflicts) > 8 else "")
            flash(f"Skipped {len(conflicts)} student(s) due to Admission No./Register No. conflicts in the destination class — resolve manually: {preview}", "error")
        return redirect(url_for("admin_promote"))

    conn.close()
    return render_template(
        "admin_promote.html", classes=classes, from_class_id=from_class_id, students=students,
        student_full_name=student_full_name,
    )


# ---------- automated timetable v2 ----------

DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
TIMETABLE_EDIT_ROLES = {"admin", "sub_admin", "Timetable Manager"}
TIMETABLE_APPROVER_ROLES = {"admin", "sub_admin", "Principal / Head of School", "HOD / Timetable Reviewer"}


def _tt_school(conn):
    sid = current_school_id()
    return conn.execute("SELECT * FROM schools WHERE id=?", (sid,)).fetchone()


def _tt_tenant(conn):
    school = _tt_school(conn)
    return (school["tenant_id"] if school and "tenant_id" in school.keys() else None) or str(current_school_id())


def _tt_role(conn):
    if session.get("role") == "admin":
        return "School Admin"
    if session.get("role") == "sub_admin":
        return "Sub-Admin"
    row = conn.execute("SELECT rbac_role,position FROM users WHERE id=? AND school_id=?", (session.get("user_id"), current_school_id())).fetchone()
    return ((row["rbac_role"] if row and row["rbac_role"] else None) or (row["position"] if row and row["position"] else None) or "Subject Teacher")


def _tt_can_manage(conn):
    return session.get("role") in ("admin", "sub_admin") or _tt_role(conn) in TIMETABLE_EDIT_ROLES


def _tt_can_approve(conn):
    return session.get("role") in ("admin", "sub_admin") or _tt_role(conn) in TIMETABLE_APPROVER_ROLES


def _tt_can_publish(conn):
    return session.get("role") in ("admin", "sub_admin") or _tt_role(conn) in {"Authorized Publisher", "Principal / Head of School"}


def _tt_scope_entry(conn, entry_id):
    return conn.execute("SELECT * FROM timetable_entries_v2 WHERE id=? AND school_id=? AND tenant_id=?", (entry_id, current_school_id(), _tt_tenant(conn))).fetchone()


def _tt_version(conn, version_id):
    return conn.execute("SELECT * FROM timetable_versions_v2 WHERE id=? AND school_id=? AND tenant_id=?", (version_id, current_school_id(), _tt_tenant(conn))).fetchone()


def _tt_slots(conn, template_id=None):
    sid=current_school_id(); tid=_tt_tenant(conn)
    q="SELECT ss.*,sd.day_name,sd.day_code,sd.day_order FROM schedule_slots ss JOIN school_days_v2 sd ON sd.id=ss.day_id WHERE ss.school_id=? AND ss.tenant_id=? AND ss.is_active=1"
    params=[sid,tid]
    if template_id:
        q += " AND ss.schedule_template_id=?"; params.append(template_id)
    return conn.execute(q+" ORDER BY sd.day_order,ss.slot_number,ss.id",params).fetchall()


def _tt_validate(conn, version_id):
    version=_tt_version(conn,version_id)
    if not version: return [], []
    sid=current_school_id(); tid=_tt_tenant(conn)
    conn.execute("DELETE FROM timetable_conflicts_v2 WHERE timetable_version_id=? AND school_id=?",(version_id,sid))
    entries=conn.execute("""SELECT te.*,ss.slot_type,ss.start_time,ss.end_time,ss.slot_number,ss.allows_timetable_entry,
        c.name class_name,s.name subject_name,u.name teacher_name,r.room_name
        FROM timetable_entries_v2 te JOIN schedule_slots ss ON ss.id=te.slot_id
        JOIN classes c ON c.id=te.class_id JOIN subjects s ON s.id=te.subject_id
        LEFT JOIN users u ON u.id=te.teacher_id LEFT JOIN timetable_rooms_v2 r ON r.id=te.room_id
        WHERE te.timetable_version_id=? AND te.school_id=? AND te.tenant_id=?""",(version_id,sid,tid)).fetchall()
    errors=[]; warnings=[]
    def add(kind,severity,entity,desc,action):
        msg=f"{severity} — {entity} — {desc} — {action}"
        (errors if severity=="ERROR" else warnings).append(msg)
        conn.execute("INSERT INTO timetable_conflicts_v2(tenant_id,school_id,timetable_version_id,conflict_type,severity,entity_type,entity_id,description,suggested_action,resolved) VALUES(?,?,?,?,?,?,?,?,?,0)",(tid,sid,version_id,kind,severity,entity,entity.get("id") if isinstance(entity,dict) else None,desc,action))
    # Hard conflicts by resource/slot.
    for key,label in [("teacher_id","Teacher"),("class_id","Class"),("room_id","Room")]:
        seen={}
        for e in entries:
            if not e[key]: continue
            k=(e[key],e["slot_id"])
            if k in seen:
                add("DOUBLE_BOOKING","ERROR",{"id":e["id"]},f"{label} {e[key]} is double-booked in {e['day_name']} {e['slot_number']}",f"Move one {label.lower()} assignment to another teaching slot")
            else: seen[k]=e["id"]
    for e in entries:
        if e["slot_type"]!="TEACHING" or not e["allows_timetable_entry"]:
            add("SLOT","ERROR",{"id":e["id"]},f"{e['day_name']} slot {e['slot_number']} is not a teaching slot", "Move the lesson to a TEACHING slot")
        if e["teacher_id"]:
            av=conn.execute("SELECT availability_status,is_hard_constraint FROM teacher_availability_v2 WHERE teacher_id=? AND day_id=? AND slot_id=? AND school_id=? AND tenant_id=? ORDER BY id DESC LIMIT 1",(e["teacher_id"],e["day_id"],e["slot_id"],sid,tid)).fetchone()
            if av and av["availability_status"]=="Unavailable" and av["is_hard_constraint"]:
                add("AVAILABILITY","ERROR",{"id":e["id"]},f"{e['teacher_name']} is unavailable in {e['day_name']} P{e['slot_number']}","Choose an available slot")
            eligible=conn.execute("SELECT 1 FROM class_subjects WHERE class_id=? AND subject_id=? AND teacher_id=?",(e["class_id"],e["subject_id"],e["teacher_id"])).fetchone()
            if not eligible:
                add("TEACHER_ASSIGNMENT","ERROR",{"id":e["id"]},f"{e['teacher_name']} is not assigned to {e['subject_name']} for {e['class_name']}","Assign the teacher to the subject/class first")
        if e["room_id"]:
            room=conn.execute("SELECT capacity,status FROM timetable_rooms_v2 WHERE id=? AND school_id=? AND tenant_id=?",(e["room_id"],sid,tid)).fetchone()
            if not room or room["status"]!="active":
                add("ROOM","ERROR",{"id":e["id"]},"Selected room is inactive or outside the school", "Select an active school room")
    # Weekly requirements.
    reqs=conn.execute("SELECT * FROM class_subject_requirements_v2 WHERE school_id=? AND tenant_id=? AND status='active'",(sid,tid)).fetchall()
    for r in reqs:
        count=sum(1 for e in entries if e["class_id"]==r["class_id"] and e["subject_id"]==r["subject_id"])
        if count<r["periods_per_week"]:
            add("REQUIREMENT","ERROR",{"id":r["id"]},f"{r['class_id']} subject {r['subject_id']} has {count}/{r['periods_per_week']} required periods","Add the missing periods")
        if r["periods_per_day_limit"]:
            for day in range(1,7):
                c=sum(1 for e in entries if e["class_id"]==r["class_id"] and e["subject_id"]==r["subject_id"] and e["day_id"]==day)
                if c>r["periods_per_day_limit"]:
                    add("DAILY_LIMIT","ERROR",{"id":r["id"]},f"Subject exceeds daily limit for class {r['class_id']}","Move one occurrence to another day")
        if r["requires_double_period"] or r["requires_triple_period"]:
            needed=3 if r["requires_triple_period"] else 2; found=False
            for day in range(1,7):
                es=sorted([e for e in entries if e["class_id"]==r["class_id"] and e["subject_id"]==r["subject_id"] and e["day_id"]==day], key=lambda x:x["slot_number"])
                run=1; prev=None
                for e in es:
                    if prev is not None and e["slot_number"]==prev+1: run+=1
                    else: run=1
                    prev=e["slot_number"]
                    if run>=needed: found=True; break
                if found: break
            if not found:
                add("BLOCK","ERROR",{"id":r["id"]},f"Required {'triple' if needed==3 else 'double'} period for subject {r['subject_id']} is not consecutive","Place the required periods in consecutive TEACHING slots")
    conn.execute("UPDATE timetable_versions_v2 SET validation_status=?,status=CASE WHEN ?=1 AND status IN ('DRAFT','SAVED','VALIDATED') THEN 'VALIDATED' ELSE status END,updated_at=CURRENT_TIMESTAMP WHERE id=?",("PASSED" if not errors else "FAILED",0 if errors else 1,version_id))
    conn.commit()
    return errors,warnings


def _tt_generate_greedy(conn, version_id):
    """Constraint-aware generator. OR-Tools is used when installed; the deterministic
    fallback keeps the online module functional in minimal deployments."""
    sid=current_school_id(); tid=_tt_tenant(conn)
    reqs=conn.execute("SELECT * FROM class_subject_requirements_v2 WHERE school_id=? AND tenant_id=? AND status='active' ORDER BY priority DESC,id",(sid,tid)).fetchall()
    slots=[x for x in _tt_slots(conn) if x["slot_type"]=="TEACHING" and x["allows_timetable_entry"]]
    teachers=conn.execute("SELECT * FROM teacher_workload_profiles_v2 WHERE school_id=? AND tenant_id=? AND status='active'",(sid,tid)).fetchall()
    teacher_limits={r["teacher_id"]:(r["max_periods_per_day"],r["max_periods_per_week"]) for r in teachers}
    rooms=conn.execute("SELECT * FROM timetable_rooms_v2 WHERE school_id=? AND tenant_id=? AND status='active' ORDER BY id",(sid,tid)).fetchall()
    conn.execute("DELETE FROM timetable_entries_v2 WHERE timetable_version_id=?",(version_id,))
    teacher_used=set(); class_used=set(); room_used=set(); teacher_week={}; teacher_day={}; class_subject_day={}; created=0
    for req in reqs:
        assignments=conn.execute("SELECT teacher_id FROM class_subjects WHERE class_id=? AND subject_id=? AND teacher_id IS NOT NULL",(req["class_id"],req["subject_id"])).fetchall()
        teachers_for=[a["teacher_id"] for a in assignments]
        for n in range(req["periods_per_week"]):
            placed=False
            for sl in slots:
                day=sl["day_id"]; sk=(req["class_id"],sl["id"])
                if sk in class_used: continue
                for teacher_id in teachers_for or [None]:
                    if teacher_id and (teacher_id,sl["id"]) in teacher_used: continue
                    if teacher_id:
                        av=conn.execute("SELECT availability_status,is_hard_constraint FROM teacher_availability_v2 WHERE teacher_id=? AND day_id=? AND slot_id=? AND school_id=? AND tenant_id=? ORDER BY id DESC LIMIT 1",(teacher_id,day,sl["id"],sid,tid)).fetchone()
                        if av and av["availability_status"]=="Unavailable" and av["is_hard_constraint"]: continue
                        lim=teacher_limits.get(teacher_id,(99,9999));
                        if teacher_day.get((teacher_id,day),0)>=lim[0] or teacher_week.get(teacher_id,0)>=lim[1]: continue
                    if class_subject_day.get((req["class_id"],req["subject_id"],day),0)>=req["periods_per_day_limit"]: continue
                    room_id=None
                    special_required=bool(conn.execute("SELECT 1 FROM subject_room_requirements_v2 WHERE subject_id=? AND requirement_type='Required' AND school_id=? AND tenant_id=? LIMIT 1",(req["subject_id"],sid,tid)).fetchone())
                    if special_required:
                        compatible=conn.execute("SELECT room_id FROM subject_room_requirements_v2 WHERE subject_id=? AND requirement_type='Required' AND school_id=? AND tenant_id=?",(req["subject_id"],sid,tid)).fetchall()
                        for rr in compatible:
                            if (rr["room_id"],sl["id"]) not in room_used: room_id=rr["room_id"]; break
                        if not room_id: continue
                    else:
                        for r in rooms:
                            if (r["id"],sl["id"]) not in room_used and (not r["capacity"] or not req["arm_id"] or r["capacity"]>=0): room_id=r["id"]; break
                    conn.execute("INSERT INTO timetable_entries_v2(tenant_id,school_id,timetable_version_id,day_id,slot_id,class_id,arm_id,subject_id,teacher_id,room_id,entry_type,is_fixed) VALUES(?,?,?,?,?,?,?,?,?,?,?,0)",(tid,sid,version_id,day,sl["id"],req["class_id"],req["arm_id"],req["subject_id"],teacher_id,room_id,"LESSON"))
                    class_used.add(sk); class_subject_day[(req["class_id"],req["subject_id"],day)]=class_subject_day.get((req["class_id"],req["subject_id"],day),0)+1; created+=1
                    if teacher_id: teacher_used.add((teacher_id,sl["id"])); teacher_week[teacher_id]=teacher_week.get(teacher_id,0)+1; teacher_day[(teacher_id,day)]=teacher_day.get((teacher_id,day),0)+1
                    if room_id: room_used.add((room_id,sl["id"]))
                    placed=True; break
                if placed: break
            if not placed: break
    conn.commit()
    return created


@app.route("/timetable")
@login_required()
def timetable_hub():
    conn=get_db(); sid=current_school_id(); tid=_tt_tenant(conn)
    versions=conn.execute("SELECT * FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=? ORDER BY id DESC LIMIT 20",(sid,tid)).fetchall()
    classes=conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY level,name,arm",(sid,)).fetchall()
    teachers=conn.execute("SELECT id,name,rbac_role,position FROM users WHERE school_id=? AND role='teacher' AND COALESCE(is_active,1)=1 ORDER BY name",(sid,)).fetchall()
    latest=versions[0] if versions else None
    counts={"scheduled":0,"unassigned":0,"conflicts":0}
    if latest:
        counts["scheduled"]=conn.execute("SELECT COUNT(*) n FROM timetable_entries_v2 WHERE timetable_version_id=?",(latest["id"],)).fetchone()["n"]
        counts["conflicts"]=conn.execute("SELECT COUNT(*) n FROM timetable_conflicts_v2 WHERE timetable_version_id=? AND severity='ERROR' AND resolved=0",(latest["id"],)).fetchone()["n"]
    can_edit=_tt_can_manage(conn)
    conn.close()
    return render_template("timetable_hub.html",classes=classes,teachers=teachers,versions=versions,latest=latest,counts=counts,can_edit=can_edit)


@app.route("/timetable/setup", methods=["GET","POST"])
@login_required()
def timetable_setup():
    if not _tt_can_manage(get_db()):
        flash("You are not authorized to manage timetable setup.", "error"); return redirect(url_for("timetable_hub"))
    conn=get_db(); sid=current_school_id(); tid=_tt_tenant(conn)
    ensure_school_v61_defaults(conn, sid)   # schools created before the timetable existed had no days, leaving the Day list empty
    if request.method=="POST":
        action=request.form.get("action")
        try:
            if action in ("slot","edit_slot"):
                if not conn.execute("SELECT 1 FROM school_days_v2 WHERE id=? AND school_id=? AND tenant_id=? AND is_active=1",(request.form.get("day_id",type=int),sid,tid)).fetchone():
                    raise ValueError("Select a valid school day.")
            if action=="toggle_day":
                d=conn.execute("SELECT * FROM school_days_v2 WHERE id=? AND school_id=? AND tenant_id=?",(request.form.get("day_id",type=int),sid,tid)).fetchone()
                if not d: raise ValueError("Day not found.")
                if d["is_active"] and conn.execute("SELECT 1 FROM schedule_slots WHERE day_id=? AND school_id=? AND is_active=1 LIMIT 1",(d["id"],sid)).fetchone():
                    raise ValueError(f"{d['day_name']} still has schedule slots. Remove them before switching the day off.")
                conn.execute("UPDATE school_days_v2 SET is_active=? WHERE id=?",(0 if d["is_active"] else 1,d["id"]))
            elif action=="edit_slot":
                slot_id=request.form.get("slot_id",type=int); day_id=int(request.form["day_id"]); name=request.form["slot_name"].strip(); st=request.form["start_time"]; et=request.form["end_time"]; typ=request.form.get("slot_type","TEACHING")
                if typ not in ("TEACHING","BREAK","ASSEMBLY","ACTIVITY","OTHER"): raise ValueError("Choose a valid slot type.")
                cur_slot=conn.execute("SELECT * FROM schedule_slots WHERE id=? AND school_id=? AND tenant_id=?",(slot_id,sid,tid)).fetchone()
                if not cur_slot: raise ValueError("Slot not found.")
                if not name: raise ValueError("Slot name is required.")
                if st>=et: raise ValueError("Start time must be earlier than end time.")
                if conn.execute("SELECT 1 FROM schedule_slots WHERE school_id=? AND tenant_id=? AND day_id=? AND is_active=1 AND id<>? AND start_time<? AND end_time>?",(sid,tid,day_id,slot_id,et,st)).fetchone():
                    raise ValueError("Schedule slots on the same day cannot overlap.")
                if typ!="TEACHING" and conn.execute("SELECT 1 FROM timetable_entries_v2 WHERE slot_id=? AND school_id=? LIMIT 1",(slot_id,sid)).fetchone():
                    raise ValueError("Lessons are already scheduled in this slot, so it cannot become a break or non-teaching slot.")
                sh,sm=map(int,st.split(":")); eh,em=map(int,et.split(":"))
                conn.execute("UPDATE schedule_slots SET day_id=?,slot_name=?,slot_type=?,start_time=?,end_time=?,duration_minutes=?,allows_timetable_entry=? WHERE id=? AND school_id=? AND tenant_id=?",
                             (day_id,name,typ,st,et,(eh*60+em)-(sh*60+sm),1 if typ=="TEACHING" else 0,slot_id,sid,tid))
            elif action=="slot":
                day_id=int(request.form["day_id"]); name=request.form["slot_name"].strip(); st=request.form["start_time"]; et=request.form["end_time"]; typ=request.form.get("slot_type","TEACHING")
                session_id=request.form.get("academic_session_id",type=int); term_id=request.form.get("term_id",type=int)
                if session_id and not conn.execute("SELECT 1 FROM sessions WHERE id=? AND school_id=?",(session_id,sid)).fetchone(): raise ValueError("Select a valid academic session.")
                if term_id and not conn.execute("SELECT 1 FROM terms t JOIN sessions s ON s.id=t.session_id WHERE t.id=? AND s.school_id=?",(term_id,sid)).fetchone(): raise ValueError("Select a valid academic term.")
                if st>=et: raise ValueError("Start time must be earlier than end time.")
                overlap=conn.execute("SELECT 1 FROM schedule_slots WHERE school_id=? AND tenant_id=? AND day_id=? AND is_active=1 AND start_time<? AND end_time>?",(sid,tid,day_id,et,st)).fetchone()
                if overlap: raise ValueError("Schedule slots on the same day cannot overlap.")
                tmpl=conn.execute("SELECT id FROM schedule_templates WHERE school_id=? AND tenant_id=? ORDER BY is_default DESC,id LIMIT 1",(sid,tid)).fetchone()
                if not tmpl:
                    conn.execute("INSERT INTO schedule_templates(tenant_id,school_id,name,is_default,status) VALUES(?,?,?,?,?)",(tid,sid,"Standard School Schedule",1,"active")); tmpl=conn.execute("SELECT last_insert_rowid() id").fetchone()
                sh,sm=map(int,st.split(":")); eh,em=map(int,et.split(":")); duration=(eh*60+em)-(sh*60+sm)
                maxno=conn.execute("SELECT COALESCE(MAX(slot_number),0) n FROM schedule_slots WHERE day_id=?",(day_id,)).fetchone()["n"]
                conn.execute("INSERT INTO schedule_slots(tenant_id,school_id,academic_session_id,term_id,day_id,schedule_template_id,slot_number,slot_name,slot_type,start_time,end_time,duration_minutes,is_active,is_fixed,allows_timetable_entry) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",(tid,sid,session_id,term_id,day_id,tmpl["id"],maxno+1,name,typ,st,et,duration,0 if typ=="TEACHING" else 1,1 if typ=="TEACHING" else 0))
            elif action=="requirement":
                cid=int(request.form["class_id"]); sub=int(request.form["subject_id"]); teacher_id=request.form.get("teacher_id",type=int); ppw=max(1,min(40,int(request.form.get("periods_per_week",1)))); daily=max(1,min(8,int(request.form.get("periods_per_day_limit",1)))); dbl=1 if request.form.get("requires_double_period") else 0; tri=1 if request.form.get("requires_triple_period") else 0
                if not class_in_school(conn,cid) or not subject_in_school(conn,sub): raise ValueError("Class or subject is outside this school.")
                conn.execute("INSERT INTO class_subject_requirements_v2(tenant_id,school_id,class_id,arm_id,subject_id,periods_per_week,periods_per_day_limit,requires_double_period,requires_triple_period,preferred_period_type,priority,status) VALUES(?,?,?,?,?,?,?,?,?,?,?, 'active') ON CONFLICT(tenant_id,school_id,class_id,subject_id) DO UPDATE SET periods_per_week=excluded.periods_per_week,periods_per_day_limit=excluded.periods_per_day_limit,requires_double_period=excluded.requires_double_period,requires_triple_period=excluded.requires_triple_period",(tid,sid,cid,cid,sub,ppw,daily,dbl,tri,"ANY",1))
                if teacher_id:
                    conn.execute("UPDATE class_subjects SET teacher_id=? WHERE class_id=? AND subject_id=?",(teacher_id,cid,sub))
            elif action=="room":
                name=request.form["room_name"].strip(); code=request.form.get("room_code","").strip(); cap=max(0,int(request.form.get("capacity",0) or 0)); typ=request.form.get("room_type","ROOM");
                if not name: raise ValueError("Room name is required.")
                conn.execute("INSERT INTO timetable_rooms_v2(tenant_id,school_id,room_name,room_code,room_type,capacity,status) VALUES(?,?,?,?,?,?, 'active')",(tid,sid,name,code,typ,cap))
            elif action=="availability":
                teacher=int(request.form["teacher_id"]); day=int(request.form["day_id"]); slot=int(request.form["slot_id"]); status=request.form.get("availability_status","Available"); hard=1 if request.form.get("is_hard_constraint") else 0
                conn.execute("INSERT INTO teacher_availability_v2(tenant_id,school_id,teacher_id,day_id,slot_id,availability_status,reason,is_hard_constraint) VALUES(?,?,?,?,?,?,?,?)",(tid,sid,teacher,day,slot,status,request.form.get("reason",""),hard))
            elif action=="delete_slot":
                slot=int(request.form["slot_id"]); conn.execute("DELETE FROM schedule_slots WHERE id=? AND school_id=? AND tenant_id=?",(slot,sid,tid))
            elif action=="delete_room":
                room=int(request.form["room_id"]); conn.execute("UPDATE timetable_rooms_v2 SET status='inactive' WHERE id=? AND school_id=? AND tenant_id=?",(room,sid,tid))
            conn.commit(); flash("Timetable setup saved.","success")
        except Exception as exc:
            conn.rollback(); flash(str(exc) if isinstance(exc,ValueError) else "The timetable setup could not be saved. Please review the values.","error")
        conn.close(); return redirect(url_for("timetable_setup"))
    days=conn.execute("SELECT * FROM school_days_v2 WHERE school_id=? AND tenant_id=? AND is_active=1 ORDER BY day_order",(sid,tid)).fetchall()
    all_days=conn.execute("SELECT * FROM school_days_v2 WHERE school_id=? AND tenant_id=? ORDER BY day_order",(sid,tid)).fetchall()
    sessions=conn.execute("SELECT * FROM sessions WHERE school_id=? ORDER BY id DESC",(sid,)).fetchall(); active_session=next((x for x in sessions if x["is_active"]), sessions[0] if sessions else None)
    terms=conn.execute("SELECT t.*,s.name session_name FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.school_id=? ORDER BY t.id DESC",(sid,)).fetchall(); active_term=next((x for x in terms if x["is_active"]), terms[0] if terms else None)
    slots=_tt_slots(conn); classes=conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY level,name,arm",(sid,)).fetchall(); subjects=conn.execute("SELECT * FROM subjects WHERE school_id=? ORDER BY name",(sid,)).fetchall(); teachers=conn.execute("SELECT id,name FROM users WHERE school_id=? AND role='teacher' AND COALESCE(is_active,1)=1 ORDER BY name",(sid,)).fetchall(); rooms=conn.execute("SELECT * FROM timetable_rooms_v2 WHERE school_id=? AND tenant_id=? ORDER BY room_name",(sid,tid)).fetchall(); reqs=conn.execute("SELECT r.*,c.name class_name,s.name subject_name FROM class_subject_requirements_v2 r JOIN classes c ON c.id=r.class_id JOIN subjects s ON s.id=r.subject_id WHERE r.school_id=? AND r.tenant_id=? ORDER BY c.name,s.name",(sid,tid)).fetchall()
    conn.close(); return render_template("timetable_setup_v2.html",days=days,all_days=all_days,slots=slots,classes=classes,subjects=subjects,teachers=teachers,rooms=rooms,requirements=reqs,sessions=sessions,terms=terms,active_session=active_session,active_term=active_term)


@app.route("/timetable/generate",methods=["GET","POST"])
@login_required()
def timetable_generate():
    if not _tt_can_manage(get_db()):
        flash("You are not authorized to generate timetables.", "error"); return redirect(url_for("timetable_hub"))
    conn=get_db(); sid=current_school_id(); tid=_tt_tenant(conn)
    if request.method=="POST":
        # Never overwrite published data. Create a new draft/version.
        current=conn.execute("SELECT COALESCE(MAX(version_number),0) n FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=?",(sid,tid)).fetchone()["n"]
        session_row=conn.execute("SELECT s.id session_id,t.id term_id FROM sessions s LEFT JOIN terms t ON t.session_id=s.id AND t.is_active=1 WHERE s.school_id=? AND s.is_active=1 ORDER BY s.id DESC LIMIT 1",(sid,)).fetchone()
        session_id=session_row["session_id"] if session_row else None; term_id=session_row["term_id"] if session_row else None
        tt_type=conn.execute("SELECT id FROM timetable_types_v2 WHERE school_id=? AND tenant_id=? AND type_code='REGULAR' LIMIT 1",(sid,tid)).fetchone()
        if not tt_type:
            conn.execute("INSERT INTO timetable_types_v2(tenant_id,school_id,name,type_code,description) VALUES(?,?,?,?,?)",(tid,sid,'Regular Academic Timetable','REGULAR','Standard academic timetable')); tt_type=conn.execute("SELECT last_insert_rowid() id").fetchone()
        conn.execute("INSERT INTO timetable_versions_v2(tenant_id,school_id,academic_session_id,term_id,timetable_type_id,version_number,status,validation_status,is_current,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",(tid,sid,session_id,term_id,tt_type["id"],current+1,"DRAFT","PENDING",1,session.get("user_id")))
        vid=conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        created=_tt_generate_greedy(conn,vid); errors,warnings=_tt_validate(conn,vid)
        conn.execute("UPDATE timetable_versions_v2 SET status='VALIDATED' WHERE id=? AND validation_status='PASSED'",(vid,)); conn.commit(); conn.close(); flash(f"Generated draft version {current+1} with {created} lesson(s)." + (f" {len(errors)} blocking issue(s) remain." if errors else " Validation passed."),"success" if not errors else "error"); return redirect(url_for("timetable_version",version_id=vid))
    req_count=conn.execute("SELECT COUNT(*) n FROM class_subject_requirements_v2 WHERE school_id=? AND tenant_id=? AND status='active'",(sid,tid)).fetchone()["n"]; slot_count=conn.execute("SELECT COUNT(*) n FROM schedule_slots WHERE school_id=? AND tenant_id=? AND is_active=1",(sid,tid)).fetchone()["n"]; teacher_count=conn.execute("SELECT COUNT(*) n FROM class_subjects cs JOIN classes c ON c.id=cs.class_id WHERE c.school_id=? AND cs.teacher_id IS NOT NULL",(sid,)).fetchone()["n"]; room_count=conn.execute("SELECT COUNT(*) n FROM timetable_rooms_v2 WHERE school_id=? AND tenant_id=? AND status='active'",(sid,tid)).fetchone()["n"]
    conn.close(); return render_template("timetable_generate_v2.html",req_count=req_count,slot_count=slot_count,teacher_count=teacher_count,room_count=room_count,ready=all(x>0 for x in (req_count,slot_count,teacher_count)))


@app.route("/timetable/version/<int:version_id>")
@login_required()
def timetable_version(version_id):
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v: conn.close(); flash("Timetable version not found.","error"); return redirect(url_for("timetable_hub"))
    entries=conn.execute("""SELECT te.*,c.name class_name,s.name subject_name,u.name teacher_name,r.room_name,ss.slot_name,ss.start_time,ss.end_time,sd.day_name,sd.day_order
        FROM timetable_entries_v2 te JOIN classes c ON c.id=te.class_id JOIN subjects s ON s.id=te.subject_id LEFT JOIN users u ON u.id=te.teacher_id LEFT JOIN timetable_rooms_v2 r ON r.id=te.room_id JOIN schedule_slots ss ON ss.id=te.slot_id JOIN school_days_v2 sd ON sd.id=te.day_id WHERE te.timetable_version_id=? AND te.school_id=? AND te.tenant_id=? ORDER BY sd.day_order,ss.slot_number,c.name""",(version_id,current_school_id(),_tt_tenant(conn))).fetchall()
    conflicts=conn.execute("SELECT * FROM timetable_conflicts_v2 WHERE timetable_version_id=? ORDER BY CASE severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,id",(version_id,)).fetchall(); can_edit=_tt_can_manage(conn) and v["status"] in ("DRAFT","SAVED","VALIDATED","CHANGES_REQUESTED")
    conn.close(); return render_template("timetable_version_v2.html",version=v,entries=entries,conflicts=conflicts,can_edit=can_edit)


@app.route("/timetable/version/<int:version_id>/edit",methods=["GET","POST"])
@login_required()
def timetable_edit(version_id):
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v or not _tt_can_manage(conn) or v["status"] not in ("DRAFT","SAVED","VALIDATED","CHANGES_REQUESTED"):
        conn.close(); flash("Only authorized users can edit draft timetable versions.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    if request.method=="POST":
        entry_id=request.form.get("entry_id",type=int); slot_id=request.form.get("slot_id",type=int); teacher_id=request.form.get("teacher_id",type=int); room_id=request.form.get("room_id",type=int)
        entry=conn.execute("SELECT * FROM timetable_entries_v2 WHERE id=? AND timetable_version_id=? AND school_id=? AND tenant_id=?",(entry_id,version_id,current_school_id(),_tt_tenant(conn))).fetchone()
        slot=conn.execute("SELECT * FROM schedule_slots WHERE id=? AND school_id=? AND tenant_id=? AND is_active=1",(slot_id,current_school_id(),_tt_tenant(conn))).fetchone()
        if not entry or not slot or slot["slot_type"]!="TEACHING":
            conn.close(); flash("Invalid timetable edit.","error"); return redirect(url_for("timetable_edit",version_id=version_id))
        _sid_,_tid_=current_school_id(),_tt_tenant(conn)
        if teacher_id and not conn.execute("SELECT 1 FROM users WHERE id=? AND school_id=? AND role='teacher'",(teacher_id,_sid_)).fetchone():
            conn.close(); flash("Choose a teacher from this school.","error"); return redirect(url_for("timetable_edit",version_id=version_id))
        if room_id and not conn.execute("SELECT 1 FROM timetable_rooms_v2 WHERE id=? AND school_id=? AND tenant_id=? AND status='active'",(room_id,_sid_,_tid_)).fetchone():
            conn.close(); flash("Choose a room from this school.","error"); return redirect(url_for("timetable_edit",version_id=version_id))
        for col,val,label in (("teacher_id",teacher_id,"This teacher is already teaching another class"),("class_id",entry["class_id"],"This class already has a lesson"),("room_id",room_id,"This room is already booked")):
            if val and conn.execute(f"SELECT 1 FROM timetable_entries_v2 WHERE timetable_version_id=? AND slot_id=? AND {col}=? AND id<>? AND school_id=?",(version_id,slot_id,val,entry_id,_sid_)).fetchone():
                conn.close(); flash(label+" in that slot. Nothing was changed.","error"); return redirect(url_for("timetable_edit",version_id=version_id))
        conn.execute("UPDATE timetable_entries_v2 SET day_id=?,slot_id=?,teacher_id=?,room_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(slot["day_id"],slot_id,teacher_id,room_id,entry_id)); conn.execute("UPDATE timetable_versions_v2 SET status='DRAFT',validation_status='PENDING',updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(session.get("user_id"),version_id)); conn.commit(); errors,_=_tt_validate(conn,version_id); conn.close(); flash("Timetable change saved and revalidated." if not errors else f"Change saved; {len(errors)} blocking conflict(s) detected.","success" if not errors else "error"); return redirect(url_for("timetable_edit",version_id=version_id))
    entries=conn.execute("SELECT te.*,c.name class_name,s.name subject_name,u.name teacher_name,ss.slot_name,ss.start_time,ss.end_time,sd.day_name FROM timetable_entries_v2 te JOIN classes c ON c.id=te.class_id JOIN subjects s ON s.id=te.subject_id LEFT JOIN users u ON u.id=te.teacher_id JOIN schedule_slots ss ON ss.id=te.slot_id JOIN school_days_v2 sd ON sd.id=te.day_id WHERE te.timetable_version_id=? ORDER BY sd.day_order,ss.slot_number,c.name",(version_id,)).fetchall(); slots=_tt_slots(conn); teachers=conn.execute("SELECT id,name FROM users WHERE school_id=? AND role='teacher' AND COALESCE(is_active,1)=1 ORDER BY name",(current_school_id(),)).fetchall(); rooms=conn.execute("SELECT id,room_name FROM timetable_rooms_v2 WHERE school_id=? AND tenant_id=? AND status='active' ORDER BY room_name",(current_school_id(),_tt_tenant(conn))).fetchall(); conn.close(); return render_template("timetable_edit_v2.html",version=v,entries=entries,slots=slots,teachers=teachers,rooms=rooms)


@app.route("/timetable/version/<int:version_id>/validate",methods=["POST"])
@login_required()
def timetable_validate(version_id):
    if not _tt_can_manage(get_db()):
        flash("You are not authorized to validate timetables.", "error"); return redirect(url_for("timetable_hub"))
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v: conn.close(); flash("Timetable version not found.","error"); return redirect(url_for("timetable_hub"))
    errors,warnings=_tt_validate(conn,version_id); conn.close(); flash("Validation passed." if not errors else f"Validation found {len(errors)} blocking error(s).","success" if not errors else "error"); return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/timetable/version/<int:version_id>/submit",methods=["POST"])
@login_required()
def timetable_submit(version_id):
    if not _tt_can_manage(get_db()):
        flash("You are not authorized to submit timetables.", "error"); return redirect(url_for("timetable_hub"))
    conn=get_db(); v=_tt_version(conn,version_id); errors,_=_tt_validate(conn,version_id) if v else (["missing"],[])
    if not v or errors: conn.close(); flash("A timetable must pass validation before submission.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    conn.execute("UPDATE timetable_versions_v2 SET status='SUBMITTED',submitted_by=?,submitted_at=CURRENT_TIMESTAMP WHERE id=?",(session.get("user_id"),version_id)); conn.execute("INSERT INTO timetable_audit_v2(tenant_id,school_id,timetable_version_id,user_id,role,action,previous_status,new_status,reason) VALUES(?,?,?,?,?,?,?,?,?)",(_tt_tenant(conn),current_school_id(),version_id,session.get("user_id"),_tt_role(conn),"Submit",v["status"],"SUBMITTED","")); conn.commit(); conn.close(); flash("Timetable submitted for review.","success"); return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/timetable/version/<int:version_id>/approve",methods=["POST"])
@login_required()
def timetable_approve(version_id):
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v or not _tt_can_approve(conn): conn.close(); flash("You are not authorized to approve this timetable.","error"); return redirect(url_for("timetable_hub"))
    if v["created_by"]==session.get("user_id") and session.get("role") not in ("admin","sub_admin"): conn.close(); flash("Self-approval is blocked by default.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    errors,_=_tt_validate(conn,version_id)
    if errors: conn.close(); flash("Final validation failed. Resolve blocking conflicts first.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    conn.execute("UPDATE timetable_versions_v2 SET status='APPROVED',validation_status='PASSED',updated_at=CURRENT_TIMESTAMP WHERE id=?",(version_id,)); conn.execute("INSERT INTO timetable_approvals_v2(tenant_id,school_id,timetable_version_id,approval_level,assigned_role,assigned_user_id,status,decision,comment,decided_by,decided_at) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",(_tt_tenant(conn),current_school_id(),version_id,1,_tt_role(conn),session.get("user_id"),"approved","APPROVED",request.form.get("comment",""),session.get("user_id"))); conn.commit(); conn.close(); flash("Timetable approved.","success"); return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/timetable/version/<int:version_id>/request-changes",methods=["POST"])
@login_required()
def timetable_request_changes(version_id):
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v or not _tt_can_approve(conn): conn.close(); flash("You are not authorized to review this timetable.","error"); return redirect(url_for("timetable_hub"))
    comment=request.form.get("comment","").strip()
    if not comment: conn.close(); flash("Reviewer comment is required.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    conn.execute("UPDATE timetable_versions_v2 SET status='CHANGES_REQUESTED',updated_at=CURRENT_TIMESTAMP WHERE id=?",(version_id,)); conn.execute("INSERT INTO timetable_audit_v2(tenant_id,school_id,timetable_version_id,user_id,role,action,previous_status,new_status,reason) VALUES(?,?,?,?,?,?,?,?,?)",(_tt_tenant(conn),current_school_id(),version_id,session.get("user_id"),_tt_role(conn),"Request changes",v["status"],"CHANGES_REQUESTED",comment)); conn.commit(); conn.close(); flash("Changes requested.","success"); return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/timetable/version/<int:version_id>/reject",methods=["POST"])
@login_required()
def timetable_reject(version_id):
    conn=get_db(); v=_tt_version(conn,version_id); comment=request.form.get("comment","").strip()
    if not v or not _tt_can_approve(conn) or not comment: conn.close(); flash("Rejection requires approval permission and a reviewer comment.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    conn.execute("UPDATE timetable_versions_v2 SET status='REJECTED',updated_at=CURRENT_TIMESTAMP WHERE id=?",(version_id,)); conn.execute("INSERT INTO timetable_audit_v2(tenant_id,school_id,timetable_version_id,user_id,role,action,previous_status,new_status,reason) VALUES(?,?,?,?,?,?,?,?,?)",(_tt_tenant(conn),current_school_id(),version_id,session.get("user_id"),_tt_role(conn),"Reject",v["status"],"REJECTED",comment)); conn.commit(); conn.close(); flash("Timetable rejected. Create a revision to continue.","success"); return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/timetable/version/<int:version_id>/revision",methods=["POST"])
@login_required()
def timetable_revision(version_id):
    if not _tt_can_manage(get_db()):
        flash("You are not authorized to create timetable revisions.", "error"); return redirect(url_for("timetable_hub"))
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v: conn.close(); flash("Timetable version not found.","error"); return redirect(url_for("timetable_hub"))
    new_no=conn.execute("SELECT COALESCE(MAX(version_number),0)+1 n FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=?",(current_school_id(),_tt_tenant(conn))).fetchone()["n"]
    conn.execute("INSERT INTO timetable_versions_v2(tenant_id,school_id,academic_session_id,term_id,timetable_type_id,version_number,status,validation_status,is_current,parent_version_id,created_by,revision_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(_tt_tenant(conn),current_school_id(),v["academic_session_id"],v["term_id"],v["timetable_type_id"],new_no,"DRAFT","PENDING",1,version_id,session.get("user_id"),request.form.get("reason","").strip()))
    nid=conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    rows=conn.execute("SELECT day_id,slot_id,class_id,arm_id,subject_id,teacher_id,room_id,entry_type,is_fixed FROM timetable_entries_v2 WHERE timetable_version_id=?",(v["id"],)).fetchall()
    for r in rows: conn.execute("INSERT INTO timetable_entries_v2(tenant_id,school_id,timetable_version_id,day_id,slot_id,class_id,arm_id,subject_id,teacher_id,room_id,entry_type,is_fixed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(_tt_tenant(conn),current_school_id(),nid,*r))
    conn.commit(); conn.close(); flash(f"Revision {new_no} created.","success"); return redirect(url_for("timetable_version",version_id=nid))


@app.route("/timetable/version/<int:version_id>/publish",methods=["POST"])
@login_required()
def timetable_publish(version_id):
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v or not _tt_can_publish(conn) or v["status"]!="APPROVED": conn.close(); flash("Publication requires an approved timetable and publication permission.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    errors,_=_tt_validate(conn,version_id)
    if errors: conn.close(); flash("Final validation failed; publication is blocked.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    conn.execute("UPDATE timetable_versions_v2 SET status='SUPERSEDED',is_current=0 WHERE school_id=? AND tenant_id=? AND status='PUBLISHED'",(current_school_id(),_tt_tenant(conn)))
    conn.execute("UPDATE timetable_versions_v2 SET status='PUBLISHED',is_current=1,published_by=?,published_at=CURRENT_TIMESTAMP WHERE id=?",(session.get("user_id"),version_id))
    conn.execute("INSERT INTO timetable_audit_v2(tenant_id,school_id,timetable_version_id,user_id,role,action,previous_status,new_status,reason) VALUES(?,?,?,?,?,?,?,?,?)",(_tt_tenant(conn),current_school_id(),version_id,session.get("user_id"),_tt_role(conn),"Publish",v["status"],"PUBLISHED","")); conn.commit(); conn.close(); flash("Timetable published successfully.","success"); return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/timetable/class/<int:class_id>")
@login_required()
def timetable_class(class_id):
    conn=get_db(); sid=current_school_id(); tid=_tt_tenant(conn); cls=conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?",(class_id,sid)).fetchone()
    if not cls: conn.close(); flash("Class not found.","error"); return redirect(url_for("timetable_hub"))
    version=conn.execute("SELECT * FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=? AND status='PUBLISHED' ORDER BY id DESC LIMIT 1",(sid,tid)).fetchone()
    if not version: version=conn.execute("SELECT * FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=? ORDER BY id DESC LIMIT 1",(sid,tid)).fetchone()
    entries=[]
    if version: entries=conn.execute("SELECT te.*,s.name subject_name,u.name teacher_name,r.room_name,ss.slot_name,ss.start_time,ss.end_time,sd.day_name,sd.day_order FROM timetable_entries_v2 te JOIN subjects s ON s.id=te.subject_id LEFT JOIN users u ON u.id=te.teacher_id LEFT JOIN timetable_rooms_v2 r ON r.id=te.room_id JOIN schedule_slots ss ON ss.id=te.slot_id JOIN school_days_v2 sd ON sd.id=te.day_id WHERE te.timetable_version_id=? AND te.class_id=? ORDER BY sd.day_order,ss.slot_number",(version["id"],class_id)).fetchall()
    conn.close(); return render_template("timetable_class_v2.html",class_row=cls,version=version,entries=entries,days=DAY_NAMES)


@app.route("/timetable/teacher/<int:teacher_id>")
@login_required()
def timetable_teacher(teacher_id):
    conn=get_db(); sid=current_school_id(); tid=_tt_tenant(conn); teacher=conn.execute("SELECT id,name,school_id FROM users WHERE id=? AND school_id=?",(teacher_id,sid)).fetchone()
    if not teacher: conn.close(); flash("Teacher not found.","error"); return redirect(url_for("timetable_hub"))
    if session.get("role") not in ("admin","sub_admin") and teacher_id!=session.get("user_id"):
        assigned=conn.execute("SELECT 1 FROM class_subjects cs JOIN classes c ON c.id=cs.class_id WHERE cs.teacher_id=? AND c.form_teacher_id=? AND c.school_id=? LIMIT 1",(session.get("user_id"),teacher_id,sid)).fetchone()
        if teacher_id!=session.get("user_id") and not assigned: conn.close(); flash("You don't have access to that teacher timetable.","error"); return redirect(url_for("timetable_hub"))
    version=conn.execute("SELECT * FROM timetable_versions_v2 WHERE school_id=? AND tenant_id=? AND status='PUBLISHED' ORDER BY id DESC LIMIT 1",(sid,tid)).fetchone(); entries=[]
    if version: entries=conn.execute("SELECT te.*,s.name subject_name,c.name class_name,r.room_name,ss.slot_name,ss.start_time,ss.end_time,sd.day_name,sd.day_order FROM timetable_entries_v2 te JOIN subjects s ON s.id=te.subject_id JOIN classes c ON c.id=te.class_id LEFT JOIN timetable_rooms_v2 r ON r.id=te.room_id JOIN schedule_slots ss ON ss.id=te.slot_id JOIN school_days_v2 sd ON sd.id=te.day_id WHERE te.timetable_version_id=? AND te.teacher_id=? ORDER BY sd.day_order,ss.slot_number",(version["id"],teacher_id)).fetchall()
    conn.close(); return render_template("timetable_teacher_v2.html",teacher=teacher,version=version,entries=entries)


@app.route("/timetable/export/<int:version_id>/<fmt>")
@login_required()
def timetable_export(version_id,fmt):
    conn=get_db(); v=_tt_version(conn,version_id)
    if not v: conn.close(); flash("Timetable version not found.","error"); return redirect(url_for("timetable_hub"))
    if v["status"] not in ("APPROVED","PUBLISHED","SUPERSEDED","ARCHIVED") and session.get("role") not in ("admin","sub_admin"):
        conn.close(); flash("You can only export published or approved timetables.","error"); return redirect(url_for("timetable_version",version_id=version_id))
    rows=conn.execute("SELECT sd.day_name,ss.slot_name,ss.start_time,ss.end_time,c.name,s.name,u.name,r.room_name FROM timetable_entries_v2 te JOIN school_days_v2 sd ON sd.id=te.day_id JOIN schedule_slots ss ON ss.id=te.slot_id JOIN classes c ON c.id=te.class_id JOIN subjects s ON s.id=te.subject_id LEFT JOIN users u ON u.id=te.teacher_id LEFT JOIN timetable_rooms_v2 r ON r.id=te.room_id WHERE te.timetable_version_id=? ORDER BY sd.day_order,ss.slot_number,c.name",(version_id,)).fetchall(); conn.close()
    headers=["Day","Slot","Start","End","Class/Arm","Subject","Teacher","Room"]; data=[tuple(r) for r in rows]
    if fmt=="csv":
        return send_file(build_csv(headers,data),as_attachment=True,download_name=f"timetable-v{v['version_number']}.csv",mimetype="text/csv")
    if fmt=="xlsx":
        return send_file(build_xlsx(f"Timetable v{v['version_number']}",headers,data),as_attachment=True,download_name=f"timetable-v{v['version_number']}.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if fmt=="pdf":
        school=_tt_school(get_db()); buf=build_generic_table_pdf("School Timetable",f"Version {v['version_number']} · {v['status']}",headers,data,school_name=school['name'] if school else None); return send_file(buf,as_attachment=True,download_name=f"timetable-v{v['version_number']}.pdf",mimetype="application/pdf")
    return redirect(url_for("timetable_version",version_id=version_id))


@app.route("/my-class")
@login_required()
def my_class():
    conn = get_db()
    class_ids = form_teacher_class_ids(conn, session["user_id"])
    conn.close()
    if not class_ids:
        flash("You are not currently assigned as a Form Teacher for any class. Please ask your administrator to assign you.", "error")
        return redirect(url_for("dashboard"))
    if len(class_ids) == 1:
        return redirect(url_for("my_class_roster", class_id=class_ids[0]))
    conn = get_db()
    classes = conn.execute(
        f"SELECT * FROM classes WHERE id IN ({','.join('?'*len(class_ids))}) ORDER BY name", class_ids
    ).fetchall()
    conn.close()
    return render_template("my_class_picker.html", classes=classes)


@app.route("/my-class/<int:class_id>", methods=["GET", "POST"])
@login_required()
def my_class_roster(class_id):
    conn = get_db()
    class_row = class_in_school(conn, class_id)
    if not class_row:
        conn.close()
        flash("Class not found.", "error")
        return redirect(url_for("dashboard"))
    if session["role"] not in ("admin", "sub_admin") and class_id not in form_teacher_class_ids(conn, session["user_id"]):
        conn.close()
        flash("You're not the form teacher for that class.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        try:
            cur = conn.execute(
                "INSERT INTO students (admission_no, first_name, last_name, other_names, "
                "gender, class_id, date_of_birth, religion, parent_name, parent_address, parent_email, parent_phone, parent_relationship) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request.form["admission_no"].strip(),
                    request.form["first_name"].strip(),
                    request.form["last_name"].strip(),
                    request.form.get("other_names", "").strip() or None,
                    request.form.get("gender") or None,
                    class_id,
                    request.form.get("date_of_birth", "").strip() or None,
                    request.form.get("religion", "").strip() or None,
                    request.form.get("parent_name", "").strip() or None,
                    request.form.get("parent_address", "").strip() or None,
                    request.form.get("parent_email", "").strip() or None,
                    request.form.get("parent_phone", "").strip() or None,
                    request.form.get("parent_relationship", "").strip() or None,
                ),
            )
            upsert_enrollment(conn, cur.lastrowid, class_id)
            conn.commit()
            flash("Student added to your class register.", "success")
        except Exception:
            flash("That Admission No. / Register No. is already in use in this class.", "error")

    students = conn.execute(
        "SELECT * FROM students WHERE class_id=? AND is_active=1 ORDER BY admission_no, last_name", (class_id,)
    ).fetchall()
    conn.close()
    return render_template(
        "my_class_roster.html", class_row=class_row, students=students, student_full_name=student_full_name
    )


from jinja2 import pass_context as _pass_context


@app.template_filter("school_dt")
@_pass_context
def _school_dt(ctx, value, part="both"):
    """Show a stored UTC timestamp ('YYYY-MM-DD HH:MM:SS') in the school's own timezone."""
    if not value:
        return "—"
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("T", " ")[:19]).replace(tzinfo=datetime.timezone.utc)
        try:
            tz = ZoneInfo(ctx.get("school_timezone") or "Africa/Lagos")
        except Exception:
            tz = ZoneInfo("Africa/Lagos")
        loc = dt.astimezone(tz)
    except Exception:
        return str(value)
    if part == "date":
        return loc.strftime("%d/%m/%Y")
    if part == "time":
        return loc.strftime("%I:%M:%S %p").lstrip("0")
    return loc.strftime("%d/%m/%Y %I:%M %p").replace(" 0", " ")


# ---------- Server-controlled attendance clock ----------
from zoneinfo import ZoneInfo

FUTURE_ATTENDANCE_MSG = "Future attendance cannot be recorded. Please record attendance on the correct date."
BACKDATED_ATTENDANCE_MSG = "Backdated attendance is not allowed. Attendance must be recorded on the current date."
STUDENT_ATTENDANCE_TYPES = ("present", "late", "absent", "excused")      # DB status: present/late -> 'present', absent/excused -> 'absent'
STUDENT_ATTENDANCE_LABELS = {"present": "Present", "late": "Late", "absent": "Absent", "excused": "Excused"}


def school_tz(conn, school_id=None):
    """The school's configured timezone (default Africa/Lagos, WAT UTC+1)."""
    sid = school_id or current_school_id()
    row = conn.execute("SELECT timezone FROM schools WHERE id=?", (sid,)).fetchone() if sid else None
    name = (row["timezone"] if row and row["timezone"] else "Africa/Lagos")
    try:
        return ZoneInfo(name), name
    except Exception:
        return ZoneInfo("Africa/Lagos"), "Africa/Lagos"


def school_now(conn, school_id=None):
    """Current date/time in the school's timezone, from the SERVER clock. The browser/device clock is never consulted."""
    tz, _ = school_tz(conn, school_id)
    return datetime.datetime.now(tz)


def school_today(conn, school_id=None):
    return school_now(conn, school_id).date().isoformat()


def server_utc_stamp():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def school_clock_text(conn, school_id=None):
    """e.g. 'Friday, 03/10/2026 — 7:02 PM' (in the school's timezone)."""
    now = school_now(conn, school_id)
    return f"{now.strftime('%A')}, {now.strftime('%d/%m/%Y')} — {now.strftime('%I:%M %p').lstrip('0')}"


def attendance_date_error(submitted, today):
    """None when `submitted` equals the school's current date; otherwise the message to show. The rule is exact equality."""
    try:
        d = datetime.date.fromisoformat((submitted or "").strip())
    except ValueError:
        return "That attendance date is not valid."
    t = datetime.date.fromisoformat(today)
    if d > t:
        return FUTURE_ATTENDANCE_MSG
    if d < t:
        return BACKDATED_ATTENDANCE_MSG
    return None


def attendance_audit_log(conn, kind, subject_id, attendance_date, action, old_status=None, new_status=None, class_id=None, reason=None):
    sid = current_school_id()
    conn.execute(
        "INSERT INTO attendance_audit (school_id,tenant_id,kind,subject_id,class_id,attendance_date,action,old_status,new_status,actor_id,actor_name,actor_role,reason) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, current_tenant_id(), kind, subject_id, class_id, attendance_date, action, old_status, new_status,
         session.get("user_id"), session.get("name"), recorder_role_label(), reason))


def recorder_role_label():
    roles = session_roles() if session.get("role") == "teacher" else []
    return ", ".join(roles) if roles else (session.get("role") or "user").replace("_", " ").title()


def _require_own_class(conn, class_id):
    class_row = class_in_school(conn, class_id)
    if not class_row:
        return None
    if session["role"] not in ("admin", "sub_admin"):
        # Class attendance belongs to the Class Teacher / Form Teacher of THAT class only.
        if "Class Teacher / Form Teacher" not in session_roles() or class_id not in form_teacher_class_ids(conn, session["user_id"]):
            return None
    return class_row


@app.route("/my-class/<int:class_id>/roll-call", methods=["GET", "POST"])
@login_required()
def roll_call(class_id):
    conn = get_db()
    class_row = _require_own_class(conn, class_id)
    if not class_row:
        conn.close()
        flash("You're not the form teacher for that class.", "error")
        return redirect(url_for("dashboard"))

    term = current_term(conn)
    if not term:
        conn.close()
        flash("There's no active term set up yet. Ask your admin to set one under Setup → Terms.", "error")
        return redirect(url_for("dashboard"))

    # The attendance date is NEVER chosen by the user: it is today's date in the school's timezone, from the server clock.
    today = school_today(conn)
    requested = (request.values.get("date") or "").strip()
    if requested:
        problem = attendance_date_error(requested, today)
        if problem:
            attendance_audit_log(conn, "student", None, requested, "rejected", class_id=class_id, reason=problem)
            conn.commit()
            conn.close()
            flash(problem, "error")
            return redirect(url_for("roll_call", class_id=class_id))
    date_str = today

    students = conn.execute(
        "SELECT * FROM students WHERE class_id=? AND is_active=1 AND COALESCE(status,'Active')='Active' ORDER BY admission_no, last_name", (class_id,)
    ).fetchall()
    existing_rows = {
        r["student_id"]: r for r in conn.execute(
            "SELECT * FROM attendance_records WHERE class_id=? AND term_id=? AND date=?", (class_id, term["id"], date_str)).fetchall()
    }

    def row_type(r):
        return (r["attendance_type"] if "attendance_type" in r.keys() and r["attendance_type"] else r["status"])

    if request.method == "POST":
        reason = (request.form.get("correction_reason") or "").strip()[:300]
        wanted = {}
        for s_ in students:
            t = request.form.get(f"status_{s_['id']}")
            wanted[s_["id"]] = t if t in STUDENT_ATTENDANCE_TYPES else "present"
        changes = [sid_ for sid_, t in wanted.items() if sid_ in existing_rows and row_type(existing_rows[sid_]) != t]
        if changes and not reason:
            conn.close()
            flash("Attendance for today has already been recorded. To change it, enter the reason for the correction.", "error")
            return redirect(url_for("roll_call", class_id=class_id))
        counts = {t: 0 for t in STUDENT_ATTENDANCE_TYPES}
        stamp = server_utc_stamp()
        role_label = recorder_role_label()
        for s_ in students:
            typ = wanted[s_["id"]]
            counts[typ] += 1
            status = "absent" if typ in ("absent", "excused") else "present"
            ex = existing_rows.get(s_["id"])
            if ex is None:
                conn.execute(
                    "INSERT INTO attendance_records (student_id, class_id, term_id, date, status, attendance_type, recorded_by, recorder_role, "
                    "recorded_at, source, school_id, tenant_id, class_arm) VALUES (?,?,?,?,?,?,?,?,?,'online',?,?,?)",
                    (s_["id"], class_id, term["id"], date_str, status, typ, session["user_id"], role_label, stamp,
                     current_school_id(), current_tenant_id(), class_row["arm"] if "arm" in class_row.keys() else None))
                attendance_audit_log(conn, "student", s_["id"], date_str, "recorded", None, typ, class_id=class_id)
            elif row_type(ex) != typ:
                conn.execute(
                    "UPDATE attendance_records SET status=?, attendance_type=?, corrected_by=?, corrected_at=?, correction_note=?, "
                    "original_status=COALESCE(original_status, ?) WHERE id=? AND class_id=?",
                    (status, typ, session["user_id"], stamp, reason, row_type(ex), ex["id"], class_id))
                attendance_audit_log(conn, "student", s_["id"], date_str, "corrected", row_type(ex), typ, class_id=class_id, reason=reason)
            recompute_attendance(conn, s_["id"], term["id"])
        conn.commit()
        log_audit(
            conn, session["role"], session.get("name"),
            "roll_call",
            f"{class_row['name']} — {date_str}: " + ", ".join(f"{n} {STUDENT_ATTENDANCE_LABELS[t].lower()}" for t, n in counts.items() if n),
            school_id=current_school_id(),
        )
        flash(("Correction saved" if changes else "Attendance saved") + f" for {format_dmy(date_str)} — "
              + ", ".join(f"{n} {STUDENT_ATTENDANCE_LABELS[t].lower()}" for t, n in counts.items() if n) + ".", "success")
        conn.close()
        return redirect(url_for("roll_call", class_id=class_id))

    existing = {sid_: row_type(r) for sid_, r in existing_rows.items()}
    recorded_info = None
    if existing_rows:
        any_row = next(iter(existing_rows.values()))
        recorded_info = {"at": any_row["recorded_at"], "role": any_row["recorder_role"] if "recorder_role" in any_row.keys() else None}
    clock = school_clock_text(conn)
    _, tz_name = school_tz(conn)
    conn.close()
    return render_template(
        "roll_call.html", class_row=class_row, students=students, student_full_name=student_full_name,
        date_str=date_str, existing=existing, today=today, clock=clock, tz_name=tz_name, recorded_info=recorded_info,
        types=STUDENT_ATTENDANCE_TYPES, labels=STUDENT_ATTENDANCE_LABELS,
    )


@app.route("/my-class/<int:class_id>/roll-call/history")
@login_required()
def roll_call_history(class_id):
    conn = get_db()
    class_row = _require_own_class(conn, class_id)
    if not class_row:
        conn.close()
        flash("You're not the form teacher for that class.", "error")
        return redirect(url_for("dashboard"))

    term = current_term(conn)
    if not term:
        conn.close()
        flash("There's no active term set up yet. Ask your admin to set one under Setup → Terms.", "error")
        return redirect(url_for("dashboard"))

    students = conn.execute(
        "SELECT s.*, sti.days_school_opened, sti.days_present, sti.days_absent "
        "FROM students s LEFT JOIN student_term_info sti ON sti.student_id=s.id AND sti.term_id=? "
        "WHERE s.class_id=? AND s.is_active=1 ORDER BY s.admission_no, s.last_name",
        (term["id"], class_id),
    ).fetchall()
    summaries = []
    for s in students:
        opened = s["days_school_opened"] or 0
        present = s["days_present"] or 0
        absent = s["days_absent"] or 0
        summaries.append({
            "student": s, "opened": opened, "present": present, "absent": absent,
            "percentage": attendance_percentage(present, opened),
        })

    dates = conn.execute(
        "SELECT date, "
        "SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) AS present, "
        "SUM(CASE WHEN status='absent' THEN 1 ELSE 0 END) AS absent "
        "FROM attendance_records WHERE class_id=? AND term_id=? GROUP BY date ORDER BY date DESC",
        (class_id, term["id"]),
    ).fetchall()
    conn.close()
    return render_template(
        "roll_call_history.html", class_row=class_row, summaries=summaries, dates=dates,
        student_full_name=student_full_name,
    )


@app.route("/my-class/<int:class_id>/csv_template")
@login_required()
def my_class_csv_template(class_id):
    conn = get_db()
    class_row = _require_own_class(conn, class_id)
    if not class_row:
        conn.close()
        flash("You're not the form teacher for that class.", "error")
        return redirect(url_for("dashboard"))
    students = conn.execute(
        "SELECT * FROM students WHERE class_id=? AND is_active=1 ORDER BY admission_no, last_name", (class_id,)
    ).fetchall()
    conn.close()

    buf = io.StringIO()
    writer = csv_module.writer(buf)
    writer.writerow([
        "admission_no", "first_name", "last_name", "other_names", "gender",
        "date_of_birth", "religion", "parent_name", "parent_address", "parent_email", "parent_phone", "parent_relationship",
    ])
    for s in students:
        writer.writerow([
            s["admission_no"], s["first_name"], s["last_name"], s["other_names"] or "",
            s["gender"] or "", s["date_of_birth"] or "", s["religion"] or "",
            s["parent_name"] or "", s["parent_address"] or "", s["parent_email"] or "", s["parent_phone"] or "",
            s["parent_relationship"] or "",
        ])
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    fname = f"class_register_{class_row['name']}.csv".replace(" ", "_")
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=fname)


@app.route("/my-class/<int:class_id>/csv_upload", methods=["POST"])
@login_required()
def my_class_csv_upload(class_id):
    conn = get_db()
    class_row = _require_own_class(conn, class_id)
    if not class_row:
        conn.close()
        flash("You're not the form teacher for that class.", "error")
        return redirect(url_for("dashboard"))

    file = request.files.get("csv_file")
    if not file or file.filename == "":
        conn.close()
        flash("Please choose a CSV file to upload.", "error")
        return redirect(url_for("my_class_roster", class_id=class_id))

    existing_by_adm = {
        s["admission_no"]: s["id"]
        for s in conn.execute("SELECT * FROM students WHERE class_id=?", (class_id,)).fetchall()
    }
    text = file.read().decode("utf-8-sig")
    reader = csv_module.DictReader(io.StringIO(text))
    required_cols = {"admission_no", "first_name", "last_name"}
    if not required_cols.issubset(set(c.strip() for c in (reader.fieldnames or []))):
        conn.close()
        flash(f"CSV must at least have these columns: {', '.join(sorted(required_cols))}. Download the template for reference.", "error")
        return redirect(url_for("my_class_roster", class_id=class_id))

    added, updated, skipped = 0, 0, []
    for i, row in enumerate(reader, start=2):
        adm = (row.get("admission_no") or "").strip()
        fn = (row.get("first_name") or "").strip()
        ln = (row.get("last_name") or "").strip()
        if not (adm and fn and ln):
            skipped.append(f"Row {i}: missing required field(s)")
            continue
        fields = (
            row.get("other_names", "").strip() or None,
            row.get("gender", "").strip().upper()[:1] or None,
            row.get("date_of_birth", "").strip() or None,
            row.get("religion", "").strip() or None,
            row.get("parent_name", "").strip() or None,
            row.get("parent_address", "").strip() or None,
            row.get("parent_email", "").strip() or None,
            row.get("parent_phone", "").strip() or None,
            row.get("parent_relationship", "").strip() or None,
        )
        try:
            if adm in existing_by_adm:
                conn.execute(
                    "UPDATE students SET first_name=?, last_name=?, other_names=?, gender=?, date_of_birth=?, "
                    "religion=?, parent_name=?, parent_address=?, parent_email=?, parent_phone=?, parent_relationship=? "
                    "WHERE id=?",
                    (fn, ln, *fields, existing_by_adm[adm]),
                )
                updated += 1
            else:
                cur = conn.execute(
                    "INSERT INTO students (admission_no, first_name, last_name, other_names, gender, class_id, "
                    "date_of_birth, religion, parent_name, parent_address, parent_email, parent_phone, parent_relationship) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (adm, fn, ln, fields[0], fields[1], class_id, fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8]),
                )
                upsert_enrollment(conn, cur.lastrowid, class_id)
                added += 1
        except Exception:
            skipped.append(f"Row {i}: couldn't save '{fn} {ln}' ({adm})")

    conn.commit()
    conn.close()
    if added or updated:
        flash(f"Imported: {added} new student(s) added, {updated} existing student(s) updated.", "success")
    if skipped:
        preview = "; ".join(skipped[:8]) + (f" (+{len(skipped)-8} more)" if len(skipped) > 8 else "")
        flash(f"Skipped {len(skipped)} row(s): {preview}", "error")
    return redirect(url_for("my_class_roster", class_id=class_id))


@app.route("/my-class/<int:class_id>/students/<int:student_id>/edit", methods=["POST"])
@login_required()
def my_class_edit_student(class_id, student_id):
    conn = get_db()
    class_row = class_in_school(conn, class_id)
    if not class_row or (session["role"] not in ("admin", "sub_admin") and class_id not in form_teacher_class_ids(conn, session["user_id"])):
        conn.close()
        flash("You're not the form teacher for that class.", "error")
        return redirect(url_for("dashboard"))
    existing_student = conn.execute("SELECT * FROM students WHERE id=? AND class_id=?", (student_id, class_id)).fetchone()
    if not existing_student:
        conn.close()
        flash("Student not found in this class.", "error")
        return redirect(url_for("my_class_roster", class_id=class_id))
    is_school_admin_user = session["role"] in ("admin", "sub_admin")
    try:
        status = request.form.get("status", "Active")
        if status not in ("Active", "Graduated", "Transferred", "Withdrawn", "Suspended"):
            status = "Active"
        # Protected fields (Admission No. / Register No., administrative status) can only be changed by the school administration.
        if not is_school_admin_user:
            status = existing_student["status"] or "Active"
            protected_admission_no = existing_student["admission_no"]
        else:
            protected_admission_no = request.form["admission_no"].strip()
        conn.execute(
            "UPDATE students SET first_name=?, last_name=?, other_names=?, admission_no=?, gender=?, "
            "date_of_birth=?, religion=?, parent_name=?, parent_address=?, parent_email=?, parent_phone=?, parent_relationship=?, "
            "status=?, phone=?, is_active=? "
            "WHERE id=? AND class_id=?",
            (
                request.form["first_name"].strip(),
                request.form["last_name"].strip(),
                request.form.get("other_names", "").strip() or None,
                protected_admission_no,
                request.form.get("gender") or None,
                request.form.get("date_of_birth", "").strip() or None,
                request.form.get("religion", "").strip() or None,
                request.form.get("parent_name", "").strip() or None,
                request.form.get("parent_address", "").strip() or None,
                request.form.get("parent_email", "").strip() or None,
                request.form.get("parent_phone", "").strip() or None,
                request.form.get("parent_relationship", "").strip() or None,
                status,
                request.form.get("phone", "").strip() or None,
                (1 if status == "Active" else 0) if is_school_admin_user else existing_student["is_active"],
                student_id, class_id,
            ),
        )
        conn.commit()
        flash("Student details updated.", "success")
    except sqlite3.IntegrityError:
        conn.rollback()
        flash("That Admission No. / Register No. is already used by another student in this school.", "error")
    except Exception:
        conn.rollback()
        app.logger.exception("Roster student edit failed")
        flash("The student could not be saved. Please check the details and try again.", "error")
    conn.close()
    return redirect(url_for("my_class_roster", class_id=class_id))


# ---------- score entry (teacher) ----------

@app.route("/scores/<int:class_id>/<int:subject_id>", methods=["GET", "POST"])
@login_required()
def score_entry(class_id, subject_id):
    conn = get_db()
    term = current_term(conn)
    if not term:
        conn.close()
        flash("No active term set. Ask the admin to activate a term.", "error")
        return redirect(url_for("dashboard"))

    class_row = class_in_school(conn, class_id)
    subject_row = subject_in_school(conn, subject_id)
    if not class_row or not subject_row:
        conn.close()
        flash("Class or subject not found.", "error")
        return redirect(url_for("dashboard"))
    level = class_row["level"] if "level" in class_row.keys() else None
    needed = "edit" if request.method == "POST" else "view"
    if not can_enter_scores(conn, class_id, subject_id):
        conn.close()
        flash("You do not have permission for this class and subject.", "error")
        return redirect(url_for("dashboard"))

    cs = conn.execute(
        "SELECT * FROM class_subjects WHERE class_id=? AND subject_id=?", (class_id, subject_id)
    ).fetchone()
    if not cs:
        conn.close()
        flash("This subject is not assigned to this class.", "error")
        return redirect(url_for("dashboard"))
    if session["role"] == "teacher" and cs["teacher_id"] != session["user_id"]:
        conn.close()
        flash("You are not assigned to teach this subject/class.", "error")
        return redirect(url_for("dashboard"))

    config = get_grading_config(conn)

    if request.method == "POST":
        students_ids = request.form.getlist("student_id")
        allowed_ids = {r["id"] for r in conn.execute(
            "SELECT id FROM students WHERE class_id=?", (class_id,)).fetchall()}
        use_ca3 = ca3_enabled(config)
        bad_rows = []
        for sid in students_ids:
            if not sid.isdigit() or int(sid) not in allowed_ids:
                continue  # never write a score for a student outside this class
            sid = int(sid)
            try:
                ca1 = float(request.form.get(f"ca1_{sid}", "0") or "0")
                ca2 = float(request.form.get(f"ca2_{sid}", "0") or "0")
                ca3 = float(request.form.get(f"ca3_{sid}", "0") or "0") if use_ca3 else 0.0
                exam = float(request.form.get(f"exam_{sid}", "0") or "0")
            except ValueError:
                bad_rows.append(f"student {sid}: scores must be numbers")
                continue
            errs = score_range_errors(config, ca1, ca2, ca3, exam)
            if errs:
                bad_rows.append(f"student {sid}: " + "; ".join(errs))
                continue
            try:
                save_score(conn, sid, subject_id, term["id"], ca1, ca2, ca3, exam, session["user_id"],
                           reason=request.form.get("change_reason"))
            except ScoreChangeError as exc:
                bad_rows.append(f"student {sid}: {exc}")
        conn.commit()
        if bad_rows:
            flash("Some rows were not saved — " + " | ".join(bad_rows[:5]), "error")
        else:
            flash("Scores saved.", "success")

    students = conn.execute(
        "SELECT * FROM students WHERE class_id=? AND is_active=1 ORDER BY admission_no, last_name", (class_id,)
    ).fetchall()
    existing = {
        row["student_id"]: row
        for row in conn.execute(
            "SELECT * FROM scores WHERE subject_id=? AND term_id=? AND student_id IN "
            "(SELECT id FROM students WHERE class_id=?)", (subject_id, term["id"], class_id)
        ).fetchall()
    }
    conn.close()
    return render_template(
        "score_entry.html", students=students, existing=existing, config=config,
        class_row=class_row, subject_row=subject_row, term=term, student_full_name=student_full_name,
    )


@app.route("/scores/<int:class_id>/<int:subject_id>/csv_template")
@login_required()
def score_csv_template(class_id, subject_id):
    conn = get_db()
    class_row = class_in_school(conn, class_id)
    subject_row = subject_in_school(conn, subject_id)
    term = current_term(conn)
    if not class_row or not subject_row or not term:
        conn.close()
        flash("Class, subject, or active term not found.", "error")
        return redirect(url_for("dashboard"))
    level = class_row["level"] if "level" in class_row.keys() else None
    if not can_access_scope(session.get("user_id"), current_school_id(), "view", school_level=level, class_id=class_id, subject_id=subject_id):
        conn.close()
        flash("You do not have permission for this class and subject.", "error")
        return redirect(url_for("dashboard"))

    config = get_grading_config(conn)
    students = conn.execute(
        "SELECT * FROM students WHERE class_id=? AND is_active=1 ORDER BY admission_no, last_name", (class_id,)
    ).fetchall()
    existing = {
        row["student_id"]: row
        for row in conn.execute(
            "SELECT * FROM scores WHERE subject_id=? AND term_id=? AND student_id IN "
            "(SELECT id FROM students WHERE class_id=?)", (subject_id, term["id"], class_id)
        ).fetchall()
    }
    conn.close()

    buf = io.StringIO()
    writer = csv_module.writer(buf)
    use_ca3 = ca3_enabled(config)
    maxes = f"CA1: {config['ca1_max']}, CA2: {config['ca2_max']}, " + (f"CA3: {config['ca3_max']}, " if use_ca3 else "") + f"Exam: {config['exam_max']}"
    writer.writerow([f"# Max marks — {maxes}"])
    writer.writerow(["admission_no", "student_name", "ca1", "ca2"] + (["ca3"] if use_ca3 else []) + ["exam", "total"])
    for s in students:
        sc = existing.get(s["id"])
        ca1 = sc["ca1"] if sc else ""
        ca2 = sc["ca2"] if sc else ""
        ca3 = (sc["ca3"] or 0) if sc else ""
        exam = sc["exam"] if sc else ""
        total = compute_total(ca1, ca2, exam, ca3 or 0) if sc else ""
        writer.writerow([s["admission_no"], student_full_name(s), ca1, ca2] + ([ca3] if use_ca3 else []) + [exam, total])
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    fname = f"scores_{class_row['name']}_{subject_row['name']}.csv".replace(" ", "_")
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=fname)


@app.route("/scores/<int:class_id>/<int:subject_id>/csv_upload", methods=["POST"])
@login_required()
def score_csv_upload(class_id, subject_id):
    conn = get_db()
    class_row = class_in_school(conn, class_id)
    subject_row = subject_in_school(conn, subject_id)
    term = current_term(conn)
    if not class_row or not subject_row or not term:
        conn.close()
        flash("Class, subject, or active term not found.", "error")
        return redirect(url_for("dashboard"))
    level = class_row["level"] if "level" in class_row.keys() else None
    if not can_enter_scores(conn, class_id, subject_id):
        conn.close()
        flash("You do not have permission for this class and subject.", "error")
        return redirect(url_for("dashboard"))

    cs = conn.execute("SELECT * FROM class_subjects WHERE class_id=? AND subject_id=?", (class_id, subject_id)).fetchone()
    if session["role"] == "teacher" and (not cs or cs["teacher_id"] != session["user_id"]):
        conn.close()
        flash("You are not assigned to teach this subject/class.", "error")
        return redirect(url_for("dashboard"))

    file = request.files.get("csv_file")
    if not file or file.filename == "":
        conn.close()
        flash("Please choose a CSV file to upload.", "error")
        return redirect(url_for("score_entry", class_id=class_id, subject_id=subject_id))

    students_by_adm = {
        s["admission_no"]: s
        for s in conn.execute("SELECT * FROM students WHERE class_id=?", (class_id,)).fetchall()
    }
    config = get_grading_config(conn)
    text = file.read().decode("utf-8-sig")
    # Skip a leading "# Max marks..." comment line if present (from our own
    # template). The CSV writer may have wrapped it in quotes since it
    # contains commas, so check for both forms.
    lines = text.splitlines()
    if lines and lines[0].strip().lstrip('"').startswith("#"):
        text = "\n".join(lines[1:])
    reader = csv_module.DictReader(io.StringIO(text))
    updated, skipped = 0, []
    for i, row in enumerate(reader, start=2):
        adm = (row.get("admission_no") or "").strip()
        student = students_by_adm.get(adm)
        if not student:
            skipped.append(f"Row {i}: no student with Admission No./Register No. '{adm}' in this class")
            continue
        sid = student["id"]
        student_label = f"{student_full_name(student)} ({adm})"
        try:
            ca1 = float(row.get("ca1") or 0)
            ca2 = float(row.get("ca2") or 0)
            ca3 = float(row.get("ca3") or 0) if ca3_enabled(config) else 0.0
            exam = float(row.get("exam") or 0)
        except ValueError:
            skipped.append(f"Row {i} ({student_label}, {subject_row['name']}): CA1/CA2/CA3/Exam must be numbers")
            continue

        row_errors = score_range_errors(config, ca1, ca2, ca3, exam)
        if row_errors:
            skipped.append(f"Row {i} ({student_label}, {subject_row['name']}): " + "; ".join(row_errors))
            continue

        try:
            save_score(conn, sid, subject_id, term["id"], ca1, ca2, ca3, exam, session["user_id"],
                       reason=request.form.get("change_reason"), source="csv_import")
        except ScoreChangeError as exc:
            skipped.append(f"Row {i} ({student_label}, {subject_row['name']}): {exc}")
            continue
        updated += 1

    conn.commit()
    conn.close()
    if updated:
        flash(f"Updated scores for {updated} student(s) from the uploaded file.", "success")
    if skipped:
        preview = "; ".join(skipped[:8]) + (f" (+{len(skipped)-8} more)" if len(skipped) > 8 else "")
        flash(f"Skipped {len(skipped)} row(s): {preview}", "error")
    return redirect(url_for("score_entry", class_id=class_id, subject_id=subject_id))


@app.route("/scores/<int:class_id>/<int:subject_id>/history")
@login_required()
def score_history_view(class_id, subject_id):
    conn = get_db()
    class_row = class_in_school(conn, class_id)
    subject_row = subject_in_school(conn, subject_id)
    if not class_row or not subject_row:
        conn.close()
        flash("Class or subject not found.", "error")
        return redirect(url_for("dashboard"))
    level = class_row["level"] if "level" in class_row.keys() else None
    if not can_access_scope(session.get("user_id"), current_school_id(), "view", school_level=level, class_id=class_id, subject_id=subject_id):
        conn.close()
        flash("You do not have permission for this class and subject.", "error")
        return redirect(url_for("dashboard"))
    cs = conn.execute("SELECT * FROM class_subjects WHERE class_id=? AND subject_id=?", (class_id, subject_id)).fetchone()
    if session["role"] == "teacher" and (not cs or cs["teacher_id"] != session["user_id"]):
        conn.close()
        flash("You are not assigned to teach this subject/class.", "error")
        return redirect(url_for("dashboard"))

    term_id = request.args.get("term_id", type=int)
    term_row = None
    if term_id:
        term_row = conn.execute("SELECT t.* FROM terms t JOIN sessions se ON se.id=t.session_id WHERE t.id=? AND se.school_id=?",
                                (term_id, current_school_id())).fetchone()
    if not term_row:
        term_row = resolve_term(conn, None)
    history = conn.execute(
        "SELECT * FROM score_audit WHERE school_id=? AND tenant_id=? AND class_id=? AND subject_id=? AND term_id=? ORDER BY id DESC",
        (current_school_id(), session.get("tenant_id"), class_id, subject_id, term_row["id"] if term_row else -1)
    ).fetchall()
    terms = all_terms_for_school(conn)
    conn.close()
    return render_template(
        "score_history.html", class_row=class_row, subject_row=subject_row, history=history,
        student_full_name=student_full_name, term=term_row, all_terms=terms,
    )


# ---------- broadsheet ----------

def build_broadsheet_data(conn, class_id, term_id):
    school_id = current_school_id()
    subjects = conn.execute(
        "SELECT s.* FROM subjects s JOIN class_subjects cs ON cs.subject_id=s.id "
        "WHERE cs.class_id=? ORDER BY s.name", (class_id,)
    ).fetchall()
    # Use the enrollment record for this term's session if one exists (so a
    # later promotion doesn't rewrite which class a student appears under
    # for a past term); fall back to their current class otherwise.
    term_row = conn.execute("SELECT session_id FROM terms WHERE id=?", (term_id,)).fetchone()
    session_id = term_row["session_id"] if term_row else None
    students = conn.execute(
        "SELECT s.* FROM students s "
        "LEFT JOIN enrollments e ON e.student_id = s.id AND e.session_id = ? "
        "WHERE COALESCE(e.class_id, s.class_id) = ? AND s.is_active=1 ORDER BY s.last_name",
        (session_id, class_id),
    ).fetchall()

    rows = []
    for st in students:
        subj_scores = {}
        total = 0
        count = 0
        for subj in subjects:
            score = conn.execute(
                "SELECT * FROM scores WHERE student_id=? AND subject_id=? AND term_id=?",
                (st["id"], subj["id"], term_id),
            ).fetchone()
            if score:
                t = compute_total(score["ca1"], score["ca2"], score["exam"], score["ca3"])
                grade, remark = grade_for(t, conn, school_id)
                subj_scores[subj["id"]] = {"total": t, "grade": grade}
                total += t
                count += 1
            else:
                subj_scores[subj["id"]] = {"total": "-", "grade": "-"}
        average = round(total / count, 2) if count else 0
        rows.append({
            "student": st, "scores": subj_scores, "total": total, "average": average
        })

    rows.sort(key=lambda r: r["total"], reverse=True)
    for i, r in enumerate(rows, start=1):
        r["position"] = i

    return subjects, rows


def build_cumulative_broadsheet_data(conn, class_id, session_id):
    """Annual/Cumulative broadsheet: for each subject, averages the totals
    from every term in the session that has a score recorded (a term with
    no score for that subject simply isn't counted — it doesn't drag the
    average down to 0), then ranks students by their overall cumulative
    average."""
    school_id = current_school_id()
    subjects = conn.execute(
        "SELECT s.* FROM subjects s JOIN class_subjects cs ON cs.subject_id=s.id "
        "WHERE cs.class_id=? ORDER BY s.name", (class_id,)
    ).fetchall()
    terms = terms_for_session(conn, session_id)
    students = conn.execute(
        "SELECT s.* FROM students s "
        "LEFT JOIN enrollments e ON e.student_id = s.id AND e.session_id = ? "
        "WHERE COALESCE(e.class_id, s.class_id) = ? AND s.is_active=1 ORDER BY s.last_name",
        (session_id, class_id),
    ).fetchall()

    rows = []
    for st in students:
        subj_cumulative = {}
        overall_total = 0
        overall_count = 0
        for subj in subjects:
            term_values = []
            present_totals = []
            for term in terms:
                score = conn.execute(
                    "SELECT * FROM scores WHERE student_id=? AND subject_id=? AND term_id=?",
                    (st["id"], subj["id"], term["id"]),
                ).fetchone()
                if score:
                    t = compute_total(score["ca1"], score["ca2"], score["exam"], score["ca3"])
                    term_values.append(t)
                    present_totals.append(t)
                else:
                    term_values.append(None)
            if present_totals:
                cum_avg = round(sum(present_totals) / len(present_totals), 2)
                grade, remark = grade_for(cum_avg, conn, school_id)
                overall_total += cum_avg
                overall_count += 1
            else:
                cum_avg, grade, remark = "-", "-", "-"
            subj_cumulative[subj["id"]] = {"term_values": term_values, "average": cum_avg, "grade": grade}
        overall_average = round(overall_total / overall_count, 2) if overall_count else 0
        rows.append({"student": st, "subjects": subj_cumulative, "average": overall_average})

    rows.sort(key=lambda r: r["average"], reverse=True)
    for i, r in enumerate(rows, start=1):
        r["position"] = i

    return subjects, terms, rows


def build_cumulative_result_data(conn, student_id, session_id):
    student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    class_id = student_class_for_session(conn, student_id, session_id)
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    subjects, terms, rows = build_cumulative_broadsheet_data(conn, class_id, session_id)

    my_row = next((r for r in rows if r["student"]["id"] == student_id), None)
    school_id = current_school_id()
    average = my_row["average"] if my_row else 0
    grade, remark = grade_for(average, conn, school_id) if my_row else ("-", "-")

    subject_details = []
    for subj in subjects:
        cell = my_row["subjects"][subj["id"]] if my_row else {"term_values": [None] * len(terms), "average": "-", "grade": "-"}
        subject_details.append({"name": subj["name"], **cell})

    return {
        "student": student, "class_row": class_row, "terms": terms, "subjects": subject_details,
        "average": average, "grade": grade, "remark": remark,
        "position": my_row["position"] if my_row else "-", "class_size": len(rows),
    }


@app.route("/broadsheet/<int:class_id>")
@login_required()
def broadsheet(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    subjects, rows = build_broadsheet_data(conn, class_id, term["id"])
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    all_terms = all_terms_for_school(conn)
    th = broadsheet_theme(conn)
    conn.close()
    return render_template(
        "broadsheet.html", subjects=subjects, rows=rows, class_row=class_row, term=term,
        student_full_name=student_full_name, all_terms=all_terms, th=th,
    )


def broadsheet_theme(conn):
    """The broadsheet INHERITS the result sheet's look: same colours, fonts, header (logo, school text, alignments), title
    and logo on/off switch. There is no separate colour/typography setup for broadsheets."""
    rs = result_sheet_settings(conn, current_school_id())
    school = get_school(conn, current_school_id())
    font = WEB_FONTS.get((school["web_font"] if school and school["web_font"] else "system"), WEB_FONTS["system"])
    return {"rs": rs, "accent": rs["accent"], "secondary": rs["secondary"], "logo": rs["logo"], "logo_path": rs["logo_path"],
            "logo_align": rs["logo_align"], "text_align": rs["text_align"], "school_name": rs["school_name"],
            "font_css": font["css"] if isinstance(font, dict) else font,
            "pdf_font": school["pdf_font"] if school and school["pdf_font"] else "Helvetica"}


@app.route("/broadsheet/<int:class_id>/print")
@login_required()
def broadsheet_print(class_id):
    """Print-only broadsheet: a standalone landscape A4 page with no sidebar, menus, buttons or dashboard."""
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    subjects, rows = build_broadsheet_data(conn, class_id, term["id"])
    class_row = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, current_school_id())).fetchone()
    th = broadsheet_theme(conn)
    conn.close()
    return render_template("broadsheet_print.html", kind="term", title="Broadsheet", subjects=subjects, rows=rows,
                           class_row=class_row, subtitle=f"{term['session_name']} — {term['name']}", logo=th["logo"], th=th,
                           school_name=th["school_name"], student_full_name=student_full_name,
                           back_url=url_for("broadsheet", class_id=class_id, term_id=term["id"]),
                           autoprint=bool(request.args.get("auto")))


@app.route("/cumulative/<int:class_id>/print")
@login_required()
def cumulative_broadsheet_print(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id) or require_cumulative_enabled(conn)
    if denied:
        conn.close()
        return denied
    session_row = resolve_session(conn, request.args.get("session_id", type=int))
    if not session_row:
        conn.close()
        flash("No academic session set up yet.", "error")
        return redirect(url_for("dashboard"))
    subjects, terms, rows = build_cumulative_broadsheet_data(conn, class_id, session_row["id"])
    class_row = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, current_school_id())).fetchone()
    th = broadsheet_theme(conn)
    conn.close()
    return render_template("broadsheet_print.html", kind="cumulative", title="Annual / Cumulative Broadsheet", subjects=subjects,
                           rows=rows, class_row=class_row, subtitle=session_row["name"], logo=th["logo"], th=th,
                           school_name=th["school_name"], student_full_name=student_full_name,
                           back_url=url_for("cumulative_broadsheet", class_id=class_id, session_id=session_row["id"]),
                           autoprint=bool(request.args.get("auto")))


@app.route("/broadsheet/<int:class_id>/pdf")
@login_required()
def broadsheet_pdf(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    subjects, rows = build_broadsheet_data(conn, class_id, term["id"])
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    school = get_school(conn, current_school_id())
    th = broadsheet_theme(conn)
    conn.close()
    buf = build_broadsheet_pdf(
        class_row, term, subjects, rows,
        school_name=school["name"] if school else None,
        logo_path=th["logo_path"], student_full_name=student_full_name,
        font_choice=th["pdf_font"], accent_color=th["accent"],
        logo_align=th["logo_align"], name_align=th["text_align"],
    )
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                      download_name=f"broadsheet_{class_row['name']}_{term['name']}.pdf".replace(" ", "_"))


@app.route("/cumulative/<int:class_id>")
@login_required()
def cumulative_broadsheet(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    denied = require_cumulative_enabled(conn)
    if denied:
        conn.close()
        return denied
    session_row = resolve_session(conn, request.args.get("session_id", type=int))
    if not session_row:
        conn.close()
        flash("No academic session set up yet.", "error")
        return redirect(url_for("dashboard"))
    subjects, terms, rows = build_cumulative_broadsheet_data(conn, class_id, session_row["id"])
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    all_sessions = conn.execute(
        "SELECT * FROM sessions WHERE school_id=? ORDER BY id DESC", (current_school_id(),)
    ).fetchall()
    th = broadsheet_theme(conn)
    conn.close()
    return render_template(
        "cumulative_broadsheet.html", class_row=class_row, academic_session=session_row, subjects=subjects,
        terms=terms, rows=rows, all_sessions=all_sessions, student_full_name=student_full_name, th=th,
    )


@app.route("/class/<int:class_id>/email_results", methods=["POST"])
@login_required()
def email_class_results(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    term = current_term(conn)
    if not term:
        conn.close()
        flash("No active term set.", "error")
        return redirect(url_for("dashboard"))
    if not term["is_published"]:
        conn.close()
        flash(
            "This term's results haven't been published yet. Ask your admin/principal to "
            "publish the term (Setup → Terms) before emailing results to parents.",
            "error",
        )
        return redirect(url_for("broadsheet", class_id=class_id))

    school = get_school(conn, current_school_id())
    students = conn.execute(
        "SELECT * FROM students WHERE class_id=? AND is_active=1 ORDER BY last_name", (class_id,)
    ).fetchall()

    sent, skipped = 0, 0
    for st in students:
        if not st["parent_email"]:
            skipped += 1
            continue
        data = build_result_data(conn, st["id"], term["id"])
        logo_path = None
        if school and school["logo_filename"]:
            p = os.path.join(INSTANCE_DIR, school["logo_filename"])
            if os.path.exists(p):
                logo_path = p
        pdf_buf = build_result_pdf(data, term, school_name=school["name"] if school else None,
                                    logo_path=logo_path, student_full_name=student_full_name,
                                    font_choice=school["pdf_font"] if school else "Helvetica")
        ok, _ = send_email(
            school, st["parent_email"],
            f"{student_full_name(st)}'s Result — {term['session_name']} {term['name']}",
            f"Please find attached {student_full_name(st)}'s result for {term['session_name']} {term['name']}.",
            attachment_bytes=pdf_buf.getvalue(),
            attachment_filename=f"result_{st['admission_no']}.pdf".replace("/", "-"),
        )
        if ok:
            sent += 1
        else:
            skipped += 1
    conn.close()
    flash(f"Emailed {sent} result(s). {skipped} skipped (no parent email on file, or sending failed).",
          "success" if sent else "error")
    return redirect(url_for("broadsheet", class_id=class_id))


# ---------- terminal result ----------

def compute_subject_positions(conn, student_ids, subject_ids, term_id):
    """{subject_id: {student_id: position}} using standard competition ranking (1,2,2,4): equal totals share a
    position. Only students with a recorded score in that subject are ranked. Calculated on every render, so the
    school can switch the display on later without recalculating anything."""
    out = {sj: {} for sj in subject_ids}
    if not student_ids or not subject_ids:
        return out
    ph_s, ph_j = ",".join("?" * len(student_ids)), ",".join("?" * len(subject_ids))
    rows = conn.execute(
        f"SELECT student_id, subject_id, ca1, ca2, ca3, exam FROM scores WHERE term_id=? AND student_id IN ({ph_s}) AND subject_id IN ({ph_j})",
        (term_id, *student_ids, *subject_ids)).fetchall()
    per = {}
    for r in rows:
        per.setdefault(r["subject_id"], []).append((r["student_id"], compute_total(r["ca1"], r["ca2"], r["exam"], r["ca3"])))
    for sj, lst in per.items():
        lst.sort(key=lambda x: -x[1])
        pos, prev, rank = 0, None, 0
        for i, (stu, tot) in enumerate(lst, 1):
            if tot != prev:
                rank = i
                prev = tot
            out[sj][stu] = rank
    return out


def _file_data_uri(path, max_side=900):
    """Inline an image so the printable sheet is self-contained (preview == print == screen).
    Large uploads used to be dropped silently (that is why a logo 'did not appear'); they are now scaled down with the
    aspect ratio preserved instead. Returns None only when the file is missing or is not an image."""
    import base64, io as _io, mimetypes
    try:
        if not path or not os.path.exists(path):
            return None
        mime = mimetypes.guess_type(path)[0] or "image/png"
        if not mime.startswith("image/"):
            return None
        raw = open(path, "rb").read()
        if len(raw) > 200 * 1024 or mime not in ("image/png", "image/jpeg", "image/gif"):
            try:
                from PIL import Image as _PI
                with _PI.open(_io.BytesIO(raw)) as im:
                    im.load()
                    if max(im.size) > max_side:
                        im.thumbnail((max_side, max_side))
                    has_alpha = im.mode in ("RGBA", "LA", "P")
                    buf = _io.BytesIO()
                    if has_alpha:
                        im.convert("RGBA").save(buf, "PNG", optimize=True); mime = "image/png"
                    else:
                        im.convert("RGB").save(buf, "JPEG", quality=88, optimize=True); mime = "image/jpeg"
                    raw = buf.getvalue()
            except Exception:
                if len(raw) > 600 * 1024:
                    return None
        return f"data:{mime};base64," + base64.b64encode(raw).decode()
    except OSError:
        return None


def ordinal_text(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    suf = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suf}"


def result_sheet_settings(conn, school_id):
    """Everything the result sheet needs from School Setup -> Result Display Settings.
    `rs["d"]` holds the on/off switches (see result_display.py); the HTML sheet, print page and PDF
    all read it, so a setting can never apply to one and not the others."""
    import result_display as RD
    sc = get_school(conn, school_id)
    k = sc.keys() if sc else []
    g = lambda name, default=None: (sc[name] if sc is not None and name in k and sc[name] is not None else default)
    d = RD.display_settings(sc)
    logo = None
    logo_path = None
    if sc is not None and g("logo_filename") and d["logo"]:
        logo_path = os.path.join(INSTANCE_DIR, sc["logo_filename"])
        logo = _file_data_uri(logo_path)
        if not logo:
            logo_path = None
    contact = " · ".join(x for x in (g("school_address"), g("registered_phone"), g("registered_email")) if x)
    tmpl = g("result_template", "classic")
    return {
        "d": d, "school_name": g("name", ""), "tagline": g("school_tagline"), "logo": logo, "logo_path": logo_path,
        "show_overall_position": d["overall_position"], "show_subject_position": d["subject_position"],
        "template": tmpl if tmpl in RD.TEMPLATE_KEYS else "classic",
        "title": g("result_title") or "Terminal Report Sheet", "footer": g("result_footer_text"),
        "watermark": (g("result_watermark_text") or g("name", "")) if d["watermark"] else None,
        "show_passport": d["passport"], "show_contact": d["contact"], "contact": contact,
        "show_grading_key": d["grading_key"], "show_promotion": d["promotion"],
        "accent": g("result_accent_color") or "#1f3a5f", "secondary": g("result_secondary_color") or "#c9a227",
        "logo_align": g("logo_align", "left") if g("logo_align", "left") in ("left", "center", "right") else "left",
        "text_align": g("name_align", "center") if g("name_align", "center") in ("left", "center", "right") else "center",
        "signature_layout": g("result_signature_layout", "split"),
    }


def custom_field_rows(conn, school_id, student_id, term_id, where="result"):
    """Enabled custom fields (this school only) with the student's value for the term.
    where='result' -> fields switched on for the result sheet; 'profile' -> for the student profile; 'edit' -> all enabled."""
    flag = {"result": "AND show_on_result=1", "profile": "AND show_on_profile=1", "edit": ""}[where]
    out = []
    for f in conn.execute(f"SELECT * FROM result_custom_fields WHERE school_id=? AND enabled=1 {flag} ORDER BY display_order, id", (school_id,)).fetchall():
        v = conn.execute("SELECT value FROM student_custom_values WHERE field_id=? AND student_id=? AND school_id=? AND term_id=?",
                         (f["id"], student_id, school_id, term_id if f["scope"] == "term" else 0)).fetchone()
        out.append({"id": f["id"], "label": f["label"], "type": f["field_type"], "scope": f["scope"],
                    "options": [o.strip() for o in (f["options"] or "").split(",") if o.strip()], "value": (v["value"] if v and v["value"] is not None else "")})
    return out


def save_custom_values(conn, school_id, student_id, term_id, form):
    """Store submitted custom field values. Only this school's enabled fields are accepted; values are validated by type."""
    errors = []
    for f in conn.execute("SELECT * FROM result_custom_fields WHERE school_id=? AND enabled=1", (school_id,)).fetchall():
        key = f"custom_{f['id']}"
        if key not in form:
            continue
        val = (form.get(key) or "").strip()[:200]
        if any(c in val for c in "<>"):
            errors.append(f"{f['label']}: angle brackets are not allowed."); continue
        if val:
            if f["field_type"] == "number" and not re.fullmatch(r"-?\d+(\.\d+)?", val):
                errors.append(f"{f['label']} must be a number."); continue
            if f["field_type"] == "date" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", val):
                errors.append(f"{f['label']} must be a date."); continue
            if f["field_type"] == "yesno" and val not in ("Yes", "No"):
                errors.append(f"{f['label']} must be Yes or No."); continue
            if f["field_type"] == "choice" and val not in [o.strip() for o in (f["options"] or "").split(",")]:
                errors.append(f"{f['label']}: choose one of the listed options."); continue
        tid = term_id if f["scope"] == "term" else 0
        conn.execute(
            "INSERT INTO student_custom_values(school_id,tenant_id,field_id,student_id,term_id,value,updated_by) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(field_id,student_id,term_id) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=CURRENT_TIMESTAMP",
            (school_id, current_tenant_id(), f["id"], student_id, tid, val, session.get("user_id")))
    return errors


def attendance_for_result(conn, student_id, term_id, info):
    """Days opened / present / absent for one result.
    The daily roll call is the source of truth: when it has records for this student and term the
    figures come straight from it (so nobody types them twice). Otherwise the manually entered values
    are used. Present + Absent always equals Days School Opened."""
    r = conn.execute(
        "SELECT COUNT(*) n, SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) p, "
        "SUM(CASE WHEN status='absent' THEN 1 ELSE 0 END) a FROM attendance_records WHERE student_id=? AND term_id=? AND COALESCE(is_deleted,0)=0",
        (student_id, term_id)).fetchone()
    if r and r["n"]:
        return {"opened": r["n"], "present": r["p"] or 0, "absent": r["a"] or 0, "source": "roll_call"}
    if info is not None:
        ks = info.keys()
        if "days_school_opened" in ks and info["days_school_opened"] is not None:
            return {"opened": info["days_school_opened"], "present": info["days_present"],
                    "absent": info["days_absent"], "source": "manual"}
    return {"opened": None, "present": None, "absent": None, "source": None}


def build_result_data(conn, student_id, term_id):
    student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    historical_class_id = student_class_for_term(conn, student_id, term_id)
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (historical_class_id,)).fetchone()
    subjects, rows = build_broadsheet_data(conn, historical_class_id, term_id)

    my_row = next((r for r in rows if r["student"]["id"] == student_id), None)
    class_size = len(rows)
    school_id = current_school_id()

    cohort_ids = [r["student"]["id"] for r in rows]
    subj_pos = compute_subject_positions(conn, cohort_ids, [x["id"] for x in subjects], term_id)
    subject_details = []
    subjects_written = 0
    for subj in subjects:
        score = conn.execute(
            "SELECT * FROM scores WHERE student_id=? AND subject_id=? AND term_id=?",
            (student_id, subj["id"], term_id),
        ).fetchone()
        if score:
            subjects_written += 1
            total = compute_total(score["ca1"], score["ca2"], score["exam"], score["ca3"])
            grade, remark = grade_for(total, conn, school_id)
            subject_details.append({
                "name": subj["name"], "ca1": score["ca1"], "ca2": score["ca2"], "ca3": score["ca3"] or 0,
                "exam": score["exam"], "total": total, "grade": grade, "remark": remark,
                "position": subj_pos.get(subj["id"], {}).get(student_id), "position_text": ordinal_text(subj_pos[subj["id"]][student_id]) if student_id in subj_pos.get(subj["id"], {}) else "-",
            })
        else:
            subject_details.append({
                "name": subj["name"], "ca1": "-", "ca2": "-", "ca3": "-", "exam": "-",
                "total": "-", "grade": "-", "remark": "-", "position": None, "position_text": "-"
            })

    info_row = conn.execute(
        "SELECT * FROM student_term_info WHERE student_id=? AND term_id=?", (student_id, term_id)
    ).fetchone()

    # info stays exactly as before (a Row, or None) unless this school has
    # turned on auto-generated comments — in which case we swap in a dict
    # with the comment field(s) computed from the student's grade, so
    # schools that never touch the new toggle see zero behavior change.
    info = info_row
    average = my_row["average"] if my_row else 0
    school = get_school(conn, school_id)
    if school and (school["auto_teacher_comment"] or school["auto_principal_comment"]):
        _, remark = grade_for(average, conn, school_id)
        info = dict(info_row) if info_row else {
            "days_school_opened": None, "days_present": None, "days_absent": None,
            "teacher_signed_date": None, "principal_signed_date": None,
            "teacher_comment": None, "principal_comment": None,
            "teacher_signed_by": None, "principal_signed_by": None,
        }
        if school["auto_teacher_comment"]:
            info["teacher_comment"] = generate_teacher_comment(remark, average, subjects_written)
        if school["auto_principal_comment"]:
            info["principal_comment"] = generate_principal_comment(remark, average, subjects_written)

    ratings = conn.execute(
        "SELECT st.name, st.category, r.rating FROM student_skill_ratings r "
        "JOIN skill_traits st ON st.id=r.trait_id WHERE r.student_id=? AND r.term_id=? AND COALESCE(st.is_active,1)=1 "
        "ORDER BY st.sort_order, st.name",
        (student_id, term_id),
    ).fetchall()
    ensure_school_v61_defaults(conn, school_id)
    domain_rows = conn.execute("SELECT * FROM educational_domains WHERE school_id=? AND is_active=1 ORDER BY sort_order, id", (school_id,)).fetchall()
    domain_groups = []
    for d in domain_rows:
        items = [(r["name"], r["rating"]) for r in ratings if r["category"] == d["domain_key"]]
        if items:
            domain_groups.append({"label": d["label"], "items": items})

    # Digital signatures: only shown when the specific signer recorded on
    # *this* result has one uploaded AND has turned it on — never "whoever
    # is logged in now", and teacher/principal are always looked up
    # separately so one can never appear in the other's slot.
    def _school_principal_id():
        """The school's Principal / Head Teacher: any staff member who currently HOLDS that role (multi-role aware)."""
        row = conn.execute(
            "SELECT u.id FROM users u WHERE u.school_id=? AND u.role='teacher' AND COALESCE(u.is_active,1)=1 AND ("
            " EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.user_id=u.id AND ra.school_id=u.school_id AND ra.status='active' "
            "         AND ra.role IN ('Principal','Head Teacher')) OR u.rbac_role IN ('Principal','Head Teacher') OR u.position='principal') "
            "ORDER BY (u.signature_filename IS NULL), u.id LIMIT 1", (school_id,)).fetchone()
        return row["id"] if row else None

    def _form_teacher_id():
        row = conn.execute("SELECT form_teacher_id FROM classes WHERE id=? AND school_id=?", (historical_class_id, school_id)).fetchone()
        return row["form_teacher_id"] if row else None

    def _signature_user(field):
        """Who signs: the person recorded on this result, otherwise the class's Form Teacher / the school's Principal.
        Works even before any result details were saved. Their uploaded signature is used when they have switched it on."""
        signer_id = info[field] if info and field in info.keys() else None
        if not signer_id:
            signer_id = _form_teacher_id() if field == "teacher_signed_by" else _school_principal_id()
        if not signer_id:
            return None
        row = conn.execute(
            "SELECT id, name, signature_filename, use_digital_signature FROM users WHERE id=? AND school_id=?",
            (signer_id, school_id),
        ).fetchone()
        if row and row["signature_filename"] and row["use_digital_signature"]:
            return row
        return None

    _d = result_sheet_settings(conn, school_id)["d"]
    teacher_signature_user = _signature_user("teacher_signed_by") if _d["teacher_signature"] else None
    principal_signature_user = _signature_user("principal_signed_by") if _d["principal_signature"] else None
    teacher_name = teacher_signature_user["name"] if teacher_signature_user and _d["teacher_name"] else None
    principal_name = principal_signature_user["name"] if principal_signature_user and _d["principal_name"] else None

    rs = result_sheet_settings(conn, school_id)
    # Passport: shown only when the setting is ON *and* the student has an uploaded photo. No photo -> a
    # blank passport area (never an avatar, initial, silhouette or placeholder).
    rs["passport"] = _file_data_uri(os.path.join(STUDENT_PHOTOS_DIR, student["photo_filename"])) if student["photo_filename"] and rs["show_passport"] else None
    rs["passport_path"] = os.path.join(STUDENT_PHOTOS_DIR, student["photo_filename"]) if rs["passport"] else None
    rs["teacher_sig"] = _file_data_uri(os.path.join(SIGNATURES_DIR, teacher_signature_user["signature_filename"])) if teacher_signature_user else None
    rs["principal_sig"] = _file_data_uri(os.path.join(SIGNATURES_DIR, principal_signature_user["signature_filename"])) if principal_signature_user else None
    rs["grading_scale"] = conn.execute("SELECT grade,min_score,max_score,remark FROM grade_scale WHERE school_id=? ORDER BY min_score DESC", (school_id,)).fetchall()
    rs["info_fields"] = [f for f in conn.execute("SELECT label,value FROM school_info_fields WHERE school_id=? AND show_on_result=1 AND COALESCE(value,'')<>'' ORDER BY display_order,id", (school_id,)).fetchall()]
    promotion = None
    if info is not None and "promotion_status" in info.keys():
        promotion = info["promotion_status"]
    return {
        "custom_fields": [f for f in custom_field_rows(conn, school_id, student_id, term_id, "result") if f["value"]],
        "custom_inputs": custom_field_rows(conn, school_id, student_id, term_id, "edit"),
        "rs": rs, "domain_groups": domain_groups, "position_text": ordinal_text(my_row["position"]) if my_row and str(my_row["position"]).isdigit() else (my_row["position"] if my_row else "-"),
        "promotion_status": promotion, "student_status": student["status"] if "status" in student.keys() else None,
        "student": student, "class_row": class_row, "subjects": subject_details,
        "total": my_row["total"] if my_row else 0,
        "average": my_row["average"] if my_row else 0,
        "position": my_row["position"] if my_row else "-",
        "class_size": class_size, "info": info, "ratings": ratings,
        "subjects_written": subjects_written,
        "show_ca3": ca3_enabled(conn.execute(
            "SELECT ca3_max FROM grading_config WHERE school_id=? LIMIT 1", (school_id,)).fetchone()),
        # The date saved on this student's result (never "today" and never an automatic issue date).
        "result_date": (format_dmy(info["result_date"]) if info is not None and "result_date" in info.keys() and info["result_date"] and _d["result_date"] else None),
        "result_date_raw": (info["result_date"] if info is not None and "result_date" in info.keys() else None),
        "attendance": attendance_for_result(conn, student_id, term_id, info),
        "teacher_signature_user": teacher_signature_user,
        "principal_signature_user": principal_signature_user,
        "teacher_signature_path": os.path.join(SIGNATURES_DIR, teacher_signature_user["signature_filename"]) if teacher_signature_user else None,
        "principal_signature_path": os.path.join(SIGNATURES_DIR, principal_signature_user["signature_filename"]) if principal_signature_user else None,
        "teacher_name": teacher_name, "principal_name": principal_name,
        "show_form_teacher_name": _d["teacher_name"], "show_form_teacher_signature": _d["teacher_signature"],
        "show_principal_name": _d["principal_name"], "show_principal_signature": _d["principal_signature"],
    }


@app.route("/result/<int:student_id>")
@login_required()
def result(student_id):
    conn = get_db()
    student_row = student_in_school(conn, student_id)
    if not student_row:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    historical_class_id = student_class_for_term(conn, student_id, term["id"])
    denied = require_class_result_access(conn, historical_class_id)
    if denied:
        conn.close()
        return denied
    data = build_result_data(conn, student_id, term["id"])
    all_traits = conn.execute("SELECT * FROM skill_traits WHERE school_id=? ORDER BY category, name", (current_school_id(),)).fetchall()
    all_terms = all_terms_for_school(conn)
    # Rating inputs: every active trait, grouped under its configured domain, with the student's current rating.
    current = {r["trait_id"]: r["rating"] for r in conn.execute(
        "SELECT trait_id, rating FROM student_skill_ratings WHERE student_id=? AND term_id=?", (student_id, term["id"]))}
    rating_groups = []
    for d in conn.execute("SELECT * FROM educational_domains WHERE school_id=? AND is_active=1 ORDER BY sort_order, id", (current_school_id(),)):
        items = [{"id": t["id"], "name": t["name"], "rating": current.get(t["id"])} for t in conn.execute(
            "SELECT * FROM skill_traits WHERE school_id=? AND category=? AND COALESCE(is_active,1)=1 ORDER BY sort_order, name", (current_school_id(), d["domain_key"]))]
        if items:
            rating_groups.append({"label": d["label"], "items": items})
    edit_perm = result_edit_permissions(conn, historical_class_id)
    conn.close()
    return render_template(
        "result.html", term=term, all_traits=all_traits, student_full_name=student_full_name,
        all_terms=all_terms, rating_groups=rating_groups, edit_perm=edit_perm, **data
    )


@app.route("/result/<int:student_id>/pdf")
@login_required()
def result_pdf(student_id):
    conn = get_db()
    student_row = student_in_school(conn, student_id)
    if not student_row:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    historical_class_id = student_class_for_term(conn, student_id, term["id"])
    denied = require_class_result_access(conn, historical_class_id)
    if denied:
        conn.close()
        return denied
    data = build_result_data(conn, student_id, term["id"])
    school = get_school(conn, current_school_id())
    logo_path = None
    if school and school["logo_filename"]:
        p = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(p):
            logo_path = p
    teacher_signature = None
    if data.get("teacher_signature_user"):
        u = data["teacher_signature_user"]
        teacher_signature = {"path": os.path.join(SIGNATURES_DIR, u["signature_filename"]), "name": u["name"]}
    principal_signature = None
    if data.get("principal_signature_user"):
        u = data["principal_signature_user"]
        principal_signature = {"path": os.path.join(SIGNATURES_DIR, u["signature_filename"]), "name": u["name"]}
    conn.close()
    buf = build_result_pdf(
        data, term, school_name=school["name"] if school else None,
        logo_path=logo_path, student_full_name=student_full_name,
        font_choice=school["pdf_font"] if school else "Helvetica",
        accent_color=school["result_accent_color"] if school and school["result_accent_color"] else "#1f3a5f",
        name_align=school["name_align"] if school else None,
        teacher_signature=teacher_signature, principal_signature=principal_signature,
    )
    fname = f"result_{data['student']['admission_no']}_{term['name']}.pdf".replace(" ", "_").replace("/", "-")
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)


@app.route("/cumulative/student/<int:student_id>")
@login_required()
def cumulative_result(student_id):
    conn = get_db()
    student_row = student_in_school(conn, student_id)
    if not student_row:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    denied = require_cumulative_enabled(conn)
    if denied:
        conn.close()
        return denied
    session_row = resolve_session(conn, request.args.get("session_id", type=int))
    if not session_row:
        conn.close()
        flash("No academic session set up yet.", "error")
        return redirect(url_for("dashboard"))
    historical_class_id = student_class_for_session(conn, student_id, session_row["id"])
    denied = require_class_result_access(conn, historical_class_id)
    if denied:
        conn.close()
        return denied
    data = build_cumulative_result_data(conn, student_id, session_row["id"])
    all_sessions = conn.execute(
        "SELECT * FROM sessions WHERE school_id=? ORDER BY id DESC", (current_school_id(),)
    ).fetchall()
    conn.close()
    return render_template(
        "cumulative_result.html", academic_session=session_row, all_sessions=all_sessions,
        student_full_name=student_full_name, **data
    )


@app.route("/cumulative/student/<int:student_id>/pdf")
@login_required()
def cumulative_result_pdf(student_id):
    conn = get_db()
    student_row = student_in_school(conn, student_id)
    if not student_row:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    denied = require_cumulative_enabled(conn)
    if denied:
        conn.close()
        return denied
    session_row = resolve_session(conn, request.args.get("session_id", type=int))
    if not session_row:
        conn.close()
        flash("No academic session set up yet.", "error")
        return redirect(url_for("dashboard"))
    historical_class_id = student_class_for_session(conn, student_id, session_row["id"])
    denied = require_class_result_access(conn, historical_class_id)
    if denied:
        conn.close()
        return denied
    data = build_cumulative_result_data(conn, student_id, session_row["id"])
    school = get_school(conn, current_school_id())
    logo_path = None
    if school and school["logo_filename"]:
        p = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(p):
            logo_path = p
    conn.close()
    buf = build_cumulative_result_pdf(
        data, session_row, school_name=school["name"] if school else None,
        logo_path=logo_path, student_full_name=student_full_name,
        font_choice=school["pdf_font"] if school else "Helvetica",
        accent_color=school["result_accent_color"] if school and school["result_accent_color"] else "#1f3a5f",
        name_align=school["name_align"] if school else None,
    )
    fname = f"annual_result_{data['student']['admission_no']}_{session_row['name']}.pdf".replace(" ", "_").replace("/", "-")
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)


@app.route("/result/<int:student_id>/email", methods=["POST"])
@login_required()
def email_result(student_id):
    conn = get_db()
    student_row = student_in_school(conn, student_id)
    if not student_row:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    denied = require_class_result_access(conn, student_row["class_id"])
    if denied:
        conn.close()
        return denied
    if not student_row["parent_email"]:
        conn.close()
        flash("This student has no parent email on file. Add one from Setup → Students.", "error")
        return redirect(url_for("result", student_id=student_id))

    term = current_term(conn)
    if not term:
        conn.close()
        flash("No active term set.", "error")
        return redirect(url_for("dashboard"))
    if not term["is_published"]:
        conn.close()
        flash(
            "This term's results haven't been published yet. Ask your admin/principal to "
            "publish the term (Setup → Terms) before emailing results to parents.",
            "error",
        )
        return redirect(url_for("result", student_id=student_id))

    data = build_result_data(conn, student_id, term["id"])
    school = get_school(conn, current_school_id())
    logo_path = None
    if school and school["logo_filename"]:
        p = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(p):
            logo_path = p
    pdf_buf = build_result_pdf(data, term, school_name=school["name"] if school else None,
                                logo_path=logo_path, student_full_name=student_full_name,
                                font_choice=school["pdf_font"] if school else "Helvetica")
    conn.close()
    ok, msg = send_email(
        school, student_row["parent_email"],
        f"{student_full_name(student_row)}'s Result — {term['session_name']} {term['name']}",
        f"Please find attached {student_full_name(student_row)}'s result for {term['session_name']} {term['name']}.",
        attachment_bytes=pdf_buf.getvalue(),
        attachment_filename=f"result_{student_row['admission_no']}.pdf".replace("/", "-"),
    )
    flash(msg, "success" if ok else "error")
    return redirect(url_for("result", student_id=student_id))


def result_edit_permissions(conn, class_id):
    """Who may change which part of a result. Teacher comment and Principal comment are separate fields
    with separate permissions: a class teacher cannot write the principal's comment (or sign date) and
    vice versa. The role is read from the current session, which is refreshed from the database on every
    request, so a role change by the School Admin applies immediately."""
    role = session.get("role")
    pos = session.get("position") or ""
    admin = role in ("admin", "sub_admin")
    principal = admin or any(r in ("Principal", "Head Teacher", "Vice Principal", "Vice Principal / Deputy Principal") for r in session_roles()) \
        or pos in ("principal", "vice_principal")
    is_ft = False
    if role == "teacher" and class_id:
        is_ft = "Class Teacher / Form Teacher" in session_roles() and int(class_id) in set(form_teacher_class_ids(conn, session.get("user_id")))
    can_ft = admin or principal or is_ft
    return {"teacher": can_ft, "principal": principal, "attendance": can_ft, "date": can_ft, "promotion": can_ft,
            "ratings": can_ft, "any": can_ft}


@app.route("/result/<int:student_id>/extra", methods=["POST"])
@login_required()
def result_extra(student_id):
    conn = get_db()
    student_row = student_in_school(conn, student_id)
    if not student_row:
        conn.close()
        flash("Student not found.", "error")
        return redirect(url_for("dashboard"))
    denied = require_class_result_access(conn, student_row["class_id"], permission="edit")
    if denied:
        conn.close()
        return denied
    term_id = request.form.get("term_id", type=int)
    if not term_id or not conn.execute("SELECT 1 FROM terms t JOIN sessions se ON se.id=t.session_id WHERE t.id=? AND se.school_id=?", (term_id, current_school_id())).fetchone():
        conn.close()
        flash("That term does not belong to your school.", "error")
        return redirect(url_for("result", student_id=student_id))
    back = url_for("result", student_id=student_id, term_id=term_id)
    perm = result_edit_permissions(conn, student_class_for_term(conn, student_id, term_id))
    if not perm["any"]:
        conn.close()
        flash("You do not have permission to change this result.", "error")
        return redirect(back)
    existing = conn.execute("SELECT * FROM student_term_info WHERE student_id=? AND term_id=?", (student_id, term_id)).fetchone()
    cur = dict(existing) if existing else {}

    def keep(field, default=None):
        return cur.get(field, default)

    def whole_number(name):
        raw = (request.form.get(name) or "").strip()
        if raw == "":
            return None
        if not re.fullmatch(r"-?\d{1,4}", raw):
            raise ValueError(f"{name.replace('_', ' ').title()} must be a whole number.")
        return int(raw)

    # --- attendance: only when the roll call has nothing for this student/term (otherwise it is automatic) ---
    roll = conn.execute("SELECT COUNT(*) n FROM attendance_records WHERE student_id=? AND term_id=? AND COALESCE(is_deleted,0)=0", (student_id, term_id)).fetchone()["n"]
    days_opened, days_present, days_absent = keep("days_school_opened"), keep("days_present"), keep("days_absent")
    attendance_source = keep("attendance_source")
    if perm["attendance"] and not roll and any(k in request.form for k in ("days_school_opened", "days_present", "days_absent")):
        try:
            o, p_, a_ = whole_number("days_school_opened"), whole_number("days_present"), whole_number("days_absent")
        except ValueError as exc:
            conn.close(); flash(str(exc), "error"); return redirect(back)
        if o is not None or p_ is not None or a_ is not None:
            o, p_, a_ = (o or 0), (p_ or 0), (a_ or 0)
            if o < 0 or p_ < 0 or a_ < 0:
                conn.close(); flash("Attendance figures can't be negative.", "error"); return redirect(back)
            if p_ > o:
                conn.close(); flash(f"Invalid attendance: Days Present ({p_}) cannot be more than Days School Opened ({o}).", "error"); return redirect(back)
            if a_ > o:
                conn.close(); flash(f"Invalid attendance: Days Absent ({a_}) cannot be more than Days School Opened ({o}).", "error"); return redirect(back)
            if p_ + a_ != o:
                conn.close()
                flash(f"Attendance figures do not agree: Days Present ({p_}) + Days Absent ({a_}) = {p_ + a_}, "
                      f"but Days School Opened is {o}. They must add up exactly.", "error")
                return redirect(back)
            days_opened, days_present, days_absent, attendance_source = o, p_, a_, "manual"

    promotion_status = keep("promotion_status")
    if perm["promotion"] and "promotion_status" in request.form:
        promotion_status = (request.form.get("promotion_status", "") or "").strip()[:80] or None

    # --- teacher part: comment + sign date (never touched by someone without the teacher permission) ---
    teacher_comment, teacher_signed_date, teacher_signed_by = keep("teacher_comment"), keep("teacher_signed_date"), keep("teacher_signed_by")
    if perm["teacher"] and "teacher_comment" in request.form:
        teacher_comment = request.form.get("teacher_comment", "").strip()[:1000]
    if perm["teacher"] and "teacher_signed_date" in request.form:
        new_td = request.form.get("teacher_signed_date", "").strip() or None
        if new_td and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", new_td):
            conn.close(); flash("Teacher sign date is not a valid date.", "error"); return redirect(back)
        teacher_signed_date = new_td
        if new_td and session.get("role") == "teacher":
            teacher_signed_by = session["user_id"]

    # --- principal part: its OWN comment field, its OWN sign date, its OWN permission ---
    principal_comment, principal_signed_date, principal_signed_by = keep("principal_comment"), keep("principal_signed_date"), keep("principal_signed_by")
    if perm["principal"] and "principal_comment" in request.form:
        principal_comment = request.form.get("principal_comment", "").strip()[:1000]
    if perm["principal"] and "principal_signed_date" in request.form:
        new_pd = request.form.get("principal_signed_date", "").strip() or None
        if new_pd and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", new_pd):
            conn.close(); flash("Principal sign date is not a valid date.", "error"); return redirect(back)
        principal_signed_date = new_pd
        # The SIGNER is the Principal. A School Admin typing the date does not become the signer (they would have no
        # signature image); the sheet then falls back to the school's Principal.
        if new_pd and session.get("role") == "teacher":
            principal_signed_by = session["user_id"]

    # --- result date: stored per student per term so it survives saving and reopening ---
    result_date = keep("result_date")
    if perm["date"] and "result_date" in request.form:
        new_rd = request.form.get("result_date", "").strip() or None
        if new_rd and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", new_rd):
            conn.close(); flash("Result date is not a valid date.", "error"); return redirect(back)
        result_date = new_rd

    if perm["teacher"]:
        cerrs = save_custom_values(conn, current_school_id(), student_id, term_id, request.form)
        if cerrs:
            conn.rollback(); conn.close(); flash(" ".join(cerrs), "error"); return redirect(back)
    conn.execute(
        "INSERT INTO student_term_info (student_id, term_id, days_present, days_absent, days_school_opened, attendance_source, "
        "teacher_comment, principal_comment, teacher_signed_date, principal_signed_date, teacher_signed_by, principal_signed_by, "
        "promotion_status, result_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(student_id, term_id) DO UPDATE SET days_present=excluded.days_present, days_absent=excluded.days_absent, "
        "days_school_opened=excluded.days_school_opened, attendance_source=excluded.attendance_source, "
        "teacher_comment=excluded.teacher_comment, principal_comment=excluded.principal_comment, "
        "teacher_signed_date=excluded.teacher_signed_date, principal_signed_date=excluded.principal_signed_date, "
        "teacher_signed_by=excluded.teacher_signed_by, principal_signed_by=excluded.principal_signed_by, "
        "promotion_status=excluded.promotion_status, result_date=excluded.result_date",
        (student_id, term_id, days_present if days_present is not None else 0, days_absent if days_absent is not None else 0,
         days_opened if days_opened is not None else 0, attendance_source, teacher_comment, principal_comment,
         teacher_signed_date, principal_signed_date, teacher_signed_by, principal_signed_by, promotion_status, result_date),
    )
    all_traits = conn.execute("SELECT * FROM skill_traits WHERE school_id=? AND COALESCE(is_active,1)=1", (current_school_id(),)).fetchall() if perm["ratings"] else []
    for trait in all_traits:
        val = request.form.get(f"trait_{trait['id']}")
        if val and val.isdigit() and 1 <= int(val) <= 5:
            conn.execute(
                "INSERT INTO student_skill_ratings (student_id, term_id, trait_id, rating) "
                "VALUES (?,?,?,?) ON CONFLICT(student_id, term_id, trait_id) "
                "DO UPDATE SET rating=excluded.rating",
                (student_id, term_id, trait["id"], int(val)),
            )
    conn.commit()
    conn.close()
    flash("Report card details updated.", "success")
    return redirect(back)


@app.route("/class/<int:class_id>/results")
@login_required()
def class_results_list(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    students = conn.execute(
        "SELECT s.* FROM students s "
        "LEFT JOIN enrollments e ON e.student_id = s.id AND e.session_id = ? "
        "WHERE COALESCE(e.class_id, s.class_id) = ? AND s.is_active=1 ORDER BY s.last_name",
        (term["session_id"], class_id),
    ).fetchall()
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    all_terms = all_terms_for_school(conn)
    conn.close()
    return render_template(
        "class_results_list.html", students=students, class_row=class_row, term=term,
        student_full_name=student_full_name, all_terms=all_terms,
    )


@app.route("/class/<int:class_id>/results_pdf")
@login_required()
def class_results_pdf(class_id):
    conn = get_db()
    denied = require_class_result_access(conn, class_id)
    if denied:
        conn.close()
        return denied
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("dashboard"))
    students = conn.execute(
        "SELECT s.* FROM students s "
        "LEFT JOIN enrollments e ON e.student_id = s.id AND e.session_id = ? "
        "WHERE COALESCE(e.class_id, s.class_id) = ? AND s.is_active=1 ORDER BY s.last_name",
        (term["session_id"], class_id),
    ).fetchall()
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    if not students:
        conn.close()
        flash("No students found for this class/term.", "error")
        return redirect(url_for("class_results_list", class_id=class_id, term_id=term["id"]))

    school = get_school(conn, current_school_id())
    logo_path = None
    if school and school["logo_filename"]:
        p = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(p):
            logo_path = p

    data_list = [build_result_data(conn, s["id"], term["id"]) for s in students]
    conn.close()
    buf = build_class_results_pdf(
        data_list, term, school_name=school["name"] if school else None,
        logo_path=logo_path, student_full_name=student_full_name,
        font_choice=school["pdf_font"] if school else "Helvetica",
        accent_color=school["result_accent_color"] if school and school["result_accent_color"] else "#1f3a5f",
        name_align=school["name_align"] if school else None,
    )
    fname = f"all_results_{class_row['name']}_{term['name']}.pdf".replace(" ", "_")
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)


@app.route("/classes")
@login_required()
def classes_list():
    conn = get_db()
    classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (current_school_id(),)).fetchall()
    accessible = get_accessible_class_ids(conn, session.get("role"), session.get("position"), session["user_id"])
    conn.close()
    return render_template("classes_list.html", classes=classes, accessible=accessible)


# ---------- learning materials ----------

def _material_extension(filename):
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _staff_accessible_classes(conn):
    """Classes this staff member is allowed to see materials for — the
    exact same rule already used for results/broadsheets, so a subject
    teacher who isn't a Form Teacher sees the same classes here as
    everywhere else in the app, no new permission surface."""
    accessible = get_accessible_class_ids(conn, session.get("role"), session.get("position"), session["user_id"])
    if accessible == "all":
        return conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (current_school_id(),)).fetchall()
    if not accessible:
        return []
    placeholders = ",".join("?" * len(accessible))
    return conn.execute(
        f"SELECT * FROM classes WHERE id IN ({placeholders}) ORDER BY name", accessible
    ).fetchall()


@app.route("/materials", methods=["GET", "POST"])
@login_required()
def materials():
    conn = get_db()
    school_id = current_school_id()
    can_upload = session.get("role") in ("admin", "sub_admin") and require_scoped_permission("create")

    if request.method == "POST":
        if not can_upload:
            conn.close()
            flash("You do not have permission to upload learning materials in your assigned scope.", "error")
            return redirect(url_for("materials"))
        session_id = request.form.get("session_id", type=int)
        class_id = request.form.get("class_id", type=int)
        subject_id = request.form.get("subject_id", type=int)
        title = request.form.get("title", "").strip()
        kind = request.form.get("kind", "Notes")
        external_url = request.form.get("external_url", "").strip()
        kind = kind if kind in MATERIAL_KINDS else "Notes"

        owner_session = conn.execute("SELECT * FROM sessions WHERE id=? AND school_id=?", (session_id, school_id)).fetchone()
        owner_class = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, school_id)).fetchone()
        owner_subject = conn.execute(
            "SELECT s.* FROM subjects s JOIN class_subjects cs ON cs.subject_id=s.id "
            "WHERE s.id=? AND cs.class_id=? AND s.school_id=?", (subject_id, class_id, school_id)
        ).fetchone()

        file = request.files.get("file")
        has_file = file and file.filename

        if not (owner_session and owner_class and owner_subject):
            flash("Choose a valid session, class and subject.", "error")
        elif not can_access_scope(session.get("user_id"), school_id, "create",
                                  school_level=owner_class["level"] if "level" in owner_class.keys() else None,
                                  class_id=class_id, subject_id=subject_id):
            flash("You do not have permission for this class and subject.", "error")
        elif not title:
            flash("Give the material a title.", "error")
        elif not has_file and not external_url:
            flash("Attach a file or provide a link.", "error")
        else:
            filename = original_filename = None
            if has_file:
                ext = _material_extension(file.filename)
                if ext not in MATERIAL_EXTENSIONS:
                    conn.close()
                    flash("File type not supported. Upload a PDF, Word, PowerPoint or image file — for videos, paste a link instead.", "error")
                    return redirect(url_for("materials"))
                size_error = _reject_oversize(file, "learning_material")
                if size_error:
                    conn.close(); flash(size_error, "error"); return redirect(url_for("materials", session_id=session_id, class_id=class_id, subject_id=subject_id))
                school_dir = os.path.join(MATERIALS_DIR, str(school_id))
                os.makedirs(school_dir, exist_ok=True)
                original_filename = secure_filename(file.filename)
                filename = f"{secrets.token_hex(8)}.{ext}"
                file.save(os.path.join(school_dir, filename))

            conn.execute(
                "INSERT INTO materials (school_id, session_id, class_id, subject_id, title, kind, "
                "filename, original_filename, external_url, uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (school_id, session_id, class_id, subject_id, title, kind,
                 filename, original_filename, external_url or None, session["user_id"]),
            )
            conn.commit()
            log_audit(conn, session["role"], session.get("name"), "material_upload",
                       f"{title} — {owner_class['name']} / {owner_subject['name']}", school_id=school_id)
            conn.commit()
            flash("Material uploaded.", "success")
        return redirect(url_for(
            "materials", session_id=session_id, class_id=class_id, subject_id=subject_id
        ))

    accessible_classes = _staff_accessible_classes(conn)
    accessible_ids = [c["id"] for c in accessible_classes]

    all_sessions = conn.execute("SELECT * FROM sessions WHERE school_id=? ORDER BY id DESC", (school_id,)).fetchall()
    active_session = conn.execute("SELECT * FROM sessions WHERE school_id=? AND is_active=1", (school_id,)).fetchone()
    session_id = request.args.get("session_id", type=int) or (active_session["id"] if active_session else None)

    class_id = request.args.get("class_id", type=int)
    if class_id not in accessible_ids:
        class_id = accessible_ids[0] if accessible_ids else None

    subjects = []
    items = []
    if class_id:
        subjects = conn.execute(
            "SELECT s.* FROM subjects s JOIN class_subjects cs ON cs.subject_id=s.id "
            "WHERE cs.class_id=? ORDER BY s.name", (class_id,)
        ).fetchall()
        subject_id = request.args.get("subject_id", type=int)
        query = (
            "SELECT m.*, sub.name as subject_name, u.name as uploaded_by_name FROM materials m "
            "JOIN subjects sub ON sub.id=m.subject_id LEFT JOIN users u ON u.id=m.uploaded_by "
            "WHERE m.class_id=? AND m.session_id=?"
        )
        params = [class_id, session_id]
        if subject_id:
            query += " AND m.subject_id=?"
            params.append(subject_id)
        query += " ORDER BY m.uploaded_at DESC"
        items = conn.execute(query, params).fetchall()

    conn.close()
    return render_template(
        "materials.html", can_upload=can_upload, accessible_classes=accessible_classes,
        all_sessions=all_sessions, session_id=session_id, class_id=class_id,
        subjects=subjects, items=items, kinds=MATERIAL_KINDS,
        selected_subject_id=request.args.get("subject_id", type=int),
    )


@app.route("/materials/<int:material_id>/delete", methods=["POST"])
@login_required("admin", "sub_admin")
def delete_material(material_id):
    conn = get_db()
    m = conn.execute("SELECT * FROM materials WHERE id=? AND school_id=?", (material_id, current_school_id())).fetchone()
    if not m:
        conn.close()
        flash("Material not found.", "error")
        return redirect(url_for("materials"))
    class_row = class_in_school(conn, m["class_id"])
    if not class_row or not can_access_scope(session.get("user_id"), current_school_id(), "delete",
                                             school_level=class_row["level"] if "level" in class_row.keys() else None,
                                             class_id=m["class_id"], subject_id=m["subject_id"]):
        conn.close()
        flash("You do not have permission to delete that material.", "error")
        return redirect(url_for("materials"))
    if m["filename"]:
        p = os.path.join(MATERIALS_DIR, str(current_school_id()), m["filename"])
        if os.path.exists(p):
            os.remove(p)
    conn.execute("DELETE FROM materials WHERE id=?", (material_id,))
    conn.commit()
    log_audit(conn, session["role"], session.get("name"), "material_delete", m["title"], school_id=current_school_id())
    conn.commit()
    conn.close()
    flash("Material removed.", "success")
    return redirect(url_for("materials", session_id=m["session_id"], class_id=m["class_id"]))


def _authorize_material_for_download(conn, material_id):
    """Returns the material row if the current staff member is allowed to
    see it — the same class-access rule already used for results and
    broadsheets — or None otherwise, so the caller can refuse."""
    m = conn.execute("SELECT * FROM materials WHERE id=? AND school_id=?", (material_id, current_school_id())).fetchone()
    if not m:
        return None
    class_row = class_in_school(conn, m["class_id"])
    if class_row and can_access_scope(session.get("user_id"), current_school_id(), "view",
                                      school_level=class_row["level"] if "level" in class_row.keys() else None,
                                      class_id=m["class_id"], subject_id=m["subject_id"]):
        return m
    if not can_view_class_results(conn, session.get("role"), session.get("position"), session.get("user_id"), m["class_id"]):
        return None
    return m


@app.route("/materials/<int:material_id>/download")
@login_required()
def download_material(material_id):
    conn = get_db()
    m = _authorize_material_for_download(conn, material_id)
    conn.close()
    if not m:
        flash("You don't have access to that material.", "error")
        return redirect(url_for("materials"))
    if m["external_url"]:
        return redirect(m["external_url"])
    return send_from_directory(
        os.path.join(MATERIALS_DIR, str(current_school_id())), m["filename"],
        as_attachment=True, download_name=m["original_filename"] or m["filename"],
    )


# ---------- staff attendance ----------

@app.route("/admin/staff-attendance", methods=["GET", "POST"])
@login_required("admin", "sub_admin")
def staff_attendance():
    conn = get_db()
    school_id = current_school_id()
    today = school_today(conn)
    requested = (request.values.get("date") or "").strip()
    if requested:
        problem = attendance_date_error(requested, today)
        if problem:
            attendance_audit_log(conn, "staff", None, requested, "rejected", reason=problem)
            conn.commit(); conn.close()
            flash(problem, "error")
            return redirect(url_for("staff_attendance"))
    date_str = today     # always today, in the school's timezone, from the server clock

    if request.method == "POST":
        staff = conn.execute("SELECT * FROM users WHERE school_id=? ORDER BY name", (school_id,)).fetchall()
        existing_rows = {r["user_id"]: r for r in conn.execute("SELECT * FROM staff_attendance WHERE school_id=? AND date=?", (school_id, date_str)).fetchall()}
        reason = (request.form.get("correction_reason") or "").strip()[:300]
        wanted = {}
        for member in staff:
            st = request.form.get(f"status_{member['id']}", "Present")
            wanted[member["id"]] = st if st in STAFF_ATTENDANCE_STATUSES else "Present"
        changes = [uid for uid, st in wanted.items() if uid in existing_rows and existing_rows[uid]["status"] != st]
        if changes and not reason:
            conn.close()
            flash("Today's staff attendance is already recorded. To change it, enter the reason for the correction.", "error")
            return redirect(url_for("staff_attendance"))
        counts = {x: 0 for x in STAFF_ATTENDANCE_STATUSES}
        stamp = server_utc_stamp()
        role_label = recorder_role_label()
        for member in staff:
            status = wanted[member["id"]]
            counts[status] += 1
            ex = existing_rows.get(member["id"])
            if ex is None:
                conn.execute(
                    "INSERT INTO staff_attendance (school_id,tenant_id,user_id,date,status,recorded_by,recorder_role,recorded_at,source) VALUES (?,?,?,?,?,?,?,?,'online')",
                    (school_id, current_tenant_id(), member["id"], date_str, status, session["user_id"], role_label, stamp))
                attendance_audit_log(conn, "staff", member["id"], date_str, "recorded", None, status)
            elif ex["status"] != status:
                conn.execute(
                    "UPDATE staff_attendance SET status=?, corrected_by=?, corrected_at=?, correction_note=?, original_status=COALESCE(original_status,?) "
                    "WHERE id=? AND school_id=?", (status, session["user_id"], stamp, reason, ex["status"], ex["id"], school_id))
                attendance_audit_log(conn, "staff", member["id"], date_str, "corrected", ex["status"], status, reason=reason)
        conn.commit()
        log_audit(conn, session["role"], session.get("name"), "staff_attendance",
                  f"{date_str}: " + ", ".join(f"{v} {k}" for k, v in counts.items() if v), school_id=school_id)
        conn.commit(); conn.close()
        flash(("Correction saved" if changes else "Staff attendance saved") + f" for {format_dmy(date_str)}.", "success")
        return redirect(url_for("staff_attendance", q=request.form.get("q", ""), status=request.form.get("filter_status", "")))

    q = request.args.get("q", "").strip().lower()
    filter_status = request.args.get("status", "").strip()
    params = [school_id]
    sql = "SELECT * FROM users WHERE school_id=?"
    if q:
        sql += " AND (LOWER(name) LIKE ? OR LOWER(COALESCE(username,'')) LIKE ? OR LOWER(COALESCE(position,'')) LIKE ?)"
        like = f"%{q}%"; params.extend([like, like, like])
    sql += " ORDER BY name"
    staff = conn.execute(sql, params).fetchall()
    rows = conn.execute("SELECT * FROM staff_attendance WHERE school_id=? AND date=?", (school_id, date_str)).fetchall()
    all_existing = {r["user_id"]: r for r in rows}
    existing = {uid: r for uid, r in all_existing.items() if not filter_status or r["status"] == filter_status}
    if filter_status:
        staff = [m for m in staff if m["id"] in existing]
    staff_role_map = {m["id"]: user_roles(conn, m["id"], school_id) for m in staff}
    clock = school_clock_text(conn)
    _, tz_name = school_tz(conn)
    conn.close()
    return render_template("staff_attendance.html", staff=staff, date_str=date_str, existing=existing, any_recorded=bool(all_existing),
                           today=today, statuses=STAFF_ATTENDANCE_STATUSES, position_labels=POSITION_LABELS,
                           search=q, filter_status=filter_status, clock=clock, tz_name=tz_name, staff_role_map=staff_role_map)


@app.route("/admin/staff-attendance/history")
@login_required()
def staff_attendance_history():
    conn = get_db()
    school_id = current_school_id()
    today = datetime.date.today()
    start = request.args.get("start", "").strip() or today.replace(day=1).isoformat()
    end = request.args.get("end", "").strip() or today.isoformat()
    try:
        datetime.date.fromisoformat(start)
        datetime.date.fromisoformat(end)
    except ValueError:
        start, end = today.replace(day=1).isoformat(), today.isoformat()

    if session.get("role") in ("admin", "sub_admin"):
        staff = conn.execute("SELECT * FROM users WHERE school_id=? ORDER BY role, name", (school_id,)).fetchall()
    else:
        staff = conn.execute("SELECT * FROM users WHERE id=? AND school_id=?", (session.get("user_id"), school_id)).fetchall()
    summaries = []
    for member in staff:
        counts = {s: 0 for s in STAFF_ATTENDANCE_STATUSES}
        rows = conn.execute(
            "SELECT status, COUNT(*) as c FROM staff_attendance "
            "WHERE school_id=? AND user_id=? AND date BETWEEN ? AND ? GROUP BY status",
            (school_id, member["id"], start, end),
        ).fetchall()
        for r in rows:
            counts[r["status"]] = r["c"]
        summaries.append({"staff": member, "counts": counts, "total": sum(counts.values())})

    days = conn.execute(
        "SELECT date, "
        "SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present, "
        "SUM(CASE WHEN status='Absent' THEN 1 ELSE 0 END) AS absent, "
        "SUM(CASE WHEN status='Late' THEN 1 ELSE 0 END) AS late, "
        "SUM(CASE WHEN status='Leave' THEN 1 ELSE 0 END) AS leave_count "
        "FROM staff_attendance WHERE school_id=? AND date BETWEEN ? AND ? GROUP BY date ORDER BY date DESC",
        (school_id, start, end),
    ).fetchall()
    conn.close()
    return render_template(
        "staff_attendance_history.html", summaries=summaries, days=days, start=start, end=end,
        position_labels=POSITION_LABELS,
    )


@app.route("/reports/staff_attendance")
@login_required("admin", "sub_admin")
def report_staff_attendance(fmt=None):
    fmt = request.args.get("format", "csv")
    conn = get_db()
    school_id = current_school_id()
    today = datetime.date.today()
    start = request.args.get("start", "").strip() or today.replace(day=1).isoformat()
    end = request.args.get("end", "").strip() or today.isoformat()
    try:
        datetime.date.fromisoformat(start)
        datetime.date.fromisoformat(end)
    except ValueError:
        start, end = today.replace(day=1).isoformat(), today.isoformat()

    staff = conn.execute("SELECT * FROM users WHERE school_id=? ORDER BY role, name", (school_id,)).fetchall()
    headers = ["Staff Name", "Role", "Present", "Absent", "Late", "Leave", "Days Recorded"]
    rows = []
    for member in staff:
        counts = {s: 0 for s in STAFF_ATTENDANCE_STATUSES}
        for r in conn.execute(
            "SELECT status, COUNT(*) as c FROM staff_attendance WHERE user_id=? AND date BETWEEN ? AND ? GROUP BY status",
            (member["id"], start, end),
        ).fetchall():
            counts[r["status"]] = r["c"]
        role_label = POSITION_LABELS.get(member["position"], member["role"].replace("_", " ").title())
        rows.append([
            member["name"], role_label, counts["Present"], counts["Absent"], counts["Late"], counts["Leave"],
            sum(counts.values()),
        ])
    conn.close()
    fname = f"staff_attendance_{start}_to_{end}".replace("/", "-")
    return _send_report(fmt, "Staff Attendance", headers, rows, fname, subtitle=f"{format_dmy(start)} to {format_dmy(end)}")


# ---------- staff self check-in/out ----------

@app.route("/staff-attendance/check-in", methods=["POST"])
@login_required()
def staff_attendance_check_in():
    conn=get_db(); sid=current_school_id(); uid=session.get("user_id")
    if session.get("role") not in ("admin","sub_admin","teacher"):
        conn.close(); return jsonify({"ok":False,"error":"You do not have permission to record Staff Attendance."}),403
    now=school_now(conn).replace(microsecond=0); date_str=now.date().isoformat(); stamp=now.strftime('%H:%M:%S')
    ex=conn.execute("SELECT * FROM staff_attendance WHERE school_id=? AND user_id=? AND date=?",(sid,uid,date_str)).fetchone()
    if ex is None:
        conn.execute("INSERT INTO staff_attendance (school_id,tenant_id,user_id,date,status,recorded_by,recorder_role,recorded_at,source,check_in_at) VALUES (?,?,?,?,?,?,?,?,'online',?)",
                     (sid,current_tenant_id(),uid,date_str,"Present",uid,recorder_role_label(),server_utc_stamp(),stamp))
        attendance_audit_log(conn,"staff",uid,date_str,"recorded",None,"Present",reason="Self check-in")
    else:
        if ex["check_in_at"]:
            conn.close(); return jsonify({"ok":True,"date":date_str,"time":ex["check_in_at"],"status":"checked_in","note":"Already checked in today."})
        if ex["status"]=="Absent":
            conn.execute("UPDATE staff_attendance SET status='Present', check_in_at=?, corrected_by=?, corrected_at=?, correction_note='Self check-in after being marked absent', original_status=COALESCE(original_status,?) WHERE id=? AND school_id=? AND user_id=?",
                         (stamp,uid,server_utc_stamp(),ex["status"],ex["id"],sid,uid))
            attendance_audit_log(conn,"staff",uid,date_str,"corrected","Absent","Present",reason="Self check-in after being marked absent")
        else:
            conn.execute("UPDATE staff_attendance SET check_in_at=? WHERE id=? AND school_id=? AND user_id=?",(stamp,ex["id"],sid,uid))
    conn.commit(); conn.close(); return jsonify({"ok":True,"date":date_str,"time":stamp,"status":"checked_in"})

@app.route("/staff-attendance/check-out", methods=["POST"])
@login_required()
def staff_attendance_check_out():
    conn=get_db(); sid=current_school_id(); uid=session.get("user_id")
    if session.get("role") not in ("admin","sub_admin","teacher"):
        conn.close(); return jsonify({"ok":False,"error":"You do not have permission to record Staff Attendance."}),403
    now=school_now(conn).replace(microsecond=0); date_str=now.date().isoformat()
    row=conn.execute("SELECT id FROM staff_attendance WHERE school_id=? AND user_id=? AND date=?",(sid,uid,date_str)).fetchone()
    if not row:
        conn.close(); return jsonify({"ok":False,"error":"Check in before checking out."}),400
    stamp=now.strftime('%H:%M:%S')
    conn.execute("UPDATE staff_attendance SET check_out_at=COALESCE(check_out_at,?) WHERE id=? AND school_id=? AND user_id=?",(stamp,row["id"],sid,uid))
    log_audit(conn,session.get("role"),session.get("name"),"staff_check_out",f"{date_str} {stamp}",school_id=sid)
    conn.commit(); conn.close(); return jsonify({"ok":True,"date":date_str,"time":stamp,"status":"checked_out"})

# ---------- reports & analytics ----------

@app.route("/reports")
@login_required()
def reports_hub():
    conn = get_db()
    school_id = current_school_id()
    all_classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (school_id,)).fetchall()
    classes = [c for c in all_classes if can_access_scope(session.get("user_id"), school_id, "view",
                                                         school_level=c["level"] if "level" in c.keys() else None,
                                                         class_id=c["id"])]
    all_terms = all_terms_for_school(conn)
    students = conn.execute(
        "SELECT s.*, c.name as class_name FROM students s JOIN classes c ON c.id=s.class_id "
        "WHERE c.school_id=? AND s.is_active=1 ORDER BY c.name, s.last_name", (school_id,)
    ).fetchall()
    conn.close()
    return render_template("reports_hub.html", classes=classes, all_terms=all_terms, students=students, student_full_name=student_full_name)


def _send_report(fmt, title, headers, rows, filename_base, subtitle=""):
    if fmt == "xlsx":
        buf = build_xlsx(title, headers, rows)
        return send_file(
            buf, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True, download_name=f"{filename_base}.xlsx",
        )
    if fmt == "pdf":
        conn = get_db()
        school = get_school(conn, current_school_id())
        logo_path = None
        if school and school["logo_filename"]:
            p = os.path.join(INSTANCE_DIR, school["logo_filename"])
            if os.path.exists(p):
                logo_path = p
        conn.close()
        buf = build_generic_table_pdf(
            title.upper(), subtitle, headers, rows,
            school_name=school["name"] if school else None, logo_path=logo_path,
            font_choice=school["pdf_font"] if school else "Helvetica",
        )
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=f"{filename_base}.pdf")
    buf = build_csv(headers, rows)
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name=f"{filename_base}.csv")


@app.route("/reports/broadsheet")
@login_required("admin", "sub_admin")
def report_broadsheet(fmt=None):
    fmt = request.args.get("format", "csv")
    class_id = request.args.get("class_id", type=int)
    conn = get_db()
    class_row = class_in_school(conn, class_id) if class_id else None
    if not class_row:
        conn.close()
        flash("Please choose a class.", "error")
        return redirect(url_for("reports_hub"))
    if not can_access_scope(session.get("user_id"), current_school_id(), "view",
                            school_level=class_row["level"] if "level" in class_row.keys() else None, class_id=class_id):
        conn.close()
        flash("You do not have permission to view this class report.", "error")
        return redirect(url_for("reports_hub"))
    term = resolve_term(conn, request.args.get("term_id", type=int))
    subjects, rows_data = build_broadsheet_data(conn, class_id, term["id"])
    conn.close()

    headers = ["S/N", "Admission No. / Register No.", "Student Name"] + [s["name"] for s in subjects] + ["Total", "Average", "Position"]
    rows = []
    for i, r in enumerate(rows_data, start=1):
        row = [i, r["student"]["admission_no"], student_full_name(r["student"])]
        for subj in subjects:
            row.append(r["scores"][subj["id"]]["total"])
        row.extend([r["total"], r["average"], r["position"]])
        rows.append(row)

    fname = f"broadsheet_{class_row['name']}_{term['name']}".replace(" ", "_")
    return _send_report(fmt, "Broadsheet", headers, rows, fname)


@app.route("/reports/subject_performance")
@login_required("admin", "sub_admin")
def report_subject_performance(fmt=None):
    fmt = request.args.get("format", "csv")
    conn = get_db()
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("reports_hub"))

    school_id = current_school_id()
    all_classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (school_id,)).fetchall()
    classes = [c for c in all_classes if can_access_scope(session.get("user_id"), school_id, "view",
                                                         school_level=c["level"] if "level" in c.keys() else None, class_id=c["id"])]
    headers = ["Class", "Subject", "Students with Scores", "Average", "Highest", "Lowest"]
    rows = []
    for class_row in classes:
        subjects, rows_data = build_broadsheet_data(conn, class_row["id"], term["id"])
        for subj in subjects:
            totals = [
                r["scores"][subj["id"]]["total"] for r in rows_data
                if r["scores"][subj["id"]]["total"] != "-"
            ]
            if totals:
                rows.append([
                    class_row["name"], subj["name"], len(totals),
                    round(sum(totals) / len(totals), 2), max(totals), min(totals),
                ])
            else:
                rows.append([class_row["name"], subj["name"], 0, "-", "-", "-"])
    conn.close()

    fname = f"subject_performance_{term['session_name']}_{term['name']}".replace(" ", "_").replace("/", "-")
    return _send_report(fmt, "Subject Performance", headers, rows, fname)


@app.route("/reports/attendance")
@login_required("admin", "sub_admin")
def report_attendance(fmt=None):
    fmt = request.args.get("format", "csv")
    conn = get_db()
    term = resolve_term(conn, request.args.get("term_id", type=int))
    if not term:
        conn.close()
        flash("No term set yet.", "error")
        return redirect(url_for("reports_hub"))
    class_id = request.args.get("class_id", type=int)

    school_id = current_school_id()
    if class_id:
        class_row = class_in_school(conn, class_id)
        if not class_row or not can_access_scope(session.get("user_id"), school_id, "view",
                                                 school_level=class_row["level"] if "level" in class_row.keys() else None, class_id=class_id):
            conn.close()
            flash("You do not have permission to view attendance for this class.", "error")
            return redirect(url_for("reports_hub"))
    query = (
        "SELECT s.*, c.name as class_name, sti.days_school_opened, sti.days_present, sti.days_absent "
        "FROM students s JOIN classes c ON c.id=s.class_id "
        "LEFT JOIN student_term_info sti ON sti.student_id=s.id AND sti.term_id=? "
        "WHERE c.school_id=? AND s.is_active=1"
    )
    params = [term["id"], school_id]
    if class_id:
        query += " AND c.id=?"
        params.append(class_id)
    query += " ORDER BY c.name, s.last_name"
    students = conn.execute(query, params).fetchall()
    conn.close()

    headers = ["Admission No. / Register No.", "Student Name", "Class", "Days School Opened", "Days Present", "Days Absent", "Attendance %"]
    rows = []
    for s in students:
        opened = s["days_school_opened"] or 0
        present = s["days_present"] or 0
        absent = s["days_absent"] or 0
        pct = round((present / opened) * 100, 1) if opened else "-"
        rows.append([s["admission_no"], student_full_name(s), s["class_name"], opened, present, absent, pct])

    fname = f"attendance_{term['session_name']}_{term['name']}".replace(" ", "_").replace("/", "-")
    return _send_report(fmt, "Attendance", headers, rows, fname)


@app.route("/reports/student_history")
@login_required("admin", "sub_admin")
def report_student_history(fmt=None):
    fmt = request.args.get("format", "csv")
    student_id = request.args.get("student_id", type=int)
    conn = get_db()
    student = student_in_school(conn, student_id) if student_id else None
    if not student:
        conn.close()
        flash("Please choose a student.", "error")
        return redirect(url_for("reports_hub"))
    student_class = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (student["class_id"], current_school_id())).fetchone()
    if not student_class or not can_access_scope(session.get("user_id"), current_school_id(), "view",
                                                 school_level=student_class["level"] if "level" in student_class.keys() else None, class_id=student_class["id"]):
        conn.close()
        flash("You do not have permission to view this student's history.", "error")
        return redirect(url_for("reports_hub"))

    terms = all_terms_for_school(conn)
    headers = ["Session", "Term", "Class / Arm", "Subject", "CA1", "CA2", "Exam", "Total", "Grade"]
    rows = []
    school_id = current_school_id()
    for term in terms:
        enrolled = conn.execute(
            "SELECT 1 FROM enrollments WHERE student_id=? AND session_id=?", (student_id, term["session_id"])
        ).fetchone()
        if not enrolled:
            continue
        class_id = student_class_for_term(conn, student_id, term["id"])
        class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
        subjects = conn.execute(
            "SELECT s.* FROM subjects s JOIN class_subjects cs ON cs.subject_id=s.id WHERE cs.class_id=? ORDER BY s.name",
            (class_id,),
        ).fetchall()
        for subj in subjects:
            score = conn.execute(
                "SELECT * FROM scores WHERE student_id=? AND subject_id=? AND term_id=?",
                (student_id, subj["id"], term["id"]),
            ).fetchone()
            if score:
                total = compute_total(score["ca1"], score["ca2"], score["exam"], score["ca3"])
                grade, _ = grade_for(total, conn, school_id)
                rows.append([term["session_name"], term["name"], class_row["name"], subj["name"],
                             score["ca1"], score["ca2"], score["exam"], total, grade])
    conn.close()

    fname = f"academic_history_{student['admission_no']}".replace("/", "-")
    return _send_report(fmt, "Academic History", headers, rows, fname)




def student_login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "student_id" not in session:
            return redirect(url_for("student_login"))
        # A student session must never outlive or cross its account: re-check the
        # student, class, school and tenant on every request.
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT s.id, s.is_active, s.tenant_id AS s_tenant, c.school_id, sc.tenant_id AS school_tenant, "
                "sc.activation_status, sc.is_suspended, sc.is_archived "
                "FROM students s JOIN classes c ON c.id=s.class_id JOIN schools sc ON sc.id=c.school_id "
                "WHERE s.id=?", (session["student_id"],)).fetchone()
        finally:
            conn.close()
        ok = bool(row and row["is_active"] and session.get("school_id") == row["school_id"]
                  and session.get("tenant_id") == row["school_tenant"]
                  and row["activation_status"] == "active" and not row["is_suspended"] and not row["is_archived"])
        if not ok:
            session.clear()
            flash("Your session is no longer valid. Please sign in again.", "error")
            return redirect(url_for("student_login"))
        return f(*args, **kwargs)
    return wrapped


@app.route("/student/login", methods=["GET", "POST"])
@rate_limit(max_attempts=10, window_seconds=300)
def student_login():
    if request.method == "POST":
        try:
            return _student_login_post()
        except Exception:
            # Full technical detail goes to the server log; the student sees a clear, safe message.
            app.logger.exception("Student login failed unexpectedly")
            flash("We could not complete your sign-in right now. Please try again shortly or contact your school.", "error")
            return render_template("student_login.html"), 500
    return render_template("student_login.html")


STUDENT_MAX_FAILS = 8
STUDENT_LOCK_MINUTES = 15
_DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing")
GENERIC_STUDENT_LOGIN_ERROR = "Invalid login details. Please check them and try again."


def normalize_class_code(raw):
    return re.sub(r"[^A-Z0-9]", "", str(raw or "").upper())


def find_active_class_code(conn, raw_code):
    """Return the class_login_codes row for a live code, or None. Expired codes are retired on sight."""
    code = normalize_class_code(raw_code)
    if len(code) < 6:
        return None
    row = conn.execute("SELECT * FROM class_login_codes WHERE code=? AND status='active'", (code,)).fetchone()
    if not row:
        return None
    if row["expires_at"] and row["expires_at"] < datetime.datetime.utcnow().isoformat(timespec="seconds"):
        conn.execute("UPDATE class_login_codes SET status='expired', ended_at=CURRENT_TIMESTAMP, end_reason='expired' WHERE id=? AND status='active'", (row["id"],))
        conn.commit()
        return None
    return row


def _student_login_post():
    identifier = (request.form.get("identifier") or request.form.get("username") or "").strip()[:60]
    password = request.form.get("password", "")
    # The Class Login Code is for enrolment/linking only. It is never needed (and never checked) for normal sign-in.
    hint = request.form.get("school_code", "").strip().lower()
    now = datetime.datetime.utcnow()
    now_iso = now.isoformat(timespec="seconds")

    def fail(msg=GENERIC_STUDENT_LOGIN_ERROR):
        flash(msg, "error")
        return render_template("student_login.html")

    conn = get_db()
    try:
        candidates = []
        if identifier and password:
            ident = identifier.lower()
            # Username, Admission No. or Register No. + password. The school/tenant always comes from the matched student's own record.
            candidates = conn.execute(
                "SELECT st.*, COALESCE(c.school_id, st.school_id) AS cls_school, st.class_id AS cls_id FROM students st "
                "LEFT JOIN classes c ON c.id=st.class_id "
                "WHERE (LOWER(st.username)=? OR LOWER(TRIM(st.admission_no))=? "
                "OR LOWER(TRIM(COALESCE(st.register_no,'')))=?)", (ident, ident, ident)).fetchall()
        code_row = None
        # The tenant always comes from the matched student's own class/school, never from the browser.
        # A school hint or a class code can only NARROW the candidates; it never grants access.
        schools = {}
        scoped = []
        for st in candidates:
            sc = schools.get(st["cls_school"]) or get_school(conn, st["cls_school"])
            schools[st["cls_school"]] = sc
            if not sc:
                continue
            if hint and hint not in {str(sc["school_code"] or "").lower(), str(sc["tenant_id"] or "").lower(),
                                     str(sc["school_id_public"] or "").lower(), str(sc["id"])}:
                continue
            scoped.append(st)
        matches = []
        locked_seen = False
        for st in scoped:
            locked = bool(st["locked_until"] and st["locked_until"] > now_iso)
            locked_seen = locked_seen or locked
            has_pw = bool(st["password_hash"])
            ok = check_password_hash(st["password_hash"] if has_pw else _DUMMY_PASSWORD_HASH, password)
            if ok and has_pw and not locked:
                matches.append(st)
        if not scoped:
            check_password_hash(_DUMMY_PASSWORD_HASH, password or "x")   # constant-ish timing for unknown identifiers
        if len(matches) > 1:
            # Several schools have a student with this number AND this exact password. Only reachable with a correct
            # password, so it leaks nothing; we refuse rather than guess whose account to open.
            return fail("Your details match more than one school. Open \"Two schools use my number?\", enter your School ID and try again.")
        # Count failures against the accounts this identifier points to (only when the password was wrong).
        if len(matches) != 1:
            for st in scoped:
                if st in matches:
                    continue
                fails = (st["failed_logins"] or 0) + 1
                lock = (now + datetime.timedelta(minutes=STUDENT_LOCK_MINUTES)).isoformat(timespec="seconds") if fails >= STUDENT_MAX_FAILS else st["locked_until"]
                conn.execute("UPDATE students SET failed_logins=?, locked_until=? WHERE id=?", (0 if fails >= STUDENT_MAX_FAILS else fails, lock, st["id"]))
            if scoped:
                conn.commit()
            try:
                security_event(conn, "STUDENT_LOGIN_FAILED", "failed", f"identifier_len={len(identifier)} candidates={len(scoped)} locked={locked_seen}", "student")
                conn.commit()
            except Exception:
                pass
            return fail()
        student = matches[0]
        school = schools[student["cls_school"]]
        # ---- the account must be linked to a real class of its own school (checked only after the credentials proved who this is) ----
        if not conn.execute("SELECT 1 FROM classes WHERE id=? AND school_id=?", (student["class_id"], school["id"])).fetchone():
            app.logger.error("Student %s has a missing/foreign class link (class_id=%s); login blocked", student["id"], student["class_id"])
            return fail("Your account is not linked to a class yet. Please contact the school office.")
        # ---- the account itself must be active (checked only after the credentials proved who this is) ----
        st_status = (student["status"] if "status" in student.keys() and student["status"] else "Active")
        if not student["is_active"] or st_status != "Active":
            label = st_status if st_status != "Active" else "inactive"
            return fail(f"This student account is not active (status: {label}). Please contact the school office.")
        # ---- school state (only reported after the credentials proved who this is) ----
        if school["activation_status"] != "active":
            return fail("This school hasn't been activated yet.")
        if school["is_archived"]:
            return fail("This school's account has been archived. Contact the platform administrator.")
        if school["is_suspended"]:
            return fail("This school's account has been suspended. Contact the platform administrator.")
        if not subscription_login_allowed(school):
            return fail("This school's subscription or trial has expired. Contact the platform administrator.")
        if g.portal_school and school["id"] != g.portal_school["id"]:
            return fail(GENERIC_STUDENT_LOGIN_ERROR)
        if not school["tenant_id"]:
            app.logger.error("School %s has no tenant_id; student login blocked", school["id"])
            return fail("This school's account setup is incomplete. Please contact the platform administrator.")
        conn.execute("UPDATE students SET failed_logins=0, locked_until=NULL, last_login_at=?, "
                     "first_login_completed_at=COALESCE(first_login_completed_at, ?) WHERE id=?", (now_iso, now_iso, student["id"]))
        conn.commit()
        session.clear()
        session["student_id"] = student["id"]
        session["role"] = "student"
        session["school_id"] = school["id"]
        session["tenant_id"] = school["tenant_id"]
        session["school_code"] = school["school_code"]
        session["login_time"] = now_iso
        return redirect(url_for("student_dashboard"))
    finally:
        conn.close()


@app.route("/student/logout")
def student_logout():
    session.clear()
    return redirect(url_for("student_login"))


@app.route("/student/dashboard")
@student_login_required
def student_dashboard():
    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE id=?", (session["student_id"],)).fetchone()
    if not student:
        session.clear()
        conn.close()
        return redirect(url_for("student_login"))
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (student["class_id"],)).fetchone()
    published_terms = conn.execute(
        "SELECT terms.*, sessions.name as session_name FROM terms "
        "JOIN sessions ON sessions.id = terms.session_id "
        "JOIN enrollments e ON e.session_id = sessions.id "
        "WHERE e.student_id=? AND terms.is_published=1 "
        "ORDER BY sessions.id DESC, terms.id DESC",
        (student["id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "student_dashboard.html", student=student, class_row=class_row,
        published_terms=published_terms, student_full_name=student_full_name,
    )


@app.route("/parent/messages/<int:student_id>/<int:teacher_id>",methods=["GET","POST"])
@parent_login_required
def parent_message_thread(student_id,teacher_id):
    conn=get_db(); child=parent_child(conn,session["parent_id"],student_id)
    teacher=conn.execute("SELECT u.* FROM users u WHERE u.id=? AND u.school_id=? AND u.role='teacher' AND COALESCE(u.is_active,1)=1 AND (EXISTS(SELECT 1 FROM class_subjects cs WHERE cs.teacher_id=u.id AND cs.class_id=?) OR EXISTS(SELECT 1 FROM classes c WHERE c.form_teacher_id=u.id AND c.id=?))",(teacher_id,current_school_id(),child["class_id"] if child else -1,child["class_id"] if child else -1)).fetchone() if child else None
    if not child or not teacher:
        conn.close(); flash("That teacher is not authorized for this child.","error"); return redirect(url_for("parent_children_page"))
    if request.method=="POST":
        body=request.form.get("body","").strip()
        if not body or len(body)>4000: flash("Message must contain 1–4000 characters.","error")
        else:
            conn.execute("INSERT INTO parent_teacher_messages(school_id,parent_id,teacher_id,student_id,body,sender_type) VALUES (?,?,?,?,?,'parent')",(current_school_id(),session["parent_id"],teacher_id,student_id,body))
            conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",(session.get("name","Parent"),current_school_id(),"teacher","New parent message",f"A parent sent you a message about {student_full_name(child)}."))
            conn.commit(); flash("Message sent.","success")
    messages=conn.execute("SELECT * FROM parent_teacher_messages WHERE school_id=? AND parent_id=? AND teacher_id=? AND student_id=? ORDER BY id",(current_school_id(),session["parent_id"],teacher_id,student_id)).fetchall()
    conn.execute("UPDATE parent_teacher_messages SET is_read=1 WHERE school_id=? AND parent_id=? AND teacher_id=? AND student_id=? AND sender_type='teacher'",(current_school_id(),session["parent_id"],teacher_id,student_id)); conn.commit(); conn.close()
    return render_template("parent_message_thread.html",child=child,teacher=teacher,messages=messages)


@app.route("/teacher/parent-messages")
@login_required("admin","sub_admin","teacher")
def teacher_parent_messages():
    conn=get_db(); school_id=current_school_id(); teacher_id=session["user_id"]
    threads=conn.execute("SELECT m.parent_id,m.student_id,m.teacher_id,MAX(m.id) latest_id,MAX(m.created_at) latest_at,p.name parent_name,s.first_name||' '||s.last_name student_name,c.name class_name,SUM(CASE WHEN m.sender_type='parent' AND m.is_read=0 THEN 1 ELSE 0 END) unread FROM parent_teacher_messages m JOIN parent_accounts p ON p.id=m.parent_id JOIN students s ON s.id=m.student_id JOIN classes c ON c.id=s.class_id WHERE m.school_id=? AND m.teacher_id=? GROUP BY m.parent_id,m.student_id,m.teacher_id ORDER BY latest_id DESC",(school_id,teacher_id)).fetchall()
    conn.close(); return render_template("teacher_parent_messages.html",threads=threads)


@app.route("/teacher/parent-messages/<int:parent_id>/<int:student_id>",methods=["GET","POST"])
@login_required("admin","sub_admin","teacher")
def teacher_parent_thread(parent_id,student_id):
    conn=get_db(); school_id=current_school_id(); teacher_id=session["user_id"]
    child=conn.execute("SELECT s.*,c.name class_name FROM students s JOIN classes c ON c.id=s.class_id WHERE s.id=? AND c.school_id=?",(student_id,school_id)).fetchone()
    parent=conn.execute("SELECT p.* FROM parent_accounts p JOIN parent_students ps ON ps.parent_id=p.id WHERE p.id=? AND ps.student_id=? AND p.school_id=?",(parent_id,student_id,school_id)).fetchone()
    authorized=bool(child and parent and (conn.execute("SELECT 1 FROM class_subjects WHERE teacher_id=? AND class_id=?",(teacher_id,child["class_id"])).fetchone() or conn.execute("SELECT 1 FROM classes WHERE id=? AND form_teacher_id=?",(child["class_id"],teacher_id)).fetchone() or session.get("role") in ("admin","sub_admin")))
    if not authorized:
        conn.close(); flash("You are not authorized to access this conversation.","error"); return redirect(url_for("teacher_parent_messages"))
    if request.method=="POST":
        body=request.form.get("body","").strip()
        if body and len(body)<=4000:
            conn.execute("INSERT INTO parent_teacher_messages(school_id,parent_id,teacher_id,student_id,body,sender_type,is_read) VALUES (?,?,?,?,?,'teacher',1)",(school_id,parent_id,teacher_id,student_id,body))
            conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",(session.get("name","Teacher"),school_id,"parent","Teacher replied",f"Your teacher replied about {student_full_name(child)}."))
            conn.commit(); flash("Reply sent.","success")
    messages=conn.execute("SELECT * FROM parent_teacher_messages WHERE school_id=? AND parent_id=? AND teacher_id=? AND student_id=? ORDER BY id",(school_id,parent_id,teacher_id,student_id)).fetchall()
    conn.execute("UPDATE parent_teacher_messages SET is_read=1 WHERE school_id=? AND parent_id=? AND teacher_id=? AND student_id=? AND sender_type='parent'",(school_id,parent_id,teacher_id,student_id)); conn.commit(); conn.close()
    return render_template("teacher_parent_thread.html",parent=parent,child=child,messages=messages)


@app.route("/student/notifications")
@student_login_required
def student_notifications():
    conn = get_db()
    notifications = notification_rows(conn, notification_reader())
    conn.close()
    return render_template("notifications_inbox.html", notifications=notifications)


@app.route("/student/materials")
@student_login_required
def student_materials():
    conn = get_db()
    student_id = session["student_id"]
    student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    if not student:
        session.clear()
        conn.close()
        return redirect(url_for("student_login"))

    # A student may only browse sessions they were actually enrolled in —
    # never an arbitrary session_id typed into the URL.
    enrolled_sessions = conn.execute(
        "SELECT sessions.* FROM sessions JOIN enrollments e ON e.session_id=sessions.id "
        "WHERE e.student_id=? ORDER BY sessions.id DESC", (student_id,)
    ).fetchall()
    active_session = conn.execute(
        "SELECT * FROM sessions WHERE school_id=? AND is_active=1", (session.get("school_id"),)
    ).fetchone()
    requested_session_id = request.args.get("session_id", type=int)
    valid_ids = [s["id"] for s in enrolled_sessions]
    if requested_session_id in valid_ids:
        session_id = requested_session_id
    elif active_session and active_session["id"] in valid_ids:
        session_id = active_session["id"]
    elif valid_ids:
        session_id = valid_ids[0]
    else:
        session_id = None

    class_id = student["class_id"]
    if session_id:
        enrollment = conn.execute(
            "SELECT class_id FROM enrollments WHERE student_id=? AND session_id=?", (student_id, session_id)
        ).fetchone()
        if enrollment:
            class_id = enrollment["class_id"]

    subjects = []
    items = []
    if session_id and class_id:
        subjects = conn.execute(
            "SELECT s.* FROM subjects s JOIN class_subjects cs ON cs.subject_id=s.id "
            "WHERE cs.class_id=? ORDER BY s.name", (class_id,)
        ).fetchall()
        items = conn.execute(
            "SELECT m.*, sub.name as subject_name FROM materials m "
            "JOIN subjects sub ON sub.id=m.subject_id "
            "WHERE m.class_id=? AND m.session_id=? ORDER BY sub.name, m.uploaded_at DESC",
            (class_id, session_id),
        ).fetchall()
    class_row = conn.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone() if class_id else None
    conn.close()
    return render_template(
        "student_materials.html", enrolled_sessions=enrolled_sessions, session_id=session_id,
        class_row=class_row, subjects=subjects, items=items,
    )


@app.route("/student/materials/<int:material_id>/download")
@student_login_required
def student_download_material(material_id):
    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE id=?", (session["student_id"],)).fetchone()
    if not student:
        conn.close()
        return redirect(url_for("student_login"))
    m = conn.execute("SELECT * FROM materials WHERE id=? AND school_id=?", (material_id, session.get("school_id"))).fetchone()
    # A student's class for that material's OWN session is the access
    # boundary — not just their current class — so materials from before a
    # promotion stay reachable, but a material from any other class
    # (including another category/arm at the same level) never is.
    my_class_for_that_session = student_class_for_session(conn, student["id"], m["session_id"]) if m else None
    conn.close()
    if not m or my_class_for_that_session != m["class_id"]:
        flash("That material isn't available to you.", "error")
        return redirect(url_for("student_materials"))
    if m["external_url"]:
        return redirect(m["external_url"])
    return send_from_directory(
        os.path.join(MATERIALS_DIR, str(session["school_id"])), m["filename"],
        as_attachment=True, download_name=m["original_filename"] or m["filename"],
    )


@app.route("/student/result/<int:term_id>")
@student_login_required
def student_result(term_id):
    conn = get_db()
    student_id = session["student_id"]
    term = conn.execute(
        "SELECT terms.*, sessions.name as session_name FROM terms "
        "JOIN sessions ON sessions.id=terms.session_id WHERE terms.id=?", (term_id,)
    ).fetchone()
    if not term or not term["is_published"]:
        conn.close()
        flash("That term's result isn't published yet.", "error")
        return redirect(url_for("student_dashboard"))
    enrolled = conn.execute(
        "SELECT 1 FROM enrollments WHERE student_id=? AND session_id=?", (student_id, term["session_id"])
    ).fetchone()
    if not enrolled:
        conn.close()
        flash("You weren't enrolled in that term.", "error")
        return redirect(url_for("student_dashboard"))
    data = build_result_data(conn, student_id, term_id)
    all_traits = conn.execute(
        "SELECT * FROM skill_traits WHERE school_id=? ORDER BY category, name", (session["school_id"],)
    ).fetchall()
    conn.close()
    return render_template(
        "student_result.html", term=term, student_full_name=student_full_name, all_traits=all_traits, **data
    )


@app.route("/student/result/<int:term_id>/pdf")
@student_login_required
def student_result_pdf(term_id):
    conn = get_db()
    student_id = session["student_id"]
    term = conn.execute(
        "SELECT terms.*, sessions.name as session_name FROM terms "
        "JOIN sessions ON sessions.id=terms.session_id WHERE terms.id=?", (term_id,)
    ).fetchone()
    if not term or not term["is_published"]:
        conn.close()
        flash("That term's result isn't published yet.", "error")
        return redirect(url_for("student_dashboard"))
    enrolled = conn.execute(
        "SELECT 1 FROM enrollments WHERE student_id=? AND session_id=?", (student_id, term["session_id"])
    ).fetchone()
    if not enrolled:
        conn.close()
        flash("You weren't enrolled in that term.", "error")
        return redirect(url_for("student_dashboard"))
    data = build_result_data(conn, student_id, term_id)
    school = get_school(conn, session["school_id"])
    logo_path = None
    if school and school["logo_filename"]:
        p = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(p):
            logo_path = p
    conn.close()
    buf = build_result_pdf(data, term, school_name=school["name"] if school else None,
                            logo_path=logo_path, student_full_name=student_full_name,
                            font_choice=school["pdf_font"] if school else "Helvetica")
    fname = f"result_{data['student']['admission_no']}_{term['name']}.pdf".replace(" ", "_").replace("/", "-")
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)


# ---------- platform (super admin) tier ----------
#
# A Super Admin oversees the whole platform, not any one school. Their login
# is completely separate from school staff/students (platform_admins table),
# and their access to school data is deliberately limited to metadata and
# moderation (counts, status, suspend/activate/delete) rather than browsing
# actual student names/scores — that stays isolated to each school's own
# staff, per the "strict data isolation between schools" requirement.

def platform_admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "platform_admin_id" not in session:
            return redirect(url_for("platform_login"))
        return f(*args, **kwargs)
    return wrapped


@app.route("/platform/login", methods=["GET", "POST"])
@rate_limit(max_attempts=10, window_seconds=300)
def platform_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        admin = conn.execute("SELECT * FROM platform_admins WHERE username=?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["platform_admin_id"] = admin["id"]
            session["platform_admin_name"] = admin["name"]
            log_audit(conn, "platform_admin", admin["name"], "login")
            conn.close()
            return redirect(url_for("platform_dashboard"))
        conn.close()
        flash("Invalid username or password.", "error")
    return render_template("platform_login.html")


@app.route("/platform/logout")
def platform_logout():
    session.clear()
    return redirect(url_for("platform_login"))


@app.route("/platform/dashboard")
@platform_admin_required
def platform_dashboard():
    conn = get_db()
    stats = {
        "schools_total": conn.execute("SELECT COUNT(*) c FROM schools").fetchone()["c"],
        "schools_active": conn.execute("SELECT COUNT(*) c FROM schools WHERE is_suspended=0").fetchone()["c"],
        "schools_suspended": conn.execute("SELECT COUNT(*) c FROM schools WHERE is_suspended=1").fetchone()["c"],
        "students": conn.execute("SELECT COUNT(*) c FROM students WHERE is_active=1").fetchone()["c"],
        "teachers": conn.execute("SELECT COUNT(*) c FROM users WHERE role='teacher'").fetchone()["c"],
        "admins": conn.execute("SELECT COUNT(*) c FROM users WHERE role IN ('admin','sub_admin')").fetchone()["c"],
        "classes": conn.execute("SELECT COUNT(*) c FROM classes").fetchone()["c"],
        "published_terms": conn.execute("SELECT COUNT(*) c FROM terms WHERE is_published=1").fetchone()["c"],
    }
    recent_audit = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    return render_template("platform_dashboard.html", stats=stats, recent_audit=recent_audit)


@app.route("/platform/control-center")
@platform_admin_required
def platform_control_center():
    """Platform-wide non-sensitive health/readiness view for all schools."""
    conn = get_db()
    schools = conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
    rows = []
    totals = {"ready": 0, "pending": 0, "suspended": 0, "archived": 0, "attention": 0}
    for school in schools:
        try:
            checks, ready = school_readiness_checks(conn, school["id"])
        except Exception:
            app.logger.exception("Readiness check failed for school %s", school["id"])
            checks, ready = [], False
        identity = [
            bool((school["school_code"] or "").strip()),
            bool((school["tenant_id"] or "").strip()),
            (conn.execute("SELECT COUNT(*) n FROM schools WHERE school_code=?", (school["school_code"],)).fetchone()["n"] == 1 if school["school_code"] else False),
            (conn.execute("SELECT COUNT(*) n FROM schools WHERE tenant_id=?", (school["tenant_id"],)).fetchone()["n"] == 1 if school["tenant_id"] else False),
        ]
        admin_mismatch = conn.execute(
            "SELECT COUNT(*) n FROM users WHERE school_id=? AND role='admin' AND (tenant_id IS NULL OR tenant_id<>?)",
            (school["id"], school["tenant_id"]),
        ).fetchone()["n"]
        role_mismatch = 0
        if table_exists(conn, "role_assignments"):
            role_mismatch = conn.execute(
                "SELECT COUNT(*) n FROM role_assignments WHERE school_id=? AND (tenant_id IS NULL OR tenant_id<>?)",
                (school["id"], school["tenant_id"]),
            ).fetchone()["n"]
        identity_ok = all(identity) and admin_mismatch == 0 and role_mismatch == 0
        failed_readiness = sum(1 for _, ok in checks if not ok)
        status = school["readiness_status"] or ("ready" if ready else "pending")
        archived = bool(school["is_archived"])
        suspended = bool(school["is_suspended"])
        attention = (not identity_ok) or failed_readiness > 0 or archived or suspended or school["activation_status"] != "active"
        if status == "ready": totals["ready"] += 1
        else: totals["pending"] += 1
        if suspended: totals["suspended"] += 1
        if archived: totals["archived"] += 1
        if attention: totals["attention"] += 1
        total_checks = len(checks) or 1
        passed = total_checks - failed_readiness
        rows.append({
            "school": school,
            "ready": ready,
            "status": status,
            "identity_ok": identity_ok,
            "failed_readiness": failed_readiness,
            "readiness_percent": round(passed * 100 / total_checks),
            "attention": attention,
            "admin_mismatch": admin_mismatch,
            "role_mismatch": role_mismatch,
        })
    conn.close()
    # Subscription breakdown uses the same rules as the Subscriptions page (expiry dates beat stale status text).
    sub_totals = {"total": len(rows), "Active": 0, "Trial": 0, "Expired": 0, "Suspended": 0}
    for r in rows:
        try:
            r["sub_status"] = app.jinja_env.globals["subscription_label"](r["school"])
        except Exception:
            app.logger.exception("Could not work out subscription status for school %s", r["school"]["id"])
            r["sub_status"] = "Unknown"
        if r["sub_status"] in sub_totals:
            sub_totals[r["sub_status"]] += 1
    sub_totals["active_schools"] = sum(1 for r in rows if (r["school"]["activation_status"] == "active") and not r["school"]["is_suspended"] and not r["school"]["is_archived"])
    return render_template("platform_control_center.html", rows=rows, totals=totals, sub_totals=sub_totals)


@app.route("/platform/plans", methods=["GET", "POST"])
@platform_admin_required
def platform_plans():
    conn = get_db()
    if request.method == "POST":
        code = (request.form.get("code") or "").strip().lower()
        try:
            row = conn.execute("SELECT id FROM subscription_plans WHERE code=?", (code,)).fetchone()
            if not row: raise ValueError("Plan not found")
            price = max(0, float(request.form.get("price_ngn", "0")))
            billing_days = max(1, min(3650, int(request.form.get("billing_days", "365"))))
            max_students = max(1, int(request.form.get("max_students", "1")))
            max_teachers = max(1, int(request.form.get("max_teachers", "1")))
            max_storage = max(1, int(request.form.get("max_storage_mb", "100")))
            name = (request.form.get("name") or code.title()).strip()[:80]
            features = {k: True for k in request.form.getlist("feature")}
            conn.execute("UPDATE subscription_plans SET name=?,price_ngn=?,billing_days=?,max_students=?,max_teachers=?,max_storage_mb=?,features_json=?,updated_at=CURRENT_TIMESTAMP WHERE code=?", (name,price,billing_days,max_students,max_teachers,max_storage,json.dumps(features),code))
            conn.commit(); flash(f"Updated {name} plan.", "success")
        except (ValueError, TypeError) as e:
            conn.rollback(); flash(f"Plan update failed: {e}", "error")
        finally:
            conn.close()
        return redirect(url_for("platform_plans"))
    plans = conn.execute("SELECT * FROM subscription_plans ORDER BY CASE code WHEN 'trial' THEN 1 WHEN 'basic' THEN 2 WHEN 'standard' THEN 3 WHEN 'premium' THEN 4 ELSE 5 END, name").fetchall()
    conn.close()
    return render_template("platform_plans.html", plans=plans)



def _gateway_secret(provider):
    provider = (provider or "").lower()
    if provider == "paystack":
        return os.environ.get("PAYSTACK_WEBHOOK_SECRET", "")
    if provider == "flutterwave":
        return os.environ.get("FLUTTERWAVE_WEBHOOK_SECRET", "")
    return ""

def _verify_gateway_signature(provider, raw_body):
    """Verify provider webhook authenticity without exposing secrets.

    Paystack signs the raw request body with HMAC-SHA512. Flutterwave uses
    the configured secret hash in the verif-hash header.
    """
    secret = _gateway_secret(provider)
    if not secret:
        return False, "gateway webhook secret is not configured"
    if provider == "paystack":
        supplied = request.headers.get("x-paystack-signature", "")
        expected = hmac.new(secret.encode(), raw_body, hashlib.sha512).hexdigest()
        return bool(supplied) and hmac.compare_digest(supplied, expected), "invalid Paystack signature"
    supplied = request.headers.get("verif-hash", "")
    return bool(supplied) and hmac.compare_digest(supplied, secret), "invalid Flutterwave verification hash"

def _gateway_payload(provider):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValueError("Invalid JSON webhook payload")
    if provider == "paystack":
        event_type = str(payload.get("event") or "")[:100]
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        provider_event_id = str(data.get("id") or data.get("reference") or payload.get("id") or data.get("reference") or "")[:150]
        reference = str(data.get("reference") or "")[:100]
        status = str(data.get("status") or "")[:50].lower()
        amount_kobo = data.get("amount")
        amount_ngn = float(amount_kobo or 0) / 100.0
        currency = str(data.get("currency") or "NGN")[:10].upper()
        return event_type, provider_event_id, reference, status, amount_ngn, currency, data
    event_type = str(payload.get("event") or payload.get("event.type") or "")[:100]
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    provider_event_id = str(data.get("id") or data.get("tx_ref") or data.get("transaction_id") or payload.get("id") or "")[:150]
    reference = str(data.get("tx_ref") or data.get("flw_ref") or data.get("reference") or "")[:100]
    status = str(data.get("status") or payload.get("status") or "")[:50].lower()
    amount_ngn = float(data.get("amount") or 0)
    currency = str(data.get("currency") or "NGN")[:10].upper()
    return event_type, provider_event_id, reference, status, amount_ngn, currency, data



def _financial_audit(conn, event_type, actor_type, actor_name=None, school_id=None, payment_id=None, invoice_id=None, reference=None, details=None):
    """Append-only financial audit event. Never edits or deletes prior events."""
    conn.execute(
        """INSERT INTO billing_financial_audit
        (event_type,actor_type,actor_name,school_id,payment_id,invoice_id,reference,details)
        VALUES (?,?,?,?,?,?,?,?)""",
        (event_type, actor_type, actor_name, school_id, payment_id, invoice_id, reference, details),
    )

def _issue_billing_receipt(conn, payment):
    existing = conn.execute("SELECT * FROM billing_receipts WHERE payment_id=?", (payment["id"],)).fetchone()
    if existing:
        return existing
    number = "RCT-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3).upper()
    conn.execute("""INSERT INTO billing_receipts
        (school_id,invoice_id,payment_id,receipt_number,amount_ngn,currency,provider,payment_reference)
        VALUES (?,?,?,?,?,?,?,?)""",
        (payment["school_id"], payment["invoice_id"], payment["id"], number, payment["amount_ngn"], payment["currency"], payment["provider"], payment["payment_reference"]))
    return conn.execute("SELECT * FROM billing_receipts WHERE payment_id=?", (payment["id"],)).fetchone()

def _confirm_billing_payment(conn, payment_id, confirmed_by, provider_event=None):
    payment = conn.execute("SELECT * FROM billing_payments WHERE id=?", (payment_id,)).fetchone()
    if not payment:
        raise ValueError("Payment not found")
    if payment["status"] == "confirmed":
        return payment, conn.execute("SELECT * FROM billing_receipts WHERE payment_id=?", (payment_id,)).fetchone(), False
    invoice = conn.execute("SELECT * FROM billing_invoices WHERE id=?", (payment["invoice_id"],)).fetchone() if payment["invoice_id"] else None
    if not invoice:
        raise ValueError("Linked invoice not found")
    plan = conn.execute("SELECT * FROM subscription_plans WHERE code=? AND is_active=1", (invoice["plan_code"],)).fetchone()
    if not plan:
        raise ValueError("The invoice plan is no longer active")
    if payment["currency"].upper() != "NGN":
        raise ValueError("Only NGN billing is supported")
    if abs(float(payment["amount_ngn"]) - float(invoice["amount_ngn"])) > 0.01:
        raise ValueError("Payment amount does not match the invoice")
    now = datetime.datetime.utcnow()
    end = now + datetime.timedelta(days=int(invoice["billing_days"] or plan["billing_days"]))
    confirmed_by = (confirmed_by or "gateway")[:100]
    conn.execute("UPDATE billing_payments SET status='confirmed',confirmed_at=?,confirmed_by=? WHERE id=?", (_iso_utc(now), confirmed_by, payment_id))
    conn.execute("UPDATE billing_invoices SET status='paid',paid_at=?,payment_reference=? WHERE id=?", (_iso_utc(now), payment["payment_reference"], invoice["id"]))
    conn.execute("UPDATE schools SET subscription_plan=?,subscription_status='active',subscription_started_at=?,subscription_ends_at=?,grace_ends_at=NULL,subscription_reference=? WHERE id=?", (invoice["plan_code"], _iso_utc(now), _iso_utc(end), payment["payment_reference"], payment["school_id"]))
    payment = conn.execute("SELECT * FROM billing_payments WHERE id=?", (payment_id,)).fetchone()
    receipt = _issue_billing_receipt(conn, payment)
    _financial_audit(conn, "payment_confirmed", "platform_or_gateway", confirmed_by, payment["school_id"], payment_id, invoice["id"], payment["payment_reference"], f"Receipt {receipt["receipt_number"]}; provider={payment["provider"]}")
    return payment, receipt, True


def _process_gateway_webhook(provider):
    raw = request.get_data(cache=True)
    ok, reason = _verify_gateway_signature(provider, raw)
    if not ok:
        return jsonify({"ok": False, "error": reason}), 401
    try:
        event_type, event_id, reference, status, amount, currency, data = _gateway_payload(provider)
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not event_id or not reference:
        return jsonify({"ok": False, "error": "Webhook is missing a provider event ID or payment reference"}), 400
    payload_hash = hashlib.sha256(raw).hexdigest()
    conn = get_db()
    try:
        existing = conn.execute("SELECT * FROM billing_webhook_events WHERE provider=? AND provider_event_id=?", (provider, event_id)).fetchone()
        if existing:
            conn.close()
            return jsonify({"ok": True, "duplicate": True, "status": existing["status"]}), 200
        conn.execute("INSERT INTO billing_webhook_events(provider,provider_event_id,event_type,payment_reference,payload_hash,status) VALUES (?,?,?,?,?,'received')", (provider,event_id,event_type,reference,payload_hash))
        if status not in {"success", "successful", "completed"} or (provider == "paystack" and event_type != "charge.success"):
            conn.execute("UPDATE billing_webhook_events SET status='ignored',processed_at=CURRENT_TIMESTAMP WHERE provider=? AND provider_event_id=?", (provider,event_id))
            conn.commit(); conn.close()
            return jsonify({"ok": True, "processed": False, "reason": "non-success event"}), 200
        invoice = conn.execute("SELECT * FROM billing_invoices WHERE payment_reference=? OR invoice_number=?", (reference, reference)).fetchone()
        # Paystack references normally belong to the payment record; our hosted checkout reference
        # can be the invoice number. Accept either, but never activate without a matching invoice.
        if not invoice:
            invoice = conn.execute("SELECT * FROM billing_invoices WHERE invoice_number=?", (reference,)).fetchone()
        if not invoice:
            raise ValueError("No matching invoice for payment reference")
        if currency.upper() != "NGN" or abs(float(amount) - float(invoice["amount_ngn"])) > 0.01:
            raise ValueError("Webhook amount or currency does not match the invoice")
        payment = conn.execute("SELECT * FROM billing_payments WHERE payment_reference=?", (reference,)).fetchone()
        if not payment:
            conn.execute("INSERT INTO billing_payments(school_id,invoice_id,provider,payment_reference,amount_ngn,currency,status,paid_at,raw_metadata) VALUES (?,?,?,?,?,?, 'pending', ?, ?)", (invoice["school_id"],invoice["id"],provider,reference,amount,currency,_iso_utc(datetime.datetime.utcnow()),json.dumps(data, separators=(",",":"))))
            payment = conn.execute("SELECT * FROM billing_payments WHERE payment_reference=?", (reference,)).fetchone()
        elif payment["invoice_id"] != invoice["id"] or payment["school_id"] != invoice["school_id"]:
            raise ValueError("Payment is linked to a different school or invoice")
        conn.execute("UPDATE billing_payments SET raw_metadata=?,paid_at=? WHERE id=?", (json.dumps(data, separators=(",",":")), _iso_utc(datetime.datetime.utcnow()), payment["id"]))
        payment, receipt, changed = _confirm_billing_payment(conn, payment["id"], f"{provider}_webhook", provider_event=event_id)
        conn.execute("UPDATE billing_webhook_events SET status='processed',processed_at=CURRENT_TIMESTAMP WHERE provider=? AND provider_event_id=?", (provider,event_id))
        log_audit(conn, "gateway", provider, "payment_webhook_confirmed", details=f"Confirmed {reference}; receipt {receipt['receipt_number']}", school_id=invoice["school_id"])
        conn.commit(); conn.close()
        return jsonify({"ok": True, "processed": True, "receipt_number": receipt["receipt_number"], "changed": changed}), 200
    except Exception as exc:
        conn.execute("UPDATE billing_webhook_events SET status='failed',error_message=?,processed_at=CURRENT_TIMESTAMP WHERE provider=? AND provider_event_id=?", (str(exc)[:500],provider,event_id))
        conn.commit(); conn.close()
        return jsonify({"ok": False, "error": "Webhook received but could not be applied"}), 200


@app.route("/webhooks/paystack", methods=["POST"])
def paystack_webhook():
    return _process_gateway_webhook("paystack")


@app.route("/webhooks/flutterwave", methods=["POST"])
def flutterwave_webhook():
    return _process_gateway_webhook("flutterwave")



def _billing_notification_insert(conn, school_id, event_key, notification_type, title, message):
    """Insert an automated in-app billing notification once per unique event key."""
    try:
        cur = conn.execute(
            "INSERT INTO billing_notification_events(school_id,event_key,notification_type) VALUES (?,?,?)",
            (school_id, event_key, notification_type),
        )
    except sqlite3.IntegrityError:
        return False
    conn.execute(
        "INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",
        ("Billing System", school_id, "admin", title[:150], message),
    )
    return True


def _run_billing_notifications(conn, now=None):
    """Generate tenant-scoped in-app billing reminders.

    This function is idempotent: each school/event combination is recorded once.
    It never changes subscription state and never deletes billing or school data.
    """
    now = now or datetime.datetime.utcnow()
    schools = conn.execute("SELECT * FROM schools ORDER BY id").fetchall()
    sent = []
    for school in schools:
        school_id = school["id"]
        state = subscription_state(school, now)
        status = state.get("status")
        days = state.get("days_left")
        if status in ("trial", "active") and days is not None:
            try:
                days = int(days)
            except (TypeError, ValueError):
                days = None
            if days in (14, 7, 3, 1):
                label = "trial" if status == "trial" else "subscription"
                event_key = f"{label}-expiry-{school['subscription_ends_at'] if 'subscription_ends_at' in school.keys() and school['subscription_ends_at'] else (school['trial_ends_at'] if 'trial_ends_at' in school.keys() else None)}-{days}"
                title = f"{label.title()} expires in {days} day{'s' if days != 1 else ''}"
                message = (f"Your {label} for {school['name']} expires in {days} day{'s' if days != 1 else ''}. "
                           "Open Billing & Subscription to review your plan and renewal options.")
                if _billing_notification_insert(conn, school_id, event_key, "expiry_reminder", title, message):
                    sent.append((school_id, "expiry_reminder"))
        elif status in ("expired", "suspended", "cancelled"):
            event_key = f"access-status-{status}-{school['subscription_ends_at'] if 'subscription_ends_at' in school.keys() and school['subscription_ends_at'] else (school['trial_ends_at'] if 'trial_ends_at' in school.keys() else None)}"
            title = "Subscription access requires attention"
            message = (f"Your school's billing status is {status}. Existing school data is retained. "
                       "Contact the platform administrator or open Billing & Subscription for details.")
            if _billing_notification_insert(conn, school_id, event_key, "status_alert", title, message):
                sent.append((school_id, "status_alert"))

        invoices = conn.execute(
            "SELECT * FROM billing_invoices WHERE school_id=? AND status='pending' ORDER BY id DESC",
            (school_id,),
        ).fetchall()
        for invoice in invoices:
            due = invoice["due_at"]
            if not due:
                continue
            try:
                due_dt = datetime.datetime.fromisoformat(str(due).replace("Z", ""))
            except ValueError:
                continue
            delta = (due_dt - now).total_seconds() / 86400.0
            if -0.5 <= delta <= 1.5:
                bucket = "due-today"
            elif delta < -0.5:
                bucket = "overdue"
            elif delta <= 7.5:
                bucket = "due-soon"
            else:
                continue
            event_key = f"invoice-{invoice['id']}-{bucket}"
            if bucket == "overdue":
                title = f"Invoice {invoice['invoice_number']} is overdue"
                message = f"Invoice {invoice['invoice_number']} for ₦{float(invoice['amount_ngn']):,.2f} is overdue. Review Billing & Subscription for payment instructions."
            elif bucket == "due-today":
                title = f"Invoice {invoice['invoice_number']} is due today"
                message = f"Invoice {invoice['invoice_number']} for ₦{float(invoice['amount_ngn']):,.2f} is due today. Review Billing & Subscription to complete payment."
            else:
                title = f"Invoice {invoice['invoice_number']} is due soon"
                message = f"Invoice {invoice['invoice_number']} for ₦{float(invoice['amount_ngn']):,.2f} is due within 7 days. Review Billing & Subscription to complete payment."
            if _billing_notification_insert(conn, school_id, event_key, "invoice_reminder", title, message):
                sent.append((school_id, "invoice_reminder"))
    return sent


def _billing_email_enabled():
    return os.environ.get("BILLING_EMAIL_NOTIFICATIONS_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")


def _run_billing_email_notifications(conn, now=None):
    """Deliver newly-created billing notifications by email and retry failures.

    Email delivery is best-effort and never changes subscription/payment state.
    Only the school's registered administrator email is used.
    """
    if not _billing_email_enabled():
        return {"sent": 0, "failed": 0, "skipped": 0}
    now = now or datetime.datetime.utcnow()
    stats = {"sent": 0, "failed": 0, "skipped": 0}
    rows = conn.execute("""
        SELECT e.school_id, e.event_key, e.notification_type, n.title, n.message,
               s.name AS school_name, s.registered_email, s.billing_email_notifications
        FROM billing_notification_events e
        JOIN schools s ON s.id=e.school_id
        JOIN notifications n ON n.school_id=e.school_id AND n.target_role='admin'
             AND n.title=e.event_key COLLATE NOCASE
        WHERE 1=0
    """).fetchall()
    # The notification table has no event-key foreign key, so match by event creation time
    # through the deterministic event key and title/message generated below.
    events = conn.execute("""
        SELECT e.school_id, e.event_key, e.notification_type, e.created_at,
               s.name AS school_name, s.registered_email, s.billing_email_notifications
        FROM billing_notification_events e
        JOIN schools s ON s.id=e.school_id
        WHERE COALESCE(s.billing_email_notifications,1)=1
          AND s.registered_email IS NOT NULL AND TRIM(s.registered_email)<>''
        ORDER BY e.id ASC
    """).fetchall()
    for event in events:
        school_id = event["school_id"]
        key = event["event_key"]
        recipient = event["registered_email"].strip()
        # Reconstruct the human-readable billing message from the event type/key.
        if event["notification_type"] == "expiry_reminder":
            m = re.search(r"-(\d+)$", key)
            days = int(m.group(1)) if m else None
            subject = f"Billing reminder – {event['school_name']}"
            message = (f"Your school account ({event['school_name']}) has a billing item requiring attention."
                       + (f" Your subscription/trial expires in {days} day{'s' if days != 1 else ''}." if days is not None else "")
                       + " Please sign in to Billing & Subscription to review renewal options.")
        elif event["notification_type"] == "invoice_reminder":
            subject = f"School billing invoice reminder – {event['school_name']}"
            message = f"Your school account ({event['school_name']}) has a pending billing invoice. Please sign in to Billing & Subscription to review payment instructions."
        else:
            subject = f"School subscription status – {event['school_name']}"
            message = f"Your school account ({event['school_name']}) has a subscription status requiring attention. Existing school data is retained. Please sign in to Billing & Subscription or contact the platform administrator."

        row = conn.execute("SELECT * FROM billing_email_delivery WHERE school_id=? AND event_key=?", (school_id, key)).fetchone()
        if row and row["status"] == "sent":
            stats["skipped"] += 1
            continue
        if not row:
            conn.execute("INSERT INTO billing_email_delivery(school_id,event_key,recipient,notification_type,subject,status) VALUES (?,?,?,?,?,'pending')", (school_id,key,recipient,event["notification_type"],subject))
            row = conn.execute("SELECT * FROM billing_email_delivery WHERE school_id=? AND event_key=?", (school_id,key)).fetchone()
        else:
            conn.execute("UPDATE billing_email_delivery SET recipient=?,subject=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (recipient,subject,row["id"]))

        ok, msg = send_platform_email(recipient, subject, message)
        if ok:
            conn.execute("UPDATE billing_email_delivery SET status='sent',attempt_count=attempt_count+1,last_error=NULL,sent_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (_iso_utc(now), row["id"]))
            stats["sent"] += 1
        else:
            conn.execute("UPDATE billing_email_delivery SET status='failed',attempt_count=attempt_count+1,last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (msg[:500], row["id"]))
            stats["failed"] += 1
    return stats


def _acquire_billing_job_lock(conn, job_name="billing_notifications", stale_minutes=30):
    """Acquire a short-lived database lock so duplicate cron invocations cannot overlap."""
    now = datetime.datetime.utcnow()
    stale_before = now - datetime.timedelta(minutes=stale_minutes)
    try:
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute(
            "SELECT id, started_at FROM billing_job_runs WHERE job_name=? AND status='running' ORDER BY id DESC LIMIT 1",
            (job_name,),
        ).fetchone()
        if active:
            try:
                started = datetime.datetime.fromisoformat(str(active["started_at"]).replace("Z", ""))
            except ValueError:
                started = now
            if started > stale_before:
                conn.rollback()
                return None
            conn.execute("UPDATE billing_job_runs SET status='stale', finished_at=? WHERE id=?", (_iso_utc(now), active["id"]))
        cur = conn.execute("INSERT INTO billing_job_runs(job_name,started_at,status) VALUES (?,?, 'running')", (job_name, _iso_utc(now)))
        run_id = cur.lastrowid
        conn.commit()
        return run_id
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise


def _finish_billing_job(conn, run_id, status, result=None, error_message=None):
    conn.execute(
        "UPDATE billing_job_runs SET status=?, finished_at=?, result_json=?, error_message=? WHERE id=?",
        (status, _iso_utc(datetime.datetime.utcnow()), json.dumps(result or {}, separators=(",", ":")), (error_message or "")[:1000] or None, run_id),
    )
    conn.commit()


@app.route("/internal/billing-notifications", methods=["POST"])
def internal_billing_notifications():
    """Cron-safe endpoint for automated billing reminders; protected and overlap-safe."""
    expected = os.environ.get("BILLING_NOTIFICATION_CRON_SECRET", "").strip()
    supplied = request.headers.get("X-Billing-Cron-Secret", "").strip()
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    run_id = None
    try:
        run_id = _acquire_billing_job_lock(conn)
        if run_id is None:
            return jsonify({"ok": True, "skipped": True, "reason": "billing job already running"}), 202
        sent = _run_billing_notifications(conn)
        email_stats = _run_billing_email_notifications(conn)
        result = {"notifications_created": len(sent), "email": email_stats}
        _finish_billing_job(conn, run_id, "completed", result=result)
        return jsonify({"ok": True, "run_id": run_id, **result})
    except Exception as exc:
        conn.rollback()
        if run_id is not None:
            try:
                _finish_billing_job(conn, run_id, "failed", error_message=str(exc))
            except Exception:
                pass
        return jsonify({"ok": False, "error": str(exc)[:300], "run_id": run_id}), 500
    finally:
        conn.close()


@app.route("/billing")
@login_required("admin")
def school_billing_portal():
    """School Admin's read-only billing portal.

    Billing records are always constrained to the authenticated user's school;
    no school ID supplied by the browser is trusted for authorization.
    """
    school_id = current_school_id()
    conn = get_db()
    school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
    if not school:
        conn.close()
        session.clear()
        return redirect(url_for("login"))
    state = subscription_state(school)
    plan = subscription_plan_for_school(conn, school)
    usage = school_plan_usage(conn, school_id)
    limits = plan_limit_state(plan, usage)
    invoices = conn.execute(
        "SELECT * FROM billing_invoices WHERE school_id=? ORDER BY id DESC", (school_id,)
    ).fetchall()
    payments = conn.execute(
        "SELECT p.*, i.invoice_number, i.plan_code FROM billing_payments p "
        "LEFT JOIN billing_invoices i ON i.id=p.invoice_id "
        "WHERE p.school_id=? ORDER BY p.id DESC", (school_id,)
    ).fetchall()
    receipts = conn.execute(
        "SELECT r.*, i.invoice_number FROM billing_receipts r "
        "LEFT JOIN billing_invoices i ON i.id=r.invoice_id "
        "WHERE r.school_id=? ORDER BY r.id DESC", (school_id,)
    ).fetchall()
    email_deliveries = conn.execute(
        "SELECT event_key, notification_type, recipient, status, attempt_count, last_error, sent_at, created_at "
        "FROM billing_email_delivery WHERE school_id=? ORDER BY id DESC LIMIT 20", (school_id,)
    ).fetchall()
    conn.close()
    return render_template(
        "school_billing_portal.html",
        school=school, state=state, plan=plan, limits=limits,
        invoices=invoices, payments=payments, receipts=receipts, email_deliveries=email_deliveries,
    )


@app.route("/billing/email-preferences", methods=["POST"])
@login_required("admin")
def billing_email_preferences():
    _check_csrf()
    school_id = current_school_id()
    enabled = 1 if request.form.get("billing_email_notifications") else 0
    conn = get_db()
    conn.execute("UPDATE schools SET billing_email_notifications=? WHERE id=?", (enabled, school_id))
    log_audit(conn, session.get("user_id"), "billing_email_preference_changed", details=f"Billing email notifications {'enabled' if enabled else 'disabled'}", school_id=school_id)
    conn.commit(); conn.close()
    flash("Billing email notifications updated.", "success")
    return redirect(url_for("school_billing_portal"))


@app.route("/billing/receipt/<int:receipt_id>")
@login_required("admin")
def school_billing_receipt(receipt_id):
    """Printable receipt; receipt must belong to the authenticated school."""
    school_id = current_school_id()
    conn = get_db()
    receipt = conn.execute(
        "SELECT r.*, i.invoice_number, i.plan_code, i.billing_days "
        "FROM billing_receipts r LEFT JOIN billing_invoices i ON i.id=r.invoice_id "
        "WHERE r.id=? AND r.school_id=?", (receipt_id, school_id)
    ).fetchone()
    school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
    conn.close()
    if not receipt or not school:
        flash("Receipt not found.", "error")
        return redirect(url_for("school_billing_portal"))
    return render_template("school_billing_receipt.html", school=school, receipt=receipt)


@app.route("/platform/billing-analytics")
@platform_admin_required
def platform_billing_analytics():
    """Aggregated Super Admin billing analytics. No student-level data is exposed."""
    conn = get_db()
    now = datetime.datetime.utcnow()
    # Confirmed payments are the revenue source; pending/failed transactions are excluded.
    total_confirmed = conn.execute(
        "SELECT COALESCE(SUM(amount_ngn),0) AS total FROM billing_payments WHERE status='confirmed'"
    ).fetchone()["total"]
    confirmed_count = conn.execute(
        "SELECT COUNT(*) AS n FROM billing_payments WHERE status='confirmed'"
    ).fetchone()["n"]
    pending_amount = conn.execute(
        "SELECT COALESCE(SUM(amount_ngn),0) AS total FROM billing_payments WHERE status='pending'"
    ).fetchone()["total"]
    overdue_amount = conn.execute(
        "SELECT COALESCE(SUM(amount_ngn),0) AS total FROM billing_invoices WHERE status='pending' AND due_at IS NOT NULL AND due_at < ?",
        (_iso_utc(now),),
    ).fetchone()["total"]
    invoice_total = conn.execute("SELECT COUNT(*) AS n FROM billing_invoices").fetchone()["n"]
    paid_invoice_count = conn.execute(
        "SELECT COUNT(DISTINCT invoice_id) AS n FROM billing_payments WHERE status='confirmed' AND invoice_id IS NOT NULL"
    ).fetchone()["n"]
    collection_rate = (paid_invoice_count / invoice_total * 100.0) if invoice_total else 0.0

    monthly_rows = conn.execute("""
        SELECT substr(COALESCE(p.paid_at, p.created_at),1,7) AS month,
               COALESCE(SUM(p.amount_ngn),0) AS revenue,
               COUNT(*) AS payments
        FROM billing_payments p
        WHERE p.status='confirmed'
          AND COALESCE(p.paid_at, p.created_at) >= ?
        GROUP BY substr(COALESCE(p.paid_at, p.created_at),1,7)
        ORDER BY month ASC
    """, (_iso_utc(now - datetime.timedelta(days=365)),)).fetchall()
    monthly = {r["month"]: {"revenue": float(r["revenue"] or 0), "payments": int(r["payments"] or 0)} for r in monthly_rows}
    months = []
    cursor = datetime.datetime(now.year, now.month, 1)
    for _ in range(12):
        key = cursor.strftime("%Y-%m")
        months.append({"month": key, **monthly.get(key, {"revenue": 0.0, "payments": 0})})
        cursor = (cursor.replace(day=1) - datetime.timedelta(days=1)).replace(day=1)
    months.reverse()

    plan_rows = conn.execute("""
        SELECT COALESCE(NULLIF(subscription_plan,''),'legacy') AS plan,
               COUNT(*) AS schools
        FROM schools
        WHERE is_archived=0
        GROUP BY COALESCE(NULLIF(subscription_plan,''),'legacy')
        ORDER BY schools DESC, plan ASC
    """).fetchall()
    status_rows = conn.execute("""
        SELECT COALESCE(subscription_status,'unknown') AS status, COUNT(*) AS schools
        FROM schools WHERE is_archived=0
        GROUP BY COALESCE(subscription_status,'unknown')
        ORDER BY schools DESC
    """).fetchall()
    top_revenue = conn.execute("""
        SELECT s.id, s.name, s.school_code,
               COALESCE(SUM(CASE WHEN p.status='confirmed' THEN p.amount_ngn ELSE 0 END),0) AS revenue,
               COUNT(CASE WHEN p.status='confirmed' THEN 1 END) AS payments
        FROM schools s LEFT JOIN billing_payments p ON p.school_id=s.id
        WHERE s.is_archived=0
        GROUP BY s.id, s.name, s.school_code
        ORDER BY revenue DESC, s.name ASC LIMIT 20
    """).fetchall()
    recent_confirmed = conn.execute("""
        SELECT p.payment_reference, p.amount_ngn, p.paid_at, p.provider,
               s.name AS school_name, s.school_code, i.invoice_number
        FROM billing_payments p JOIN schools s ON s.id=p.school_id
        LEFT JOIN billing_invoices i ON i.id=p.invoice_id
        WHERE p.status='confirmed'
        ORDER BY COALESCE(p.paid_at,p.created_at) DESC LIMIT 25
    """).fetchall()
    conn.close()
    return render_template(
        "platform_billing_analytics.html",
        total_confirmed=float(total_confirmed or 0), confirmed_count=int(confirmed_count or 0),
        pending_amount=float(pending_amount or 0), overdue_amount=float(overdue_amount or 0),
        invoice_total=int(invoice_total or 0), paid_invoice_count=int(paid_invoice_count or 0),
        collection_rate=collection_rate, months=months, plan_rows=plan_rows,
        status_rows=status_rows, top_revenue=top_revenue, recent_confirmed=recent_confirmed,
    )



def _billing_report_date_range():
    """Return an inclusive UTC date range for Super Admin billing exports."""
    today = datetime.datetime.utcnow().date()
    start_raw = (request.args.get("start") or "").strip()
    end_raw = (request.args.get("end") or "").strip()
    try:
        start = datetime.date.fromisoformat(start_raw) if start_raw else today.replace(day=1)
    except ValueError:
        start = today.replace(day=1)
    try:
        end = datetime.date.fromisoformat(end_raw) if end_raw else today
    except ValueError:
        end = today
    if end < start:
        start, end = end, start
    return start, end


def _billing_export_response(title, headers, rows, fmt, filename):
    if fmt == "xlsx":
        payload = build_xlsx(title, headers, rows)
        return send_file(payload, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name=filename)
    payload = build_csv(headers, rows)
    return send_file(payload, mimetype="text/csv", as_attachment=True, download_name=filename)


@app.route("/platform/billing-reports")
@platform_admin_required
def platform_billing_reports():
    """Super Admin financial reporting hub. Reports contain billing data only."""
    start, end = _billing_report_date_range()
    return render_template("platform_billing_reports.html", start=start.isoformat(), end=end.isoformat())


@app.route("/platform/billing-reports/<report_name>")
@platform_admin_required
def platform_billing_report_export(report_name):
    """Export billing financial reports as CSV or XLSX for the selected date range."""
    start, end = _billing_report_date_range()
    fmt = (request.args.get("format") or "csv").lower()
    if fmt not in {"csv", "xlsx"}:
        fmt = "csv"
    start_iso = start.isoformat() + " 00:00:00"
    end_iso = (end + datetime.timedelta(days=1)).isoformat() + " 00:00:00"
    conn = get_db()

    if report_name == "payments":
        headers = ["Payment ID", "School", "School ID", "Invoice", "Provider", "Payment Reference", "Amount NGN", "Currency", "Status", "Paid At", "Confirmed At"]
        rows = conn.execute("""
            SELECT p.id, s.name, s.school_code, COALESCE(i.invoice_number,''), p.provider,
                   p.payment_reference, p.amount_ngn, p.currency, p.status, p.paid_at, p.confirmed_at
            FROM billing_payments p JOIN schools s ON s.id=p.school_id
            LEFT JOIN billing_invoices i ON i.id=p.invoice_id
            WHERE COALESCE(p.paid_at,p.created_at) >= ? AND COALESCE(p.paid_at,p.created_at) < ?
            ORDER BY COALESCE(p.paid_at,p.created_at) DESC
        """, (start_iso, end_iso)).fetchall()
        rows = [tuple(r) for r in rows]
        title, filename = "Payments", f"billing_payments_{start}_{end}.{fmt}"
    elif report_name == "invoices":
        headers = ["Invoice ID", "Invoice Number", "School", "School ID", "Plan", "Amount NGN", "Billing Days", "Status", "Issued At", "Due At", "Paid At", "Payment Reference"]
        rows = conn.execute("""
            SELECT i.id, i.invoice_number, s.name, s.school_code, i.plan_code, i.amount_ngn,
                   i.billing_days, i.status, i.issued_at, i.due_at, i.paid_at, COALESCE(i.payment_reference,'')
            FROM billing_invoices i JOIN schools s ON s.id=i.school_id
            WHERE i.issued_at >= ? AND i.issued_at < ?
            ORDER BY i.issued_at DESC
        """, (start_iso, end_iso)).fetchall()
        rows = [tuple(r) for r in rows]
        title, filename = "Invoices", f"billing_invoices_{start}_{end}.{fmt}"
    elif report_name == "revenue":
        headers = ["Month", "Confirmed Revenue NGN", "Confirmed Payments", "Paid Invoices"]
        rows = conn.execute("""
            SELECT substr(COALESCE(p.paid_at,p.confirmed_at,p.created_at),1,7) AS month,
                   COALESCE(SUM(p.amount_ngn),0), COUNT(*), COUNT(DISTINCT p.invoice_id)
            FROM billing_payments p
            WHERE p.status='confirmed'
              AND COALESCE(p.paid_at,p.confirmed_at,p.created_at) >= ?
              AND COALESCE(p.paid_at,p.confirmed_at,p.created_at) < ?
            GROUP BY month ORDER BY month ASC
        """, (start_iso, end_iso)).fetchall()
        rows = [tuple(r) for r in rows]
        title, filename = "Revenue Summary", f"billing_revenue_{start}_{end}.{fmt}"
    elif report_name == "renewals":
        headers = ["School", "School ID", "Plan", "Subscription Status", "Start", "Expiry", "Days Remaining", "Confirmed Revenue NGN"]
        rows = conn.execute("""
            SELECT s.name, s.school_code, COALESCE(s.subscription_plan,'legacy'),
                   COALESCE(s.subscription_status,'unknown'), s.subscription_start, s.subscription_end,
                   CASE WHEN s.subscription_end IS NULL THEN NULL
                        ELSE CAST(julianday(substr(s.subscription_end,1,10)) - julianday(?) AS INTEGER) END,
                   COALESCE((SELECT SUM(p.amount_ngn) FROM billing_payments p
                             WHERE p.school_id=s.id AND p.status='confirmed'
                               AND COALESCE(p.paid_at,p.confirmed_at,p.created_at) >= ?
                               AND COALESCE(p.paid_at,p.confirmed_at,p.created_at) < ?),0)
            FROM schools s
            WHERE s.is_archived=0
            ORDER BY s.name ASC
        """, (datetime.datetime.utcnow().date().isoformat(), start_iso, end_iso)).fetchall()
        rows = [tuple(r) for r in rows]
        title, filename = "Subscription Renewals", f"billing_renewals_{start}_{end}.{fmt}"
    else:
        conn.close()
        return jsonify({"error": "Unknown billing report."}), 404

    conn.execute("INSERT INTO billing_report_downloads(actor_type,actor_name,report_name,format,start_date,end_date,row_count) VALUES (?,?,?,?,?,?,?)", ("platform_admin", session.get("platform_admin_name"), report_name, fmt, start.isoformat(), end.isoformat(), len(rows)))
    _financial_audit(conn, "report_exported", "platform_admin", session.get("platform_admin_name"), None, None, None, report_name, f"format={fmt}; start={start.isoformat()}; end={end.isoformat()}; rows={len(rows)}")
    conn.commit()
    conn.close()
    return _billing_export_response(title, headers, rows, fmt, filename)


@app.route("/platform/billing-audit")
@platform_admin_required
def platform_billing_audit():
    """Read-only Super Admin financial audit trail."""
    conn = get_db()
    events = conn.execute("""
        SELECT a.*, s.name AS school_name, s.school_code
        FROM billing_financial_audit a
        LEFT JOIN schools s ON s.id=a.school_id
        ORDER BY a.id DESC LIMIT 300
    """).fetchall()
    history = conn.execute("""
        SELECT h.*, s.name AS school_name, s.school_code
        FROM billing_payment_history h
        LEFT JOIN schools s ON s.id=h.school_id
        ORDER BY h.id DESC LIMIT 200
    """).fetchall()
    downloads = conn.execute("SELECT * FROM billing_report_downloads ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("platform_billing_audit.html", events=events, history=history, downloads=downloads)


@app.route("/platform/billing-operations")
@platform_admin_required
def platform_billing_operations():
    """Super Admin operational billing health dashboard; no school-level secrets or student records."""
    conn = get_db()
    now = datetime.datetime.utcnow()
    now_iso = _iso_utc(now)
    horizon_iso = _iso_utc(now + datetime.timedelta(days=14))

    invoice_counts = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, COUNT(*) n FROM billing_invoices GROUP BY status"
    ).fetchall()}
    payment_counts = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, COUNT(*) n FROM billing_payments GROUP BY status"
    ).fetchall()}
    email_counts = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, COUNT(*) n FROM billing_email_delivery GROUP BY status"
    ).fetchall()}

    overdue_invoices = conn.execute("""
        SELECT i.*, s.name AS school_name, s.school_code
        FROM billing_invoices i JOIN schools s ON s.id=i.school_id
        WHERE i.status='pending' AND i.due_at IS NOT NULL AND i.due_at < ?
        ORDER BY i.due_at ASC LIMIT 100
    """, (now_iso,)).fetchall()

    expiring = conn.execute("""
        SELECT id, name, school_code, tenant_id, subscription_plan, subscription_status,
               trial_ends_at, subscription_ends_at, grace_ends_at
        FROM schools
        WHERE is_archived=0 AND subscription_status IN ('trial','active')
          AND COALESCE(subscription_ends_at, trial_ends_at) IS NOT NULL
          AND COALESCE(subscription_ends_at, trial_ends_at) >= ?
          AND COALESCE(subscription_ends_at, trial_ends_at) <= ?
        ORDER BY COALESCE(subscription_ends_at, trial_ends_at) ASC LIMIT 100
    """, (now_iso, horizon_iso)).fetchall()

    failed_emails = conn.execute("""
        SELECT e.*, s.name AS school_name, s.school_code
        FROM billing_email_delivery e JOIN schools s ON s.id=e.school_id
        WHERE e.status='failed'
        ORDER BY e.updated_at DESC LIMIT 100
    """).fetchall()

    recent_payments = conn.execute("""
        SELECT p.*, s.name AS school_name, s.school_code, i.invoice_number
        FROM billing_payments p JOIN schools s ON s.id=p.school_id
        LEFT JOIN billing_invoices i ON i.id=p.invoice_id
        ORDER BY p.id DESC LIMIT 50
    """).fetchall()

    job_runs = conn.execute("""
        SELECT * FROM billing_job_runs
        WHERE job_name='billing_notifications'
        ORDER BY id DESC LIMIT 25
    """).fetchall()
    latest_job = job_runs[0] if job_runs else None

    attention = {
        "overdue_invoices": len(overdue_invoices),
        "expiring_subscriptions": len(expiring),
        "failed_emails": len(failed_emails),
        "failed_payments": payment_counts.get('failed', 0),
        "job_failures": sum(1 for r in job_runs if r["status"] == "failed"),
    }
    conn.close()
    return render_template(
        "platform_billing_operations.html",
        invoice_counts=invoice_counts, payment_counts=payment_counts, email_counts=email_counts,
        overdue_invoices=overdue_invoices, expiring=expiring, failed_emails=failed_emails,
        recent_payments=recent_payments, job_runs=job_runs, latest_job=latest_job, attention=attention,
    )


@app.route("/platform/billing")
@platform_admin_required
def platform_billing():
    conn = get_db()
    invoices = conn.execute("""SELECT i.*, s.name AS school_name, s.school_code
        FROM billing_invoices i JOIN schools s ON s.id=i.school_id
        ORDER BY i.id DESC LIMIT 200""").fetchall()
    payments = conn.execute("""SELECT p.*, s.name AS school_name, s.school_code, i.invoice_number
        FROM billing_payments p JOIN schools s ON s.id=p.school_id
        LEFT JOIN billing_invoices i ON i.id=p.invoice_id
        ORDER BY p.id DESC LIMIT 200""").fetchall()
    counts = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) n FROM billing_invoices GROUP BY status").fetchall()}
    webhook_counts = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) n FROM billing_webhook_events GROUP BY status").fetchall()}
    receipts = conn.execute("SELECT r.*, s.name AS school_name, i.invoice_number FROM billing_receipts r JOIN schools s ON s.id=r.school_id LEFT JOIN billing_invoices i ON i.id=r.invoice_id ORDER BY r.id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("platform_billing.html", invoices=invoices, payments=payments, counts=counts, webhook_counts=webhook_counts, receipts=receipts)


@app.route("/platform/schools/<int:school_id>/billing", methods=["GET", "POST"])
@platform_admin_required
def platform_school_billing(school_id):
    conn = get_db()
    school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
    if not school:
        conn.close(); flash("School not found.", "error"); return redirect(url_for("platform_billing"))
    if request.method == "POST":
        action = request.form.get("action", "").strip()
        try:
            if action == "create_invoice":
                plan_code = (request.form.get("plan") or "standard").strip().lower()
                plan = conn.execute("SELECT * FROM subscription_plans WHERE code=? AND is_active=1", (plan_code,)).fetchone()
                if not plan or plan_code == "trial": raise ValueError("Select an active paid plan")
                days = max(1, min(3650, int(request.form.get("days") or plan["billing_days"])))
                invoice_no = "INV-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3).upper()
                conn.execute("INSERT INTO billing_invoices (school_id,invoice_number,plan_code,amount_ngn,billing_days,status,due_at,created_by) VALUES (?,?,?,?,?,'pending',?,?)", (school_id, invoice_no, plan_code, float(plan["price_ngn"]), days, _iso_utc(datetime.datetime.utcnow()+datetime.timedelta(days=7)), session.get("platform_admin_name")))
                event = f"Created invoice {invoice_no}"
            elif action == "record_payment":
                invoice_id = int(request.form.get("invoice_id") or 0)
                invoice = conn.execute("SELECT * FROM billing_invoices WHERE id=? AND school_id=?", (invoice_id, school_id)).fetchone()
                if not invoice: raise ValueError("Invoice not found")
                ref = (request.form.get("payment_reference") or "").strip()[:100]
                if not ref: raise ValueError("Payment reference is required")
                amount = max(0, float(request.form.get("amount_ngn") or invoice["amount_ngn"]))
                conn.execute("INSERT INTO billing_payments (school_id,invoice_id,provider,payment_reference,amount_ngn,paid_at,status) VALUES (?,?,?, ?,?,?,'pending')", (school_id, invoice_id, (request.form.get("provider") or "manual").strip()[:40], ref, amount, _iso_utc(datetime.datetime.utcnow())))
                event = f"Recorded payment reference {ref} as pending"
            elif action == "confirm_payment":
                payment_id = int(request.form.get("payment_id") or 0)
                payment = conn.execute("SELECT * FROM billing_payments WHERE id=? AND school_id=?", (payment_id, school_id)).fetchone()
                if not payment: raise ValueError("Payment not found")
                if payment["status"] == "confirmed": raise ValueError("Payment is already confirmed")
                invoice = conn.execute("SELECT * FROM billing_invoices WHERE id=?", (payment["invoice_id"],)).fetchone() if payment["invoice_id"] else None
                if not invoice: raise ValueError("Linked invoice not found")
                plan = conn.execute("SELECT * FROM subscription_plans WHERE code=? AND is_active=1", (invoice["plan_code"],)).fetchone()
                if not plan: raise ValueError("The invoice plan is no longer active")
                payment, receipt, changed = _confirm_billing_payment(conn, payment_id, session.get("platform_admin_name"))
                event = f"Confirmed payment {payment['payment_reference']} and activated {plan['name']} (receipt {receipt['receipt_number']})"
            else:
                raise ValueError("Unknown billing action")
            log_audit(conn, "platform_admin", session.get("platform_admin_name"), "billing_change", details=f"{event} for '{school['name']}'", school_id=school_id)
            _financial_audit(conn, "billing_action", "platform_admin", session.get("platform_admin_name"), school_id, payment_id if action == "confirm_payment" else None, invoice_id if action in ("create_invoice", "record_payment") else None, ref if action == "record_payment" else None, event)
            conn.commit(); flash(event + ".", "success")
        except (ValueError, TypeError, sqlite3.IntegrityError) as e:
            conn.rollback(); flash(f"Billing action failed: {e}", "error")
        finally:
            conn.close()
        return redirect(url_for("platform_school_billing", school_id=school_id))
    plans = conn.execute("SELECT * FROM subscription_plans WHERE is_active=1 AND code!='trial' ORDER BY price_ngn").fetchall()
    invoices = conn.execute("SELECT * FROM billing_invoices WHERE school_id=? ORDER BY id DESC", (school_id,)).fetchall()
    payments = conn.execute("SELECT p.*, i.invoice_number FROM billing_payments p LEFT JOIN billing_invoices i ON i.id=p.invoice_id WHERE p.school_id=? ORDER BY p.id DESC", (school_id,)).fetchall()
    state = subscription_state(school)
    conn.close()
    return render_template("platform_school_billing.html", school=school, plans=plans, invoices=invoices, payments=payments, state=state)


@app.route("/platform/subscriptions")
@platform_admin_required
def platform_subscriptions():
    conn = get_db()
    schools = conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
    rows = []
    counts = {"legacy": 0, "trial": 0, "active": 0, "grace": 0, "expired": 0, "suspended": 0, "cancelled": 0}
    for school in schools:
        state = subscription_state(school)
        counts[state["status"]] = counts.get(state["status"], 0) + 1
        rows.append({"school": school, "state": state})
    conn.close()
    return render_template("platform_subscriptions.html", rows=rows, counts=counts)


@app.route("/platform/schools/<int:school_id>/subscription", methods=["GET", "POST"])
@platform_admin_required
def platform_school_subscription(school_id):
    conn = get_db()
    school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
    if not school:
        conn.close(); flash("School not found.", "error"); return redirect(url_for("platform_subscriptions"))
    if request.method == "POST":
        action = request.form.get("action", "").strip()
        now = datetime.datetime.utcnow()
        try:
            if action == "start_trial":
                days = max(1, min(365, int(request.form.get("days", "30"))))
                end = now + datetime.timedelta(days=days)
                conn.execute("UPDATE schools SET subscription_plan='trial', subscription_status='trial', trial_started_at=?, trial_ends_at=?, subscription_started_at=NULL, subscription_ends_at=NULL, grace_ends_at=NULL WHERE id=?", (_iso_utc(now), _iso_utc(end), school_id))
                event = f"Started {days}-day trial"
            elif action == "activate":
                plan = (request.form.get("plan") or "standard").strip().lower()[:50]
                plan_row = conn.execute("SELECT * FROM subscription_plans WHERE code=? AND is_active=1", (plan,)).fetchone()
                if not plan_row or plan == "trial": raise ValueError("Select an active paid plan")
                days = max(1, min(3650, int(request.form.get("days") or plan_row["billing_days"])))
                end = now + datetime.timedelta(days=days)
                conn.execute("UPDATE schools SET subscription_plan=?, subscription_status='active', subscription_started_at=?, subscription_ends_at=?, grace_ends_at=NULL WHERE id=?", (plan, _iso_utc(now), _iso_utc(end), school_id))
                event = f"Activated {plan_row['name']} subscription for {days} days"
            elif action == "extend":
                days = max(1, min(3650, int(request.form.get("days", "30"))))
                state = subscription_state(school)
                base_raw = school["subscription_ends_at"] if "subscription_ends_at" in school.keys() else None
                if state["status"] == "trial": base_raw = school["trial_ends_at"]
                base = now
                if base_raw:
                    try: base = max(now, datetime.datetime.fromisoformat(base_raw.replace("Z", "")))
                    except ValueError: pass
                end = base + datetime.timedelta(days=days)
                field = "trial_ends_at" if state["status"] == "trial" else "subscription_ends_at"
                conn.execute(f"UPDATE schools SET {field}=? WHERE id=?", (_iso_utc(end), school_id))
                event = f"Extended {state['label']} by {days} days"
            elif action == "grace":
                days = max(1, min(90, int(request.form.get("days", "7"))))
                end = now + datetime.timedelta(days=days)
                conn.execute("UPDATE schools SET grace_ends_at=? WHERE id=?", (_iso_utc(end), school_id))
                event = f"Granted {days}-day grace period"
            elif action == "suspend":
                conn.execute("UPDATE schools SET subscription_status='suspended' WHERE id=?", (school_id,)); event = "Suspended subscription"
            elif action == "cancel":
                conn.execute("UPDATE schools SET subscription_status='cancelled' WHERE id=?", (school_id,)); event = "Cancelled subscription"
            elif action == "legacy":
                conn.execute("UPDATE schools SET subscription_plan='legacy', subscription_status='legacy', grace_ends_at=NULL WHERE id=?", (school_id,)); event = "Restored legacy access"
            else:
                raise ValueError("Unknown subscription action")
            log_audit(conn, "platform_admin", session.get("platform_admin_name"), "subscription_change", details=f"{event} for '{school['name']}'", school_id=school_id)
            conn.commit(); flash(f"{event} for {school['name']}.", "success")
        except (ValueError, TypeError) as e:
            conn.rollback(); flash(f"Subscription change failed: {e}", "error")
        finally:
            conn.close()
        return redirect(url_for("platform_school_subscription", school_id=school_id))
    state = subscription_state(school)
    plan = subscription_plan_for_school(conn, school)
    usage = school_plan_usage(conn, school_id)
    limits = plan_limit_state(plan, usage)
    plans = conn.execute("SELECT * FROM subscription_plans WHERE is_active=1 AND code != 'trial' ORDER BY price_ngn").fetchall()
    conn.close()
    return render_template("platform_school_subscription.html", school=school, state=state, plan=plan, usage=usage, limits=limits, plans=plans)


@app.route("/platform/schools")
@platform_admin_required
def platform_schools():
    conn = get_db()
    platform_q = (request.args.get("q") or "").strip().lower()[:60]
    schools = conn.execute(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM users u WHERE u.school_id=s.id AND u.role IN ('admin','sub_admin')) as admin_count, "
        "(SELECT COUNT(*) FROM users u WHERE u.school_id=s.id AND u.role='teacher') as teacher_count, "
        "(SELECT COUNT(*) FROM classes c WHERE c.school_id=s.id) as class_count, "
        "(SELECT COUNT(*) FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=s.id AND st.is_active=1) as student_count, "
        "(SELECT ac.code FROM activation_codes ac WHERE ac.school_id=s.id ORDER BY ac.id DESC LIMIT 1) as activation_code "
        "FROM schools s WHERE (?='' OR LOWER(s.name) LIKE ? OR LOWER(COALESCE(s.school_code,'')) LIKE ? OR LOWER(COALESCE(s.registered_email,'')) LIKE ?) ORDER BY s.name",
        (platform_q, f"%{platform_q}%", f"%{platform_q}%", f"%{platform_q}%")
    ).fetchall()
    code_status = {s["id"]: current_activation_code_status(conn, s["id"]) for s in schools}
    conn.close()
    return render_template("platform_schools.html", schools=schools, code_status=code_status)


@app.route("/platform/schools/new", methods=["GET", "POST"])
@platform_admin_required
def platform_new_school():
    if request.method == "POST":
        school_name = request.form.get("school_name", "").strip()
        registered_email = request.form.get("registered_email", "").strip()
        admin_name = request.form.get("admin_name", "").strip()
        admin_username = request.form.get("admin_username", "").strip()

        errors = []
        if not school_name or not registered_email or not admin_name or not admin_username:
            errors.append("Please fill in every field.")
        if registered_email and ("@" not in registered_email or "." not in registered_email.split("@")[-1]):
            errors.append("Please provide a valid school email address.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("platform_new_school.html")

        conn = get_db()
        try:
            trial_start = datetime.datetime.utcnow()
            trial_end = trial_start + datetime.timedelta(days=30)
            # Generate a collision-safe permanent School ID *before* the INSERT.
            # The previous implementation inserted the base school_code first, so
            # a UNIQUE constraint could fail before the collision-repair UPDATE ran.
            tenant_id = "TEN-" + secrets.token_hex(6).upper()
            while conn.execute("SELECT 1 FROM schools WHERE tenant_id=?", (tenant_id,)).fetchone():
                tenant_id = "TEN-" + secrets.token_hex(6).upper()

            code = generate_school_code(conn, school_name)

            cur = conn.execute(
                "INSERT INTO schools (name, registered_email, activation_status, tenant_id, school_code, subscription_plan, subscription_status, trial_started_at, trial_ends_at) VALUES (?,?, 'pending', ?, ?, 'trial', 'trial', ?, ?)",
                (school_name, registered_email, tenant_id, code, _iso_utc(trial_start), _iso_utc(trial_end)),
            )
            school_id = cur.lastrowid
            # No usable password yet — the School Admin sets a real one during activation.
            placeholder_hash = generate_password_hash(secrets.token_urlsafe(32))
            tenant_id = conn.execute("SELECT tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()["tenant_id"]
            conn.execute(
                "INSERT INTO users (school_id, tenant_id, name, username, password_hash, role, first_login_required) VALUES (?,?,?,?,?, 'admin', 1)",
                (school_id, tenant_id, admin_name, admin_username, placeholder_hash),
            )
            code, expires_at = generate_activation_code(conn, school_id, created_by=session.get("platform_admin_name"))
            log_audit(conn, "platform_admin", session.get("platform_admin_name"), "onboard_school",
                      details=f"Onboarded '{school_name}' ({registered_email})", school_id=school_id)
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.rollback()
            conn.close()
            if "users.username" in str(e):
                flash("That admin username is already taken — please choose another.", "error")
            else:
                flash(f"Couldn't create the school: {e}", "error")
            return render_template("platform_new_school.html")

        conn.close()
        flash(f"'{school_name}' created and placed in pending activation.", "success")
        return redirect(url_for("platform_activation_requests"))

    return render_template("platform_new_school.html")


@app.route("/platform/schools/<int:school_id>/verification")
@platform_admin_required
def platform_school_verification(school_id):
    """Platform-only tenant identity and readiness verification for one school."""
    conn = get_db()
    school = get_school(conn, school_id)
    if not school:
        conn.close()
        flash("School not found.", "error")
        return redirect(url_for("platform_schools"))

    checks, ready = school_readiness_checks(conn, school_id)
    identity_checks = []
    identity_checks.append(("School has a permanent School ID", bool((school["school_code"] or "").strip())))
    identity_checks.append(("School has a permanent Tenant ID", bool((school["tenant_id"] or "").strip())))
    identity_checks.append(("School ID is unique", conn.execute("SELECT COUNT(*) n FROM schools WHERE school_code=?", (school["school_code"],)).fetchone()["n"] == 1 if school["school_code"] else False))
    identity_checks.append(("Tenant ID is unique", conn.execute("SELECT COUNT(*) n FROM schools WHERE tenant_id=?", (school["tenant_id"],)).fetchone()["n"] == 1 if school["tenant_id"] else False))
    identity_checks.append(("School Admin users carry the same Tenant ID", conn.execute("SELECT COUNT(*) n FROM users WHERE school_id=? AND role='admin' AND (tenant_id IS NULL OR tenant_id<>?)", (school_id, school["tenant_id"])).fetchone()["n"] == 0))
    role_mismatch = 0
    if table_exists(conn, "role_assignments"):
        role_mismatch = conn.execute("SELECT COUNT(*) n FROM role_assignments WHERE school_id=? AND (tenant_id IS NULL OR tenant_id<>?)", (school_id, school["tenant_id"])).fetchone()["n"]
    identity_checks.append(("Role assignments carry the same Tenant ID", role_mismatch == 0))
    data_counts = {
        "students": conn.execute("SELECT COUNT(*) n FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=?", (school_id,)).fetchone()["n"],
        "teachers": conn.execute("SELECT COUNT(*) n FROM users WHERE school_id=? AND role='teacher'", (school_id,)).fetchone()["n"],
        "classes": conn.execute("SELECT COUNT(*) n FROM classes WHERE school_id=?", (school_id,)).fetchone()["n"],
        "subjects": conn.execute("SELECT COUNT(*) n FROM subjects WHERE school_id=?", (school_id,)).fetchone()["n"],
        "sessions": conn.execute("SELECT COUNT(*) n FROM sessions WHERE school_id=?", (school_id,)).fetchone()["n"],
    }
    conn.close()
    return render_template("platform_school_verification.html", school=school, readiness_checks=checks, readiness_ready=ready, identity_checks=identity_checks, data_counts=data_counts)


@app.route("/platform/schools/<int:school_id>/provisioning")
@platform_admin_required
def platform_school_provisioning(school_id):
    """Show a non-sensitive onboarding/provisioning checklist for one school."""
    conn = get_db()
    school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
    if not school:
        conn.close()
        flash("School not found.", "error")
        return redirect(url_for("platform_schools"))
    admin = conn.execute(
        "SELECT id, name, username, role FROM users WHERE school_id=? AND role='admin' ORDER BY id LIMIT 1",
        (school_id,),
    ).fetchone()
    role_count = conn.execute(
        "SELECT COUNT(*) AS n FROM role_assignments WHERE school_id=? AND status='active'",
        (school_id,),
    ).fetchone()["n"] if table_exists(conn, "role_assignments") else 0
    class_count = conn.execute("SELECT COUNT(*) AS n FROM classes WHERE school_id=?", (school_id,)).fetchone()["n"]
    student_count = conn.execute(
        "SELECT COUNT(*) AS n FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=?",
        (school_id,),
    ).fetchone()["n"]
    code_status = current_activation_code_status(conn, school_id)
    checks = {
        "school_id": bool(school["school_code"]),
        "tenant_id": bool(school["tenant_id"]),
        "admin": bool(admin),
        "activated": school["activation_status"] == "active",
        "not_suspended": not bool(school["is_suspended"]),
        "not_archived": not bool(school["is_archived"]),
        "role_assignment": role_count > 0,
    }
    conn.close()
    return render_template(
        "platform_school_provisioning.html", school=school, admin=admin,
        role_count=role_count, class_count=class_count, student_count=student_count,
        code_status=code_status, checks=checks,
    )


@app.route("/platform/schools/<int:school_id>/regenerate_code", methods=["POST"])
@platform_admin_required
def platform_regenerate_code(school_id):
    conn = get_db()
    school = get_school(conn, school_id)
    if not school:
        conn.close()
        flash("School not found.", "error")
        return redirect(url_for("platform_schools"))
    code, expires_at = generate_activation_code(conn, school_id, created_by=session.get("platform_admin_name"))
    log_audit(conn, "platform_admin", session.get("platform_admin_name"), "regenerate_activation_code",
              details=f"Regenerated code for '{school['name']}'", school_id=school_id)
    conn.commit()
    sent, msg = (False, "No registered email on file.")
    if school["registered_email"]:
        sent, msg = send_platform_email(
            school["registered_email"], f"New activation code for {school['name']}",
            f"A new activation code has been issued: {code}\nThis code expires {format_dmy(expires_at)} "
            "and invalidates any previous code.",
        )
    conn.close()
    if sent:
        flash(f"Activation code generated and sent successfully. Super Admin can also view the current code in the Schools / Activation Requests screens: {code}", "success")
    else:
        # Delivery configuration is optional. The Super Admin is authorized to
        # view the newly generated code in the protected platform screens, so
        # missing email/SMS/WhatsApp configuration must not make regeneration
        # look like a failed operation.
        flash(f"Activation code generated successfully. Delivery is not configured, so use the protected Super Admin screen to view the code: {code}", "success")
    return redirect(url_for("platform_schools"))


@app.route("/platform/schools/<int:school_id>/archive", methods=["POST"])
@platform_admin_required
def platform_archive_school(school_id):
    conn = get_db()
    school = get_school(conn, school_id)
    if school:
        conn.execute("UPDATE schools SET is_archived=1 WHERE id=?", (school_id,))
        log_audit(conn, "platform_admin", session.get("platform_admin_name"), "archive_school",
                  details=f"Archived '{school['name']}'", school_id=school_id)
        conn.commit()
        flash(f"'{school['name']}' has been archived. Its staff and students can no longer log in.", "success")
    conn.close()
    return redirect(url_for("platform_schools"))


@app.route("/platform/schools/<int:school_id>/unarchive", methods=["POST"])
@platform_admin_required
def platform_unarchive_school(school_id):
    conn = get_db()
    school = get_school(conn, school_id)
    if school:
        conn.execute("UPDATE schools SET is_archived=0 WHERE id=?", (school_id,))
        log_audit(conn, "platform_admin", session.get("platform_admin_name"), "unarchive_school",
                  details=f"Unarchived '{school['name']}'", school_id=school_id)
        conn.commit()
        flash(f"'{school['name']}' has been unarchived.", "success")
    conn.close()
    return redirect(url_for("platform_schools"))


@app.route("/platform/schools/<int:school_id>/force_logout", methods=["POST"])
@platform_admin_required
def platform_force_logout_school(school_id):
    conn = get_db()
    school = get_school(conn, school_id)
    if school:
        conn.execute("UPDATE schools SET force_logout_at=? WHERE id=?",
                     (datetime.datetime.utcnow().isoformat(timespec="seconds"), school_id))
        log_audit(conn, "platform_admin", session.get("platform_admin_name"), "force_logout_school",
                  details=f"Forced logout for all of '{school['name']}'s users", school_id=school_id)
        conn.commit()
        flash(f"All of '{school['name']}'s staff and students will be signed out on their next action.", "success")
    conn.close()
    return redirect(url_for("platform_schools"))


@app.route("/activate", methods=["GET", "POST"])
@rate_limit(max_attempts=8, window_seconds=600)
def activate_school():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        code = request.form.get("code", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(?) AND role='admin'", (username,)).fetchone()
        if not user:
            conn.close()
            flash("No pending school admin account found with that username.", "error")
            return render_template("activate.html")
        school = get_school(conn, user["school_id"])
        if school["activation_status"] == "active":
            conn.close()
            flash("This school is already active — please log in instead.", "error")
            return redirect(url_for("login"))
        if len(password) < 6:
            conn.close()
            flash("Password must be at least 6 characters.", "error")
            return render_template("activate.html")
        if password != confirm:
            conn.close()
            flash("Password and confirmation don't match.", "error")
            return render_template("activate.html")

        ok, reason = verify_activation_code(conn, school["id"], code)
        if not ok:
            conn.close()
            flash(reason, "error")
            return render_template("activate.html")

        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), user["id"]))
        conn.execute(
            "UPDATE schools SET activation_status='active', activated_at=? WHERE id=?",
            (datetime.datetime.utcnow().isoformat(timespec="seconds"), school["id"]),
        )
        log_audit(conn, "admin", user["name"], "school_activated", details=f"'{school['name']}' activated", school_id=school["id"])
        conn.commit()
        conn.close()

        session.clear()
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]
        session["position"] = user["position"]
        session["school_id"] = user["school_id"]
        session["tenant_id"] = school["tenant_id"] if "tenant_id" in school.keys() else None
        session["school_code"] = school["school_code"] if "school_code" in school.keys() else None
        session["login_time"] = datetime.datetime.utcnow().isoformat(timespec="seconds")
        flash(f"Welcome! '{school['name']}' is now active — let's complete your first-time setup.", "success")
        return redirect(url_for("admin_first_login"))

    return render_template("activate.html")


@app.route("/platform/schools/export")
@platform_admin_required
def platform_schools_export():
    fmt = request.args.get("format", "csv")
    conn = get_db()
    schools = conn.execute(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM users u WHERE u.school_id=s.id AND u.role IN ('admin','sub_admin')) as admin_count, "
        "(SELECT COUNT(*) FROM users u WHERE u.school_id=s.id AND u.role='teacher') as teacher_count, "
        "(SELECT COUNT(*) FROM classes c WHERE c.school_id=s.id) as class_count, "
        "(SELECT COUNT(*) FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=s.id AND st.is_active=1) as student_count, "
        "(SELECT ac.code FROM activation_codes ac WHERE ac.school_id=s.id ORDER BY ac.id DESC LIMIT 1) as activation_code "
        "FROM schools s ORDER BY s.name"
    ).fetchall()
    conn.close()

    headers = ["School ID", "School", "Registered Email", "Activation Status", "Account Status",
               "Admins", "Teachers", "Classes", "Students", "Date Registered", "Date Activated"]
    rows = [
        [s["id"], s["name"], s["registered_email"] or "-",
         "Active" if s["activation_status"] == "active" else "Pending",
         "Archived" if s["is_archived"] else ("Suspended" if s["is_suspended"] else "Active"),
         s["admin_count"], s["teacher_count"], s["class_count"], s["student_count"],
         format_dmy(s["created_at"]), format_dmy(s["activated_at"]) if s["activated_at"] else "-"]
        for s in schools
    ]
    return _send_report(fmt, "Schools", headers, rows, "platform_schools_summary")


@app.route("/platform/schools/<int:school_id>/suspend", methods=["POST"])
@platform_admin_required
def platform_suspend_school(school_id):
    conn = get_db()
    school = get_school(conn, school_id)
    if school:
        conn.execute("UPDATE schools SET is_suspended=1 WHERE id=?", (school_id,))
        log_audit(conn, "platform_admin", session.get("platform_admin_name"), "suspend_school",
                  details=f"Suspended '{school['name']}'", school_id=school_id)
        conn.commit()
        flash(f"'{school['name']}' has been suspended. Its staff and students can no longer log in.", "success")
    conn.close()
    return redirect(url_for("platform_schools"))


@app.route("/platform/schools/<int:school_id>/activate", methods=["POST"])
@platform_admin_required
def platform_activate_school(school_id):
    conn = get_db()
    school = get_school(conn, school_id)
    if school:
        conn.execute("UPDATE schools SET is_suspended=0 WHERE id=?", (school_id,))
        log_audit(conn, "platform_admin", session.get("platform_admin_name"), "activate_school",
                  details=f"Activated '{school['name']}'", school_id=school_id)
        conn.commit()
        flash(f"'{school['name']}' has been reactivated.", "success")
    conn.close()
    return redirect(url_for("platform_schools"))


@app.route("/platform/schools/<int:school_id>/delete", methods=["POST"])
@platform_admin_required
def platform_delete_school(school_id):
    if request.form.get("confirm_text", "").strip().upper() != "DELETE":
        flash("You must type DELETE exactly to confirm.", "error")
        return redirect(url_for("platform_schools"))

    conn = get_db()
    school = get_school(conn, school_id)
    if not school:
        conn.close()
        flash("School not found.", "error")
        return redirect(url_for("platform_schools"))

    school_name = school["name"]
    class_ids = [r["id"] for r in conn.execute("SELECT id FROM classes WHERE school_id=?", (school_id,)).fetchall()]
    if class_ids:
        placeholders = ",".join("?" * len(class_ids))
        student_ids = [r["id"] for r in conn.execute(
            f"SELECT id FROM students WHERE class_id IN ({placeholders})", class_ids
        ).fetchall()]
        if student_ids:
            sp = ",".join("?" * len(student_ids))
            conn.execute(f"DELETE FROM student_skill_ratings WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM student_term_info WHERE student_id IN ({sp})", student_ids)
            audit_scores_deleted(conn, list(student_ids))
            conn.execute(f"DELETE FROM score_history WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM scores WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM enrollments WHERE student_id IN ({sp})", student_ids)
            conn.execute(f"DELETE FROM students WHERE id IN ({sp})", student_ids)
        conn.execute(f"DELETE FROM class_subjects WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM timetable_entries WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM timetable_entries_v2 WHERE class_id IN ({placeholders})", class_ids)
        conn.execute(f"DELETE FROM classes WHERE id IN ({placeholders})", class_ids)
    conn.execute("DELETE FROM timetable_periods WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM subjects WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM skill_traits WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM grade_scale WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM grading_config WHERE school_id=?", (school_id,))
    term_ids = [r["id"] for r in conn.execute(
        "SELECT terms.id FROM terms JOIN sessions ON sessions.id=terms.session_id WHERE sessions.school_id=?",
        (school_id,),
    ).fetchall()]
    if term_ids:
        tp = ",".join("?" * len(term_ids))
        conn.execute(f"DELETE FROM terms WHERE id IN ({tp})", term_ids)
    conn.execute("DELETE FROM sessions WHERE school_id=?", (school_id,))
    conn.execute("DELETE FROM users WHERE school_id=?", (school_id,))
    if school["logo_filename"]:
        old_path = os.path.join(INSTANCE_DIR, school["logo_filename"])
        if os.path.exists(old_path):
            os.remove(old_path)
    conn.execute("DELETE FROM schools WHERE id=?", (school_id,))
    log_audit(conn, "platform_admin", session.get("platform_admin_name"), "delete_school",
              details=f"Permanently deleted '{school_name}'", school_id=None)
    conn.commit()
    conn.close()
    flash(f"'{school_name}' and all its data have been permanently deleted.", "success")
    return redirect(url_for("platform_schools"))


@app.route("/platform/users")
@platform_admin_required
def platform_users():
    conn = get_db()
    school_filter = request.args.get("school_id", type=int)
    schools = conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
    query = (
        "SELECT u.*, s.name as school_name FROM users u JOIN schools s ON s.id=u.school_id"
    )
    params = ()
    if school_filter:
        query += " WHERE u.school_id=?"
        params = (school_filter,)
    query += " ORDER BY s.name, u.role, u.name"
    users = conn.execute(query, params).fetchall()
    conn.close()
    return render_template("platform_users.html", users=users, schools=schools, school_filter=school_filter)


@app.route("/platform/users/<int:user_id>/reset_password", methods=["POST"])
@platform_admin_required
def platform_reset_user_password(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("platform_users"))
    new_password = secrets.token_urlsafe(6)
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_password), user_id))
    log_audit(conn, "platform_admin", session.get("platform_admin_name"), "reset_user_password",
              details=f"Reset password for {user['name']} ({user['username']})", school_id=user["school_id"])
    conn.commit()
    conn.close()
    flash(f"Password reset for {user['name']} (username: {user['username']}). New temporary password: {new_password}", "success")
    return redirect(url_for("platform_users"))


@app.route("/platform/backups")
@platform_admin_required
def platform_backups():
    """Super Admin backup dashboard. Shows metadata only; never exposes database contents."""
    import os as _os
    import sqlite3 as _sqlite3
    import backup_db as _backup_db
    dest = _backup_db.db.INSTANCE_DIR + "/backups"
    _os.makedirs(dest, exist_ok=True)
    files=[]
    for name in sorted(_os.listdir(dest), reverse=True):
        if not (name.startswith("school-") and name.endswith(".db")): continue
        path=_os.path.join(dest,name)
        try:
            size=_os.path.getsize(path)
            c=_sqlite3.connect(path, timeout=10)
            integrity=c.execute("PRAGMA integrity_check").fetchone()[0]
            schools=c.execute("SELECT COUNT(*) FROM schools").fetchone()[0]
            c.close()
            status="OK" if integrity=="ok" else "FAILED"
        except Exception:
            size=0; schools=0; status="FAILED"
        files.append({"name":name,"size":size,"schools":schools,"status":status})
    return render_template("platform_backups.html", backups=files)


@app.route("/platform/backups/create", methods=["POST"])
@platform_admin_required
def platform_backup_create():
    import backup_db as _backup_db
    try:
        path, schools = _backup_db.make_backup(keep=14)
        log_audit(get_db(), "platform_admin", session.get("platform_admin_name"), "database_backup_created", details=f"Verified backup created ({schools} schools)")
        flash("Verified database backup created successfully.", "success")
    except Exception as exc:
        flash(f"Backup failed safely: {exc}", "error")
    return redirect(url_for("platform_backups"))


@app.route("/platform/backups/download/<path:name>")
@platform_admin_required
def platform_backup_download(name):
    import os as _os
    from flask import send_from_directory
    import backup_db as _backup_db
    if not (name.startswith("school-") and name.endswith(".db") and _os.path.basename(name)==name):
        abort(404)
    dest=_backup_db.db.INSTANCE_DIR + "/backups"
    path=_os.path.join(dest,name)
    if not _os.path.isfile(path): abort(404)
    log_audit(get_db(), "platform_admin", session.get("platform_admin_name"), "database_backup_downloaded", details="Backup file downloaded")
    return send_from_directory(dest, name, as_attachment=True)


@app.route("/platform/audit")
@platform_admin_required
def platform_audit():
    conn = get_db()
    logs = conn.execute(
        "SELECT audit_log.*, schools.name as school_name FROM audit_log "
        "LEFT JOIN schools ON schools.id = audit_log.school_id "
        "ORDER BY audit_log.id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return render_template("platform_audit.html", logs=logs)


@app.route("/platform/security-audit")
@platform_admin_required
def platform_security_audit():
    conn = get_db()
    report = run_security_audit(conn)
    conn.close()
    return render_template("platform_security_audit.html", report=report)


@app.route("/admin/roles/<int:assignment_id>/scope", methods=["POST"])
@login_required("admin")
def admin_role_scope(assignment_id):
    conn=get_db(); sid=current_school_id()
    ra=conn.execute("SELECT * FROM role_assignments WHERE id=? AND school_id=?",(assignment_id,sid)).fetchone()
    if not ra:
        conn.close(); flash("Role assignment not found.","error"); return redirect(url_for("admin_roles"))
    level=request.form.get("school_level","All").strip(); department=request.form.get("department","").strip() or None
    class_id=request.form.get("class_id",type=int); class_arm=request.form.get("class_arm","").strip() or None
    subject_id=request.form.get("subject_id",type=int); start_date=request.form.get("start_date","").strip() or None
    end_date=request.form.get("end_date","").strip() or None
    conn.execute("UPDATE role_assignments SET school_level=?,department=?,class_id=?,class_arm=?,subject_id=?,start_date=?,end_date=?,is_temporary=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=?",(level,department,class_id,class_arm,subject_id,start_date,end_date,1 if end_date else 0,assignment_id,sid))
    new_scope=f"level={level}; department={department or '*'}; class={class_id or '*'}; arm={class_arm or '*'}; subject={subject_id or '*'}"
    old_scope=f"level={ra['school_level']}; department={ra['department'] or '*'}; class={ra['class_id'] or '*'}; arm={ra['class_arm'] or '*'}; subject={ra['subject_id'] or '*'}"
    conn.execute("INSERT INTO role_assignment_audit (assignment_id,user_id,school_id,actor_user_id,actor_name,action,previous_role,new_role,previous_scope,new_scope,approval_status,reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(assignment_id,ra['user_id'],sid,session['user_id'],session.get('name'),'scope_changed',ra['role'],ra['role'],old_scope,new_scope,'approved','Scope updated by School Admin'))
    conn.commit(); conn.close(); flash("Role scope updated.","success"); return redirect(url_for("admin_roles"))

@app.route("/admin/roles/<int:assignment_id>/permissions", methods=["POST"])
@login_required("admin")
def admin_role_permissions(assignment_id):
    conn=get_db(); sid=current_school_id()
    ra=conn.execute("SELECT * FROM role_assignments WHERE id=? AND school_id=?",(assignment_id,sid)).fetchone()
    if not ra:
        conn.close(); flash("Role assignment not found.","error"); return redirect(url_for("admin_roles"))
    allowed=set(ROLE_CATALOG.get(ra['role'],[])); requested=set(request.form.getlist('permissions')) & allowed
    conn.execute("DELETE FROM role_assignment_permissions WHERE assignment_id=?",(assignment_id,))
    for perm in sorted(requested): conn.execute("INSERT INTO role_assignment_permissions (assignment_id,permission,granted) VALUES (?,?,1)",(assignment_id,perm))
    conn.execute("INSERT INTO role_assignment_audit (assignment_id,user_id,school_id,actor_user_id,actor_name,action,previous_role,new_role,approval_status,reason) VALUES (?,?,?,?,?,?,?,?,?,?)",(assignment_id,ra['user_id'],sid,session['user_id'],session.get('name'),'permissions_changed',ra['role'],ra['role'],'approved','Permissions updated by School Admin'))
    conn.commit(); conn.close(); flash("Permissions updated.","success"); return redirect(url_for("admin_roles"))

@app.route("/platform/roles")
@platform_admin_required
def platform_roles():
    conn = get_db()
    rows = conn.execute("""
        SELECT ra.*, u.name AS user_name, u.username, s.name AS school_name,
               s.school_code, s.tenant_id
        FROM role_assignments ra
        JOIN users u ON u.id=ra.user_id
        JOIN schools s ON s.id=ra.school_id
        ORDER BY ra.id DESC
    """).fetchall()
    schools = conn.execute("SELECT id,name FROM schools ORDER BY name").fetchall()
    conn.close()
    return render_template("platform_roles.html", assignments=rows, schools=schools,
                           roles=assignable_roles(), levels=SCHOOL_LEVELS, ROLE_CATALOG=ROLE_CATALOG)

@app.route("/platform/roles/new", methods=["GET","POST"])
@platform_admin_required
def platform_role_new():
    conn = get_db()
    if request.method == "POST":
        user_id = request.form.get("user_id", type=int)
        school_id = request.form.get("school_id", type=int)
        role = request.form.get("role","").strip()
        level = request.form.get("school_level","All").strip()
        reason = request.form.get("reason","").strip()
        if not user_id or not school_id or role not in ROLE_CATALOG or level not in SCHOOL_LEVELS:
            flash("Select a valid user, school, role and school level.", "error")
            users = conn.execute("SELECT id,name,username,school_id FROM users WHERE school_id=? ORDER BY name",(school_id or 0,)).fetchall()
            schools = conn.execute("SELECT id,name FROM schools ORDER BY name").fetchall()
            conn.close()
            return render_template("platform_role_form.html", users=users, schools=schools, roles=assignable_roles(), levels=SCHOOL_LEVELS)
        user = conn.execute("SELECT * FROM users WHERE id=? AND school_id=?", (user_id, school_id)).fetchone()
        school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
        if not user or not school:
            flash("User does not belong to the selected school.", "error")
        else:
            cur = conn.execute("""
                INSERT INTO role_assignments
                (user_id, school_id, tenant_id, school_level, role, status, requested_by, approved_by, approved_at, reason)
                VALUES (?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP,?)
            """, (user_id, school_id, school["tenant_id"], level, role,
                  None, session.get("platform_admin_id"), reason or "Assigned by Super Admin"))
            aid = cur.lastrowid
            for perm in ROLE_CATALOG[role]:
                conn.execute("INSERT INTO role_assignment_permissions (assignment_id,permission) VALUES (?,?)",(aid,perm))
            conn.execute("""
                INSERT INTO role_assignment_audit
                (assignment_id,user_id,school_id,actor_user_id,actor_name,action,new_role,new_scope,approval_status,reason)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """,(aid,user_id,school_id,None,session.get("platform_admin_name"),"assigned",role,level,"approved",reason))
            log_audit(conn, "platform_admin", session.get("platform_admin_name"), "role_assigned",
                      f"{user['name']} → {role} ({level})", school_id)
            conn.commit()
            flash("Role assigned successfully.", "success")
            conn.close()
            return redirect(url_for("platform_roles"))
    school_id = request.args.get("school_id", type=int)
    schools = conn.execute("SELECT id,name FROM schools ORDER BY name").fetchall()
    users = conn.execute(
        "SELECT id,name,username,school_id FROM users WHERE (? IS NULL OR school_id=?) ORDER BY name",
        (school_id,school_id)
    ).fetchall()
    conn.close()
    return render_template("platform_role_form.html", users=users, schools=schools,
                           roles=assignable_roles(), levels=SCHOOL_LEVELS, selected_school=school_id)

@app.route("/platform/roles/<int:assignment_id>/revoke", methods=["POST"])
@platform_admin_required
def platform_role_revoke(assignment_id):
    conn = get_db()
    ra = conn.execute("SELECT * FROM role_assignments WHERE id=?", (assignment_id,)).fetchone()
    if not ra:
        conn.close(); flash("Role assignment not found.", "error"); return redirect(url_for("platform_roles"))
    conn.execute("UPDATE role_assignments SET status='revoked', updated_at=CURRENT_TIMESTAMP WHERE id=?", (assignment_id,))
    conn.execute("""
        INSERT INTO role_assignment_audit
        (assignment_id,user_id,school_id,actor_name,action,previous_role,previous_scope,approval_status,reason)
        VALUES (?,?,?,?,?,?,?,?,?)
    """,(assignment_id,ra["user_id"],ra["school_id"],session.get("platform_admin_name"),
        "revoked",ra["role"],ra["school_level"],"approved","Revoked by Super Admin"))
    log_audit(conn, "platform_admin", session.get("platform_admin_name"), "role_revoked", ra["role"], ra["school_id"])
    conn.commit(); conn.close()
    flash("Role assignment revoked.", "success")
    return redirect(url_for("platform_roles"))

@app.route("/admin/roles")
@login_required("admin","sub_admin")
def admin_roles():
    conn = get_db()
    sid = current_school_id()
    users = conn.execute("SELECT id,name,username,role FROM users WHERE school_id=? ORDER BY name",(sid,)).fetchall()
    assignments = conn.execute("""
        SELECT ra.*, u.name AS user_name
        FROM role_assignments ra JOIN users u ON u.id=ra.user_id
        WHERE ra.school_id=? ORDER BY ra.id DESC
    """,(sid,)).fetchall()
    # Saved permissions per assignment (the checkboxes must show what is really granted).
    granted = {}
    for r in conn.execute("""SELECT rap.assignment_id, rap.permission FROM role_assignment_permissions rap
                             JOIN role_assignments ra ON ra.id=rap.assignment_id
                             WHERE ra.school_id=? AND rap.granted=1""", (sid,)).fetchall():
        granted.setdefault(r["assignment_id"], set()).add(r["permission"])
    conn.close()
    return render_template("admin_roles.html", users=users, assignments=assignments,
                           roles=assignable_roles(), levels=SCHOOL_LEVELS,
                           ROLE_CATALOG=ROLE_CATALOG, granted=granted)

@app.route("/admin/roles", methods=["POST"])
@login_required("admin")
def admin_role_assign():
    conn = get_db(); sid = current_school_id()
    user_id = request.form.get("user_id",type=int)
    role = request.form.get("role","").strip()
    level = request.form.get("school_level","All").strip()
    reason = request.form.get("reason","").strip()
    if not user_id or role not in ROLE_CATALOG or level not in SCHOOL_LEVELS:
        conn.close(); flash("Invalid role assignment.", "error"); return redirect(url_for("admin_roles"))
    if role in ("School Admin",):
        conn.close(); flash("School Admin is controlled by the platform and cannot be assigned here.", "error"); return redirect(url_for("admin_roles"))
    user = conn.execute("SELECT * FROM users WHERE id=? AND school_id=?",(user_id,sid)).fetchone()
    school = conn.execute("SELECT * FROM schools WHERE id=?",(sid,)).fetchone()
    if not user:
        conn.close(); flash("User not found in your school.", "error"); return redirect(url_for("admin_roles"))
    if role in ADMIN_ONLY_ROLES or user["role"] == "admin":
        conn.close(); flash("School Admin is an administrative account, not a staff role.", "error"); return redirect(url_for("admin_roles"))
    if user["role"] == "teacher":
        res = add_staff_role(conn, user_id, sid, role, session["user_id"], session.get("name"), school_level=level,
                             reason=reason or "Assigned by School Admin")
        conn.commit(); conn.close()
        flash("That staff member already has this role." if res == "exists" else "Role added and active immediately.", "success" if res != "exists" else "error")
        return redirect(url_for("admin_roles"))
    cur = conn.execute("""
        INSERT INTO role_assignments
        (user_id,school_id,tenant_id,school_level,role,status,requested_by,approved_by,approved_at,reason)
        VALUES (?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP,?)
    """,(user_id,sid,school["tenant_id"],level,role,session["user_id"],session["user_id"],reason or "Assigned by School Admin"))
    aid=cur.lastrowid
    for perm in ROLE_CATALOG[role]:
        conn.execute("INSERT INTO role_assignment_permissions (assignment_id,permission) VALUES (?,?)",(aid,perm))
    conn.execute("""
        INSERT INTO role_assignment_audit
        (assignment_id,user_id,school_id,actor_user_id,actor_name,action,new_role,new_scope,approval_status,reason)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """,(aid,user_id,sid,session["user_id"],session.get("name"),"assigned",role,level,"approved",reason))
    conn.commit(); conn.close()
    flash("Role assigned.", "success")
    return redirect(url_for("admin_roles"))

@app.route("/admin/roles/<int:assignment_id>/revoke", methods=["POST"])
@login_required("admin")
def admin_role_revoke(assignment_id):
    conn=get_db(); sid=current_school_id()
    ra=conn.execute("SELECT * FROM role_assignments WHERE id=? AND school_id=?",(assignment_id,sid)).fetchone()
    if not ra:
        conn.close(); flash("Role assignment not found.", "error"); return redirect(url_for("admin_roles"))
    holder = conn.execute("SELECT role FROM users WHERE id=? AND school_id=?", (ra["user_id"], sid)).fetchone()
    if holder and holder["role"] == "teacher":
        remove_staff_role(conn, ra["user_id"], sid, ra["role"], session["user_id"], session.get("name"), reason="Revoked by School Admin")
    else:
        conn.execute("UPDATE role_assignments SET status='revoked',updated_at=CURRENT_TIMESTAMP WHERE id=?",(assignment_id,))
        conn.execute("""
            INSERT INTO role_assignment_audit
            (assignment_id,user_id,school_id,actor_user_id,actor_name,action,previous_role,previous_scope,approval_status,reason)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """,(assignment_id,ra["user_id"],sid,session["user_id"],session.get("name"),"revoked",ra["role"],ra["school_level"],"approved","Revoked by School Admin"))
    conn.commit(); conn.close()
    flash("Role revoked.", "success"); return redirect(url_for("admin_roles"))


@app.route("/platform/notifications", methods=["GET", "POST"])
@platform_admin_required
def platform_notifications():
    conn = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()
        target_role = request.form.get("target_role", "all")
        if target_role not in ("all", "admin", "teacher", "student", "parent"):
            target_role = "all"
        school_id = request.form.get("school_id") or None  # blank = all schools

        if not title or not message:
            flash("Please fill in both a title and a message.", "error")
        else:
            conn.execute(
                "INSERT INTO notifications (sender_label, school_id, target_role, title, message) VALUES (?,?,?,?,?)",
                (f"Platform Admin: {session.get('platform_admin_name')}", school_id, target_role, title, message),
            )
            school_row = get_school(conn, school_id) if school_id else None
            log_audit(
                conn, "platform_admin", session.get("platform_admin_name"), "send_notification",
                details=f"'{title}' to {target_role} in {school_row['name'] if school_row else 'ALL schools'}",
                school_id=school_id,
            )
            conn.commit()
            flash("Notification sent.", "success")
            conn.close()
            return redirect(url_for("platform_notifications"))

    schools = conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
    sent = conn.execute(
        "SELECT n.*, s.name as school_name FROM notifications n LEFT JOIN schools s ON s.id=n.school_id "
        "ORDER BY n.id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return render_template("platform_notifications.html", schools=schools, sent=sent)


# ---------- AI layer / architecture UI ----------
def _ai_settings(conn, sid):
    row=conn.execute("SELECT * FROM school_ai_settings WHERE school_id=?",(sid,)).fetchone()
    if not row:
        conn.execute("INSERT INTO school_ai_settings(school_id) VALUES (?)",(sid,)); conn.commit(); row=conn.execute("SELECT * FROM school_ai_settings WHERE school_id=?",(sid,)).fetchone()
    return row

def _ai_consent(conn, student_id):
    r=conn.execute("SELECT status FROM student_ai_consent WHERE student_id=? AND school_id=?",(student_id,current_school_id())).fetchone()
    return (r["status"]=="granted" if r else False),(r["status"] if r else "pending")

def _ai_log(conn,feature,action,student_id=None,consent_status=None,scope="minimal",request_summary="",output_summary=""):
    conn.execute("INSERT INTO ai_audit_log(school_id,user_id,feature,student_id,consent_status,data_scope,action,request_summary,output_summary) VALUES (?,?,?,?,?,?,?,?,?)",(current_school_id(),session.get("user_id"),feature,student_id,consent_status,scope,action,request_summary[:500],output_summary[:1000])); conn.commit()


def _ai_teacher_allowed(conn, student_id):
    if session.get("role") != "teacher": return True
    row=conn.execute("SELECT class_id FROM students WHERE id=?",(student_id,)).fetchone()
    return bool(row and can_view_class_results(conn,session.get("role"),session.get("position"),session["user_id"],row["class_id"]))

def _ai_rows(conn,student_id,term_id):
    return conn.execute("SELECT sc.*,sub.name subject_name FROM scores sc JOIN subjects sub ON sub.id=sc.subject_id JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id WHERE sc.student_id=? AND sc.term_id=? AND c.school_id=?",(student_id,term_id,current_school_id())).fetchall()

def _att(conn,student_id,term_id):
    r=conn.execute("SELECT COUNT(*) n,SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) p FROM attendance_records WHERE student_id=? AND term_id=?",(student_id,term_id)).fetchone(); return (r["p"] or 0)/(r["n"] or 1)*100 if r["n"] else None

def _prev_term(conn,term):
    return conn.execute("SELECT t.*,s.name session_name FROM terms t JOIN sessions s ON s.id=t.session_id WHERE t.session_id=? AND t.id<? ORDER BY t.id DESC LIMIT 1",(term["session_id"],term["id"])).fetchone() if term else None

@app.route("/ai")
@login_required("admin","sub_admin","teacher")
def ai_command_center():
    conn=get_db(); sid=current_school_id(); term=current_term(conn); settings=_ai_settings(conn,sid); recent=conn.execute("SELECT * FROM ai_outputs WHERE school_id=? ORDER BY id DESC LIMIT 8",(sid,)).fetchall(); conn.close()
    return render_template("ai_command_center.html",ai_settings=settings,term=term,recent=recent,provider_configured=ai_provider_configured())

@app.route("/ai/settings",methods=["GET","POST"])
@login_required("admin","sub_admin")
def ai_settings_page():
    conn=get_db(); sid=current_school_id(); settings=_ai_settings(conn,sid)
    if request.method=="POST":
        names=["result_analysis","teacher_comments","principal_comments","performance_alerts","ai_tutor","learning_materials","result_assistant"]; vals=[1 if request.form.get(n) else 0 for n in names]
        try: retention=max(30,min(int(request.form.get("retention_days") or 365),3650))
        except ValueError: retention=365
        conn.execute("UPDATE school_ai_settings SET enabled=?,process_student_data=?,result_analysis=?,teacher_comments=?,principal_comments=?,performance_alerts=?,ai_tutor=?,learning_materials=?,result_assistant=?,retention_days=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE school_id=?",(1 if request.form.get("enabled") else 0,1 if request.form.get("process_student_data") else 0,*vals,retention,session["user_id"],sid)); _ai_log(conn,"privacy","settings_updated",scope="school"); conn.close(); flash("AI privacy settings saved.","success"); return redirect(url_for("ai_settings_page"))
    cons=conn.execute("SELECT status,COUNT(*) c FROM student_ai_consent WHERE school_id=? GROUP BY status",(sid,)).fetchall(); audit=conn.execute("SELECT * FROM ai_audit_log WHERE school_id=? ORDER BY id DESC LIMIT 25",(sid,)).fetchall(); conn.close(); return render_template("ai_privacy.html",ai_settings=settings,consent_counts={r["status"]:r["c"] for r in cons},audit=audit,provider_configured=ai_provider_configured())

@app.route("/ai/consent",methods=["GET","POST"])
@login_required("admin","sub_admin")
def ai_consent():
    conn=get_db(); sid=current_school_id()
    if request.method=="POST":
        student_id=request.form.get("student_id",type=int); status=request.form.get("status","pending"); status=status if status in ("pending","granted","withdrawn") else "pending"
        ok=conn.execute("SELECT st.id FROM students st JOIN classes c ON c.id=st.class_id WHERE st.id=? AND c.school_id=?",(student_id,sid)).fetchone()
        if ok:
            conn.execute("INSERT INTO student_ai_consent(student_id,school_id,status,granted_by_type,granted_by_id,policy_version,granted_at,withdrawn_at) VALUES (?,?,?,?,?,?,CASE WHEN ?='granted' THEN CURRENT_TIMESTAMP END,CASE WHEN ?='withdrawn' THEN CURRENT_TIMESTAMP END) ON CONFLICT(student_id) DO UPDATE SET status=excluded.status,granted_by_type=excluded.granted_by_type,granted_by_id=excluded.granted_by_id,policy_version=excluded.policy_version,granted_at=excluded.granted_at,withdrawn_at=excluded.withdrawn_at",(student_id,sid,status,"school_admin",session["user_id"],"1.0",status,status)); _ai_log(conn,"privacy","consent_changed",student_id,status,scope="student",consent_status=status); flash("Consent status updated.","success")
        conn.close(); return redirect(url_for("ai_consent"))
    students=conn.execute("SELECT st.id,st.first_name,st.last_name,c.name class_name,COALESCE(a.status,'pending') consent_status FROM students st JOIN classes c ON c.id=st.class_id LEFT JOIN student_ai_consent a ON a.student_id=st.id AND a.school_id=? WHERE c.school_id=? AND st.is_active=1 ORDER BY c.name,st.last_name",(sid,sid)).fetchall(); conn.close(); return render_template("ai_consent.html",students=students)

@app.route("/ai/result-analysis")
@login_required("admin","sub_admin","teacher")
def ai_result_analysis():
    conn=get_db(); sid=current_school_id(); students=conn.execute("SELECT st.id,st.first_name,st.last_name,c.name class_name FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1 ORDER BY c.name,st.last_name",(sid,)).fetchall(); terms=conn.execute("SELECT t.*,s.name session_name FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.school_id=? ORDER BY t.id DESC",(sid,)).fetchall(); conn.close(); return render_template("ai_result_analysis.html",students=students,terms=terms)

@app.route("/ai/analyze",methods=["POST"])
@login_required("admin","sub_admin","teacher")
def ai_analyze():
    conn=get_db(); sid=current_school_id(); student_id=request.form.get("student_id",type=int); term=resolve_term(conn,request.form.get("term_id",type=int)); student=conn.execute("SELECT st.*,c.name class_name FROM students st JOIN classes c ON c.id=st.class_id WHERE st.id=? AND c.school_id=?",(student_id,sid)).fetchone(); settings=_ai_settings(conn,sid); allowed,cs=_ai_consent(conn,student_id)
    if not student or not term: conn.close(); flash("Student or term not found.","error"); return redirect(url_for("ai_command_center"))
    if session.get("role")=="teacher" and not can_view_class_results(conn,session.get("role"),session.get("position"),session["user_id"],student["class_id"]): conn.close(); flash("You are not authorized for this student.","error"); return redirect(url_for("ai_command_center"))
    if not(settings["enabled"] and settings["process_student_data"] and settings["result_analysis"] and allowed): _ai_log(conn,"result_analysis","blocked",student_id,cs,scope="student",request_summary="Blocked by settings/consent"); conn.close(); flash("Enable AI processing and grant the required student consent first.","error"); return redirect(url_for("ai_command_center"))
    rows=_ai_rows(conn,student_id,term["id"]); prev=_prev_term(conn,term); old=_ai_rows(conn,student_id,prev["id"]) if prev else []; analysis=compare_analysis(rows,old); att=_att(conn,student_id,term["id"])
    facts={"student_ref":str(student_id),"term":term["id"],"average":round(analysis["average"],1),"trend":analysis["trend"],"strengths":analysis["strengths"],"support_areas":analysis["weaknesses"],"attendance":round(att,1) if att is not None else None}
    provider_text,_=ai_provider_generate("You are a school performance analyst. Use only the supplied facts. Do not infer diagnoses, promotion, exclusion, discipline or sensitive traits. Produce a concise factual analysis with strengths, support areas and trend. Do not include the student's name or invent facts.",json.dumps(facts),max_tokens=450)
    text=provider_text or f"Overall performance: {analysis['average']:.1f}%. Trend: {analysis['trend']}. Strengths: {', '.join(analysis['strengths']) or 'None above 60% yet'}. Areas for support: {', '.join(analysis['weaknesses']) or 'No subject below 50%'}."+(f" Attendance: {att:.0f}%." if att is not None else "")
    out=conn.execute("INSERT INTO ai_outputs(school_id,feature,student_id,term_id,class_id,status,output_text,generated_by) VALUES (?,?,?,?,?,?,?,?)",(sid,"result_analysis",student_id,term["id"],student["class_id"],"draft",text,session["user_id"])); _ai_log(conn,"result_analysis","generated",student_id,cs,scope="student",request_summary=f"Term {term['id']}",output_summary=text); conn.close(); return redirect(url_for("ai_output_detail",output_id=out.lastrowid))

@app.route("/ai/output/<int:output_id>")
@login_required("admin","sub_admin","teacher")
def ai_output_detail(output_id):
    conn=get_db(); out=conn.execute("SELECT * FROM ai_outputs WHERE id=? AND school_id=?",(output_id,current_school_id())).fetchone();
    if not out:
        conn.close(); flash("AI output not found.","error"); return redirect(url_for("ai_command_center"))
    student=conn.execute("SELECT st.*,c.name class_name FROM students st JOIN classes c ON c.id=st.class_id WHERE st.id=? AND c.school_id=?",(out["student_id"],current_school_id())).fetchone() if out["student_id"] else None
    if out["student_id"] and not _ai_teacher_allowed(conn,out["student_id"]):
        conn.close(); flash("You are not authorized to view this AI output.","error"); return redirect(url_for("ai_command_center"))
    conn.close()
    return render_template("ai_output.html",output=out,student=student)

@app.route("/ai/output/<int:output_id>/review",methods=["POST"])
@login_required("admin","sub_admin","teacher")
def ai_output_review(output_id):
    action=request.form.get("action"); action=action if action in ("approved","rejected") else "rejected"; conn=get_db(); out=conn.execute("SELECT * FROM ai_outputs WHERE id=? AND school_id=?",(output_id,current_school_id())).fetchone()
    if not out: conn.close(); flash("AI output not found.","error"); return redirect(url_for("ai_command_center"))
    if out["student_id"] and not _ai_teacher_allowed(conn,out["student_id"]): conn.close(); flash("You are not authorized to review this AI output.","error"); return redirect(url_for("ai_command_center"))
    text=request.form.get("output_text","").strip() or out["output_text"]; conn.execute("UPDATE ai_outputs SET output_text=?,status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",(text,action,session["user_id"],output_id)); _ai_log(conn,out["feature"],f"output_{action}",out["student_id"],None,scope="student",request_summary=f"Review {output_id}",output_summary=text); conn.close(); flash("AI draft reviewed.","success"); return redirect(url_for("ai_output_detail",output_id=output_id))

@app.route("/ai/comments",methods=["GET","POST"])
@login_required("admin","sub_admin","teacher")
def ai_comments():
    conn=get_db(); sid=current_school_id(); term=current_term(conn); students=conn.execute("SELECT st.id,st.first_name,st.last_name,c.name class_name FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1 ORDER BY c.name,st.last_name",(sid,)).fetchall()
    if request.method=="POST":
        student_id=request.form.get("student_id",type=int); kind=request.form.get("kind","teacher"); settings=_ai_settings(conn,sid); feature="teacher_comments" if kind=="teacher" else "principal_comments"; consent,cs=_ai_consent(conn,student_id); student=conn.execute("SELECT st.*,c.form_teacher_id FROM students st JOIN classes c ON c.id=st.class_id WHERE st.id=? AND c.school_id=?",(student_id,sid)).fetchone()
        if not student or not term or not(settings["enabled"] and settings["process_student_data"] and settings[feature] and consent): flash("AI comments require AI to be enabled and student consent to be granted.","error")
        elif not _ai_teacher_allowed(conn,student_id): flash("You are not authorized for this student.","error")
        else:
            prev=_prev_term(conn,term); analysis=compare_analysis(_ai_rows(conn,student_id,term["id"]),_ai_rows(conn,student_id,prev["id"]) if prev else []); att=_att(conn,student_id,term["id"]); name=f"{student['first_name']} {student['last_name']}"
            facts={"student_ref":str(student_id),"average":round(analysis["average"],1),"trend":analysis["trend"],"strengths":analysis["strengths"],"support_areas":analysis["weaknesses"],"attendance":round(att,1) if att is not None else None}
            role_text="teacher" if kind=="teacher" else "principal"
            provider_text,_=ai_provider_generate("You are a school report-writing assistant. Draft one professional, supportive comment for a student using only the supplied academic facts. Do not mention AI, diagnoses, promotion or exclusion. Do not include a name or invent facts. Return only the comment.",json.dumps({"comment_type":role_text,"facts":facts}),max_tokens=250)
            text=provider_text or (ai_teacher_comment(name,analysis,att) if kind=="teacher" else ai_principal_comment(name,analysis,att)); out=conn.execute("INSERT INTO ai_outputs(school_id,feature,student_id,term_id,class_id,status,output_text,generated_by) VALUES (?,?,?,?,?,?,?,?)",(sid,feature,student_id,term["id"],student["class_id"],"draft",text,session["user_id"])); _ai_log(conn,feature,"generated",student_id,cs,scope="student",request_summary=f"Generate {kind} comment",output_summary=text); conn.close(); return redirect(url_for("ai_output_detail",output_id=out.lastrowid))
    conn.close(); return render_template("ai_comments.html",students=students,term=term)

@app.route("/ai/alerts")
@login_required("admin","sub_admin","teacher")
def ai_alerts():
    conn=get_db(); sid=current_school_id(); term=current_term(conn); alerts=[]
    if term:
        q="SELECT st.id,st.first_name,st.last_name,c.name class_name,AVG(sc.ca1+sc.ca2+sc.exam) avg_score FROM students st JOIN classes c ON c.id=st.class_id LEFT JOIN scores sc ON sc.student_id=st.id AND sc.term_id=? WHERE c.school_id=? AND st.is_active=1"; params=[term["id"],sid]
        if session.get("role")=="teacher" and not can_view_all_results(session.get("role"),session.get("position")):
            ids=get_accessible_class_ids(conn,session.get("role"),session.get("position"),session["user_id"]); ids=[] if ids == "all" else ids; q += (" AND c.id IN ("+",".join("?"*len(ids))+")" if ids else " AND 1=0"); params += ids
        rows=conn.execute(q+" GROUP BY st.id",tuple(params)).fetchall(); prev=_prev_term(conn,term)
        for r in rows:
            if r["avg_score"] is None: continue
            reasons=[]
            if r["avg_score"]<40: reasons.append("Average below 40%")
            if prev:
                p=conn.execute("SELECT AVG(ca1+ca2+exam) avg FROM scores WHERE student_id=? AND term_id=?",(r["id"],prev["id"])).fetchone()["avg"]
                if p is not None and r["avg_score"]-p<=-10: reasons.append(f"Down {abs(r['avg_score']-p):.1f} points")
            att=_att(conn,r["id"],term["id"]);
            if att is not None and att<75: reasons.append(f"Attendance {att:.0f}%")
            if reasons: alerts.append({"student":r,"reasons":reasons})
    conn.close(); return render_template("ai_alerts.html",alerts=alerts,term=term)

@app.route("/ai/result-assistant",methods=["GET","POST"])
@login_required("admin","sub_admin","teacher")
def ai_result_assistant():
    conn=get_db(); sid=current_school_id(); term=current_term(conn); query=""; answer=None
    if request.method=="POST":
        query=request.form.get("query","").strip(); q=query.lower()
        if not term:
            answer=["No active term is configured."]
        else:
            allowed_ids=None
            if session.get("role")=="teacher" and not can_view_all_results(session.get("role"),session.get("position")):
                allowed_ids=get_accessible_class_ids(conn,session.get("role"),session.get("position"),session["user_id"]); allowed_ids=[] if allowed_ids=="all" else allowed_ids
            def class_filter(alias="c"):
                if allowed_ids is None: return "",[]
                return ((" AND %s.id IN (%s)"%(alias,",".join("?"*len(allowed_ids)))) if allowed_ids else " AND 1=0", list(allowed_ids))
            cf,cp=class_filter()
            if "below" in q and ("40" in q or "threshold" in q):
                import re as _re
                m=_re.search(r"below\s+(\d+(?:\.\d+)?)",q); threshold=float(m.group(1)) if m else 40.0
                subject="mathematics" if "mathematics" in q or "math" in q else None
                sql="SELECT st.first_name,st.last_name,c.name class_name,sub.name subject_name,(sc.ca1+sc.ca2+sc.exam) score FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id JOIN subjects sub ON sub.id=sc.subject_id WHERE c.school_id=? AND sc.term_id=? AND (sc.ca1+sc.ca2+sc.exam)<?"; params=[sid,term["id"],threshold]
                if subject: sql+=" AND lower(sub.name)=?"; params.append(subject)
                sql+=cf+" ORDER BY score"; params+=cp; rows=conn.execute(sql,tuple(params)).fetchall()
                answer=[f"{r['first_name']} {r['last_name']} ({r['class_name']}) — {r['subject_name']}: {r['score']:.1f}%" for r in rows] or [f"No students scored below {threshold:g}% for that query."]
            elif "poor" in q and "subject" in q:
                sql="SELECT sub.name subject_name,AVG(sc.ca1+sc.ca2+sc.exam) avg_score FROM scores sc JOIN subjects sub ON sub.id=sc.subject_id JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND sc.term_id=?"; params=[sid,term["id"]]; sql+=cf+" GROUP BY sub.id ORDER BY avg_score LIMIT 10"; params+=cp; rows=conn.execute(sql,tuple(params)).fetchall(); answer=[f"{r['subject_name']} — {r['avg_score']:.1f}% average" for r in rows] or ["No subject results are available."]
            elif "class" in q and "improv" in q:
                prev=_prev_term(conn,term)
                if not prev: answer=["There is no previous term to compare."]
                else:
                    sql="SELECT c.name class_name,AVG(sc.ca1+sc.ca2+sc.exam) current_avg FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND sc.term_id=?"; params=[sid,term["id"]]; sql+=cf+" GROUP BY c.id"; params+=cp; current=conn.execute(sql,tuple(params)).fetchall(); answer=[]
                    for r in current:
                        pr=conn.execute("SELECT AVG(sc.ca1+sc.ca2+sc.exam) avg FROM scores sc JOIN students st ON st.id=sc.student_id WHERE st.class_id=(SELECT id FROM classes WHERE school_id=? AND name=? LIMIT 1) AND sc.term_id=?",(sid,r["class_name"],prev["id"])).fetchone()["avg"]
                        if pr is not None: answer.append(f"{r['class_name']} — {r['current_avg']-pr:+.1f} points ({r['current_avg']:.1f}% vs {pr:.1f}%).")
                    answer=answer or ["No comparable class data is available."]
            elif "declin" in q or "drop" in q:
                prev=_prev_term(conn,term)
                if not prev: answer=["There is no previous term to compare."]
                else:
                    sql="SELECT st.id,st.first_name,st.last_name,c.name class_name,AVG(sc.ca1+sc.ca2+sc.exam) current_avg FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND sc.term_id=?"; params=[sid,term["id"]]; sql+=cf+" GROUP BY st.id"; params+=cp; rows=conn.execute(sql,tuple(params)).fetchall(); answer=[]
                    for r in rows:
                        pr=conn.execute("SELECT AVG(ca1+ca2+exam) avg FROM scores WHERE student_id=? AND term_id=?",(r["id"],prev["id"])).fetchone()["avg"]
                        if pr is not None and r["current_avg"]-pr<=-10: answer.append(f"{r['first_name']} {r['last_name']} ({r['class_name']}) — down {pr-r['current_avg']:.1f} points.")
                    answer=answer or ["No students met the current decline threshold of 10 points."]
            else:
                answer=["Try: Which subjects performed poorly?","Which classes improved?","Who scored below 40 in Mathematics?","Which students have declining performance?"]
            # Keep audit logs useful without storing the user's full natural-language query.
            query_category=("threshold" if "below" in q else "subject_performance" if "poor" in q and "subject" in q else "class_improvement" if "class" in q and "improv" in q else "decline" if ("declin" in q or "drop" in q) else "unsupported")
            _ai_log(conn,"result_assistant","query",scope="school",request_summary=f"category={query_category}",output_summary="; ".join(answer)[:1500])
    conn.close(); return render_template("ai_result_assistant.html",query=query,answer=answer,term=term)

@app.route("/ai/learning-materials",methods=["GET","POST"])
@login_required("admin","sub_admin","teacher")
def ai_learning_materials():
    conn=get_db(); sid=current_school_id(); settings=_ai_settings(conn,sid); material=None
    if request.method=="POST":
        subject=request.form.get("subject","General").strip(); topic=request.form.get("topic","").strip(); level=request.form.get("level","Secondary").strip()
        if not (settings["enabled"] and settings["learning_materials"]):
            flash("AI Learning Materials is disabled by your school administrator.","error")
        elif topic:
            prompt=json.dumps({"subject":subject,"topic":topic,"level":level,"requirements":["lesson notes","worked examples","5 revision questions","5 MCQs with answers","brief explanations"]})
            generated,_=ai_provider_generate("You are an educational content assistant. Create age-appropriate school learning material. Do not include unsafe or sensitive content. Return structured plain text with headings, examples, revision questions, MCQs, answers and explanations.",prompt,max_tokens=1200)
            text=generated or f"{topic}: key concepts, definitions and worked examples for {level} learners."
            material={"subject":subject,"topic":topic,"level":level,"notes":text,"questions":[],"answers":[]}
            _ai_log(conn,"learning_materials","generated",scope="school",request_summary=f"{subject} / {topic} / {level}",output_summary=text[:1000])
    conn.close(); return render_template("ai_learning_materials.html",material=material,enabled=bool(settings["enabled"] and settings["learning_materials"]))

@app.route("/student/ai-tutor",methods=["GET","POST"])
def student_ai_tutor():
    if "student_id" not in session: return redirect(url_for("student_login"))
    conn=get_db(); settings=_ai_settings(conn,session.get("school_id")); answer=None; question=""; subject="Mathematics"
    if request.method=="POST":
        question=request.form.get("question","").strip(); subject=request.form.get("subject","Mathematics").strip()
        if not(settings["enabled"] and settings["ai_tutor"]): flash("AI Tutor is disabled by your school administrator.","error")
        else:
            answer,_=ai_provider_generate("You are a safe educational tutor. Never expose student records.",f"Subject: {subject}\nQuestion: {question}",max_tokens=600)
            if not answer: answer=local_tutor_answer(subject,question)
    conn.close(); return render_template("ai_tutor.html",answer=answer,question=question,subject=subject,enabled=bool(settings["enabled"] and settings["ai_tutor"]))

@app.route("/admin/theme",methods=["GET","POST"])
@login_required("admin","sub_admin")
def admin_theme():
    conn=get_db(); sid=current_school_id(); school=conn.execute("SELECT * FROM schools WHERE id=?",(sid,)).fetchone(); presets={"default":("#1f6feb","#0b3b75","#7c4dff"),"green":("#138a55","#0b4f36","#16a085"),"purple":("#6d3fc0","#3b1f70","#9c6cff"),"teal":("#0f8b8d","#075e60","#ff8a34"),"orange":("#e67e22","#8a3e0a","#f4b942"),"dark":("#1d2633","#0d1420","#5c8dff"),"custom":("#1f6feb","#0b3b75","#7c4dff")}
    if request.method=="POST":
        preset=request.form.get("theme_preset","default"); primary,secondary,accent=presets.get(preset,(request.form.get("dashboard_primary_color","#1f6feb"),request.form.get("dashboard_secondary_color","#0b3b75"),request.form.get("dashboard_accent_color","#7c4dff")));
        if preset=="custom": primary=request.form.get("dashboard_primary_color","#1f6feb"); secondary=request.form.get("dashboard_secondary_color","#0b3b75"); accent=request.form.get("dashboard_accent_color","#7c4dff")
        import re as _re
        primary=primary if _re.fullmatch(r"#[0-9a-fA-F]{6}",primary) else "#1f6feb"; secondary=secondary if _re.fullmatch(r"#[0-9a-fA-F]{6}",secondary) else "#0b3b75"; accent=accent if _re.fullmatch(r"#[0-9a-fA-F]{6}",accent) else "#7c4dff"
        result_accent=request.form.get("result_accent_color", school["result_accent_color"] or "#1f3a5f"); result_header=request.form.get("result_header_layout", school["result_header_layout"] or "logo-left")
        if not _re.fullmatch(r"#[0-9a-fA-F]{6}",result_accent): result_accent="#1f3a5f"
        if result_header not in ("logo-left","logo-top-center","logo-right","no-logo"): result_header="logo-left"
        try: auth_logo_opacity=max(0.03,min(0.35,float(request.form.get("auth_logo_opacity","0.10"))))
        except (TypeError,ValueError): auth_logo_opacity=0.10
        auth_logo_position=request.form.get("auth_logo_position","center") if request.form.get("auth_logo_position","center") in ("left","center","right") else "center"
        auth_background_style=request.form.get("auth_background_style","watermark") if request.form.get("auth_background_style","watermark") in ("watermark","soft","plain") else "watermark"
        auth_show_school_name=1 if request.form.get("auth_show_school_name","1") == "1" else 0
        auth_branding_enabled=1 if request.form.get("auth_branding_enabled","1") == "1" else 0
        show_form_teacher_name=1 if request.form.get("show_form_teacher_name","1") == "1" else 0
        show_form_teacher_signature=1 if request.form.get("show_form_teacher_signature","1") == "1" else 0
        show_principal_name=1 if request.form.get("show_principal_name","1") == "1" else 0
        show_principal_signature=1 if request.form.get("show_principal_signature","1") == "1" else 0
        conn.execute("UPDATE schools SET theme_preset=?,dashboard_primary_color=?,dashboard_secondary_color=?,dashboard_accent_color=?,dashboard_sidebar_style=?,dashboard_header_style=?,school_tagline=?,auth_logo_opacity=?,auth_logo_position=?,auth_background_style=?,auth_show_school_name=?,auth_branding_enabled=? WHERE id=?",(preset,primary,secondary,accent,request.form.get("dashboard_sidebar_style","dark"),request.form.get("dashboard_header_style","solid"),request.form.get("school_tagline","").strip()[:120],auth_logo_opacity,auth_logo_position,auth_background_style,auth_show_school_name,auth_branding_enabled,sid)); conn.commit(); conn.close(); flash("Theme & branding saved.","success"); return redirect(url_for("admin_theme"))
    conn.close(); return render_template("theme_branding.html",school=school,presets=presets)


@app.route("/school-dashboard")
@login_required("admin","sub_admin")
def school_dashboard_alias(): return redirect(url_for("dashboard"))

@app.route("/school-setup")
@login_required("admin","sub_admin")
def school_setup_alias(): return redirect(url_for("admin_school"))

@app.route("/platform/activation-requests")
@platform_admin_required
def platform_activation_requests():
    conn=get_db(); rows=conn.execute("""
        SELECT r.*, s.name school_name, s.school_code, s.tenant_id, s.registered_email, s.registered_phone,
               ac.code activation_code, ac.expires_at activation_code_expires_at, ac.status activation_code_status,
               ac.used_at activation_code_used_at, ac.invalidated activation_code_invalidated
        FROM platform_activation_requests r
        JOIN schools s ON s.id=r.school_id
        LEFT JOIN activation_codes ac ON ac.id=(SELECT id FROM activation_codes WHERE school_id=s.id ORDER BY id DESC LIMIT 1)
        ORDER BY r.id DESC LIMIT 200
    """).fetchall(); conn.close(); return render_template('platform_activation_requests.html',requests=rows)

@app.route("/platform/schools/<int:school_id>/approve-activation",methods=["POST"])
@platform_admin_required
def platform_approve_activation(school_id):
    conn=get_db(); school=get_school(conn,school_id)
    if not school or school['activation_status']!='pending': conn.close(); flash('School activation request is not pending.','error'); return redirect(url_for('platform_schools'))
    code,expires=generate_activation_code(conn,school_id,created_by=session.get('platform_admin_name'))
    conn.execute("UPDATE platform_activation_requests SET status='approved',approved_by=?,approved_at=CURRENT_TIMESTAMP,activation_code_delivery_status='pending' WHERE school_id=? AND status='pending'",(session.get('platform_admin_name'),school_id))
    sent,msg=(False,'No registered email on file.')
    if school['registered_email']: sent,msg=send_platform_email(school['registered_email'],f"School activation approved — {school['name']}",f"Your school activation has been approved.\n\nActivation code: {code}\nExpires: {format_dmy(expires)}\n\nEnter this code on the secure Activate School page. The code is single-use and must not be shared publicly.")
    delivery='email' if sent else 'not_configured'; conn.execute("UPDATE platform_activation_requests SET activation_code_delivery_channel=?,activation_code_delivery_status=?,activation_code_sent_at=CURRENT_TIMESTAMP WHERE school_id=? AND status='approved'",(delivery,'sent' if sent else 'not_configured',school_id))
    log_audit(conn,'platform_admin',session.get('platform_admin_name'),'school_activation_approved',details=f"Approved activation for {school['name']}; delivery={delivery}",school_id=school_id); conn.commit(); conn.close()
    if sent:
        flash(f"Activation approved and the code was sent. Current activation code: {code}", 'success')
    else:
        flash(f"Activation approved. Delivery is not configured; the protected Super Admin screen shows the activation code: {code}", 'success')
    return redirect(url_for('platform_activation_requests'))


@app.route("/platform/notifications/inbox")
@platform_admin_required
def platform_notification_inbox():
    conn = get_db()
    rows = conn.execute("SELECT n.*,s.name school_name FROM platform_notifications n LEFT JOIN schools s ON s.id=n.school_id ORDER BY n.id DESC LIMIT 200").fetchall()
    conn.close()
    return render_template("platform_notification_inbox.html", notifications=[dict(r) | {"is_read": bool(r["read_at"])} for r in rows])


@app.route("/platform/notifications/<int:notification_id>/read", methods=["POST"])
@platform_admin_required
def platform_notification_read(notification_id):
    conn = get_db()
    conn.execute("UPDATE platform_notifications SET read_at=COALESCE(read_at,CURRENT_TIMESTAMP) WHERE id=?", (notification_id,))
    conn.commit()
    unread = conn.execute("SELECT COUNT(*) c FROM platform_notifications WHERE read_at IS NULL").fetchone()["c"]
    conn.close()
    return jsonify({"ok": True, "unread": unread})


@app.route("/platform/notifications/read-all", methods=["POST"])
@platform_admin_required
def platform_notification_read_all():
    conn = get_db()
    conn.execute("UPDATE platform_notifications SET read_at=CURRENT_TIMESTAMP WHERE read_at IS NULL")
    conn.commit(); conn.close()
    return jsonify({"ok": True, "unread": 0})


def AUTO_ADVANCE(conn, term_id):
    return _AUTO_ADVANCE_IMPL(conn, term_id)


# ---------- V61 ----------
from v61_routes import register_v61_routes
_v61_helpers = dict(
    get_db=get_db, login_required=login_required, student_login_required=student_login_required,
    platform_admin_required=platform_admin_required, current_school_id=current_school_id,
    form_teacher_class_ids=form_teacher_class_ids, active_role_assignments=active_role_assignments,
    validate_password_policy=validate_password_policy, student_full_name=student_full_name, security_event=security_event,
    all_terms_for_school=all_terms_for_school, log_audit=log_audit, _actor_role_label=_actor_role_label,
    ensure_school_v61_defaults=ensure_school_v61_defaults, table_exists=table_exists,
    build_result_data=build_result_data, student_in_school=student_in_school, resolve_term=resolve_term,
    student_class_for_term=student_class_for_term, require_class_result_access=require_class_result_access,
    parent_child=parent_child, parent_login_required=parent_login_required, current_term=current_term,
)
register_v61_routes(app, _v61_helpers)
_AUTO_ADVANCE_IMPL = _v61_helpers["auto_advance_after_publish"]

# ---------- V63: Registrar / Admissions Officer ----------
from registrar import register_registrar_routes
register_registrar_routes(app, dict(
    get_db=get_db, login_required=login_required, current_school_id=current_school_id, current_tenant_id=current_tenant_id,
    session_roles=session_roles, school_today=school_today, form_teacher_class_ids=form_teacher_class_ids,
    class_in_school=class_in_school, plan_limit_check=plan_limit_check, upsert_enrollment=upsert_enrollment,
    student_full_name=student_full_name, recorder_role_label=recorder_role_label, verify_image=_verify_image,
    reject_oversize=_reject_oversize, photos_dir=STUDENT_PHOTOS_DIR, allowed_ext=ALLOWED_LOGO_EXTENSIONS, log_audit=log_audit,
))

# ---------- V60: profiles, custom fields, audit views ----------
from profile_routes import register_profile_routes
register_profile_routes(app, dict(
    get_db=get_db, login_required=login_required, student_login_required=student_login_required,
    platform_admin_required=platform_admin_required, student_full_name=student_full_name,
    STUDENT_PHOTOS_DIR=STUDENT_PHOTOS_DIR, STAFF_PHOTOS_DIR=STAFF_PHOTOS_DIR, SIGNATURES_DIR=SIGNATURES_DIR,
    CUSTOM_FILES_DIR=CUSTOM_FILES_DIR, form_teacher_class_ids=form_teacher_class_ids,
    active_role_assignments=active_role_assignments, security_event=security_event, POSITION_LABELS=POSITION_LABELS,
))


if __name__ == "__main__":
    # Local-only dev server (no Django/gunicorn involved) - handy for quick manual testing.
    from school.devserver import run_dev_server
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    run_dev_server(app, host="0.0.0.0", port=5050, debug=debug_mode)
