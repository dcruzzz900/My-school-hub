import sqlite3
import os
import re
import datetime as _dt
import secrets as _secrets
from werkzeug.security import generate_password_hash

# DATA_DIR lets a host with an ephemeral filesystem (e.g. Railway) point the
# database, uploaded logos/materials and the generated secret key at a
# persistent volume (e.g. DATA_DIR=/data). Left unset, behaviour is unchanged.
INSTANCE_DIR = os.environ.get("DATA_DIR") or os.path.join(os.path.dirname(__file__), "instance")
DB_PATH = os.path.join(INSTANCE_DIR, "school.db")


def format_dmy(value):
    """Formats an ISO date ('YYYY-MM-DD') or a SQLite timestamp
    ('YYYY-MM-DD HH:MM:SS') as DD/MM/YYYY, with HH:MM appended for
    timestamps — the date format required throughout the system. Anything
    that isn't one of those two shapes (blank, already-formatted, or
    unexpected) is returned exactly as given rather than guessed at."""
    if not value:
        return value
    s = str(value).strip()
    date_part, _, time_part = s.partition(" ")
    try:
        d = _dt.date.fromisoformat(date_part)
    except ValueError:
        return value
    formatted = d.strftime("%d/%m/%Y")
    if time_part:
        try:
            t = _dt.datetime.strptime(time_part[:8], "%H:%M:%S").time()
            formatted += f" {t.strftime('%H:%M')}"
        except ValueError:
            pass
    return formatted


# Many devices sync at once (a whole staff room reconnecting on Monday morning), and SQLite
# lets only one connection write at a time. Two settings make that orderly instead of failing:
#   - busy_timeout: a writer WAITS (up to 30 s) for the lock instead of erroring after 5 s;
#   - WAL journal mode: readers no longer block the writer, and vice versa.
# WAL needs a normal local disk, so it is on when DATA_DIR is set (Railway volume, own server)
# and off by default otherwise (some shared hosts' file systems don't support it well).
#     SQLITE_WAL=1  force on      SQLITE_WAL=0  force off
_WAL = os.environ.get("SQLITE_WAL") == "1" or (os.environ.get("SQLITE_WAL") != "0" and bool(os.environ.get("DATA_DIR")))


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = OFF")
    if _WAL:
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        except sqlite3.Error:
            pass        # a file system that can't do WAL: carry on in the default mode
    return conn


# ---------------------------------------------------------------------------
# Migration framework — each function runs exactly once, in order, tracked
# by a version number, so a database from any earlier version of this app
# upgrades in place safely without losing data.
# ---------------------------------------------------------------------------

def table_exists(conn, table):
    return conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def column_names(conn, table):
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def ensure_column(conn, table, column, coltype):
    if column not in column_names(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def table_sql(conn, table):
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row["sql"] if row else ""


def migration_001_baseline(conn):
    with open(os.path.join(os.path.dirname(__file__), "schema.sql")) as f:
        conn.executescript(f.read())


def migration_002_multi_school(conn):
    for table in ("users", "classes", "subjects", "sessions", "grading_config", "grade_scale", "skill_traits"):
        ensure_column(conn, table, "school_id", "INTEGER")

    needs_backfill = any(
        conn.execute(f"SELECT COUNT(*) c FROM {table} WHERE school_id IS NULL").fetchone()["c"] > 0
        for table in ("users", "classes", "subjects", "sessions", "grading_config", "grade_scale", "skill_traits")
    )
    if not needs_backfill:
        return

    existing_school = conn.execute("SELECT id FROM schools LIMIT 1").fetchone()
    if existing_school:
        default_school_id = existing_school["id"]
    else:
        name, logo_filename, staff_signup_code = "My School", None, None
        if table_exists(conn, "school_settings"):
            row = conn.execute("SELECT * FROM school_settings WHERE id=1").fetchone()
            if row:
                name = row["school_name"] or name
                logo_filename = row["logo_filename"]
                if "staff_signup_code" in column_names(conn, "school_settings"):
                    staff_signup_code = row["staff_signup_code"]
        cur = conn.execute(
            "INSERT INTO schools (name, logo_filename, staff_signup_code) VALUES (?,?,?)",
            (name, logo_filename, staff_signup_code),
        )
        default_school_id = cur.lastrowid

    for table in ("users", "classes", "subjects", "sessions", "grading_config", "grade_scale", "skill_traits"):
        conn.execute(f"UPDATE {table} SET school_id=? WHERE school_id IS NULL", (default_school_id,))

    if table_exists(conn, "school_settings"):
        conn.execute("DROP TABLE school_settings")


def migration_003_student_fields(conn):
    for column, coltype in [
        ("other_names", "TEXT"),
        ("parent_name", "TEXT"),
        ("parent_email", "TEXT"),
        ("parent_phone", "TEXT"),
    ]:
        ensure_column(conn, "students", column, coltype)
    # register_no existed briefly in an earlier version of this migration;
    # it's superseded by migration_006, which merges it into admission_no.


def migration_004_school_email_and_logo_settings(conn):
    for column, coltype in [
        ("logo_align", "TEXT NOT NULL DEFAULT 'center'"),
        ("smtp_host", "TEXT"),
        ("smtp_port", "INTEGER"),
        ("smtp_username", "TEXT"),
        ("smtp_password", "TEXT"),
        ("smtp_use_tls", "INTEGER DEFAULT 1"),
        ("smtp_from_email", "TEXT"),
        ("smtp_from_name", "TEXT"),
    ]:
        ensure_column(conn, "schools", column, coltype)


def migration_005_expand_user_roles(conn):
    """Add a 'sub_admin' role who can manage everything about their own
    school except promoting/managing other admins or sub-admins."""
    if "'sub_admin'" in table_sql(conn, "users"):
        return  # already has the expanded CHECK constraint

    conn.execute("ALTER TABLE users RENAME TO users_old")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'sub_admin', 'teacher')),
            position TEXT,
            security_question TEXT,
            security_answer_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("""
        INSERT INTO users (id, school_id, name, username, password_hash, role,
            position, security_question, security_answer_hash, created_at)
        SELECT id, school_id, name, username, password_hash, role,
            position, security_question, security_answer_hash, created_at
        FROM users_old
    """)
    conn.execute("DROP TABLE users_old")


def migration_006_merge_admission_register(conn):
    """Merge the separate Register No. field into Admission No. (shown as
    "Admission No. / Register No." throughout), unique only within a class
    (arm) rather than school-wide — so two arms of the same class (e.g. SS1
    Science 1 and SS1 Science 2) can reuse the same numbers for different
    students. Also adds religion and parent address fields."""
    needs_rebuild = "admission_no TEXT UNIQUE NOT NULL" in table_sql(conn, "students")

    if needs_rebuild:
        conn.execute("ALTER TABLE students RENAME TO students_old")
        conn.execute("""
            CREATE TABLE students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admission_no TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                other_names TEXT,
                gender TEXT CHECK(gender IN ('M','F')),
                class_id INTEGER NOT NULL,
                date_of_birth TEXT,
                religion TEXT,
                parent_name TEXT,
                parent_address TEXT,
                parent_email TEXT,
                parent_phone TEXT,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY(class_id) REFERENCES classes(id)
            )
        """)
        conn.execute("""
            INSERT INTO students (id, admission_no, first_name, last_name, other_names,
                gender, class_id, date_of_birth, parent_name, parent_email, parent_phone, is_active)
            SELECT id, admission_no, first_name, last_name, other_names,
                gender, class_id, date_of_birth, parent_name, parent_email, parent_phone, is_active
            FROM students_old
        """)
        conn.execute("DROP TABLE students_old")

    for column, coltype in [("religion", "TEXT"), ("parent_address", "TEXT")]:
        ensure_column(conn, "students", column, coltype)

    conn.execute("DROP INDEX IF EXISTS idx_students_class_register_no")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_students_class_admission_no "
        "ON students(class_id, admission_no)"
    )


def migration_007_terms_publish_flag(conn):
    """Terms must be explicitly 'published' before results can be emailed
    to parents, so parents are only notified once a final result is ready
    — not on every CA/score update."""
    ensure_column(conn, "terms", "is_published", "INTEGER DEFAULT 0")


def migration_008_more_skill_traits(conn):
    new_traits = [("Club & Societies", "psychomotor"), ("Emotional Stability", "affective")]
    school_ids = [r["id"] for r in conn.execute("SELECT id FROM schools").fetchall()]
    for sid in school_ids:
        for name, cat in new_traits:
            conn.execute(
                "INSERT OR IGNORE INTO skill_traits (school_id, name, category) VALUES (?,?,?)",
                (sid, name, cat),
            )


def migration_009_signature_dates(conn):
    ensure_column(conn, "student_term_info", "teacher_signed_date", "TEXT")
    ensure_column(conn, "student_term_info", "principal_signed_date", "TEXT")


def migration_010_enrollments(conn):
    """Track which class a student was in during each academic session, so
    promoting a student to a new class doesn't rewrite their history —
    past terms' broadsheets/results still reflect the class they were
    actually in at the time."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            session_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            FOREIGN KEY(student_id) REFERENCES students(id),
            FOREIGN KEY(session_id) REFERENCES sessions(id),
            FOREIGN KEY(class_id) REFERENCES classes(id),
            UNIQUE(student_id, session_id)
        )
    """)
    # Backfill: every existing student is enrolled in their school's
    # currently active session, under their current class.
    schools = conn.execute("SELECT id FROM schools").fetchall()
    for school in schools:
        active_session = conn.execute(
            "SELECT id FROM sessions WHERE school_id=? AND is_active=1 LIMIT 1", (school["id"],)
        ).fetchone()
        if not active_session:
            continue
        students = conn.execute(
            "SELECT s.id, s.class_id FROM students s JOIN classes c ON c.id=s.class_id WHERE c.school_id=?",
            (school["id"],),
        ).fetchall()
        for st in students:
            conn.execute(
                "INSERT OR IGNORE INTO enrollments (student_id, session_id, class_id) VALUES (?,?,?)",
                (st["id"], active_session["id"], st["class_id"]),
            )


def migration_011_student_login(conn):
    """Optional student login: a student can be given a username/password
    (set by admin/sub-admin/form teacher) to view their own published
    results."""
    ensure_column(conn, "students", "username", "TEXT")
    ensure_column(conn, "students", "password_hash", "TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_students_username "
        "ON students(username) WHERE username IS NOT NULL"
    )


def migration_012_platform_tier(conn):
    """Adds the Super Admin / platform-level tier: platform_admins (a login
    completely separate from school staff/students), a per-school suspend
    flag, and a basic audit log for platform-level moderation actions."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS platform_admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            security_question TEXT,
            security_answer_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type TEXT NOT NULL,
            actor_name TEXT,
            school_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    ensure_column(conn, "schools", "is_suspended", "INTEGER DEFAULT 0")


def migration_013_notifications(conn):
    """In-app notifications: sent by Super Admin (platform-wide or to one
    school) or by a School Admin/Sub-Admin (to their own school), targeted
    at a role. Read/unread is tracked via a simple 'last seen' id."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_label TEXT NOT NULL,
            school_id INTEGER,
            target_role TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    ensure_column(conn, "users", "last_notification_seen_id", "INTEGER DEFAULT 0")
    ensure_column(conn, "students", "last_notification_seen_id", "INTEGER DEFAULT 0")


def migration_014_attendance_records(conn):
    """Daily roll call: one row per student per date per term, marked
    'present' or 'absent' by the Form Teacher. Days Open/Present/Absent and
    the attendance percentage shown on results are derived from these rows
    (see recompute_attendance below) rather than typed in by hand, so an
    "impossible" attendance value can no longer be entered."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            term_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('present','absent')),
            recorded_by INTEGER,
            recorded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES students(id),
            FOREIGN KEY(class_id) REFERENCES classes(id),
            FOREIGN KEY(term_id) REFERENCES terms(id),
            FOREIGN KEY(recorded_by) REFERENCES users(id),
            UNIQUE(student_id, term_id, date)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attendance_class_term_date "
        "ON attendance_records(class_id, term_id, date)"
    )


def migration_015_auto_comments(conn):
    """Per-school toggles: when on, the teacher's/principal's comment on a
    terminal result is generated from the student's grade for that term
    instead of relying on a manually typed comment — useful when scores
    come in via offline CSV and nobody types a comment at all."""
    ensure_column(conn, "schools", "auto_teacher_comment", "INTEGER DEFAULT 0")
    ensure_column(conn, "schools", "auto_principal_comment", "INTEGER DEFAULT 0")


def migration_016_cumulative_results(conn):
    """Per-school 'Enable Cumulative Result' toggle. When on, an
    Annual/Cumulative Result averages each subject across every term in a
    session (1st/2nd/3rd Term) that has a score recorded. When off, terms
    keep operating completely independently, exactly as before."""
    ensure_column(conn, "schools", "cumulative_enabled", "INTEGER DEFAULT 0")


def migration_017_class_category(conn):
    """Science/Arts/Commercial as a real, structured field on a class (a
    specific arm like 'SS1 Science A') instead of something only implied by
    typing it into the free-text class name — so it can be shown reliably
    on results/broadsheets and used later to scope Learning Materials by
    category, without changing how classes are identified elsewhere."""
    ensure_column(conn, "classes", "category", "TEXT")


def migration_018_learning_materials(conn):
    """Learning Materials module: a material is uploaded (or linked, for
    things like a YouTube video) against one specific session + class +
    subject. Since a class already carries its own arm and Science/Arts/
    Commercial category, scoping by class_id automatically scopes by
    arm/category too — a student only ever sees materials for their own
    class, so Science/Arts/Commercial students naturally only see their
    own materials without any extra filtering logic."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            session_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'Notes',
            filename TEXT,
            original_filename TEXT,
            external_url TEXT,
            uploaded_by INTEGER,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            FOREIGN KEY(session_id) REFERENCES sessions(id),
            FOREIGN KEY(class_id) REFERENCES classes(id),
            FOREIGN KEY(subject_id) REFERENCES subjects(id),
            FOREIGN KEY(uploaded_by) REFERENCES users(id),
            CHECK (filename IS NOT NULL OR external_url IS NOT NULL)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_materials_class_subject ON materials(class_id, subject_id)")


def migration_019_staff_attendance(conn):
    """Staff Attendance: Present/Absent/Late/Leave per staff member per
    day, recorded by an admin/sub_admin. Separate from the student roll
    call — staff aren't tied to a single class, so this is scoped to the
    whole school rather than one Form Teacher's classroom."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS staff_attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Present','Absent','Late','Leave')),
            recorded_by INTEGER,
            recorded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(recorded_by) REFERENCES users(id),
            UNIQUE(user_id, date)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_attendance_school_date ON staff_attendance(school_id, date)")


def migration_020_font_customization(conn):
    """Per-school font customization: `web_font` picks the app's UI
    typeface (a curated Google Font, or the system default), and
    `pdf_font` picks which of reportlab's base font families the printed
    result sheets, broadsheets and reports use."""
    ensure_column(conn, "schools", "web_font", "TEXT DEFAULT 'system'")
    ensure_column(conn, "schools", "pdf_font", "TEXT DEFAULT 'Helvetica'")


def migration_021_school_subdomain(conn):
    """Each school can claim a unique subdomain slug (e.g. 'greenwood').
    This column, plus the app's own host-header check, is the whole of
    what the application layer can do here — actually routing traffic
    like greenwood.yourdomain.com to this app is a DNS/hosting-level
    setup outside anything a database migration can configure; see the
    Custom Subdomain section on Setup → School Profile for what's needed."""
    ensure_column(conn, "schools", "subdomain", "TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_schools_subdomain ON schools(subdomain) WHERE subdomain IS NOT NULL")


def migration_022_result_date_toggle(conn):
    """Per-school 'Show Automatic Date on Result' toggle: when on, the
    current date (in the system's DD/MM/YYYY format) is stamped on the
    printed/downloaded result. When off, no automatic date appears there
    — this is separate from the dashboard's live clock, which must never
    itself appear on a printed/downloaded result."""
    ensure_column(conn, "schools", "show_result_date", "INTEGER DEFAULT 0")


def migration_023_school_activation(conn):
    """New-school onboarding via Super Admin: a school starts 'pending'
    until its School Admin enters a time-limited, single-use 6-digit code
    (sent to the school's registered email and/or shown to the Super
    Admin) on the public activation page. Also adds an 'archived' status
    distinct from suspension, and a force-logout timestamp so the Super
    Admin can invalidate a school's active sessions without a server-side
    session store — any session whose login predates this timestamp is
    treated as stale and signed out on its next request."""
    ensure_column(conn, "schools", "registered_email", "TEXT")
    ensure_column(conn, "schools", "activation_status", "TEXT DEFAULT 'active'")
    ensure_column(conn, "schools", "activated_at", "TEXT")
    ensure_column(conn, "schools", "is_archived", "INTEGER DEFAULT 0")
    ensure_column(conn, "schools", "force_logout_at", "TEXT")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            invalidated INTEGER DEFAULT 0,
            created_by TEXT,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activation_codes_school ON activation_codes(school_id)")


def migration_024_offline_sync(conn):
    """Offline-first support.

    Every table a device is allowed to create/edit while offline gets three
    extra columns:
      - client_uuid: generated on the device the record was first created
        on (server-side too, for rows that already existed before this
        migration). This — not the integer id — is what offline sync uses
        to identify a record, because an offline device can't know what
        integer id a brand-new row will get until it has synced; using a
        client-generated UUID as the idempotency key means retrying a push
        (e.g. after a dropped connection mid-sync) safely upserts instead
        of creating a duplicate.
      - updated_at: last-write timestamp, used for conflict detection
        (last-write-wins with a surfaced warning — see sync_api.py).
      - is_deleted: soft-delete flag, so a deletion made on one device can
        be propagated to others on their next pull instead of the row just
        silently disappearing from a diff.

    Also adds device_credentials (one row per device a user has enrolled
    for offline access — see sync_api.py's /api/offline/enroll) and
    sync_conflicts (a durable record of any push that lost a conflict, so
    an admin can review and manually reconcile it instead of data being
    quietly dropped).
    """
    syncable_tables = [
        "students", "scores", "attendance_records", "staff_attendance",
        "student_term_info", "classes", "subjects", "users",
        # Read-only reference data an offline device needs cached locally
        # to build its own dropdowns (current term, which subjects a class
        # has, etc.) even though it never writes these tables itself.
        "sessions", "terms", "class_subjects",
    ]
    for table in syncable_tables:
        ensure_column(conn, table, "client_uuid", "TEXT")
        ensure_column(conn, table, "updated_at", "TEXT")
        ensure_column(conn, table, "is_deleted", "INTEGER DEFAULT 0")
        # Backfill: every pre-existing row needs a stable client_uuid so it
        # can be referenced by future offline pulls/pushes, and an
        # updated_at so it isn't treated as "changed right now" on every
        # device's very first pull.
        conn.execute(
            f"UPDATE {table} SET client_uuid = lower(hex(randomblob(16))) "
            f"WHERE client_uuid IS NULL"
        )
        conn.execute(
            f"UPDATE {table} SET updated_at = COALESCE(updated_at, "
            f"CASE WHEN created_at IS NOT NULL THEN created_at ELSE CURRENT_TIMESTAMP END) "
            f"WHERE updated_at IS NULL"
            if "created_at" in column_names(conn, table)
            else f"UPDATE {table} SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"
        )
        conn.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_client_uuid "
            f"ON {table}(client_uuid) WHERE client_uuid IS NOT NULL"
        )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS device_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            tenant_id TEXT,
            user_id INTEGER NOT NULL,
            device_id TEXT NOT NULL UNIQUE,
            device_label TEXT,
            secret_hash TEXT NOT NULL,
            role_snapshot TEXT NOT NULL,
            position_snapshot TEXT,
            issued_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_verified_at TEXT,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            revoked_reason TEXT,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_device_credentials_user ON device_credentials(user_id)")
    ensure_column(conn, "device_credentials", "tenant_id", "TEXT")
    conn.execute("UPDATE device_credentials SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=device_credentials.school_id) WHERE tenant_id IS NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_device_credentials_school ON device_credentials(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_device_credentials_tenant ON device_credentials(tenant_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_conflicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            entity TEXT NOT NULL,
            client_uuid TEXT NOT NULL,
            device_id TEXT,
            client_payload TEXT NOT NULL,
            server_payload TEXT NOT NULL,
            detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved INTEGER DEFAULT 0,
            resolved_at TEXT,
            resolution TEXT,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_conflicts_school ON sync_conflicts(school_id, resolved)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            user_id INTEGER,
            direction TEXT NOT NULL,   -- 'push' or 'pull'
            entity TEXT,
            record_count INTEGER DEFAULT 0,
            conflict_count INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_log_school ON sync_log(school_id, created_at)")


def migration_025_deferred_actions(conn):
    """Support for the 'Functions Requiring Internet' part of the offline
    spec: things like emailing results to parents genuinely need a live
    connection (SMTP) and are never done purely locally, but a device can
    still QUEUE the request while offline, and it runs automatically the
    moment the device is back online and syncs — see /api/actions/queue in
    app.py and SyncEngine.queueAction/pushActions in sync-engine.js.

    This is a log of one-shot commands, not sync-able data: unlike the
    tables migration_024_offline_sync touches, there's nothing to pull
    back down to other devices and no "conflict" concept — an action
    either ran or it didn't."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS deferred_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            device_id TEXT,
            user_id INTEGER,
            client_uuid TEXT UNIQUE NOT NULL,
            action_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',  -- pending | done | failed
            result_message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_deferred_actions_school ON deferred_actions(school_id, created_at)")


def migration_026_sync_triggers(conn):
    """migration_024_offline_sync added client_uuid/updated_at/is_deleted
    to every syncable table and backfilled existing rows — but that
    backfill only covered rows that existed AT THAT MOMENT. Every one of
    this app's existing add-student/add-class/add-teacher/enter-scores/
    take-attendance/add-comment routes was written before offline sync
    existed and simply doesn't set these columns on INSERT, and doesn't
    bump updated_at on UPDATE either. Two concrete failures that causes:

      1. A record created through the normal online UI has client_uuid
         IS NULL. Pulled to an offline device, IndexedDB rejects it (NULL
         is not a valid key for a keyPath store) — sync breaks for that
         row.
      2. A record edited through the normal online UI doesn't bump
         updated_at. The offline conflict check in sync_api.py compares
         a device's last-known updated_at to the server's current one;
         if an online edit doesn't change it, a stale offline edit would
         look "not conflicting" and silently overwrite the online one.

    Auditing and fixing every INSERT/UPDATE site across this codebase
    would be fragile (easy to miss one, easy for a future route to
    reintroduce the gap). Triggers fix it at the one place it can't be
    bypassed: the table itself, regardless of which code path writes to
    it, sync-aware or not.

    The UPDATE trigger only fires `WHEN NEW.updated_at IS OLD.updated_at`
    — i.e. only when the UPDATE statement didn't already set updated_at
    itself — so it never clobbers the value sync_api.py's push endpoint
    explicitly computes and returns to the client.
    """
    tables = [
        "students", "scores", "attendance_records", "staff_attendance",
        "student_term_info", "classes", "subjects", "users",
        "sessions", "terms", "class_subjects",
    ]
    for table in tables:
        # One more backfill sweep — covers any row inserted between
        # migration_024 and now through a not-yet-trigger-protected path
        # (e.g. seed() running after migration_024's one-time backfill).
        conn.execute(f"UPDATE {table} SET client_uuid = lower(hex(randomblob(16))) WHERE client_uuid IS NULL")
        conn.execute(f"UPDATE {table} SET updated_at = strftime('%Y-%m-%dT%H:%M:%S','now') WHERE updated_at IS NULL")

        conn.execute(f"""
            CREATE TRIGGER IF NOT EXISTS trg_{table}_sync_defaults
            AFTER INSERT ON {table}
            FOR EACH ROW
            WHEN NEW.client_uuid IS NULL OR NEW.updated_at IS NULL
            BEGIN
                UPDATE {table} SET
                    client_uuid = COALESCE(NEW.client_uuid, lower(hex(randomblob(16)))),
                    updated_at = COALESCE(NEW.updated_at, strftime('%Y-%m-%dT%H:%M:%S','now'))
                WHERE id = NEW.id;
            END
        """)
        conn.execute(f"""
            CREATE TRIGGER IF NOT EXISTS trg_{table}_sync_touch
            AFTER UPDATE ON {table}
            FOR EACH ROW
            WHEN NEW.updated_at IS OLD.updated_at
            BEGIN
                UPDATE {table} SET updated_at = strftime('%Y-%m-%dT%H:%M:%S','now') WHERE id = NEW.id;
            END
        """)


# ---- helpers for migration_027 -------------------------------------------

def _make_syncable(conn, table):
    """Give an existing table the same client_uuid / updated_at / is_deleted
    columns, unique index and default/touch triggers that migration_024 and
    migration_026 gave the original syncable tables."""
    ensure_column(conn, table, "client_uuid", "TEXT")
    ensure_column(conn, table, "updated_at", "TEXT")
    ensure_column(conn, table, "is_deleted", "INTEGER DEFAULT 0")
    conn.execute(f"UPDATE {table} SET client_uuid = lower(hex(randomblob(16))) WHERE client_uuid IS NULL")
    conn.execute(f"UPDATE {table} SET updated_at = strftime('%Y-%m-%dT%H:%M:%S','now') WHERE updated_at IS NULL")
    conn.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_client_uuid "
        f"ON {table}(client_uuid) WHERE client_uuid IS NOT NULL"
    )
    conn.execute(f"""
        CREATE TRIGGER IF NOT EXISTS trg_{table}_sync_defaults
        AFTER INSERT ON {table}
        FOR EACH ROW
        WHEN NEW.client_uuid IS NULL OR NEW.updated_at IS NULL
        BEGIN
            UPDATE {table} SET
                client_uuid = COALESCE(NEW.client_uuid, lower(hex(randomblob(16)))),
                updated_at = COALESCE(NEW.updated_at, strftime('%Y-%m-%dT%H:%M:%S','now'))
            WHERE id = NEW.id;
        END
    """)
    _create_touch_trigger(conn, table)


def _create_touch_trigger(conn, table):
    """updated_at doubles as the row's version token for conflict detection,
    so it must change on EVERY update. Plain "now" only has one-second
    resolution: two edits inside the same second would leave it unchanged and
    a stale device's edit would slip past the conflict check. If "now" hasn't
    moved past the old value, bump it forward by one second instead."""
    conn.execute(f"DROP TRIGGER IF EXISTS trg_{table}_sync_touch")
    conn.execute(f"""
        CREATE TRIGGER trg_{table}_sync_touch
        AFTER UPDATE ON {table}
        FOR EACH ROW
        WHEN NEW.updated_at IS OLD.updated_at
        BEGIN
            UPDATE {table} SET updated_at = CASE
                WHEN OLD.updated_at IS NULL OR strftime('%Y-%m-%dT%H:%M:%S','now') > OLD.updated_at
                    THEN strftime('%Y-%m-%dT%H:%M:%S','now')
                ELSE strftime('%Y-%m-%dT%H:%M:%S', OLD.updated_at, '+1 second')
            END WHERE id = NEW.id;
        END
    """)


# How to work out which school a deleted row belonged to, evaluated inside
# the AFTER DELETE trigger against the OLD row. If the parent row is already
# gone the subquery yields NULL, and a tombstone with a NULL school is never
# delivered to anyone (fails closed rather than leaking across schools).
_TOMBSTONE_SCHOOL_EXPR = {
    "students": "(SELECT school_id FROM classes WHERE id = OLD.class_id)",
    "scores": "(SELECT c.school_id FROM students s JOIN classes c ON c.id = s.class_id WHERE s.id = OLD.student_id)",
    "student_term_info": "(SELECT c.school_id FROM students s JOIN classes c ON c.id = s.class_id WHERE s.id = OLD.student_id)",
    "attendance_records": "(SELECT school_id FROM classes WHERE id = OLD.class_id)",
    "class_subjects": "(SELECT school_id FROM classes WHERE id = OLD.class_id)",
    "terms": "(SELECT school_id FROM sessions WHERE id = OLD.session_id)",
    "staff_attendance": "OLD.school_id",
    "classes": "OLD.school_id",
    "subjects": "OLD.school_id",
    "users": "OLD.school_id",
    "sessions": "OLD.school_id",
    "grading_config": "OLD.school_id",
    "grade_scale": "OLD.school_id",
    "enrollments": "(SELECT school_id FROM classes WHERE id = OLD.class_id)",
}


def migration_027_ca3_conflicts_audit_tombstones(conn):
    """Four related additions for the multi-school, multi-device platform:

    1. Optional CA3. scores.ca3 (default 0) and grading_config.ca3_max
       (0 = CA3 switched off for that school, which is what every existing
       school keeps, so nothing changes for them until an admin opts in).
    2. Grading settings become readable by offline devices, so a device can
       work out totals/grades/positions without a server round trip.
    3. change_audit: a permanent trail of every change the sync API applied,
       merged, refused or flagged, with who/which device/when and old vs new
       values. Its (school_id, change_id) uniqueness is also what makes a
       retried push idempotent.
    4. sync_tombstones + AFTER DELETE triggers. The online screens hard-DELETE
       students, classes, subjects, etc., which a "changed since" pull can
       never report, so other devices kept deleted records forever. The
       triggers record each deletion (scoped to its school) so pulls can
       tell devices to drop them.
    """
    ensure_column(conn, "scores", "ca3", "REAL DEFAULT 0")
    ensure_column(conn, "grading_config", "ca3_max", "REAL DEFAULT 0")
    ensure_column(conn, "score_history", "old_ca3", "REAL")
    ensure_column(conn, "score_history", "new_ca3", "REAL")
    ensure_column(conn, "score_history", "source", "TEXT DEFAULT 'online'")
    ensure_column(conn, "score_history", "device_id", "TEXT")
    ensure_column(conn, "score_history", "change_id", "TEXT")

    for table in ("grading_config", "grade_scale", "enrollments"):
        _make_syncable(conn, table)
    for table in ("students", "scores", "attendance_records", "staff_attendance",
                  "student_term_info", "classes", "subjects", "users",
                  "sessions", "terms", "class_subjects"):
        _create_touch_trigger(conn, table)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS change_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            entity TEXT NOT NULL,
            client_uuid TEXT,
            change_id TEXT,
            op TEXT,
            outcome TEXT NOT NULL,      -- applied | merged | latest_wins | conflict | rejected
            device_id TEXT,
            user_id INTEGER,
            client_ts TEXT,             -- when the device says the edit was made
            server_ts TEXT DEFAULT CURRENT_TIMESTAMP,
            server_id INTEGER,
            result_updated_at TEXT,
            old_data TEXT,
            new_data TEXT,
            note TEXT,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_change_audit_school ON change_audit(school_id, id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_change_audit_record ON change_audit(school_id, entity, client_uuid)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_change_audit_change_id "
        "ON change_audit(school_id, change_id) WHERE change_id IS NOT NULL AND outcome IN ('applied','merged','latest_wins')"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_tombstones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER,
            entity TEXT NOT NULL,
            client_uuid TEXT NOT NULL,
            deleted_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_tombstones_school ON sync_tombstones(school_id, deleted_at)")
    for table, school_expr in _TOMBSTONE_SCHOOL_EXPR.items():
        conn.execute(f"""
            CREATE TRIGGER IF NOT EXISTS trg_{table}_tombstone
            AFTER DELETE ON {table}
            FOR EACH ROW
            WHEN OLD.client_uuid IS NOT NULL
            BEGIN
                INSERT INTO sync_tombstones (school_id, entity, client_uuid, deleted_at)
                VALUES ({school_expr}, '{table}', OLD.client_uuid, strftime('%Y-%m-%dT%H:%M:%S','now'));
            END
        """)


def migration_028_skills_syncable(conn):
    """Skill traits and each student's ratings become readable on devices so
    the offline result sheet can show the Psychomotor/Affective section (they
    are still entered online)."""
    for table, school_expr in (
        ("skill_traits", "OLD.school_id"),
        ("student_skill_ratings", _TOMBSTONE_SCHOOL_EXPR["scores"]),
    ):
        _make_syncable(conn, table)
        conn.execute(f"""
            CREATE TRIGGER IF NOT EXISTS trg_{table}_tombstone
            AFTER DELETE ON {table}
            FOR EACH ROW
            WHEN OLD.client_uuid IS NOT NULL
            BEGIN
                INSERT INTO sync_tombstones (school_id, entity, client_uuid, deleted_at)
                VALUES ({school_expr}, '{table}', OLD.client_uuid, strftime('%Y-%m-%dT%H:%M:%S','now'));
            END
        """)


def migration_029_class_arms(conn):
    """Optional structured class level + arm ("JSS 1" + "A"). `name` stays the
    one authoritative, unique display name ("JSS 1 A") that every screen,
    result and report already uses; level/arm just record how it was made so
    the admin screens can create several arms at once and group them. Existing
    classes keep working untouched (both columns NULL)."""
    ensure_column(conn, "classes", "level", "TEXT")
    ensure_column(conn, "classes", "arm", "TEXT")


def parse_arms(text):
    """'A, B; C' -> ['A', 'B', 'C'] (trimmed, no blanks, no repeats, sane length)."""
    seen, out = set(), []
    for raw in re.split(r"[,;\n]+", text or ""):
        arm = " ".join(raw.split())[:20]
        if arm and arm.lower() not in seen:
            seen.add(arm.lower())
            out.append(arm)
    return out[:30]



def migration_036_role_permissions(conn):
    """Controlled role assignments and scoped permissions.

    A user's legacy role remains the compatibility/authentication role. This
    layer adds explicit assignments for Nursery/Primary/Secondary workflows,
    scoped access, approval, temporary assignments and auditability.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS role_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            school_id INTEGER NOT NULL,
            tenant_id TEXT,
            school_level TEXT NOT NULL DEFAULT 'All'
                CHECK(school_level IN ('All','Nursery','Primary','Secondary')),
            role TEXT NOT NULL,
            department TEXT,
            class_id INTEGER,
            class_arm TEXT,
            subject_id INTEGER,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('pending','active','rejected','revoked','expired')),
            is_temporary INTEGER NOT NULL DEFAULT 0,
            start_date TEXT,
            end_date TEXT,
            requested_by INTEGER,
            approved_by INTEGER,
            approved_at TEXT,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_user ON role_assignments(user_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_school ON role_assignments(school_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_tenant ON role_assignments(tenant_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS role_assignment_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER NOT NULL,
            permission TEXT NOT NULL,
            granted INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(assignment_id) REFERENCES role_assignments(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_assignment_permissions_assignment ON role_assignment_permissions(assignment_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS role_assignment_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER,
            user_id INTEGER NOT NULL,
            school_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            actor_name TEXT,
            action TEXT NOT NULL,
            previous_role TEXT,
            new_role TEXT,
            previous_scope TEXT,
            new_scope TEXT,
            approval_status TEXT,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_assignment_audit_school ON role_assignment_audit(school_id, created_at)")
    # Seed one assignment from each existing school admin so the new screen
    # does not appear empty on upgraded installations.
    admins = conn.execute("""
        SELECT u.id, u.school_id, u.role, s.tenant_id
        FROM users u JOIN schools s ON s.id=u.school_id
        WHERE u.role='admin'
    """).fetchall()
    for a in admins:
        exists = conn.execute(
            "SELECT 1 FROM role_assignments WHERE user_id=? AND role='School Admin' AND status='active' LIMIT 1",
            (a["id"],)
        ).fetchone()
        if not exists:
            cur = conn.execute("""
                INSERT INTO role_assignments
                (user_id, school_id, tenant_id, school_level, role, status, requested_by, approved_by, approved_at, reason)
                VALUES (?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP,?)
            """, (a["id"], a["school_id"], a["tenant_id"], "All", "School Admin",
                  a["id"], a["id"], "Migrated from existing School Admin account"))
            aid = cur.lastrowid
            for perm in ("view","create","edit","delete","approve","verify","finalize","lock","publish","import","export","manage_users"):
                conn.execute("INSERT INTO role_assignment_permissions (assignment_id, permission) VALUES (?,?)", (aid, perm))




def migration_037_scope_indexes(conn):
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_scope_class ON role_assignments(school_id, class_id, class_arm)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_scope_subject ON role_assignments(school_id, subject_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_scope_department ON role_assignments(school_id, department)")
    conn.execute("UPDATE role_assignments SET status='expired' WHERE status='active' AND end_date IS NOT NULL AND end_date < date('now')")


def migration_038_first_login_onboarding(conn):
    """Track first-login onboarding for newly provisioned school admins.

    Existing users are left unchanged; only newly provisioned accounts can
    explicitly opt into the first-login flow.
    """
    ensure_column(conn, "users", "first_login_required", "INTEGER DEFAULT 0")
    ensure_column(conn, "users", "first_login_completed_at", "TEXT")
    ensure_column(conn, "schools", "onboarding_started_at", "TEXT")


def migration_role_scope_compat(conn):
    """Compatibility repair for upgraded databases.

    Some V4/V5/V6 databases already contain role-scope tables but do not have
    the later tenant-aware columns/indexes fully populated.  This step is
    deliberately idempotent and never deletes role assignments or permissions.
    It also fixes the historical NameError where the named migration step was
    referenced before it had a definition.
    """
    conn.execute("CREATE TABLE IF NOT EXISTS role_assignments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, school_id INTEGER NOT NULL, tenant_id TEXT, school_level TEXT NOT NULL DEFAULT 'All', role TEXT NOT NULL, department TEXT, class_id INTEGER, class_arm TEXT, subject_id INTEGER, status TEXT NOT NULL DEFAULT 'active', is_temporary INTEGER NOT NULL DEFAULT 0, start_date TEXT, end_date TEXT, requested_by INTEGER, approved_by INTEGER, approved_at TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS role_assignment_permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id INTEGER NOT NULL, permission TEXT NOT NULL, granted INTEGER NOT NULL DEFAULT 1)")
    conn.execute("CREATE TABLE IF NOT EXISTS role_assignment_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id INTEGER, user_id INTEGER NOT NULL, school_id INTEGER NOT NULL, actor_user_id INTEGER, actor_name TEXT, action TEXT NOT NULL, previous_role TEXT, new_role TEXT, previous_scope TEXT, new_scope TEXT, approval_status TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    ensure_column(conn, "role_assignments", "tenant_id", "TEXT")
    ensure_column(conn, "role_assignments", "school_level", "TEXT NOT NULL DEFAULT 'All'")
    ensure_column(conn, "role_assignments", "department", "TEXT")
    ensure_column(conn, "role_assignments", "class_id", "INTEGER")
    ensure_column(conn, "role_assignments", "class_arm", "TEXT")
    ensure_column(conn, "role_assignments", "subject_id", "INTEGER")
    ensure_column(conn, "role_assignments", "status", "TEXT NOT NULL DEFAULT 'active'")
    conn.execute("UPDATE role_assignments SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=role_assignments.school_id) WHERE tenant_id IS NULL OR tenant_id=''" )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_tenant ON role_assignments(tenant_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_scope_class ON role_assignments(school_id, class_id, class_arm)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_scope_subject ON role_assignments(school_id, subject_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_role_scope_department ON role_assignments(school_id, department)")
    conn.execute("UPDATE role_assignments SET status='expired' WHERE status='active' AND end_date IS NOT NULL AND end_date < date('now')")

MIGRATIONS = [
    migration_001_baseline,
    migration_002_multi_school,
    migration_003_student_fields,
    migration_004_school_email_and_logo_settings,
    migration_005_expand_user_roles,
    migration_006_merge_admission_register,
    migration_007_terms_publish_flag,
    migration_008_more_skill_traits,
    migration_009_signature_dates,
    migration_010_enrollments,
    migration_011_student_login,
    migration_012_platform_tier,
    migration_013_notifications,
    migration_014_attendance_records,
    migration_015_auto_comments,
    migration_016_cumulative_results,
    migration_017_class_category,
    migration_018_learning_materials,
    migration_019_staff_attendance,
    migration_020_font_customization,
    migration_021_school_subdomain,
    migration_022_result_date_toggle,
    migration_023_school_activation,
]


def migration_024_user_active_status(conn):
    """A per-user active/inactive flag, distinct from school-level suspension.
    Lets an admin switch a staff account off (and, with it, every device that
    account had enrolled for offline use) without suspending the whole school.
    (Same definition the earlier "queue-based" build used for its migration 24,
    so a database created by that build already has it.)"""
    ensure_column(conn, "users", "is_active", "INTEGER NOT NULL DEFAULT 1")


def migration_025_offline_sync_tokens(conn):
    """Table used by the earlier queue-based build to de-duplicate replayed
    offline form submissions. Nothing in this build writes to it (offline work
    goes through the sync engine, whose changes carry their own ids), but it is
    created so a database from either build is a superset of both."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS offline_sync_tokens (
            token TEXT PRIMARY KEY,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)


# Everything after migration 23 is a NAMED step, recorded in schema_steps.
# Two earlier builds of this app used the same version numbers 24-26 for
# different things (offline sync engine vs. user-active flag + replay tokens),
# so a bare "schema_version" number can't tell what a live database contains.
# Each step below is idempotent, and run_migrations() works out which steps an
# existing database already has (by looking at what's actually in it) before
# applying the rest. A database from either earlier build upgrades cleanly.
def migration_030_materials_syncable(conn):
    """Learning-material listings (title, subject, class, type, link or file name) become
    readable on devices, so the app can list every material the person may see and let them
    save chosen ones for offline use. The files themselves are never bulk-synced."""
    _make_syncable(conn, "materials")
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_materials_tombstone
        AFTER DELETE ON materials
        FOR EACH ROW
        WHEN OLD.client_uuid IS NOT NULL
        BEGIN
            INSERT INTO sync_tombstones (school_id, entity, client_uuid, deleted_at)
            VALUES (OLD.school_id, 'materials', OLD.client_uuid, strftime('%Y-%m-%dT%H:%M:%S','now'));
        END
    """)


def migration_031_user_contact_identifiers(conn):
    """Lets staff log in with an email or phone number in addition to their
    username (the login form now accepts any of the three). Both are
    optional and, when present, unique platform-wide — same as username —
    so the login lookup can never match two different accounts."""
    ensure_column(conn, "users", "email", "TEXT")
    ensure_column(conn, "users", "phone", "TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE phone IS NOT NULL")


def migration_032_student_photo_and_relationship(conn):
    """Optional passport photo (uploaded like the school logo — online only,
    never bulk-synced to devices) and a guardian relationship field
    alongside the existing parent_* contact columns."""
    ensure_column(conn, "students", "parent_relationship", "TEXT")
    ensure_column(conn, "students", "photo_filename", "TEXT")


def migration_033_school_branding_extra(conn):
    """School-name alignment is its own setting, independent of logo_align
    (a school may want its logo on the left but its name centred). Also adds
    the school's timezone and preferred date display format, used by the
    dashboard's live date/time card and anywhere else a date is rendered."""
    ensure_column(conn, "schools", "name_align", "TEXT NOT NULL DEFAULT 'center'")
    ensure_column(conn, "schools", "timezone", "TEXT NOT NULL DEFAULT 'Africa/Lagos'")
    ensure_column(conn, "schools", "date_format", "TEXT NOT NULL DEFAULT 'dmy'")


def migration_034_result_theme(conn):
    """Per-school result-sheet visual theme: an accent colour and a header
    arrangement, on top of the existing font choice. Kept as plain columns
    (not JSON) so they stay simple to validate and to read from SQL."""
    ensure_column(conn, "schools", "result_accent_color", "TEXT NOT NULL DEFAULT '#1f3a5f'")
    ensure_column(conn, "schools", "result_header_layout", "TEXT NOT NULL DEFAULT 'logo-left'")


def migration_035_digital_signatures(conn):
    """Lets a teacher or principal upload a digital signature image from
    their own account and choose whether it should be stamped automatically
    on results instead of leaving a blank line for a manual signature. Kept
    strictly separate per user (a form teacher's signature can never appear
    as the principal's, and vice versa — the result template picks the image
    from student_term_info.teacher_signed_by / principal_signed_by, each an
    explicit user id, never "whoever is logged in")."""
    ensure_column(conn, "users", "signature_filename", "TEXT")
    ensure_column(conn, "users", "use_digital_signature", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "photo_filename", "TEXT")
    ensure_column(conn, "student_term_info", "teacher_signed_by", "INTEGER")
    ensure_column(conn, "student_term_info", "principal_signed_by", "INTEGER")


def migration_036_student_status_contact(conn):
    """An explicit lifecycle status (beyond the plain is_active toggle) and
    an optional contact number for the student themselves, distinct from the
    parent/guardian's. Existing rows default to 'Active', matching the is_active
    default they already had."""
    ensure_column(conn, "students", "status", "TEXT NOT NULL DEFAULT 'Active'")
    ensure_column(conn, "students", "phone", "TEXT")
    conn.execute("UPDATE students SET status='Active' WHERE status IS NULL")


def migration_037_attendance_source(conn):
    """Records whether an attendance entry was taken online (saved straight
    to the server) or offline (saved to the device first, then synced), so
    it can be shown in the attendance history and, for offline entries, kept
    distinct from the moment it was later synced. Existing rows predate this
    column and are assumed online, since offline sync didn't exist before it."""
    ensure_column(conn, "attendance_records", "source", "TEXT NOT NULL DEFAULT 'online'")
    ensure_column(conn, "attendance_records", "synced_at", "TEXT")
    ensure_column(conn, "staff_attendance", "source", "TEXT NOT NULL DEFAULT 'online'")
    ensure_column(conn, "staff_attendance", "synced_at", "TEXT")


def migration_038_timetable(conn):
    """A school timetable: named periods (with times) shared across the
    school, and one entry per class/day/period holding the subject, teacher
    and room. Both tables are made syncable (client_uuid/updated_at/is_deleted)
    so they can be registered for offline read/write the same way classes and
    subjects are."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timetable_periods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            start_time TEXT,
            end_time TEXT,
            sort_order INTEGER NOT NULL DEFAULT 0,
            is_break INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timetable_periods_school ON timetable_periods(school_id, sort_order)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS timetable_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            day_of_week INTEGER NOT NULL,
            period_id INTEGER NOT NULL,
            subject_id INTEGER,
            teacher_id INTEGER,
            room TEXT,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            FOREIGN KEY(class_id) REFERENCES classes(id),
            FOREIGN KEY(period_id) REFERENCES timetable_periods(id),
            FOREIGN KEY(subject_id) REFERENCES subjects(id),
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        )
    """)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_timetable_entries_slot "
        "ON timetable_entries(class_id, day_of_week, period_id)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timetable_entries_teacher ON timetable_entries(teacher_id, day_of_week)")

    _make_syncable(conn, "timetable_periods")
    _make_syncable(conn, "timetable_entries")
    for table, school_expr in (
        ("timetable_periods", "OLD.school_id"),
        ("timetable_entries", "OLD.school_id"),
    ):
        conn.execute(f"""
            CREATE TRIGGER IF NOT EXISTS trg_{table}_tombstone
            AFTER DELETE ON {table}
            FOR EACH ROW
            WHEN OLD.client_uuid IS NOT NULL
            BEGIN
                INSERT INTO sync_tombstones (school_id, entity, client_uuid, deleted_at)
                VALUES ({school_expr}, '{table}', OLD.client_uuid, strftime('%Y-%m-%dT%H:%M:%S','now'));
            END
        """)


def migration_039_tenant_identifiers(conn):
    """Add permanent human-readable school and tenant identifiers.

    Existing numeric school_id values remain the internal relational key.
    tenant_id and school_code are stable identifiers used by the application
    and offline client; they are never accepted as authorization credentials.
    """
    ensure_column(conn, "schools", "tenant_id", "TEXT")
    ensure_column(conn, "schools", "school_code", "TEXT")
    ensure_column(conn, "users", "tenant_id", "TEXT")

    def make_code(name, school_id):
        raw = re.sub(r"[^A-Za-z0-9]+", "", (name or "SCHOOL").upper())
        raw = raw[:18] or "SCHOOL"
        code = raw
        n = 2
        while conn.execute("SELECT 1 FROM schools WHERE school_code=? AND id<>?", (code, school_id)).fetchone():
            suffix = str(n)
            code = (raw[:max(1, 20-len(suffix))] + suffix)
            n += 1
        return code

    schools = conn.execute("SELECT id, name, tenant_id, school_code FROM schools ORDER BY id").fetchall()
    for school in schools:
        tenant_id = school["tenant_id"]
        school_code = school["school_code"]
        if not tenant_id:
            tenant_id = "TEN-" + _secrets.token_hex(4).upper()
            while conn.execute("SELECT 1 FROM schools WHERE tenant_id=?", (tenant_id,)).fetchone():
                tenant_id = "TEN-" + _secrets.token_hex(4).upper()
        if not school_code:
            school_code = make_code(school["name"], school["id"])
        conn.execute("UPDATE schools SET tenant_id=?, school_code=? WHERE id=?",
                     (tenant_id, school_code, school["id"]))
        conn.execute("UPDATE users SET tenant_id=? WHERE school_id=?", (tenant_id, school["id"]))

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_schools_tenant_id ON schools(tenant_id)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_schools_school_code ON schools(school_code)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id)")


def migration_040_school_readiness(conn):
    """Track whether a school has completed the required pre-live setup.
    Existing schools remain usable and are treated as not-yet-verified until
    an administrator explicitly completes the readiness checklist.
    """
    ensure_column(conn, "schools", "readiness_status", "TEXT NOT NULL DEFAULT 'pending'")
    ensure_column(conn, "schools", "ready_at", "TEXT")
    ensure_column(conn, "schools", "ready_by", "INTEGER")
    ensure_column(conn, "schools", "readiness_version", "INTEGER NOT NULL DEFAULT 1")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schools_readiness ON schools(readiness_status)")


def migration_041_school_subscription(conn):
    """Add non-payment subscription/trial lifecycle fields per school.
    Existing schools default to legacy so migration never changes their access.
    """
    for column, coltype in [
        ("subscription_plan", "TEXT NOT NULL DEFAULT 'legacy'"),
        ("subscription_status", "TEXT NOT NULL DEFAULT 'legacy'"),
        ("trial_started_at", "TEXT"),
        ("trial_ends_at", "TEXT"),
        ("subscription_started_at", "TEXT"),
        ("subscription_ends_at", "TEXT"),
        ("grace_ends_at", "TEXT"),
        ("subscription_reference", "TEXT"),
    ]:
        ensure_column(conn, "schools", column, coltype)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schools_subscription_status ON schools(subscription_status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schools_trial_ends ON schools(trial_ends_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schools_subscription_ends ON schools(subscription_ends_at)")


def migration_042_subscription_plans(conn):
    """Create configurable platform subscription plans. Existing school access is untouched."""
    conn.execute("""CREATE TABLE IF NOT EXISTS subscription_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        price_ngn REAL NOT NULL DEFAULT 0,
        billing_days INTEGER NOT NULL DEFAULT 365,
        max_students INTEGER,
        max_teachers INTEGER,
        max_storage_mb INTEGER,
        features_json TEXT NOT NULL DEFAULT '{}',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    plans = [
        ('trial','30-Day Trial',0,30,100,10,500,'{"results":true,"attendance":true,"materials":true,"timetable":true,"reports":true}'),
        ('basic','Basic',15000,365,500,30,2000,'{"results":true,"attendance":true,"materials":true,"timetable":true,"reports":true}'),
        ('standard','Standard',30000,365,1500,75,5000,'{"results":true,"attendance":true,"materials":true,"timetable":true,"reports":true,"offline_sync":true}'),
        ('premium','Premium',60000,365,5000,250,15000,'{"results":true,"attendance":true,"materials":true,"timetable":true,"reports":true,"offline_sync":true,"ai":true,"advanced_reports":true}')
    ]
    for row in plans:
        conn.execute("""INSERT OR IGNORE INTO subscription_plans
            (code,name,price_ngn,billing_days,max_students,max_teachers,max_storage_mb,features_json)
            VALUES (?,?,?,?,?,?,?,?)""", row)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_subscription_plans_active ON subscription_plans(is_active)")


def migration_043_billing_payments(conn):
    """Create non-gateway billing records. No payment is considered successful until explicitly confirmed."""
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        invoice_number TEXT UNIQUE NOT NULL,
        plan_code TEXT NOT NULL,
        amount_ngn REAL NOT NULL DEFAULT 0,
        billing_days INTEGER NOT NULL DEFAULT 365,
        status TEXT NOT NULL DEFAULT 'pending',
        issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        due_at TEXT,
        paid_at TEXT,
        payment_reference TEXT,
        notes TEXT,
        created_by TEXT,
        FOREIGN KEY(school_id) REFERENCES schools(id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        invoice_id INTEGER,
        provider TEXT NOT NULL DEFAULT 'manual',
        payment_reference TEXT NOT NULL,
        amount_ngn REAL NOT NULL DEFAULT 0,
        currency TEXT NOT NULL DEFAULT 'NGN',
        status TEXT NOT NULL DEFAULT 'pending',
        paid_at TEXT,
        confirmed_at TEXT,
        confirmed_by TEXT,
        raw_metadata TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
    )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_payments_reference ON billing_payments(payment_reference)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_invoices_school ON billing_invoices(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_invoices_status ON billing_invoices(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_payments_school ON billing_payments(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_payments_status ON billing_payments(status)")


def migration_044_payment_gateway_webhooks(conn):
    """Add gateway webhook idempotency and receipt records.

    Webhook rows are immutable processing records; a repeated provider event
    must never create a second payment or renew a school twice.
    """
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_webhook_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL,
        provider_event_id TEXT NOT NULL,
        event_type TEXT,
        payment_reference TEXT,
        payload_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'received',
        error_message TEXT,
        received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        processed_at TEXT
    )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_webhook_event ON billing_webhook_events(provider, provider_event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_webhook_reference ON billing_webhook_events(payment_reference)")
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        invoice_id INTEGER,
        payment_id INTEGER NOT NULL UNIQUE,
        receipt_number TEXT UNIQUE NOT NULL,
        amount_ngn REAL NOT NULL DEFAULT 0,
        currency TEXT NOT NULL DEFAULT 'NGN',
        provider TEXT NOT NULL DEFAULT 'manual',
        payment_reference TEXT NOT NULL,
        issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id),
        FOREIGN KEY(payment_id) REFERENCES billing_payments(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_receipts_school ON billing_receipts(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_receipts_invoice ON billing_receipts(invoice_id)")


def migration_044_billing_notification_tracking(conn):
    """Track automated billing notifications so each reminder is sent once per billing event/day."""
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_notification_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        event_key TEXT NOT NULL,
        notification_type TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(school_id, event_key),
        FOREIGN KEY(school_id) REFERENCES schools(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_notification_school ON billing_notification_events(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_notification_type ON billing_notification_events(notification_type)")


def migration_045_billing_email_notifications(conn):
    """Track opt-in billing email delivery and retries without changing subscription state."""
    ensure_column(conn, "schools", "billing_email_notifications", "INTEGER DEFAULT 1")
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_email_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        event_key TEXT NOT NULL,
        recipient TEXT NOT NULL,
        notification_type TEXT NOT NULL,
        subject TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        sent_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(school_id, event_key),
        FOREIGN KEY(school_id) REFERENCES schools(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_email_school ON billing_email_delivery(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_email_status ON billing_email_delivery(status)")



def migration_046_billing_job_runs(conn):
    """Track scheduled billing-job runs and prevent overlapping executions."""
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_job_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_name TEXT NOT NULL,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        result_json TEXT,
        error_message TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_job_runs_name_started ON billing_job_runs(job_name, started_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_job_runs_status ON billing_job_runs(status)")



def migration_047_billing_financial_audit(conn):
    """Append-only financial audit trail for billing operations and exports."""
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_financial_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        actor_type TEXT NOT NULL,
        actor_name TEXT,
        school_id INTEGER,
        payment_id INTEGER,
        invoice_id INTEGER,
        reference TEXT,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id),
        FOREIGN KEY(payment_id) REFERENCES billing_payments(id),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_fin_audit_created ON billing_financial_audit(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_fin_audit_school ON billing_financial_audit(school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_fin_audit_payment ON billing_financial_audit(payment_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_fin_audit_invoice ON billing_financial_audit(invoice_id)")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_financial_audit_no_update
        BEFORE UPDATE ON billing_financial_audit
        BEGIN SELECT RAISE(ABORT, 'Financial audit records are immutable'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_financial_audit_no_delete
        BEFORE DELETE ON billing_financial_audit
        BEGIN SELECT RAISE(ABORT, 'Financial audit records are immutable'); END""")

    conn.execute("""CREATE TABLE IF NOT EXISTS billing_payment_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        payment_id INTEGER NOT NULL,
        school_id INTEGER NOT NULL,
        invoice_id INTEGER,
        action TEXT NOT NULL,
        old_status TEXT,
        new_status TEXT,
        old_amount_ngn REAL,
        new_amount_ngn REAL,
        old_reference TEXT,
        new_reference TEXT,
        actor TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(payment_id) REFERENCES billing_payments(id),
        FOREIGN KEY(school_id) REFERENCES schools(id),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_payment_history_payment ON billing_payment_history(payment_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_payment_history_school ON billing_payment_history(school_id, created_at)")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_payment_history_no_update
        BEFORE UPDATE ON billing_payment_history
        BEGIN SELECT RAISE(ABORT, 'Payment history records are immutable'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_payment_history_no_delete
        BEFORE DELETE ON billing_payment_history
        BEGIN SELECT RAISE(ABORT, 'Payment history records are immutable'); END""")

    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_payment_insert_history
        AFTER INSERT ON billing_payments
        BEGIN
            INSERT INTO billing_payment_history(payment_id,school_id,invoice_id,action,old_status,new_status,new_amount_ngn,new_reference,actor)
            VALUES (NEW.id,NEW.school_id,NEW.invoice_id,'created',NULL,NEW.status,NEW.amount_ngn,NEW.payment_reference,COALESCE(NEW.confirmed_by,'system'));
        END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_payment_update_history
        AFTER UPDATE OF status,amount_ngn,payment_reference,provider,invoice_id ON billing_payments
        WHEN OLD.status IS NOT NEW.status OR OLD.amount_ngn IS NOT NEW.amount_ngn OR OLD.payment_reference IS NOT NEW.payment_reference OR OLD.invoice_id IS NOT NEW.invoice_id
        BEGIN
            INSERT INTO billing_payment_history(payment_id,school_id,invoice_id,action,old_status,new_status,old_amount_ngn,new_amount_ngn,old_reference,new_reference,actor)
            VALUES (NEW.id,NEW.school_id,NEW.invoice_id,
                    CASE WHEN OLD.status IS NOT NEW.status AND NEW.status='confirmed' THEN 'confirmed'
                         WHEN OLD.status IS NOT NEW.status AND NEW.status IN ('reversed','refunded','cancelled') THEN 'status_changed'
                         ELSE 'changed' END,
                    OLD.status,NEW.status,OLD.amount_ngn,NEW.amount_ngn,OLD.payment_reference,NEW.payment_reference,COALESCE(NEW.confirmed_by,'system'));
        END""")

    conn.execute("""CREATE TABLE IF NOT EXISTS billing_report_downloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_type TEXT NOT NULL,
        actor_name TEXT,
        report_name TEXT NOT NULL,
        format TEXT NOT NULL,
        start_date TEXT,
        end_date TEXT,
        row_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_report_downloads_created ON billing_report_downloads(created_at)")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_report_downloads_no_update
        BEFORE UPDATE ON billing_report_downloads
        BEGIN SELECT RAISE(ABORT, 'Report download records are immutable'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_billing_report_downloads_no_delete
        BEFORE DELETE ON billing_report_downloads
        BEGIN SELECT RAISE(ABORT, 'Report download records are immutable'); END""")



def migration_048_ai_layer(conn):
    """AI layer configuration, consent, draft outputs and audit records.
    All records are explicitly tenant-scoped; AI is disabled by default."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS school_ai_settings (
            school_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            process_student_data INTEGER NOT NULL DEFAULT 0,
            result_analysis INTEGER NOT NULL DEFAULT 1,
            teacher_comments INTEGER NOT NULL DEFAULT 1,
            principal_comments INTEGER NOT NULL DEFAULT 1,
            performance_alerts INTEGER NOT NULL DEFAULT 1,
            ai_tutor INTEGER NOT NULL DEFAULT 1,
            learning_materials INTEGER NOT NULL DEFAULT 1,
            result_assistant INTEGER NOT NULL DEFAULT 0,
            retention_days INTEGER NOT NULL DEFAULT 365,
            privacy_notice_version TEXT NOT NULL DEFAULT '1.0',
            updated_by INTEGER,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS student_ai_consent (
            student_id INTEGER PRIMARY KEY,
            school_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','granted','withdrawn')),
            granted_by_type TEXT,
            granted_by_id INTEGER,
            policy_version TEXT,
            granted_at TEXT,
            withdrawn_at TEXT,
            notes TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_consent_school_status ON student_ai_consent(school_id,status)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            feature TEXT NOT NULL,
            student_id INTEGER,
            term_id INTEGER,
            class_id INTEGER,
            subject_id INTEGER,
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','rejected')),
            output_text TEXT NOT NULL,
            generated_by INTEGER,
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_outputs_school_feature ON ai_outputs(school_id,feature,created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_outputs_student ON ai_outputs(school_id,student_id,term_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            user_id INTEGER,
            feature TEXT NOT NULL,
            student_id INTEGER,
            consent_status TEXT,
            data_scope TEXT,
            action TEXT NOT NULL,
            request_summary TEXT,
            output_summary TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_audit_school_time ON ai_audit_log(school_id,created_at)")
    schools=conn.execute("SELECT id FROM schools").fetchall()
    for row in schools:
        conn.execute("INSERT OR IGNORE INTO school_ai_settings(school_id) VALUES (?)",(row["id"],))



def migration_051_registration_security_spec(conn):
    if table_exists(conn,"activation_codes"):
        for col,typ in [("max_usage","INTEGER DEFAULT 1"),("usage_count","INTEGER DEFAULT 0"),("status","TEXT DEFAULT 'active'"),("revoked_at","TEXT"),("revoked_by","INTEGER")]: ensure_column(conn,"activation_codes",col,typ)
        conn.execute("UPDATE activation_codes SET usage_count=CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END WHERE usage_count IS NULL")
    for col,typ in [("address","TEXT"),("date_of_birth","TEXT"),("gender","TEXT"),("qualifications","TEXT"),("phone2","TEXT")]:
        if table_exists(conn,"users"): ensure_column(conn,"users",col,typ)
    direct=["users","classes","subjects","sessions","grading_config","grade_scale","skill_traits","materials","staff_attendance","attendance_records","timetable_periods","timetable_entries","role_assignments","notifications","device_credentials","sync_conflicts","sync_log","deferred_actions","student_term_info","parent_accounts","parent_students","parent_teacher_messages","parent_consent_events","school_ai_settings","student_ai_consent","ai_outputs","ai_audit_log"]
    for table in direct:
        if table_exists(conn,table) and "school_id" in column_names(conn,table):
            ensure_column(conn,table,"tenant_id","TEXT"); conn.execute(f"UPDATE {table} SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id={table}.school_id) WHERE tenant_id IS NULL OR tenant_id='' "); conn.execute(f"CREATE TRIGGER IF NOT EXISTS trg_{table}_tenant_stamp AFTER INSERT ON {table} FOR EACH ROW WHEN NEW.tenant_id IS NULL OR NEW.tenant_id='' BEGIN UPDATE {table} SET tenant_id=(SELECT tenant_id FROM schools WHERE id=NEW.school_id) WHERE rowid=NEW.rowid; END")
    if table_exists(conn,"students"):
        ensure_column(conn,"students","tenant_id","TEXT"); conn.execute("UPDATE students SET tenant_id=(SELECT s.tenant_id FROM classes c JOIN schools s ON s.id=c.school_id WHERE c.id=students.class_id) WHERE tenant_id IS NULL OR tenant_id='' "); conn.execute("CREATE TRIGGER IF NOT EXISTS trg_students_tenant_stamp AFTER INSERT ON students FOR EACH ROW WHEN NEW.tenant_id IS NULL OR NEW.tenant_id='' BEGIN UPDATE students SET tenant_id=(SELECT s.tenant_id FROM classes c JOIN schools s ON s.id=c.school_id WHERE c.id=NEW.class_id) WHERE rowid=NEW.rowid; END")
    if table_exists(conn,"scores"):
        ensure_column(conn,"scores","tenant_id","TEXT"); conn.execute("UPDATE scores SET tenant_id=(SELECT s.tenant_id FROM students st JOIN classes c ON c.id=st.class_id JOIN schools s ON s.id=c.school_id WHERE st.id=scores.student_id) WHERE tenant_id IS NULL OR tenant_id='' "); conn.execute("CREATE TRIGGER IF NOT EXISTS trg_scores_tenant_stamp AFTER INSERT ON scores FOR EACH ROW WHEN NEW.tenant_id IS NULL OR NEW.tenant_id='' BEGIN UPDATE scores SET tenant_id=(SELECT s.tenant_id FROM students st JOIN classes c ON c.id=st.class_id JOIN schools s ON s.id=c.school_id WHERE st.id=NEW.student_id) WHERE rowid=NEW.rowid; END")
    if table_exists(conn,"enrollments"):
        ensure_column(conn,"enrollments","tenant_id","TEXT"); conn.execute("UPDATE enrollments SET tenant_id=(SELECT s.tenant_id FROM classes c JOIN schools s ON s.id=c.school_id WHERE c.id=enrollments.class_id) WHERE tenant_id IS NULL OR tenant_id='' "); conn.execute("CREATE TRIGGER IF NOT EXISTS trg_enrollments_tenant_stamp AFTER INSERT ON enrollments FOR EACH ROW WHEN NEW.tenant_id IS NULL OR NEW.tenant_id='' BEGIN UPDATE enrollments SET tenant_id=(SELECT s.tenant_id FROM classes c JOIN schools s ON s.id=c.school_id WHERE c.id=NEW.class_id) WHERE rowid=NEW.rowid; END")
    if table_exists(conn,"score_history"):
        ensure_column(conn,"score_history","tenant_id","TEXT"); conn.execute("UPDATE score_history SET tenant_id=(SELECT s.tenant_id FROM students st JOIN classes c ON c.id=st.class_id JOIN schools s ON s.id=c.school_id WHERE st.id=score_history.student_id) WHERE tenant_id IS NULL OR tenant_id='' "); conn.execute("CREATE TRIGGER IF NOT EXISTS trg_score_history_tenant_stamp AFTER INSERT ON score_history FOR EACH ROW WHEN NEW.tenant_id IS NULL OR NEW.tenant_id='' BEGIN UPDATE score_history SET tenant_id=(SELECT s.tenant_id FROM students st JOIN classes c ON c.id=st.class_id JOIN schools s ON s.id=c.school_id WHERE st.id=NEW.student_id) WHERE rowid=NEW.rowid; END")
    conn.execute("""CREATE TABLE IF NOT EXISTS signup_codes (id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT NOT NULL UNIQUE,code_type TEXT NOT NULL CHECK(code_type IN ('staff','student','parent_link')),school_id INTEGER NOT NULL,tenant_id TEXT NOT NULL,class_id INTEGER,student_id INTEGER,created_by INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,expires_at TEXT,max_usage INTEGER DEFAULT 1,usage_count INTEGER DEFAULT 0,status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','exhausted','revoked','suspended')),last_used_at TEXT,revoked_at TEXT,revoked_by INTEGER,FOREIGN KEY(school_id) REFERENCES schools(id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signup_codes_school_type ON signup_codes(school_id,code_type,status)")
    if table_exists(conn,"parent_students"):
        ensure_column(conn,"parent_students","tenant_id","TEXT"); ensure_column(conn,"parent_students","status","TEXT NOT NULL DEFAULT 'pending'"); ensure_column(conn,"parent_students","verified_at","TEXT"); ensure_column(conn,"parent_students","verified_by","INTEGER"); ensure_column(conn,"parent_students","revoked_at","TEXT"); conn.execute("UPDATE parent_students SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=parent_students.school_id) WHERE tenant_id IS NULL OR tenant_id='' "); conn.execute("UPDATE parent_students SET status='verified' WHERE status IS NULL OR status='' ")

def migration_049_school_theme(conn):
    """Dashboard theme tokens are per-school and safe to change without affecting data."""
    for col, typ in [
        ("theme_preset", "TEXT NOT NULL DEFAULT 'default'"),
        ("dashboard_primary_color", "TEXT NOT NULL DEFAULT '#1f6feb'"),
        ("dashboard_secondary_color", "TEXT NOT NULL DEFAULT '#0b3b75'"),
        ("dashboard_accent_color", "TEXT NOT NULL DEFAULT '#7c4dff'"),
        ("dashboard_sidebar_style", "TEXT NOT NULL DEFAULT 'dark'"),
        ("dashboard_header_style", "TEXT NOT NULL DEFAULT 'solid'"),
        ("school_tagline", "TEXT"),
    ]:
        ensure_column(conn, "schools", col, typ)


def migration_053_billing_finalization(conn):
    """V38-V47 additive financial finalization tables."""
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_reconciliation_exceptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exception_key TEXT UNIQUE NOT NULL,
        exception_type TEXT NOT NULL,
        payment_id INTEGER,
        invoice_id INTEGER,
        reference TEXT,
        details TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        reviewed_by TEXT,
        reviewed_at TEXT,
        review_note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(payment_id) REFERENCES billing_payments(id),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_recon_status ON billing_reconciliation_exceptions(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_recon_payment ON billing_reconciliation_exceptions(payment_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_recon_invoice ON billing_reconciliation_exceptions(invoice_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_adjustments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        payment_id INTEGER NOT NULL,
        invoice_id INTEGER,
        adjustment_type TEXT NOT NULL,
        amount_ngn REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'requested',
        reason TEXT NOT NULL,
        reference TEXT UNIQUE NOT NULL,
        requested_by TEXT,
        approved_by TEXT,
        rejected_by TEXT,
        processed_by TEXT,
        requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        approved_at TEXT,
        rejected_at TEXT,
        processed_at TEXT,
        external_reference TEXT,
        FOREIGN KEY(school_id) REFERENCES schools(id),
        FOREIGN KEY(payment_id) REFERENCES billing_payments(id),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_adjustments_payment ON billing_adjustments(payment_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_adjustments_status ON billing_adjustments(status)")
    conn.execute("""CREATE TABLE IF NOT EXISTS billing_renewal_recovery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_id INTEGER NOT NULL,
        school_id INTEGER NOT NULL,
        attempt_no INTEGER NOT NULL DEFAULT 1,
        next_attempt_at TEXT,
        status TEXT NOT NULL DEFAULT 'queued',
        last_message TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(invoice_id,attempt_no),
        FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id),
        FOREIGN KEY(school_id) REFERENCES schools(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_billing_recovery_status ON billing_renewal_recovery(status,next_attempt_at)")


STEPS = [    ("ai_layer", migration_048_ai_layer),
    ("school_theme", migration_049_school_theme),
    ("offline_sync", migration_024_offline_sync),
    ("deferred_actions", migration_025_deferred_actions),
    ("sync_triggers", migration_026_sync_triggers),
    ("user_active_status", migration_024_user_active_status),
    ("offline_sync_tokens", migration_025_offline_sync_tokens),
    ("ca3_conflicts_audit_tombstones", migration_027_ca3_conflicts_audit_tombstones),
    ("skills_syncable", migration_028_skills_syncable),
    ("class_arms", migration_029_class_arms),
    ("materials_syncable", migration_030_materials_syncable),
    ("user_contact_identifiers", migration_031_user_contact_identifiers),
    ("student_photo_and_relationship", migration_032_student_photo_and_relationship),
    ("school_branding_extra", migration_033_school_branding_extra),
    ("result_theme", migration_034_result_theme),
    ("digital_signatures", migration_035_digital_signatures),
    ("student_status_contact", migration_036_student_status_contact),
    ("attendance_source", migration_037_attendance_source),
    ("timetable", migration_038_timetable),
    ("tenant_identifiers", migration_039_tenant_identifiers),
    ("role_permissions", migration_036_role_permissions),
    ("scope_indexes", migration_037_scope_indexes),
    ("first_login_onboarding", migration_038_first_login_onboarding),
    ("role_scope_compat", migration_role_scope_compat),
    ("school_readiness", migration_040_school_readiness),
    ("school_subscription", migration_041_school_subscription),
    ("subscription_plans", migration_042_subscription_plans),
    ("billing_payments", migration_043_billing_payments),
    ("billing_notification_tracking", migration_044_billing_notification_tracking),
    ("billing_email_notifications", migration_045_billing_email_notifications),
    ("billing_job_runs", migration_046_billing_job_runs),
    ("payment_gateway_webhooks", migration_044_payment_gateway_webhooks),
    ("billing_financial_audit", migration_047_billing_financial_audit),
    ("billing_finalization", migration_053_billing_finalization),
]


def _adopt_legacy_steps(conn, version):
    """A database that predates schema_steps has only a version number. Numbers
    above 23 meant different things in the two earlier builds, so tell them
    apart by what is really in the database: the sync engine's device_credentials
    table exists only in the offline-sync build."""
    if version <= len(MIGRATIONS):
        return
    has_sync_engine = bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_credentials'").fetchone())
    if has_sync_engine:
        legacy = [("offline_sync", 24), ("deferred_actions", 25), ("sync_triggers", 26),
                  ("ca3_conflicts_audit_tombstones", 27), ("skills_syncable", 28), ("class_arms", 29)]
    else:
        legacy = [("user_active_status", 24), ("offline_sync_tokens", 25)]
    for name, needs_version in legacy:
        if version >= needs_version:
            conn.execute("INSERT OR IGNORE INTO schema_steps (name) VALUES (?)", (name,))
    conn.commit()


def run_migrations(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version (version) VALUES (0)")
        version = 0
    else:
        version = row["version"]

    for i, fn in enumerate(MIGRATIONS, start=1):
        if version < i:
            fn(conn)
            conn.execute("UPDATE schema_version SET version=?", (i,))
            conn.commit()

    conn.execute("CREATE TABLE IF NOT EXISTS schema_steps (name TEXT PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    if not conn.execute("SELECT 1 FROM schema_steps LIMIT 1").fetchone():
        _adopt_legacy_steps(conn, version)
    done = {r["name"] for r in conn.execute("SELECT name FROM schema_steps")}
    for name, fn in STEPS:
        # A prior deployment can have recorded a step as complete while its
        # table was later lost (for example, a partial restore or an interrupted
        # SQLite migration).  Critical parent-portal tables must be repaired
        # from the idempotent migration rather than trusting schema_steps alone.
        if name == "parent_portal" and (
            not table_exists(conn, "parent_accounts")
            or not table_exists(conn, "parent_students")
            or not table_exists(conn, "parent_teacher_messages")
            or not table_exists(conn, "parent_consent_events")
        ):
            fn(conn)
            conn.execute("INSERT OR IGNORE INTO schema_steps (name) VALUES (?)", (name,))
            conn.commit()
            continue
        if name not in done:
            fn(conn)
            conn.execute("INSERT INTO schema_steps (name) VALUES (?)", (name,))
            conn.commit()
    # schema_version stays as an informational high-water mark for older tooling.
    conn.execute("UPDATE schema_version SET version = MAX(version, ?)", (len(MIGRATIONS) + len(STEPS),))
    conn.commit()



def _migration_lock_path():
    return os.path.join(INSTANCE_DIR, "migration.lock")


def _migration_backup_path():
    return os.path.join(INSTANCE_DIR, "backups")


def _pre_migration_backup():
    """Create and integrity-check a SQLite snapshot before schema changes.

    The snapshot lives beside the persistent database, so a Railway Volume keeps
    it across deployments.  No application data is modified by this function.
    """
    os.makedirs(_migration_backup_path(), exist_ok=True)
    stamp = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    target = os.path.join(_migration_backup_path(), f"pre-migration-{stamp}.db")
    src = sqlite3.connect(DB_PATH, timeout=60)
    dst = sqlite3.connect(target, timeout=60)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    check = sqlite3.connect(target, timeout=30)
    try:
        verdict = check.execute("PRAGMA integrity_check").fetchone()[0]
        if verdict != "ok":
            raise RuntimeError(f"Pre-migration backup failed integrity check: {verdict}")
    finally:
        check.close()
    # Keep the latest 10 migration snapshots.
    backups = sorted(
        f for f in os.listdir(_migration_backup_path())
        if f.startswith("pre-migration-") and f.endswith(".db")
    )
    for old in backups[:-10]:
        try:
            os.remove(os.path.join(_migration_backup_path(), old))
        except OSError:
            pass
    return target


def _migration_work_needed(conn):
    """Return whether startup is about to change the schema."""
    row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
    if not row:
        return True
    version_row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    version = int(version_row[0]) if version_row else 0
    if version < len(MIGRATIONS):
        return True
    row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_steps'").fetchone()
    if not row:
        return True
    done = {r[0] for r in conn.execute("SELECT name FROM schema_steps")}
    return any(name not in done for name, _ in STEPS)


def _run_migrations_with_lock(conn):
    """Serialize startup migrations across Gunicorn workers/processes."""
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    lock_path = _migration_lock_path()
    with open(lock_path, "a+") as lock_file:
        try:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except (ImportError, AttributeError):
            # Windows development fallback: SQLite itself still serializes writes.
            pass
        try:
            # Another worker may have completed the migration while this process
            # was waiting for the lock, so inspect again after acquiring it.
            if _migration_work_needed(conn) and os.path.exists(DB_PATH):
                backup = _pre_migration_backup()
                os.environ["LAST_MIGRATION_BACKUP"] = backup
            run_migrations(conn)
        finally:
            try:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except (ImportError, AttributeError):
                pass

def init_db(reset=False):
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    fresh = not os.path.exists(DB_PATH)
    conn = get_db()
    _run_migrations_with_lock(conn)

    # SKIP_DEMO_SEED=1 (recommended for any public deployment): don't create
    # the demo school with its well-known admin/teacher passwords. Create the
    # first Super Admin with create_super_admin.py instead.
    if fresh and not os.environ.get("SKIP_DEMO_SEED"):
        seed(conn)
    conn.close()


def seed_school_defaults(conn, school_id):
    """Sensible starting defaults for a brand-new school: grading weights,
    a standard A-F grade scale, and common skill-rating traits."""
    conn.execute(
        "INSERT INTO grading_config (school_id, ca1_max, ca2_max, exam_max) VALUES (?,20,20,60)",
        (school_id,),
    )
    scale = [
        ("A", 70, 100, "Excellent"),
        ("B", 60, 69.99, "Very Good"),
        ("C", 50, 59.99, "Good"),
        ("D", 45, 49.99, "Fair"),
        ("E", 40, 44.99, "Pass"),
        ("F", 0, 39.99, "Fail"),
    ]
    conn.executemany(
        "INSERT INTO grade_scale (school_id, grade, min_score, max_score, remark) VALUES (?,?,?,?,?)",
        [(school_id, *s) for s in scale],
    )
    psychomotor = ["Handwriting", "Sports/Games", "Handling of Tools", "Club & Societies"]
    affective = ["Punctuality", "Neatness", "Honesty", "Relationship with Others", "Leadership", "Emotional Stability"]
    for t in psychomotor:
        conn.execute("INSERT INTO skill_traits (school_id, name, category) VALUES (?,?, 'psychomotor')", (school_id, t))
    for t in affective:
        conn.execute("INSERT INTO skill_traits (school_id, name, category) VALUES (?,?, 'affective')", (school_id, t))
    conn.commit()
    ensure_school_v61_defaults(conn, school_id)


def seed(conn):
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO schools (name, logo_filename, staff_signup_code) VALUES ('My School', NULL, NULL)"
    )
    school_id = cur.lastrowid
    cur.execute("UPDATE schools SET tenant_id=COALESCE(NULLIF(tenant_id,''),CAST(id AS TEXT)) WHERE id=?", (school_id,))
    seed_tenant = cur.execute("SELECT tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()[0]

    cur.execute(
        "INSERT INTO users (school_id, tenant_id, name, username, password_hash, role) VALUES (?,?,?,?,?,?)",
        (school_id, seed_tenant, "Administrator", "admin", generate_password_hash("admin123"), "admin"),
    )

    cur.execute(
        "INSERT INTO users (school_id, tenant_id, name, username, password_hash, role, position) VALUES (?,?,?,?,?,?,?)",
        (school_id, seed_tenant, "Mrs. Ada Okafor", "aokafor", generate_password_hash("teacher123"), "teacher", "form_teacher"),
    )
    teacher_id = cur.lastrowid

    cur.execute("INSERT INTO sessions (school_id, name, is_active) VALUES (?,?,1)", (school_id, "2025/2026"))
    session_id = cur.lastrowid
    cur.execute(
        "INSERT INTO terms (name, session_id, is_active) VALUES (?,?,1)",
        ("1st Term", session_id),
    )

    conn.commit()
    seed_school_defaults(conn, school_id)

    cur.execute("INSERT INTO classes (school_id, name) VALUES (?, 'JSS1A')", (school_id,))
    class_id = cur.lastrowid
    cur.execute("UPDATE classes SET form_teacher_id=? WHERE id=?", (teacher_id, class_id))

    subjects = ["Mathematics", "English Language", "Basic Science", "Social Studies"]
    subject_ids = []
    for s in subjects:
        cur.execute("INSERT INTO subjects (school_id, name) VALUES (?,?)", (school_id, s))
        subject_ids.append(cur.lastrowid)

    for sid in subject_ids:
        cur.execute(
            "INSERT INTO class_subjects (class_id, subject_id, teacher_id) VALUES (?,?,?)",
            (class_id, sid, teacher_id),
        )

    students = [
        ("001", "Chinedu", "Obi", "M"),
        ("002", "Amaka", "Eze", "F"),
        ("003", "Tunde", "Bakare", "M"),
    ]
    for adm, fn, ln, g in students:
        cur.execute(
            "INSERT INTO students (school_id, tenant_id, admission_no, first_name, last_name, gender, class_id) VALUES (?,?,?,?,?,?,?)",
            (school_id, seed_tenant, adm, fn, ln, g, class_id),
        )
        cur.execute(
            "INSERT INTO enrollments (student_id, session_id, class_id) VALUES (?,?,?)",
            (cur.lastrowid, session_id, class_id),
        )

    conn.commit()


def grade_for(score, conn, school_id):
    row = conn.execute(
        "SELECT grade, remark FROM grade_scale WHERE school_id=? AND ? BETWEEN min_score AND max_score",
        (school_id, score),
    ).fetchone()
    if row:
        return row["grade"], row["remark"]
    return "-", "-"


CLASS_CATEGORIES = ["Science", "Arts", "Commercial"]
MATERIAL_KINDS = ["Notes", "Assignment", "Study Guide", "Other"]
STAFF_ATTENDANCE_STATUSES = ["Present", "Absent", "Late", "Leave"]

PDF_FONT_CHOICES = ["Helvetica", "Times-Roman", "Courier"]

# Per-school web UI font. "system" needs no external request; the rest are
# loaded from Google Fonts by the browser, keyed by the exact family+weight
# query string fonts.googleapis.com expects.
WEB_FONTS = {
    "system": {"label": "System Default", "google": None,
               "css": "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"},
    "inter": {"label": "Inter", "google": "Inter:wght@400;600;700", "css": "'Inter', sans-serif"},
    "roboto": {"label": "Roboto", "google": "Roboto:wght@400;500;700", "css": "'Roboto', sans-serif"},
    "merriweather": {"label": "Merriweather (serif)", "google": "Merriweather:wght@400;700", "css": "'Merriweather', serif"},
    "poppins": {"label": "Poppins", "google": "Poppins:wght@400;600;700", "css": "'Poppins', sans-serif"},
}


ACTIVATION_CODE_EXPIRY_HOURS = 48

# A short, practical list rather than the full IANA database — every school
# using this system today is in one of these zones. "Africa/Lagos" (WAT,
# UTC+1, no DST) is the default since the app originated in Nigeria.
TIMEZONE_CHOICES = [
    "Africa/Lagos", "Africa/Accra", "Africa/Abidjan", "Africa/Nairobi",
    "Africa/Cairo", "Africa/Johannesburg", "Africa/Kampala", "Africa/Kigali",
    "Africa/Casablanca", "Europe/London", "America/New_York", "Asia/Dubai",
]

RESULT_HEADER_LAYOUTS = [
    ("logo-left", "Logo on the left, name/details beside it"),
    ("logo-top-center", "Logo above the school name, both centred"),
    ("logo-right", "Logo on the right, name/details beside it"),
    ("no-logo", "No logo — text header only"),
]


def generate_activation_code(conn, school_id, created_by=None, expiry_hours=ACTIVATION_CODE_EXPIRY_HOURS):
    """Invalidates any still-valid code for this school and issues a new
    one — regenerating always supersedes the old code, per spec, rather
    than letting two codes be valid at once."""
    conn.execute(
        "UPDATE activation_codes SET invalidated=1 WHERE school_id=? AND used_at IS NULL AND invalidated=0",
        (school_id,),
    )
    code = f"{_secrets.randbelow(1000000):06d}"
    expires_at = (_dt.datetime.utcnow() + _dt.timedelta(hours=expiry_hours)).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO activation_codes (school_id, code, expires_at, created_by, max_usage, usage_count, status) VALUES (?,?,?,?,1,0,'active')",
        (school_id, code, expires_at, created_by),
    )
    return code, expires_at


def current_activation_code_status(conn, school_id):
    """The most recent code issued for a school, and whether it's still
    usable — used to show 'Activation-code status' on the Super Admin
    dashboard without exposing the code itself once issued."""
    row = conn.execute(
        "SELECT * FROM activation_codes WHERE school_id=? ORDER BY id DESC LIMIT 1", (school_id,)
    ).fetchone()
    if not row:
        return "none"
    if row["used_at"]:
        return "used"
    if row["invalidated"]:
        return "invalidated"
    if row["expires_at"] < _dt.datetime.utcnow().isoformat(timespec="seconds"):
        return "expired"
    return "valid"


def verify_activation_code(conn, school_id, submitted_code):
    """Single-use, time-limited, school-specific check. Returns (ok, reason)."""
    row = conn.execute(
        "SELECT * FROM activation_codes WHERE school_id=? AND used_at IS NULL AND invalidated=0 AND COALESCE(status,'active')='active' AND COALESCE(usage_count,0)<COALESCE(max_usage,1) "
        "ORDER BY id DESC LIMIT 1",
        (school_id,),
    ).fetchone()
    if not row:
        return False, "No active activation code for this school. Ask the Super Admin to issue one."
    if row["expires_at"] < _dt.datetime.utcnow().isoformat(timespec="seconds"):
        return False, "This activation code has expired. Ask the Super Admin to regenerate it."
    if submitted_code.strip() != row["code"]:
        return False, "Incorrect activation code."
    conn.execute("UPDATE activation_codes SET used_at=?,usage_count=1,status='exhausted' WHERE id=?",
                 (_dt.datetime.utcnow().isoformat(timespec="seconds"), row["id"]))
    return True, "ok"


def get_school(conn, school_id):
    return conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()


def grade_band_problems(conn, school_id, grade, min_score, max_score, exclude_id=None, exclude_uuid=None):
    """Reasons a grade band (e.g. "B", 60-69.99) must be refused. Shared by the
    online Grading screen and device edits. Overlapping bands are refused because
    a total falling in two bands would get whichever happened to be stored first."""
    problems = []
    grade = (grade or "").strip()
    if not grade:
        problems.append("A grade band needs a grade (e.g. A, B, C).")
    if len(grade) > 10:
        problems.append("The grade is too long (10 characters at most).")
    if min_score != min_score or max_score != max_score:
        return ["The scores must be numbers."]
    if min_score < 0 or max_score > 100:
        problems.append("Band limits must be between 0 and 100.")
    if min_score > max_score:
        problems.append("The lowest score can't be higher than the highest.")
    if problems:
        return problems
    rows = conn.execute("SELECT id, client_uuid, grade, min_score, max_score FROM grade_scale WHERE school_id=?", (school_id,)).fetchall()
    for r in rows:
        if (exclude_id is not None and r["id"] == exclude_id) or (exclude_uuid and r["client_uuid"] == exclude_uuid):
            continue
        if min_score <= r["max_score"] and r["min_score"] <= max_score:
            problems.append(f"This overlaps the existing band {r['grade']} ({r['min_score']:g}–{r['max_score']:g}).")
            break
    return problems


def grading_problems(conn, school_id, ca1, ca2, ca3, exam):
    """Reasons a proposed set of maximum marks must be refused (empty list = fine).
    Shared by the online Grading Setup screen and offline devices' settings
    edits, so both behave the same:
      - no negative maximums;
      - the maximums can't add up to more than 100 (a student could then score
        above 100, which no grade band covers);
      - a maximum can't be lowered below a mark already recorded in this school,
        which would leave saved scores that break the new rules."""
    problems = []
    vals = {"CA1": ca1, "CA2": ca2, "CA3": ca3, "Exam": exam}
    for label, v in vals.items():
        if v < 0:
            problems.append(f"{label} maximum can't be negative.")
    if problems:
        return problems
    total = ca1 + ca2 + ca3 + exam
    if total > 100.0001:
        problems.append(f"The maximums add up to {total:g}; they can't exceed 100.")
    cols = {"CA1": ("ca1", ca1), "CA2": ("ca2", ca2), "CA3": ("ca3", ca3), "Exam": ("exam", exam)}
    for label, (col, new_max) in cols.items():
        row = conn.execute(
            f"SELECT MAX(x.{col}) AS hi FROM scores x JOIN students s ON s.id = x.student_id "
            "JOIN classes c ON c.id = s.class_id WHERE c.school_id = ?", (school_id,)).fetchone()
        hi = row["hi"] if row and row["hi"] is not None else 0
        if hi > new_max:
            problems.append(f"{label} maximum can't be lowered to {new_max:g}: a saved score is already {hi:g}.")
    return problems


def recompute_attendance(conn, student_id, term_id):
    """Derives Days Open / Present / Absent for a student's term from their
    attendance_records and writes them into student_term_info, preserving
    any comments/signed dates already stored there. Present + Absent can
    never exceed Days Open here, since each date holds exactly one status."""
    row = conn.execute(
        "SELECT "
        "COUNT(*) AS opened, "
        "SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) AS present, "
        "SUM(CASE WHEN status='absent' THEN 1 ELSE 0 END) AS absent "
        "FROM attendance_records WHERE student_id=? AND term_id=?",
        (student_id, term_id),
    ).fetchone()
    opened = row["opened"] or 0
    present = row["present"] or 0
    absent = row["absent"] or 0
    conn.execute(
        "INSERT INTO student_term_info (student_id, term_id, days_present, days_absent, days_school_opened) "
        "VALUES (?,?,?,?,?) "
        "ON CONFLICT(student_id, term_id) DO UPDATE SET "
        "days_present=excluded.days_present, days_absent=excluded.days_absent, "
        "days_school_opened=excluded.days_school_opened",
        (student_id, term_id, present, absent, opened),
    )


def attendance_percentage(present, opened):
    if not opened:
        return 0.0
    return round((present / opened) * 100, 1)


# Comment banks are keyed by the school's own grade-scale "remark" (e.g.
# "Excellent", "Fail") so auto-generated comments always match whatever
# grading system (Nigerian, British, or custom) the school has configured
# — the same remark text that already drives per-subject grades.
# Auto-generated comments are intentionally brief, name-free, and mapped
# by the school's own grade-scale "remark" (e.g. "Excellent", "Fail") so
# they always match whatever grading system (Nigerian, British, or
# custom) the school has configured — the same remark text that already
# drives per-subject grades. The same short comment is used for both the
# teacher's and principal's remark; there's no separate "formal" register.
_COMMENT_BANK = {
    "excellent": "Excellent performance. Keep it up.",
    "very good": "Very good performance. Keep it up.",
    "good": "Good performance. More effort is encouraged.",
    "fair": "Satisfactory performance. There is room for improvement.",
    "pass": "Needs more effort and consistent study.",
    "fail": "Significant improvement is needed.",
}


def _bank_comment(remark, average, subjects_written):
    if not subjects_written:
        return "No scores recorded yet for this term."
    text = _COMMENT_BANK.get((remark or "").strip().lower())
    if text:
        return text
    if average >= 70:
        return _COMMENT_BANK["excellent"]
    if average >= 60:
        return _COMMENT_BANK["very good"]
    if average >= 50:
        return _COMMENT_BANK["good"]
    if average >= 45:
        return _COMMENT_BANK["fair"]
    if average >= 40:
        return _COMMENT_BANK["pass"]
    return _COMMENT_BANK["fail"]


def generate_teacher_comment(remark, average, subjects_written):
    return _bank_comment(remark, average, subjects_written)


def generate_principal_comment(remark, average, subjects_written):
    return _bank_comment(remark, average, subjects_written)


POSITION_LABELS = {
    "principal": "Principal",
    "vice_principal": "Vice Principal",
    "exam_officer": "Exam Officer",
    "subject_teacher": "Subject Teacher",
    "form_teacher": "Class Teacher / Form Teacher",
}

FULL_ACCESS_POSITIONS = {"principal", "vice_principal", "exam_officer"}

# Roles that can manage their school's setup (classes, subjects, teachers,
# grading, school profile, etc.) — sub_admin has all of this EXCEPT managing
# other admins/sub-admins, which is reserved for the main admin only.
SCHOOL_MANAGER_ROLES = {"admin", "sub_admin"}


def is_main_admin(role):
    return role == "admin"


def can_manage_school(role):
    return role in SCHOOL_MANAGER_ROLES


def form_teacher_class_ids(conn, user_id):
    rows = conn.execute("SELECT id FROM classes WHERE form_teacher_id=?", (user_id,)).fetchall()
    return [r["id"] for r in rows]


def can_view_all_results(role, position):
    return role in SCHOOL_MANAGER_ROLES or position in FULL_ACCESS_POSITIONS


def can_view_class_results(conn, role, position, user_id, class_id):
    if can_view_all_results(role, position):
        return True
    return class_id in form_teacher_class_ids(conn, user_id)


def notification_target_role(role):
    """Normalizes admin/sub_admin into one 'admin' targeting bucket, since
    a notification aimed at "admins" should reach both."""
    return "admin" if role in ("admin", "sub_admin") else role


def get_visible_notifications(conn, role, school_id, limit=50):
    target = notification_target_role(role)
    return conn.execute(
        "SELECT n.*, s.name as school_name FROM notifications n LEFT JOIN schools s ON s.id=n.school_id "
        "WHERE (n.school_id IS NULL OR n.school_id=?) AND (n.target_role='all' OR n.target_role=?) "
        "ORDER BY n.id DESC LIMIT ?",
        (school_id, target, limit),
    ).fetchall()


def get_unread_notification_count(conn, last_seen_id, role, school_id):
    target = notification_target_role(role)
    row = conn.execute(
        "SELECT COUNT(*) c FROM notifications WHERE id > ? AND (school_id IS NULL OR school_id=?) "
        "AND (target_role='all' OR target_role=?)",
        (last_seen_id or 0, school_id, target),
    ).fetchone()
    return row["c"]


def log_audit(conn, actor_type, actor_name, action, details=None, school_id=None):
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_name, school_id, action, details) VALUES (?,?,?,?,?)",
        (actor_type, actor_name, school_id, action, details),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Offline sync helpers — used by sync_api.py. Kept here alongside the rest
# of the data-access layer rather than duplicated in the blueprint.
# ---------------------------------------------------------------------------

# How long a device may go without ANY successful contact with the server
# before its offline credential stops working (a lost phone / departed staff
# member can't use it forever). Every successful sync or check slides it
# forward. Schools that work offline for long stretches can raise it:
#     OFFLINE_CREDENTIAL_DAYS=60
try:
    OFFLINE_CREDENTIAL_LIFETIME_DAYS = max(7, min(int(os.environ.get("OFFLINE_CREDENTIAL_DAYS", "30")), 365))
except ValueError:
    OFFLINE_CREDENTIAL_LIFETIME_DAYS = 30
OFFLINE_SESSION_MAX_HOURS = 12         # how long a decrypted offline unlock is trusted before re-entering the PIN


def new_client_uuid():
    return _secrets.token_hex(16)


def now_iso():
    return _dt.datetime.utcnow().isoformat(timespec="seconds")


def issue_device_credential(conn, school_id, user_id, role, position, device_label=None, device_id=None):
    """Called while the user has a normal, online, authenticated session
    (see /api/offline/enroll). Generates a random secret that the device
    will use to prove itself offline; only its hash is kept server-side, so
    a stolen database dump can't be replayed as a working offline
    credential. Returns the plaintext secret ONCE — the caller must return
    it to the device immediately; it is never retrievable again (only
    re-issuable via a fresh online enrollment)."""
    # Re-enrolling an existing device keeps its id, but ONLY for its owner. A
    # requested id that belongs to a different user or school is ignored and a
    # fresh one is issued — otherwise anyone who learned another device's id
    # could re-key it and act as that device's user.
    if device_id:
        existing = conn.execute(
            "SELECT school_id, user_id FROM device_credentials WHERE device_id=?", (device_id,)).fetchone()
        if existing and (existing["school_id"] != school_id or existing["user_id"] != user_id):
            device_id = None
    school = get_school(conn, school_id)
    if not school or not school["tenant_id"]:
        raise ValueError("School has no valid tenant identifier")
    tenant_id = school["tenant_id"]
    user = conn.execute("SELECT school_id, tenant_id, is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if not user or user["school_id"] != school_id or user["tenant_id"] != tenant_id or not user["is_active"]:
        raise ValueError("User and school tenant do not match")
    device_id = device_id or _secrets.token_hex(12)
    secret = _secrets.token_urlsafe(32)
    expires_at = (_dt.datetime.utcnow() + _dt.timedelta(days=OFFLINE_CREDENTIAL_LIFETIME_DAYS)).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO device_credentials "
        "(school_id, tenant_id, user_id, device_id, device_label, secret_hash, role_snapshot, position_snapshot, expires_at, last_verified_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(device_id) DO UPDATE SET secret_hash=excluded.secret_hash, "
        "role_snapshot=excluded.role_snapshot, position_snapshot=excluded.position_snapshot, "
        "expires_at=excluded.expires_at, revoked=0, revoked_reason=NULL, last_verified_at=excluded.last_verified_at "
        "WHERE device_credentials.user_id = excluded.user_id AND device_credentials.school_id = excluded.school_id",
        (school_id, tenant_id, user_id, device_id, device_label, _hash_device_secret(secret), role, position, expires_at, now_iso()),
    )
    # Keep the number of live devices per person bounded (a new browser or a
    # cleared profile enrols as a new device): beyond MAX_DEVICES_PER_USER the
    # least recently used ones are switched off.
    stale = conn.execute(
        "SELECT id FROM device_credentials WHERE user_id=? AND revoked=0 AND device_id != ? "
        "ORDER BY COALESCE(last_verified_at, issued_at) DESC LIMIT -1 OFFSET ?",
        (user_id, device_id, MAX_DEVICES_PER_USER - 1),
    ).fetchall()
    for r in stale:
        conn.execute("UPDATE device_credentials SET revoked=1, revoked_reason='replaced by newer devices' WHERE id=?", (r["id"],))
    conn.commit()
    return {"device_id": device_id, "secret": secret, "expires_at": expires_at}


MAX_DEVICES_PER_USER = 10


def _hash_device_secret(secret):
    """Device secrets are 256-bit random tokens, not human passwords, so a fast
    SHA-256 is as safe as a slow password hash - and it is checked on EVERY sync
    request, where scrypt would burn about a tenth of a second of server CPU
    per call. (Older credentials hashed with scrypt still verify.)"""
    import hashlib as _hl
    return "sha256$" + _hl.sha256(secret.encode()).hexdigest()


def _check_device_secret(stored, secret):
    if stored.startswith("sha256$"):
        import hashlib as _hl
        import hmac as _hm
        return _hm.compare_digest(stored[7:], _hl.sha256(secret.encode()).hexdigest())
    from werkzeug.security import check_password_hash as _check
    return _check(stored, secret)


def verify_device_credential(conn, device_id, secret):
    """Checks an offline credential presented by a device trying to sync or
    re-verify itself. Returns (status, credential_row_or_none).
    status is one of: 'ok', 'not_found', 'bad_secret', 'revoked', 'expired',
    'school_suspended', 'school_archived'. On 'ok', extends the credential's
    expiry (a sliding window — a device that keeps reconnecting periodically
    never has to fully re-enroll) and records last_verified_at."""
    cred = conn.execute("SELECT * FROM device_credentials WHERE device_id=?", (device_id,)).fetchone()
    if not cred:
        return "not_found", None
    if not _check_device_secret(cred["secret_hash"], secret):
        return "bad_secret", cred
    if cred["revoked"]:
        return "revoked", cred
    if cred["expires_at"] and cred["expires_at"] < now_iso():
        return "expired", cred
    school = get_school(conn, cred["school_id"])
    if not school or not school["tenant_id"] or cred["tenant_id"] != school["tenant_id"]:
        return "tenant_mismatch", cred
    user = conn.execute("SELECT school_id, tenant_id, is_active FROM users WHERE id=?", (cred["user_id"],)).fetchone()
    if not user or user["school_id"] != cred["school_id"] or user["tenant_id"] != cred["tenant_id"] or not user["is_active"]:
        return "revoked", cred
    if school and school["is_suspended"]:
        return "school_suspended", cred
    if school and school["is_archived"]:
        return "school_archived", cred
    if school and school["activation_status"] != "active":
        return "school_suspended", cred
    new_expiry = (_dt.datetime.utcnow() + _dt.timedelta(days=OFFLINE_CREDENTIAL_LIFETIME_DAYS)).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE device_credentials SET last_verified_at=?, expires_at=? WHERE id=?",
        (now_iso(), new_expiry, cred["id"]),
    )
    conn.commit()
    return "ok", cred


def revoke_device_credentials_for_user(conn, user_id, reason="revoked by admin"):
    conn.execute(
        "UPDATE device_credentials SET revoked=1, revoked_reason=? WHERE user_id=?",
        (reason, user_id),
    )
    conn.commit()


def revoke_device_credentials_for_school(conn, school_id, reason="school suspended"):
    conn.execute(
        "UPDATE device_credentials SET revoked=1, revoked_reason=? WHERE school_id=?",
        (reason, school_id),
    )
    conn.commit()


def record_sync_conflict(conn, school_id, entity, client_uuid, device_id, client_payload, server_payload):
    import json as _json
    conn.execute(
        "INSERT INTO sync_conflicts (school_id, entity, client_uuid, device_id, client_payload, server_payload) "
        "VALUES (?,?,?,?,?,?)",
        (school_id, entity, client_uuid, device_id,
         _json.dumps(client_payload, default=str), _json.dumps(server_payload, default=str)),
    )
    conn.commit()


def record_sync_log(conn, school_id, device_id, user_id, direction, entity, record_count=0, conflict_count=0, error_count=0):
    conn.execute(
        "INSERT INTO sync_log (school_id, device_id, user_id, direction, entity, record_count, conflict_count, error_count) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (school_id, device_id, user_id, direction, entity, record_count, conflict_count, error_count),
    )
    conn.commit()


def upsert_enrollment(conn, student_id, class_id):
    """Record that this student is in this class for their school's
    CURRENTLY ACTIVE session — used whenever a student is added to a class
    or promoted. Past sessions' enrollment rows are never touched, so
    historical broadsheets/results stay accurate."""
    row = conn.execute(
        "SELECT s.id FROM sessions s JOIN classes c ON c.school_id=s.school_id "
        "WHERE c.id=? AND s.is_active=1 LIMIT 1", (class_id,)
    ).fetchone()
    if not row:
        return
    conn.execute(
        "INSERT INTO enrollments (student_id, session_id, class_id) VALUES (?,?,?) "
        "ON CONFLICT(student_id, session_id) DO UPDATE SET class_id=excluded.class_id",
        (student_id, row["id"], class_id),
    )


def student_full_name(student):
    parts = [student["last_name"], student["first_name"]]
    if student["other_names"]:
        parts.append(student["other_names"])
    return " ".join(p for p in parts if p)



# V52 registration/security helpers
SIGNUP_CODE_TTL_HOURS = 72

def generate_signup_code(conn, code_type, school_id, created_by=None, class_id=None, student_id=None, max_usage=1, expires_hours=SIGNUP_CODE_TTL_HOURS):
    school = conn.execute("SELECT id, tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()
    if not school:
        raise ValueError("School not found")
    max_usage = max(1, min(int(max_usage or 1), 1000))
    code = _secrets.token_urlsafe(9).replace('-', '').replace('_', '').upper()[:12]
    while conn.execute("SELECT 1 FROM signup_codes WHERE code=?", (code,)).fetchone():
        code = _secrets.token_urlsafe(9).replace('-', '').replace('_', '').upper()[:12]
    session_id = None
    if class_id:
        row = conn.execute("SELECT school_id FROM classes WHERE id=?", (class_id,)).fetchone()
        if not row or row['school_id'] != school_id:
            raise ValueError("Class does not belong to this school")
        s = conn.execute("SELECT id FROM sessions WHERE school_id=? AND is_active=1 ORDER BY id DESC LIMIT 1", (school_id,)).fetchone()
        session_id = s['id'] if s else None
    expires = (_dt.datetime.utcnow() + _dt.timedelta(hours=expires_hours)).isoformat(timespec='seconds')
    conn.execute("INSERT INTO signup_codes(code,code_type,school_id,tenant_id,class_id,student_id,created_by,expires_at,max_usage,usage_count,status,session_id) VALUES(?,?,?,?,?,?,?,?,?,0,'active',?)",
                 (code, code_type, school_id, school['tenant_id'], class_id, student_id, created_by, expires, max_usage, session_id))
    return code, expires

def verify_signup_code(conn, code, code_type, school_id=None, class_id=None, student_id=None, consume=False):
    if not code:
        return None, "This signup code is required."
    row = conn.execute("SELECT * FROM signup_codes WHERE code=? AND code_type=?", (code, code_type)).fetchone()
    if not row:
        return None, "This signup code is invalid or expired."
    now = _dt.datetime.utcnow().isoformat(timespec='seconds')
    if row['status'] != 'active':
        return None, "This signup code is invalid or expired."
    if row['expires_at'] and row['expires_at'] < now:
        conn.execute("UPDATE signup_codes SET status='expired' WHERE id=?", (row['id'],))
        return None, "This signup code is invalid or expired."
    if int(row['usage_count'] or 0) >= int(row['max_usage'] or 1):
        conn.execute("UPDATE signup_codes SET status='exhausted' WHERE id=?", (row['id'],))
        return None, "This signup code has reached its registration limit."
    if school_id is not None and row['school_id'] != school_id:
        return None, "This signup code is invalid for this school."
    if class_id is not None and row['class_id'] != class_id:
        return None, "This signup code is not valid for this class."
    if student_id is not None and row['student_id'] not in (None, student_id):
        return None, "This signup code is not valid for this student."
    if row['class_id']:
        c = conn.execute("SELECT school_id,tenant_id,level,arm FROM classes WHERE id=?", (row['class_id'],)).fetchone()
        if not c or c['school_id'] != row['school_id'] or c['tenant_id'] != row['tenant_id']:
            return None, "This signup code is invalid."
    if consume:
        new_count = int(row['usage_count'] or 0) + 1
        status = 'exhausted' if new_count >= int(row['max_usage'] or 1) else 'active'
        conn.execute("UPDATE signup_codes SET usage_count=?,last_used_at=CURRENT_TIMESTAMP,status=? WHERE id=?", (new_count,status,row['id']))
    return row, None


def migration_052_auth_signup_audit_spec(conn):
    """V52 authentication/signup/linking/audit hardening.

    Idempotent additions only: existing academic records and RBAC remain intact.
    """
    for table, cols in {
        'schools': [('school_id_public','TEXT'), ('tenant_id','TEXT')],
        'users': [('tenant_id','TEXT'), ('account_status',"TEXT DEFAULT 'active'"), ('signup_status',"TEXT DEFAULT 'approved'"), ('activation_status',"TEXT DEFAULT 'active'"), ('first_login_required','INTEGER DEFAULT 0'), ('address','TEXT'), ('date_of_birth','TEXT'), ('gender','TEXT'), ('qualifications','TEXT')],
        'students': [('tenant_id','TEXT'), ('register_no','TEXT'), ('account_status',"TEXT DEFAULT 'active'"), ('signup_status',"TEXT DEFAULT 'not_started'")],
        'parent_accounts': [('account_status',"TEXT DEFAULT 'active'"), ('signup_status',"TEXT DEFAULT 'approved'")],
        'signup_codes': [('session_id','INTEGER'), ('class_arm','TEXT')],
        'audit_log': [('request_id','TEXT'), ('actor_user_id','INTEGER'), ('tenant_id','TEXT'), ('event_category','TEXT')],
    }.items():
        if table_exists(conn, table):
            for col, typ in cols: ensure_column(conn, table, col, typ)
    if table_exists(conn,'schools'):
        conn.execute("UPDATE schools SET school_id_public=school_code WHERE school_id_public IS NULL OR school_id_public='' ")
        conn.execute("UPDATE schools SET tenant_id=COALESCE(tenant_id, 'TEN-' || upper(hex(randomblob(6)))) WHERE tenant_id IS NULL OR tenant_id='' ")
    if table_exists(conn,'users') and table_exists(conn,'schools'):
        conn.execute("UPDATE users SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=users.school_id) WHERE tenant_id IS NULL OR tenant_id='' ")
    if table_exists(conn,'students'):
        conn.execute("UPDATE students SET tenant_id=(SELECT s.tenant_id FROM classes c JOIN schools s ON s.id=c.school_id WHERE c.id=students.class_id) WHERE tenant_id IS NULL OR tenant_id='' ")
        conn.execute("UPDATE students SET register_no=admission_no WHERE register_no IS NULL OR register_no='' ")
    conn.execute("""CREATE TABLE IF NOT EXISTS signups(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, signup_type TEXT NOT NULL,
        signup_status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
        verified_at TEXT, approved_at TEXT, rejected_at TEXT, correction_requested_at TEXT,
        school_id INTEGER, tenant_id TEXT, request_id TEXT, notes TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(school_id) REFERENCES schools(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signups_school_status ON signups(school_id,signup_status)")
    conn.execute("""CREATE TABLE IF NOT EXISTS activation_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, signup_id INTEGER, user_id INTEGER, school_id INTEGER, tenant_id TEXT,
        attempt_number INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL, failure_code TEXT,
        failure_message_internal TEXT, started_at TEXT DEFAULT CURRENT_TIMESTAMP, completed_at TEXT,
        retry_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, request_id TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS status_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL,
        status_type TEXT NOT NULL, previous_status TEXT, new_status TEXT NOT NULL, changed_by INTEGER,
        reason TEXT, school_id INTEGER, tenant_id TEXT, request_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS security_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_name TEXT NOT NULL, actor_user_id INTEGER,
        actor_role TEXT, actor_name TEXT, school_id INTEGER, tenant_id TEXT, resource_type TEXT,
        resource_id INTEGER, decision TEXT, details TEXT, request_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_school_time ON security_events(school_id,created_at)")
    # Standard tenant indexes and safe one-account-per-student guard.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_students_one_account ON students(user_id) WHERE user_id IS NOT NULL") if 'user_id' in column_names(conn,'students') else None
    # Student account ownership is represented by students.user_id in V52.
    if table_exists(conn,'students') and 'user_id' not in column_names(conn,'students'):
        ensure_column(conn,'students','user_id','INTEGER')
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_students_one_account ON students(user_id) WHERE user_id IS NOT NULL")
    if table_exists(conn,'signup_codes'):
        conn.execute("UPDATE signup_codes SET class_arm=(SELECT arm FROM classes WHERE classes.id=signup_codes.class_id) WHERE class_arm IS NULL AND class_id IS NOT NULL")


# v41 Parent Portal

def migration_050_parent_portal(conn):
    """Dedicated parent accounts, explicit parent-child links and scoped conversations.
    Parent accounts are deliberately separate from staff users so existing RBAC is untouched.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parent_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            last_notification_seen_id INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            UNIQUE(school_id, username)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parent_students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            verified_at TEXT,
            verified_by INTEGER,
            revoked_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(parent_id) REFERENCES parent_accounts(id) ON DELETE CASCADE,
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            UNIQUE(parent_id, student_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_parent_students_parent ON parent_students(parent_id, school_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_parent_students_student ON parent_students(student_id, school_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parent_teacher_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            parent_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            sender_type TEXT NOT NULL CHECK(sender_type IN ('parent','teacher')),
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            FOREIGN KEY(parent_id) REFERENCES parent_accounts(id) ON DELETE CASCADE,
            FOREIGN KEY(teacher_id) REFERENCES users(id),
            FOREIGN KEY(student_id) REFERENCES students(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_parent_messages_thread ON parent_teacher_messages(school_id,parent_id,teacher_id,student_id,created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_parent_messages_teacher ON parent_teacher_messages(school_id,teacher_id,is_read)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parent_consent_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            parent_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('granted','withdrawn')),
            policy_version TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id),
            FOREIGN KEY(parent_id) REFERENCES parent_accounts(id),
            FOREIGN KEY(student_id) REFERENCES students(id)
        )
    """)

STEPS.append(("parent_portal", migration_050_parent_portal))

STEPS.append(("registration_security_v52_finalize", migration_051_registration_security_spec))
STEPS.append(("auth_signup_audit_v52", migration_052_auth_signup_audit_spec))


def migration_053_school_auth_branding(conn):
    """Per-school authentication branding controls.

    Branding is intentionally stored on the school tenant and never accepted
    as a trusted client-supplied filename or tenant identity.
    """
    if not table_exists(conn, "schools"):
        return
    for col, typ in [
        ("auth_logo_opacity", "REAL NOT NULL DEFAULT 0.10"),
        ("auth_logo_position", "TEXT NOT NULL DEFAULT 'center'"),
        ("auth_background_style", "TEXT NOT NULL DEFAULT 'watermark'"),
        ("auth_show_school_name", "INTEGER NOT NULL DEFAULT 1"),
        ("auth_branding_enabled", "INTEGER NOT NULL DEFAULT 1"),
    ]:
        ensure_column(conn, "schools", col, typ)
    conn.execute("UPDATE schools SET auth_logo_opacity=MIN(MAX(COALESCE(auth_logo_opacity,0.10),0.03),0.35)")
    conn.execute("UPDATE schools SET auth_logo_position=CASE WHEN auth_logo_position IN ('left','center','right') THEN auth_logo_position ELSE 'center' END")
    conn.execute("UPDATE schools SET auth_background_style=CASE WHEN auth_background_style IN ('watermark','soft','plain') THEN auth_background_style ELSE 'watermark' END")
    conn.execute("UPDATE schools SET auth_show_school_name=CASE WHEN auth_show_school_name IN (0,1) THEN auth_show_school_name ELSE 1 END")
    conn.execute("UPDATE schools SET auth_branding_enabled=CASE WHEN auth_branding_enabled IN (0,1) THEN auth_branding_enabled ELSE 1 END")


STEPS.append(("school_auth_branding_v52", migration_053_school_auth_branding))

def migration_054_system_enhancements(conn):
    """V52 required system enhancements: upload limits, activation approvals,
    tenant-stamped students, result signature/name toggles and RBAC role labels."""
    if table_exists(conn,"schools"):
        for col,typ in [("registered_phone","TEXT"),("show_form_teacher_name","INTEGER DEFAULT 1"),("show_form_teacher_signature","INTEGER DEFAULT 1"),("show_principal_name","INTEGER DEFAULT 1"),("show_principal_signature","INTEGER DEFAULT 1")]: ensure_column(conn,"schools",col,typ)
    if table_exists(conn,"users"):
        ensure_column(conn,"users","rbac_role","TEXT")
        conn.execute("UPDATE users SET rbac_role=CASE position WHEN 'principal' THEN 'Principal' WHEN 'vice_principal' THEN 'Vice Principal' WHEN 'exam_officer' THEN 'Examination/Result Officer' WHEN 'form_teacher' THEN 'Form Teacher' WHEN 'subject_teacher' THEN 'Subject Teacher' ELSE 'Teacher' END WHERE role='teacher' AND (rbac_role IS NULL OR rbac_role='')")
    if table_exists(conn,"students"):
        ensure_column(conn,"students","school_id","INTEGER"); ensure_column(conn,"students","tenant_id","TEXT")
        conn.execute("UPDATE students SET school_id=(SELECT school_id FROM classes WHERE classes.id=students.class_id) WHERE school_id IS NULL")
        conn.execute("UPDATE students SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=students.school_id) WHERE tenant_id IS NULL OR tenant_id='' ")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_tenant_school ON students(school_id,tenant_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS platform_activation_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT, school_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
        submitted_at TEXT DEFAULT CURRENT_TIMESTAMP, approved_by TEXT, approved_at TEXT,
        activation_code_delivery_channel TEXT, activation_code_delivery_status TEXT, activation_code_sent_at TEXT,
        FOREIGN KEY(school_id) REFERENCES schools(id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_platform_activation_requests_status ON platform_activation_requests(status,submitted_at)")
    conn.execute("""CREATE TABLE IF NOT EXISTS platform_notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, message TEXT NOT NULL,
        school_id INTEGER, read_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_platform_notifications_created ON platform_notifications(created_at DESC)")

STEPS.append(("system_enhancements_v52", migration_054_system_enhancements))


def migration_055_online_stability(conn):
    """Online-first stability additions: staff attendance check-in/out timestamps
    and canonical Class Teacher / Form Teacher role naming. Offline sync keeps
    using the same tables and remains untouched."""
    if table_exists(conn, "staff_attendance"):
        ensure_column(conn, "staff_attendance", "check_in_at", "TEXT")
        ensure_column(conn, "staff_attendance", "check_out_at", "TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_attendance_staff_date ON staff_attendance(school_id,user_id,date)")
    if table_exists(conn, "users") and "rbac_role" in column_names(conn, "users"):
        conn.execute("UPDATE users SET rbac_role='Class Teacher / Form Teacher' WHERE rbac_role IN ('Form Teacher','Class Teacher')")
    if table_exists(conn, "role_assignments"):
        conn.execute("UPDATE role_assignments SET role='Class Teacher / Form Teacher' WHERE role IN ('Form Teacher','Class Teacher')")

STEPS.append(("online_first_stability_v55", migration_055_online_stability))



def migration_056_automated_timetable_v2(conn):
    """Replace the legacy timetable UI/data model with the tenant-scoped
    ScheduleSlot + TimetableEntry architecture described in the automated
    timetable specification. Legacy timetable tables are retained only for
    backwards/offline compatibility; v2 is the active online source of truth."""
    def tbl(sql): conn.execute(sql)
    # Default school days: these are structure, not lesson times, so creating
    # them does not recreate the old timetable.
    tbl("""CREATE TABLE IF NOT EXISTS school_days_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL,
        day_name TEXT NOT NULL, day_code TEXT NOT NULL, day_order INTEGER NOT NULL, is_active INTEGER NOT NULL DEFAULT 1,
        UNIQUE(tenant_id,school_id,day_code), FOREIGN KEY(school_id) REFERENCES schools(id))""")
    # Keep the specification's logical name while using _v2 physical names to
    # avoid destroying the legacy offline sync tables.
    for school in conn.execute("SELECT id,COALESCE(tenant_id,CAST(id AS TEXT)) tenant_id FROM schools").fetchall():
        for order,name,code in [(1,'Monday','MON'),(2,'Tuesday','TUE'),(3,'Wednesday','WED'),(4,'Thursday','THU'),(5,'Friday','FRI'),(6,'Saturday','SAT')]:
            conn.execute("INSERT OR IGNORE INTO school_days_v2(tenant_id,school_id,day_name,day_code,day_order,is_active) VALUES(?,?,?,?,?,?)",(school['tenant_id'],school['id'],name,code,order,1 if order<=5 else 0))
    tbl("""CREATE TABLE IF NOT EXISTS schedule_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL,
        academic_session_id INTEGER, term_id INTEGER, name TEXT NOT NULL, description TEXT,
        is_default INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(academic_session_id) REFERENCES sessions(id), FOREIGN KEY(term_id) REFERENCES terms(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS schedule_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL,
        academic_session_id INTEGER, term_id INTEGER, day_id INTEGER NOT NULL, schedule_template_id INTEGER NOT NULL,
        slot_number INTEGER NOT NULL, slot_name TEXT NOT NULL, slot_type TEXT NOT NULL DEFAULT 'TEACHING',
        start_time TEXT NOT NULL, end_time TEXT NOT NULL, duration_minutes INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1, is_fixed INTEGER NOT NULL DEFAULT 0, allows_timetable_entry INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        CHECK(slot_type IN ('TEACHING','BREAK','ASSEMBLY','ACTIVITY','OTHER')), CHECK(start_time < end_time),
        FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(day_id) REFERENCES school_days_v2(id), FOREIGN KEY(schedule_template_id) REFERENCES schedule_templates(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS class_subject_requirements_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL,
        academic_session_id INTEGER, term_id INTEGER, class_id INTEGER NOT NULL, arm_id INTEGER, subject_id INTEGER NOT NULL,
        periods_per_week INTEGER NOT NULL DEFAULT 1, periods_per_day_limit INTEGER NOT NULL DEFAULT 1,
        requires_double_period INTEGER NOT NULL DEFAULT 0, requires_triple_period INTEGER NOT NULL DEFAULT 0,
        preferred_period_type TEXT DEFAULT 'ANY', priority INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active',
        UNIQUE(tenant_id,school_id,class_id,subject_id), FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(class_id) REFERENCES classes(id), FOREIGN KEY(subject_id) REFERENCES subjects(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS teacher_availability_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, teacher_id INTEGER NOT NULL,
        day_id INTEGER NOT NULL, slot_id INTEGER NOT NULL, availability_status TEXT NOT NULL DEFAULT 'Available', reason TEXT,
        is_hard_constraint INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(tenant_id,school_id,teacher_id,day_id,slot_id), FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(teacher_id) REFERENCES users(id), FOREIGN KEY(day_id) REFERENCES school_days_v2(id), FOREIGN KEY(slot_id) REFERENCES schedule_slots(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS teacher_workload_profiles_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, teacher_id INTEGER NOT NULL,
        max_periods_per_day INTEGER NOT NULL DEFAULT 8, max_periods_per_week INTEGER NOT NULL DEFAULT 40,
        max_consecutive_periods INTEGER NOT NULL DEFAULT 4, preferred_free_periods INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active',
        UNIQUE(tenant_id,school_id,teacher_id), FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(teacher_id) REFERENCES users(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS teacher_timetable_preferences_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, teacher_id INTEGER NOT NULL,
        day_id INTEGER NOT NULL, slot_id INTEGER NOT NULL, preference_type TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 1, reason TEXT,
        FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(teacher_id) REFERENCES users(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS class_timetable_preferences_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, class_id INTEGER NOT NULL, arm_id INTEGER,
        subject_id INTEGER, preferred_days TEXT, preferred_slots TEXT, avoid_days TEXT, avoid_slots TEXT,
        max_subject_periods_per_day INTEGER, status TEXT NOT NULL DEFAULT 'active', FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(class_id) REFERENCES classes(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_rooms_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, room_name TEXT NOT NULL,
        room_code TEXT, room_type TEXT NOT NULL DEFAULT 'ROOM', capacity INTEGER DEFAULT 0, building TEXT, floor TEXT, status TEXT NOT NULL DEFAULT 'active',
        UNIQUE(tenant_id,school_id,room_name), FOREIGN KEY(school_id) REFERENCES schools(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS subject_room_requirements_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, subject_id INTEGER NOT NULL, room_id INTEGER NOT NULL,
        requirement_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', UNIQUE(tenant_id,school_id,subject_id,room_id),
        FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(subject_id) REFERENCES subjects(id), FOREIGN KEY(room_id) REFERENCES timetable_rooms_v2(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS fixed_activities_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, academic_session_id INTEGER, term_id INTEGER,
        activity_name TEXT NOT NULL, activity_type TEXT NOT NULL, day_id INTEGER NOT NULL, slot_id INTEGER NOT NULL,
        class_id INTEGER, arm_id INTEGER, teacher_id INTEGER, room_id INTEGER, is_mandatory INTEGER DEFAULT 1, is_immovable INTEGER DEFAULT 1,
        FOREIGN KEY(school_id) REFERENCES schools(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_configurations_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, academic_session_id INTEGER, term_id INTEGER,
        allow_double_periods INTEGER DEFAULT 1, allow_triple_periods INTEGER DEFAULT 0, allow_same_subject_same_day INTEGER DEFAULT 1,
        max_same_subject_per_day INTEGER DEFAULT 2, max_teacher_consecutive_periods INTEGER DEFAULT 4, balance_teacher_workload INTEGER DEFAULT 1,
        spread_subjects INTEGER DEFAULT 1, minimize_class_gaps INTEGER DEFAULT 1, prefer_morning_subjects INTEGER DEFAULT 0, solver_time_limit INTEGER DEFAULT 30,
        status TEXT DEFAULT 'active', UNIQUE(tenant_id,school_id,academic_session_id,term_id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_types_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, name TEXT NOT NULL, type_code TEXT NOT NULL,
        description TEXT, status TEXT DEFAULT 'active', UNIQUE(tenant_id,school_id,type_code), FOREIGN KEY(school_id) REFERENCES schools(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_versions_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, academic_session_id INTEGER, term_id INTEGER,
        timetable_type_id INTEGER, version_number INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'DRAFT', validation_status TEXT NOT NULL DEFAULT 'PENDING',
        is_current INTEGER DEFAULT 1, parent_version_id INTEGER, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_by INTEGER, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        submitted_by INTEGER, submitted_at TEXT, published_by INTEGER, published_at TEXT, archived_at TEXT, revision_reason TEXT,
        UNIQUE(tenant_id,school_id,version_number), FOREIGN KEY(school_id) REFERENCES schools(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_entries_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, timetable_version_id INTEGER NOT NULL,
        day_id INTEGER NOT NULL, slot_id INTEGER NOT NULL, class_id INTEGER NOT NULL, arm_id INTEGER, subject_id INTEGER NOT NULL,
        teacher_id INTEGER, room_id INTEGER, entry_type TEXT NOT NULL DEFAULT 'LESSON', block_group_id TEXT, is_fixed INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(timetable_version_id,day_id,slot_id,class_id), FOREIGN KEY(school_id) REFERENCES schools(id), FOREIGN KEY(timetable_version_id) REFERENCES timetable_versions_v2(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_conflicts_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, timetable_version_id INTEGER NOT NULL,
        conflict_type TEXT NOT NULL, severity TEXT NOT NULL, entity_type TEXT, entity_id INTEGER, description TEXT NOT NULL, suggested_action TEXT,
        resolved INTEGER NOT NULL DEFAULT 0, resolved_by INTEGER, resolved_at TEXT, FOREIGN KEY(school_id) REFERENCES schools(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_approvals_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, timetable_version_id INTEGER NOT NULL,
        approval_level INTEGER NOT NULL, assigned_role TEXT NOT NULL, assigned_user_id INTEGER, status TEXT NOT NULL DEFAULT 'pending', decision TEXT,
        comment TEXT, decided_by INTEGER, decided_at TEXT, FOREIGN KEY(school_id) REFERENCES schools(id))""")
    tbl("""CREATE TABLE IF NOT EXISTS timetable_audit_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, school_id INTEGER NOT NULL, timetable_version_id INTEGER, user_id INTEGER,
        role TEXT, action TEXT NOT NULL, previous_status TEXT, new_status TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(school_id) REFERENCES schools(id))""")
    # Seed one timetable type and configuration per school, but no lesson slots.
    for school in conn.execute("SELECT id,COALESCE(tenant_id,CAST(id AS TEXT)) tenant_id FROM schools").fetchall():
        conn.execute("INSERT OR IGNORE INTO timetable_types_v2(tenant_id,school_id,name,type_code,description) VALUES(?,?,?,?,?)",(school['tenant_id'],school['id'],'Regular Academic Timetable','REGULAR','Standard academic timetable'))
        conn.execute("INSERT OR IGNORE INTO timetable_configurations_v2(tenant_id,school_id,allow_double_periods,allow_triple_periods,balance_teacher_workload,spread_subjects,minimize_class_gaps) VALUES(?,?,?,?,?,?,?)",(school['tenant_id'],school['id'],1,0,1,1,1))
        for row in conn.execute("SELECT id,name FROM classes WHERE school_id=?",(school['id'],)).fetchall():
            for cs in conn.execute("SELECT subject_id,teacher_id FROM class_subjects WHERE class_id=?",(row['id'],)).fetchall():
                conn.execute("INSERT OR IGNORE INTO class_subject_requirements_v2(tenant_id,school_id,class_id,arm_id,subject_id,periods_per_week,periods_per_day_limit,status) VALUES(?,?,?,?,?,?,?,'active')",(school['tenant_id'],school['id'],row['id'],row['id'],cs['subject_id'],1,1))
                if cs['teacher_id']:
                    conn.execute("INSERT OR IGNORE INTO teacher_workload_profiles_v2(tenant_id,school_id,teacher_id) VALUES(?,?,?)",(school['tenant_id'],school['id'],cs['teacher_id']))
    # Make all new timetable entities syncable for the future offline/sync phase.
    for t in ["school_days_v2","schedule_templates","schedule_slots","class_subject_requirements_v2","teacher_availability_v2","teacher_workload_profiles_v2","teacher_timetable_preferences_v2","class_timetable_preferences_v2","timetable_rooms_v2","subject_room_requirements_v2","fixed_activities_v2","timetable_configurations_v2","timetable_types_v2","timetable_versions_v2","timetable_entries_v2","timetable_conflicts_v2","timetable_approvals_v2","timetable_audit_v2"]:
        try: _make_syncable(conn,t)
        except Exception: pass

STEPS.append(("automated_timetable_v2", migration_056_automated_timetable_v2))

def migration_057_staff_profile_documents(conn):
    """Store the exact staff signup name parts and tenant-scoped staff documents.
    Existing users retain their legacy `name` value and are backfilled safely.
    """
    ensure_column(conn, "users", "first_name", "TEXT")
    ensure_column(conn, "users", "surname", "TEXT")
    ensure_column(conn, "users", "other_names", "TEXT")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS staff_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            mime_type TEXT,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, stored_filename)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_documents_tenant_user ON staff_documents(tenant_id,school_id,user_id)")
    rows=conn.execute("SELECT id,name FROM users WHERE first_name IS NULL OR surname IS NULL OR first_name='' OR surname='' ").fetchall()
    for r in rows:
        parts=(r["name"] or "").split()
        if not parts: continue
        first=parts[0]; surname=parts[-1] if len(parts)>1 else parts[0]; other=" ".join(parts[1:-1]) if len(parts)>2 else None
        conn.execute("UPDATE users SET first_name=COALESCE(NULLIF(first_name,''),?), surname=COALESCE(NULLIF(surname,''),?), other_names=COALESCE(NULLIF(other_names,''),?) WHERE id=?",(first,surname,other,r["id"]))

STEPS.append(("staff_profile_documents_v57", migration_057_staff_profile_documents))


def migration_058_runtime_schema_repair(conn):
    """Repair critical online schemas when schema_steps says a migration ran
    but a table/column was lost or an older deployment left a partial schema.
    This is deliberately additive: it never drops or deletes existing data.
    """
    if table_exists(conn, "schools"):
        for col, typ in [
            ("tenant_id", "TEXT"), ("school_code", "TEXT"), ("registered_email", "TEXT"), ("registered_phone", "TEXT"),
            ("cumulative_enabled", "INTEGER DEFAULT 0"), ("theme_preset", "TEXT NOT NULL DEFAULT 'default'"),
            ("dashboard_primary_color", "TEXT NOT NULL DEFAULT '#1f6feb'"),
            ("dashboard_secondary_color", "TEXT NOT NULL DEFAULT '#0b3b75'"),
            ("dashboard_accent_color", "TEXT NOT NULL DEFAULT '#7c4dff'"),
            ("dashboard_sidebar_style", "TEXT NOT NULL DEFAULT 'dark'"),
            ("dashboard_header_style", "TEXT NOT NULL DEFAULT 'solid'"),
            ("school_tagline", "TEXT"), ("result_accent_color", "TEXT DEFAULT '#1f3a5f'"),
            ("result_header_layout", "TEXT DEFAULT 'logo-left'"), ("web_font", "TEXT DEFAULT 'system'"),
            ("pdf_font", "TEXT DEFAULT 'Helvetica'"), ("show_result_date", "INTEGER DEFAULT 1"),
            ("auto_teacher_comment", "INTEGER DEFAULT 0"), ("auto_principal_comment", "INTEGER DEFAULT 0"),
            ("auth_logo_opacity", "REAL NOT NULL DEFAULT 0.10"), ("auth_logo_position", "TEXT NOT NULL DEFAULT 'center'"),
            ("auth_background_style", "TEXT NOT NULL DEFAULT 'watermark'"), ("auth_show_school_name", "INTEGER NOT NULL DEFAULT 1"),
            ("auth_branding_enabled", "INTEGER NOT NULL DEFAULT 1"), ("show_form_teacher_name", "INTEGER DEFAULT 1"),
            ("show_form_teacher_signature", "INTEGER DEFAULT 1"), ("show_principal_name", "INTEGER DEFAULT 1"),
            ("show_principal_signature", "INTEGER DEFAULT 1"), ("activation_status", "TEXT DEFAULT 'active'"),
            ("readiness_status", "TEXT NOT NULL DEFAULT 'pending'"), ("ready_at", "TEXT"), ("ready_by", "INTEGER"),
            ("readiness_version", "INTEGER NOT NULL DEFAULT 1"),
            ("is_suspended", "INTEGER DEFAULT 0"), ("is_archived", "INTEGER DEFAULT 0"), ("force_logout_at", "TEXT"),
        ]:
            ensure_column(conn, "schools", col, typ)
        conn.execute("UPDATE schools SET tenant_id=COALESCE(NULLIF(tenant_id,''),CAST(id AS TEXT)) WHERE tenant_id IS NULL OR tenant_id='' ")

    if table_exists(conn, "users"):
        ensure_column(conn, "users", "tenant_id", "TEXT")
        conn.execute("UPDATE users SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=users.school_id) WHERE tenant_id IS NULL OR tenant_id='' ")

    # Ensure the active v2 timetable tables exist. migration_056 is idempotent.
    critical = ["school_days_v2", "schedule_templates", "schedule_slots", "timetable_versions_v2", "timetable_entries_v2"]
    if any(not table_exists(conn, t) for t in critical):
        migration_056_automated_timetable_v2(conn)

    # Repair partial/older timetable tables without deleting existing rows.
    if table_exists(conn, "school_days_v2"):
        for col, typ in [("tenant_id", "TEXT"), ("school_id", "INTEGER"), ("day_name", "TEXT"), ("day_code", "TEXT"), ("day_order", "INTEGER"), ("is_active", "INTEGER DEFAULT 1")]:
            ensure_column(conn, "school_days_v2", col, typ)
        for school in conn.execute("SELECT id,COALESCE(tenant_id,CAST(id AS TEXT)) tenant_id FROM schools").fetchall():
            for order,name,code in [(1,'Monday','MON'),(2,'Tuesday','TUE'),(3,'Wednesday','WED'),(4,'Thursday','THU'),(5,'Friday','FRI'),(6,'Saturday','SAT')]:
                conn.execute("INSERT OR IGNORE INTO school_days_v2(tenant_id,school_id,day_name,day_code,day_order,is_active) VALUES(?,?,?,?,?,?)",(school['tenant_id'],school['id'],name,code,order,1 if order<=5 else 0))

    if table_exists(conn, "schedule_templates"):
        for col, typ in [("tenant_id","TEXT"),("school_id","INTEGER"),("academic_session_id","INTEGER"),("term_id","INTEGER"),("name","TEXT"),("description","TEXT"),("is_default","INTEGER DEFAULT 0"),("status","TEXT DEFAULT 'active'")]:
            ensure_column(conn, "schedule_templates", col, typ)
    if table_exists(conn, "schedule_slots"):
        for col, typ in [
            ("tenant_id","TEXT"),("school_id","INTEGER"),("academic_session_id","INTEGER"),("term_id","INTEGER"),
            ("day_id","INTEGER"),("schedule_template_id","INTEGER"),("slot_number","INTEGER DEFAULT 0"),
            ("slot_name","TEXT"),("slot_type","TEXT DEFAULT 'TEACHING'"),("start_time","TEXT"),("end_time","TEXT"),
            ("duration_minutes","INTEGER DEFAULT 0"),("is_active","INTEGER DEFAULT 1"),("is_fixed","INTEGER DEFAULT 0"),
            ("allows_timetable_entry","INTEGER DEFAULT 1")]:
            ensure_column(conn, "schedule_slots", col, typ)

STEPS.append(("runtime_schema_repair_v58", migration_058_runtime_schema_repair))



# ---------------------------------------------------------------------------
# V60: profiles, uniqueness, custom fields, protected audit history
# ---------------------------------------------------------------------------

def _create_unique_index_if_safe(conn, name, table, columns_sql, where_sql, dup_sql):
    """Create a unique index only when existing data already satisfies it, so an
    upgrade can never fail on a live database. When old duplicates exist the index is
    skipped, the skip is recorded in migration_notes, and the application-level checks
    still block every new duplicate."""
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", (name,)).fetchone():
        return True
    if conn.execute(dup_sql).fetchone():
        conn.execute("CREATE TABLE IF NOT EXISTS migration_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        conn.execute("INSERT INTO migration_notes(note) VALUES (?)", (f"Unique index {name} skipped: existing duplicate rows must be resolved first.",))
        return False
    conn.execute(f"CREATE UNIQUE INDEX {name} ON {table}({columns_sql}) WHERE {where_sql}")
    return True


def migration_059_profiles_customfields(conn):
    # ---- student profile columns ------------------------------------------------
    for col, typ in [("email", "TEXT"), ("state", "TEXT"), ("lga", "TEXT"), ("tribe", "TEXT"),
                     ("date_of_admission", "TEXT"), ("address", "TEXT"), ("profile_updated_at", "TEXT")]:
        ensure_column(conn, "students", col, typ)
    # ---- staff profile columns --------------------------------------------------
    for col, typ in [("state", "TEXT"), ("lga", "TEXT"), ("staff_id", "TEXT"), ("subjects_taught", "TEXT"),
                     ("profile_updated_at", "TEXT"), ("signup_name", "TEXT")]:
        ensure_column(conn, "users", col, typ)
    # The name given at signup is the initial identity record: filled once, never overwritten.
    conn.execute("UPDATE users SET signup_name=name WHERE signup_name IS NULL OR signup_name=''")
    conn.execute("DROP TRIGGER IF EXISTS trg_users_signup_name_init")
    conn.execute("""CREATE TRIGGER trg_users_signup_name_init AFTER INSERT ON users FOR EACH ROW
                    WHEN NEW.signup_name IS NULL OR NEW.signup_name=''
                    BEGIN UPDATE users SET signup_name=NEW.name WHERE id=NEW.id; END""")
    conn.execute("DROP TRIGGER IF EXISTS trg_users_signup_name_lock")
    conn.execute("""CREATE TRIGGER trg_users_signup_name_lock BEFORE UPDATE OF signup_name ON users FOR EACH ROW
                    WHEN OLD.signup_name IS NOT NULL AND OLD.signup_name<>'' AND NEW.signup_name IS NOT OLD.signup_name
                    BEGIN SELECT RAISE(ABORT,'The signup name is a permanent identity record'); END""")
    # ---- tenant backfill for legacy students (seeded/imported before tenant stamping) ----
    conn.execute("""UPDATE students SET school_id=(SELECT c.school_id FROM classes c WHERE c.id=students.class_id)
                    WHERE school_id IS NULL""")
    conn.execute("""UPDATE students SET tenant_id=(SELECT s.tenant_id FROM schools s WHERE s.id=students.school_id)
                    WHERE (tenant_id IS NULL OR tenant_id='') AND school_id IS NOT NULL""")
    conn.execute("""UPDATE schools SET tenant_id=CAST(id AS TEXT) WHERE tenant_id IS NULL OR tenant_id=''""")
    conn.execute("""UPDATE users SET tenant_id=(SELECT tenant_id FROM schools WHERE schools.id=users.school_id)
                    WHERE tenant_id IS NULL OR tenant_id=''""")
    conn.execute("""UPDATE students SET tenant_id=(SELECT s.tenant_id FROM schools s WHERE s.id=students.school_id)
                    WHERE (tenant_id IS NULL OR tenant_id='') AND school_id IS NOT NULL""")

    # ---- database-level uniqueness (tenant-aware, case-insensitive) -------------
    _create_unique_index_if_safe(
        conn, "ux_students_school_admission", "students", "school_id, LOWER(TRIM(admission_no))",
        "admission_no IS NOT NULL AND school_id IS NOT NULL",
        "SELECT 1 FROM students WHERE admission_no IS NOT NULL AND school_id IS NOT NULL "
        "GROUP BY school_id, LOWER(TRIM(admission_no)) HAVING COUNT(*)>1 LIMIT 1")
    _create_unique_index_if_safe(
        conn, "ux_students_school_email", "students", "school_id, LOWER(email)",
        "email IS NOT NULL AND email<>'' AND school_id IS NOT NULL",
        "SELECT 1 FROM students WHERE email IS NOT NULL AND email<>'' AND school_id IS NOT NULL "
        "GROUP BY school_id, LOWER(email) HAVING COUNT(*)>1 LIMIT 1")
    _create_unique_index_if_safe(
        conn, "ux_users_lower_email", "users", "LOWER(email)",
        "email IS NOT NULL AND email<>''",
        "SELECT 1 FROM users WHERE email IS NOT NULL AND email<>'' GROUP BY LOWER(email) HAVING COUNT(*)>1 LIMIT 1")
    _create_unique_index_if_safe(
        conn, "ux_users_lower_username", "users", "LOWER(username)",
        "username IS NOT NULL",
        "SELECT 1 FROM users WHERE username IS NOT NULL GROUP BY LOWER(username) HAVING COUNT(*)>1 LIMIT 1")
    _create_unique_index_if_safe(
        conn, "ux_users_school_staff_id", "users", "school_id, LOWER(staff_id)",
        "staff_id IS NOT NULL AND staff_id<>''",
        "SELECT 1 FROM users WHERE staff_id IS NOT NULL AND staff_id<>'' GROUP BY school_id, LOWER(staff_id) HAVING COUNT(*)>1 LIMIT 1")

    # ---- triggers: tenant stamping + school-wide admission-number uniqueness on EVERY write path ----
    # (CSV imports and older code paths insert without school_id; these triggers cover them too.
    #  SQLite serialises writers, so the check and the insert cannot race.)
    for t in ("trg_students_stamp_tenant", "trg_students_admission_unique_ins", "trg_students_admission_unique_upd"):
        conn.execute(f"DROP TRIGGER IF EXISTS {t}")
    conn.execute("""CREATE TRIGGER trg_students_stamp_tenant AFTER INSERT ON students FOR EACH ROW
        WHEN NEW.school_id IS NULL OR NEW.tenant_id IS NULL OR NEW.tenant_id=''
        BEGIN
          UPDATE students SET school_id=(SELECT school_id FROM classes WHERE id=NEW.class_id),
                              tenant_id=(SELECT sc.tenant_id FROM classes c JOIN schools sc ON sc.id=c.school_id WHERE c.id=NEW.class_id)
          WHERE id=NEW.id;
        END""")
    dup_check = """EXISTS (SELECT 1 FROM students s JOIN classes c ON c.id=s.class_id
                     WHERE c.school_id=(SELECT school_id FROM classes WHERE id=NEW.class_id)
                       AND LOWER(TRIM(s.admission_no))=LOWER(TRIM(NEW.admission_no)){self_clause})"""
    conn.execute("""CREATE TRIGGER trg_students_admission_unique_ins BEFORE INSERT ON students FOR EACH ROW
        WHEN NEW.admission_no IS NOT NULL AND """ + dup_check.format(self_clause="") + """
        BEGIN SELECT RAISE(ABORT,'Admission No. / Register No. already exists in this school'); END""")
    conn.execute("""CREATE TRIGGER trg_students_admission_unique_upd BEFORE UPDATE OF admission_no, class_id ON students FOR EACH ROW
        WHEN NEW.admission_no IS NOT NULL AND """ + dup_check.format(self_clause=" AND s.id<>OLD.id") + """
        BEGIN SELECT RAISE(ABORT,'Admission No. / Register No. already exists in this school'); END""")
    # Staff username / email / staff-id: case-insensitive, database-enforced on every write path.
    for t in ("trg_users_identity_unique_ins", "trg_users_identity_unique_upd"):
        conn.execute(f"DROP TRIGGER IF EXISTS {t}")
    conn.execute("""CREATE TRIGGER trg_users_identity_unique_ins BEFORE INSERT ON users FOR EACH ROW
        WHEN (NEW.email IS NOT NULL AND NEW.email<>'' AND EXISTS(SELECT 1 FROM users WHERE LOWER(email)=LOWER(NEW.email)))
          OR (NEW.staff_id IS NOT NULL AND NEW.staff_id<>'' AND EXISTS(SELECT 1 FROM users WHERE school_id=NEW.school_id AND LOWER(staff_id)=LOWER(NEW.staff_id)))
          OR EXISTS(SELECT 1 FROM users WHERE LOWER(username)=LOWER(NEW.username))
        BEGIN SELECT RAISE(ABORT,'Username, email or Staff ID already exists'); END""")
    conn.execute("""CREATE TRIGGER trg_users_identity_unique_upd BEFORE UPDATE OF username, email, staff_id ON users FOR EACH ROW
        WHEN (NEW.email IS NOT NULL AND NEW.email<>'' AND EXISTS(SELECT 1 FROM users WHERE id<>OLD.id AND LOWER(email)=LOWER(NEW.email)))
          OR (NEW.staff_id IS NOT NULL AND NEW.staff_id<>'' AND EXISTS(SELECT 1 FROM users WHERE id<>OLD.id AND school_id=NEW.school_id AND LOWER(staff_id)=LOWER(NEW.staff_id)))
          OR EXISTS(SELECT 1 FROM users WHERE id<>OLD.id AND LOWER(username)=LOWER(NEW.username))
        BEGIN SELECT RAISE(ABORT,'Username, email or Staff ID already exists'); END""")

    # ---- custom fields -----------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            applies_to TEXT NOT NULL CHECK (applies_to IN ('student','staff')),
            field_key TEXT NOT NULL,
            label TEXT NOT NULL,
            description TEXT,
            field_type TEXT NOT NULL,
            is_required INTEGER NOT NULL DEFAULT 0,
            is_unique INTEGER NOT NULL DEFAULT 0,
            is_editable INTEGER NOT NULL DEFAULT 1,
            default_value TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            is_archived INTEGER NOT NULL DEFAULT 0,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_by INTEGER, created_by_name TEXT,
            updated_by INTEGER, updated_by_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (school_id, applies_to, field_key)
        )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_custom_fields_label ON custom_fields(school_id, applies_to, LOWER(label)) WHERE is_archived=0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_custom_fields_scope ON custom_fields(school_id, tenant_id, applies_to)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_field_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            field_id INTEGER NOT NULL,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            option_value TEXT NOT NULL,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE (field_id, option_value)
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_field_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            field_id INTEGER NOT NULL,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            entity_type TEXT NOT NULL CHECK (entity_type IN ('student','staff')),
            entity_id INTEGER NOT NULL,
            value TEXT,
            unique_value TEXT,
            updated_by INTEGER,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (field_id, entity_id)
        )""")
    # DB-level enforcement of "Unique" custom fields: unique_value is only filled for unique fields.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_custom_values_unique ON custom_field_values(field_id, unique_value) WHERE unique_value IS NOT NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_custom_values_entity ON custom_field_values(school_id, entity_type, entity_id)")

    # ---- protected audit history --------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rbac_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            actor_type TEXT, actor_id INTEGER, actor_name TEXT, actor_role TEXT,
            school_id INTEGER, tenant_id TEXT,
            action TEXT NOT NULL,
            entity_type TEXT, entity_id TEXT,
            changes TEXT,
            ip_address TEXT
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rbac_audit_school ON rbac_audit_log(school_id, created_at)")
    for t in ("rbac_audit_log", "audit_log", "role_assignment_audit", "security_events"):
        if not table_exists(conn, t):
            continue
        conn.execute(f"DROP TRIGGER IF EXISTS trg_{t}_no_update")
        conn.execute(f"DROP TRIGGER IF EXISTS trg_{t}_no_delete")
        conn.execute(f"CREATE TRIGGER trg_{t}_no_update BEFORE UPDATE ON {t} BEGIN SELECT RAISE(ABORT,'Audit history is append-only'); END")
        conn.execute(f"CREATE TRIGGER trg_{t}_no_delete BEFORE DELETE ON {t} BEGIN SELECT RAISE(ABORT,'Audit history is append-only'); END")

    # ---- retire offline-only data --------------------------------------------------
    # Device credentials let a phone unlock the retired offline app; none may remain valid.
    if table_exists(conn, "device_credentials"):
        conn.execute("DELETE FROM device_credentials")


STEPS.append(("profiles_customfields_v60", migration_059_profiles_customfields))


# ---------------------------------------------------------------------------
# V61: class login codes, score audit, staff name history, result-sheet settings,
#      configurable educational domains, auto term/session, subscription history
# ---------------------------------------------------------------------------

def migration_060_v61(conn):
    # ---- students: first-login + lockout tracking -------------------------------
    for col, typ in [("first_login_completed_at", "TEXT"), ("failed_logins", "INTEGER DEFAULT 0"),
                     ("locked_until", "TEXT"), ("username_changed_at", "TEXT"), ("last_login_at", "TEXT")]:
        ensure_column(conn, "students", col, typ)
    # Students who already have a working account are not sent back through the class-code step.
    conn.execute("""UPDATE students SET first_login_completed_at=COALESCE(first_login_completed_at,CURRENT_TIMESTAMP)
                    WHERE password_hash IS NOT NULL AND password_hash<>'' AND first_login_completed_at IS NULL""")

    # ---- class login codes -----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS class_login_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            class_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','rotated','expired')),
            expires_at TEXT,
            created_by INTEGER, created_by_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            ended_at TEXT, ended_by INTEGER, ended_by_name TEXT, end_reason TEXT,
            use_count INTEGER NOT NULL DEFAULT 0
        )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_class_login_codes_code ON class_login_codes(code)")
    # One live code per class: a new code must retire the old one first.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_class_login_codes_one_active ON class_login_codes(class_id) WHERE status='active'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_class_login_codes_school ON class_login_codes(school_id, class_id)")

    # ---- staff name history ----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS staff_name_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL, tenant_id TEXT NOT NULL, user_id INTEGER NOT NULL,
            previous_first_name TEXT, previous_surname TEXT, previous_other_names TEXT, previous_name TEXT,
            new_first_name TEXT, new_surname TEXT, new_other_names TEXT, new_name TEXT,
            changed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            changed_by INTEGER, changed_by_name TEXT, admin_notified INTEGER NOT NULL DEFAULT 0
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_staff_name_history_user ON staff_name_history(school_id, user_id)")

    # ---- score audit (complete, append-only) -------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS score_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL, tenant_id TEXT NOT NULL,
            student_id INTEGER NOT NULL, student_name TEXT, admission_no TEXT,
            subject_id INTEGER NOT NULL, subject_name TEXT,
            class_id INTEGER, class_name TEXT,
            session_id INTEGER, session_name TEXT, term_id INTEGER NOT NULL, term_name TEXT,
            old_ca1 REAL, old_ca2 REAL, old_ca3 REAL, old_exam REAL, old_total REAL,
            new_ca1 REAL, new_ca2 REAL, new_ca3 REAL, new_exam REAL, new_total REAL,
            difference REAL,
            changed_by INTEGER, changed_by_name TEXT, changed_by_role TEXT,
            changed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            result_status TEXT, reason TEXT, source TEXT
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_score_audit_school ON score_audit(school_id, term_id, class_id, subject_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_score_audit_student ON score_audit(school_id, student_id)")
    for t in ("score_audit", "staff_name_history"):
        conn.execute(f"DROP TRIGGER IF EXISTS trg_{t}_no_update")
        conn.execute(f"DROP TRIGGER IF EXISTS trg_{t}_no_delete")
        conn.execute(f"CREATE TRIGGER trg_{t}_no_update BEFORE UPDATE ON {t} WHEN {'1' if t=='score_audit' else 'OLD.admin_notified=NEW.admin_notified'} BEGIN SELECT RAISE(ABORT,'History is append-only'); END")
        conn.execute(f"CREATE TRIGGER trg_{t}_no_delete BEFORE DELETE ON {t} BEGIN SELECT RAISE(ABORT,'History is append-only'); END")

    # ---- educational domains: categories become school-configurable ---------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS educational_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL, tenant_id TEXT,
            domain_key TEXT NOT NULL, label TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0,
            UNIQUE (school_id, domain_key)
        )""")
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='skill_traits'").fetchone()
    if sql and "CHECK" in (sql[0] or "").upper():
        # The old table only allowed two categories. Rebuild it without the CHECK (data preserved).
        conn.execute("ALTER TABLE skill_traits RENAME TO skill_traits_old")
        conn.execute("""CREATE TABLE skill_traits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, school_id INTEGER NOT NULL, name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'affective',
            client_uuid TEXT, updated_at TEXT, is_deleted INTEGER DEFAULT 0, tenant_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0,
            UNIQUE(school_id, name))""")
        cols = [r[1] for r in conn.execute("PRAGMA table_info(skill_traits_old)")]
        keep = [c for c in ("id", "school_id", "name", "category", "client_uuid", "updated_at", "is_deleted", "tenant_id") if c in cols]
        conn.execute(f"INSERT INTO skill_traits({','.join(keep)}) SELECT {','.join(keep)} FROM skill_traits_old")
        conn.execute("DROP TABLE skill_traits_old")
    else:
        ensure_column(conn, "skill_traits", "is_active", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(conn, "skill_traits", "sort_order", "INTEGER NOT NULL DEFAULT 0")
    for sch in conn.execute("SELECT id, COALESCE(NULLIF(tenant_id,''),CAST(id AS TEXT)) t FROM schools").fetchall():
        for i, (key, label) in enumerate([("affective", "Affective Domain"), ("psychomotor", "Psychomotor Domain")], 1):
            conn.execute("INSERT OR IGNORE INTO educational_domains(school_id,tenant_id,domain_key,label,sort_order) VALUES(?,?,?,?,?)",
                         (sch["id"], sch["t"], key, label, i))

    # ---- result-sheet settings -------------------------------------------------------
    for col, typ in [("show_overall_position", "INTEGER NOT NULL DEFAULT 1"), ("show_subject_position", "INTEGER NOT NULL DEFAULT 0"),
                     ("result_template", "TEXT NOT NULL DEFAULT 'classic'"), ("result_title", "TEXT"),
                     ("result_footer_text", "TEXT"), ("result_watermark_text", "TEXT"), ("result_show_watermark", "INTEGER NOT NULL DEFAULT 0"),
                     ("result_show_passport", "INTEGER NOT NULL DEFAULT 1"), ("result_show_contact", "INTEGER NOT NULL DEFAULT 1"),
                     ("result_secondary_color", "TEXT"), ("result_signature_layout", "TEXT NOT NULL DEFAULT 'split'"),
                     ("school_address", "TEXT"), ("result_show_grading_key", "INTEGER NOT NULL DEFAULT 1"),
                     ("result_show_promotion", "INTEGER NOT NULL DEFAULT 1")]:
        ensure_column(conn, "schools", col, typ)

    ensure_column(conn, "student_term_info", "promotion_status", "TEXT")

    # ---- automatic term / session creation ---------------------------------------------
    for col, typ in [("start_date", "TEXT"), ("end_date", "TEXT"), ("is_auto_created", "INTEGER NOT NULL DEFAULT 0"),
                     ("created_from_term_id", "INTEGER")]:
        ensure_column(conn, "terms", col, typ)
    for col, typ in [("start_date", "TEXT"), ("end_date", "TEXT"), ("is_auto_created", "INTEGER NOT NULL DEFAULT 0"),
                     ("created_from_session_id", "INTEGER")]:
        ensure_column(conn, "sessions", col, typ)

    # ---- subscription history ------------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS subscription_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL, tenant_id TEXT,
            action TEXT NOT NULL,
            previous_status TEXT, new_status TEXT, previous_plan TEXT, new_plan TEXT,
            previous_ends_at TEXT, new_ends_at TEXT, note TEXT,
            actor_id INTEGER, actor_name TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_subscription_history_school ON subscription_history(school_id, id)")
    conn.execute("DROP TRIGGER IF EXISTS trg_subscription_history_no_update")
    conn.execute("DROP TRIGGER IF EXISTS trg_subscription_history_no_delete")
    conn.execute("CREATE TRIGGER trg_subscription_history_no_update BEFORE UPDATE ON subscription_history BEGIN SELECT RAISE(ABORT,'History is append-only'); END")
    conn.execute("CREATE TRIGGER trg_subscription_history_no_delete BEFORE DELETE ON subscription_history BEGIN SELECT RAISE(ABORT,'History is append-only'); END")

    # ---- repair: the slot form stored the teaching flag inverted (breaks teachable, lessons not) ----
    if table_exists(conn, "schedule_slots"):
        conn.execute("UPDATE schedule_slots SET allows_timetable_entry=CASE WHEN slot_type='TEACHING' THEN 1 ELSE 0 END")

    # ---- school days exist for every school, and for every school created later -----------
    for sch in conn.execute("SELECT id, COALESCE(NULLIF(tenant_id,''),CAST(id AS TEXT)) t FROM schools").fetchall():
        _seed_school_days(conn, sch["id"], sch["t"])


def _seed_school_days(conn, school_id, tenant_id):
    if not table_exists(conn, "school_days_v2"):
        return
    for order, name, code in [(1, 'Monday', 'MON'), (2, 'Tuesday', 'TUE'), (3, 'Wednesday', 'WED'), (4, 'Thursday', 'THU'), (5, 'Friday', 'FRI'), (6, 'Saturday', 'SAT')]:
        conn.execute("INSERT OR IGNORE INTO school_days_v2(tenant_id,school_id,day_name,day_code,day_order,is_active) VALUES(?,?,?,?,?,?)",
                     (tenant_id, school_id, name, code, order, 1 if order <= 5 else 0))


STEPS.append(("v61_login_codes_audit_results", migration_060_v61))


def ensure_school_v61_defaults(conn, school_id):
    """Idempotent: school days and educational domains for one school. Safe to call on every page that needs them,
    so a school created after the migration ran (or restored from an old backup) is never left without them."""
    row = conn.execute("SELECT id, COALESCE(NULLIF(tenant_id,''),CAST(id AS TEXT)) t FROM schools WHERE id=?", (school_id,)).fetchone()
    if not row:
        return
    tenant = row["t"]
    if not conn.execute("SELECT 1 FROM school_days_v2 WHERE school_id=? AND tenant_id=? LIMIT 1", (school_id, tenant)).fetchone():
        # days stored under a different tenant string (e.g. tenant assigned after first seeding) are re-homed, not duplicated
        if conn.execute("SELECT 1 FROM school_days_v2 WHERE school_id=? LIMIT 1", (school_id,)).fetchone():
            conn.execute("UPDATE school_days_v2 SET tenant_id=? WHERE school_id=?", (tenant, school_id))
        else:
            _seed_school_days(conn, school_id, tenant)
    for i, (key, label) in enumerate([("affective", "Affective Domain"), ("psychomotor", "Psychomotor Domain")], 1):
        conn.execute("INSERT OR IGNORE INTO educational_domains(school_id,tenant_id,domain_key,label,sort_order) VALUES(?,?,?,?,?)",
                     (school_id, tenant, key, label, i))
    conn.commit()


def migration_061_v62_result_display(conn):
    """V62: every result-sheet visibility switch lives in schools.* (see result_display.py); the saved
    result date is stored per student per term; attendance is linked to the roll call."""
    import result_display
    result_display.migrate(conn, ensure_column)
    ensure_column(conn, "student_term_info", "result_date", "TEXT")
    ensure_column(conn, "student_term_info", "attendance_source", "TEXT")
    ensure_column(conn, "schools", "result_template", "TEXT DEFAULT 'classic'")
    ensure_column(conn, "parent_accounts", "photo_filename", "TEXT")
    conn.execute("""CREATE TABLE IF NOT EXISTS school_info_fields (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL,
        tenant_id TEXT,
        label TEXT NOT NULL,
        value TEXT,
        display_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id))""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_school_info_label ON school_info_fields(school_id, LOWER(label))")
    # A School ID is permanent: once issued it can never be changed by any user or code path.
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_school_code_permanent
        BEFORE UPDATE OF school_code ON schools
        WHEN OLD.school_code IS NOT NULL AND OLD.school_code <> '' AND NEW.school_code IS NOT OLD.school_code
        BEGIN SELECT RAISE(ABORT, 'School ID is permanent and cannot be changed'); END""")


STEPS.append(("v62_result_display", migration_061_v62_result_display))


_CODE_STOP = {"SCHOOL", "SCHOOLS", "THE", "OF", "AND", "FOR", "IN", "AT", "A"}


def school_code_prefix(name):
    """Readable 3-5 letter abbreviation of a school name (letters only), e.g.
    'Government Secondary School Goni' -> 'GSG', 'Goni' -> 'GONI'."""
    import re as _re
    words = [w for w in _re.findall(r"[A-Za-z]+", (name or "").upper()) if w not in _CODE_STOP]
    if not words:
        return "SCH"
    if len(words) == 1:
        ab = words[0][:5]
    else:
        ab = "".join(w[0] for w in words)[:5]
        if len(ab) < 3:
            ab = (ab + words[0][1:])[:4]
    return (ab + "XXX")[:max(3, len(ab))]


def generate_school_code(conn, name):
    """Unique, permanent, readable School ID such as 'SCH-GONI-0001'.
    The number is a per-abbreviation sequence (not the database id) and the code is never regenerated:
    existing schools keep the ID they already have."""
    import re as _re
    ab = school_code_prefix(name)
    stem = f"SCH-{ab}-"
    highest = 0
    for r in conn.execute("SELECT school_code FROM schools WHERE school_code LIKE ?", (stem + "%",)).fetchall():
        m = _re.fullmatch(_re.escape(stem) + r"(\d+)", r["school_code"] or "")
        if m:
            highest = max(highest, int(m.group(1)))
    n = highest + 1
    while True:
        code = f"{stem}{n:04d}"
        if not conn.execute("SELECT 1 FROM schools WHERE UPPER(school_code)=?", (code,)).fetchone():
            return code
        n += 1


def migration_062_v63_attendance_integrity(conn):
    """V63: strict, server-controlled attendance.
    * every record carries the school/tenant, who recorded it, in which role and (for students) the class arm;
    * the four requested statuses are kept in `attendance_type` (status stays present/absent so day counts keep working:
      late counts as present, excused counts as absent);
    * corrections never overwrite the original: who/when/why and the original status are stored beside it;
    * the original date, student/staff and server timestamp can no longer be changed by anyone (database triggers);
    * attendance_audit is an append-only log of every record, correction and rejected attempt."""
    for col, typ in [("school_id", "INTEGER"), ("tenant_id", "TEXT"), ("attendance_type", "TEXT"), ("recorder_role", "TEXT"),
                     ("class_arm", "TEXT"), ("corrected_by", "INTEGER"), ("corrected_at", "TEXT"), ("correction_note", "TEXT"),
                     ("original_status", "TEXT")]:
        ensure_column(conn, "attendance_records", col, typ)
    for col, typ in [("tenant_id", "TEXT"), ("recorder_role", "TEXT"), ("corrected_by", "INTEGER"), ("corrected_at", "TEXT"),
                     ("correction_note", "TEXT"), ("original_status", "TEXT")]:
        ensure_column(conn, "staff_attendance", col, typ)
    conn.execute("""UPDATE attendance_records SET
        school_id=COALESCE(school_id,(SELECT school_id FROM classes WHERE classes.id=attendance_records.class_id)),
        tenant_id=COALESCE(tenant_id,(SELECT tenant_id FROM classes WHERE classes.id=attendance_records.class_id)),
        attendance_type=COALESCE(attendance_type,status)
        WHERE school_id IS NULL OR attendance_type IS NULL""")
    conn.execute("""CREATE TABLE IF NOT EXISTS attendance_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER, tenant_id TEXT,
        kind TEXT NOT NULL,                 -- 'student' | 'staff'
        subject_id INTEGER,                 -- student id or staff user id
        class_id INTEGER,
        attendance_date TEXT,
        action TEXT NOT NULL,               -- recorded | corrected | rejected
        old_status TEXT, new_status TEXT,
        actor_id INTEGER, actor_name TEXT, actor_role TEXT,
        reason TEXT,
        server_ts TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attendance_audit_school ON attendance_audit(school_id, server_ts)")
    for tbl in ("attendance_records", "staff_attendance"):
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS trg_{tbl}_original_immutable
            BEFORE UPDATE OF recorded_at, date ON {tbl}
            WHEN (OLD.recorded_at IS NOT NULL AND NEW.recorded_at IS NOT OLD.recorded_at) OR NEW.date IS NOT OLD.date
            BEGIN SELECT RAISE(ABORT, 'The original attendance date and timestamp cannot be changed'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_attendance_audit_append_only_u BEFORE UPDATE ON attendance_audit
        BEGIN SELECT RAISE(ABORT, 'Attendance audit is append-only'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS trg_attendance_audit_append_only_d BEFORE DELETE ON attendance_audit
        BEGIN SELECT RAISE(ABORT, 'Attendance audit is append-only'); END""")


STEPS.append(("v63_attendance_integrity", migration_062_v63_attendance_integrity))


def migration_063_v63_score_audit_fields(conn):
    """V63: score audit also records the class arm, the action (entered / edited / cleared / deleted / changed after
    publication) and every role the staff member held at the time."""
    ensure_column(conn, "score_audit", "class_arm", "TEXT")
    ensure_column(conn, "score_audit", "action", "TEXT")


STEPS.append(("v63_score_audit_fields", migration_063_v63_score_audit_fields))


def migration_064_v63_custom_result_fields(conn):
    """V63: school-defined result fields (House, Club, Award, Behaviour, Health Remark ...). Definitions and values are
    tenant-specific; a field can be switched on/off and chosen to show on the student profile and/or the result sheet."""
    conn.execute("""CREATE TABLE IF NOT EXISTS result_custom_fields (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL, tenant_id TEXT,
        label TEXT NOT NULL,
        field_type TEXT NOT NULL DEFAULT 'text',      -- text | number | date | choice | yesno
        options TEXT,                                 -- comma separated, for 'choice'
        scope TEXT NOT NULL DEFAULT 'term',           -- 'student' = one value for the student, 'term' = a value per term
        enabled INTEGER NOT NULL DEFAULT 1,
        show_on_result INTEGER NOT NULL DEFAULT 1,
        show_on_profile INTEGER NOT NULL DEFAULT 1,
        display_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(school_id) REFERENCES schools(id))""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_result_custom_label ON result_custom_fields(school_id, LOWER(label))")
    conn.execute("""CREATE TABLE IF NOT EXISTS student_custom_values (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        school_id INTEGER NOT NULL, tenant_id TEXT,
        field_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
        term_id INTEGER NOT NULL DEFAULT 0,           -- 0 for student-scope fields
        value TEXT,
        updated_by INTEGER, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(field_id, student_id, term_id),
        FOREIGN KEY(field_id) REFERENCES result_custom_fields(id), FOREIGN KEY(student_id) REFERENCES students(id))""")
    ensure_column(conn, "school_info_fields", "show_on_result", "INTEGER NOT NULL DEFAULT 0")


STEPS.append(("v63_custom_result_fields", migration_064_v63_custom_result_fields))


def migration_065_v63_registrar(conn):
    """V63: admissions, student status history, transfers and register numbers."""
    for col, typ in [("admission_date", "TEXT"), ("previous_school", "TEXT"), ("admission_notes", "TEXT"),
                     ("transfer_date", "TEXT"), ("transfer_destination", "TEXT")]:
        ensure_column(conn, "students", col, typ)
    conn.execute("""CREATE TABLE IF NOT EXISTS student_status_options (
        id INTEGER PRIMARY KEY AUTOINCREMENT, school_id INTEGER NOT NULL, tenant_id TEXT,
        label TEXT NOT NULL, active_like INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_status_option_label ON student_status_options(school_id, LOWER(label))")
    conn.execute("""CREATE TABLE IF NOT EXISTS student_status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, school_id INTEGER NOT NULL, tenant_id TEXT,
        student_id INTEGER NOT NULL, old_status TEXT, new_status TEXT NOT NULL,
        effective_date TEXT, reason TEXT, destination_school TEXT, previous_school TEXT,
        actor_id INTEGER, actor_name TEXT, actor_role TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_status_history_student ON student_status_history(school_id, student_id)")
    for ev in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS trg_student_status_history_{ev.lower()}
            BEFORE {ev} ON student_status_history BEGIN SELECT RAISE(ABORT, 'Student status history is append-only'); END""")
    # Admission and register numbers are unique within a school (best effort for databases that already hold duplicates).
    for name, sql in (
        ("ux_students_school_admission", "CREATE UNIQUE INDEX IF NOT EXISTS ux_students_school_admission ON students(school_id, LOWER(TRIM(admission_no)))"),
        ("ux_students_school_register", "CREATE UNIQUE INDEX IF NOT EXISTS ux_students_school_register ON students(school_id, LOWER(TRIM(register_no))) WHERE register_no IS NOT NULL AND TRIM(register_no)<>''"),
    ):
        try:
            conn.execute(sql)
        except Exception:
            pass


STEPS.append(("v63_registrar", migration_065_v63_registrar))


def migration_066_v63_notification_reads(conn):
    """V63: per-notification read state (a reader is a staff user, a student or a parent account)."""
    conn.execute("""CREATE TABLE IF NOT EXISTS notification_reads (
        reader_type TEXT NOT NULL, reader_id INTEGER NOT NULL, notification_id INTEGER NOT NULL,
        read_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (reader_type, reader_id, notification_id))""")


STEPS.append(("v63_notification_reads", migration_066_v63_notification_reads))
