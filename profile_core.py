"""Validation, custom-field engine and audit helpers for Student / Staff profiles.

Nothing here touches Flask globals except where a request/session is passed in, so the
rules can be unit-tested directly against a SQLite connection.
"""
import datetime
import decimal
import io
import json
import os
import re
import sqlite3
import uuid

# --------------------------------------------------------------------------- limits
PASSPORT_MAX = 500 * 1024
SIGNATURE_MAX = 500 * 1024
DOCUMENT_MAX = 1024 * 1024
IMAGE_EXTS = {"png", "jpg", "jpeg", "gif"}
IMAGE_FORMATS = {"PNG", "JPEG", "GIF"}
CUSTOM_FILE_EXTS = {"pdf", "png", "jpg", "jpeg"}

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?\d{7,15}$")

NIGERIAN_STATES = [
    "Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi", "Bayelsa", "Benue", "Borno", "Cross River", "Delta",
    "Ebonyi", "Edo", "Ekiti", "Enugu", "FCT Abuja", "Gombe", "Imo", "Jigawa", "Kaduna", "Kano", "Katsina",
    "Kebbi", "Kogi", "Kwara", "Lagos", "Nasarawa", "Niger", "Ogun", "Ondo", "Osun", "Oyo", "Plateau",
    "Rivers", "Sokoto", "Taraba", "Yobe", "Zamfara",
]

# --------------------------------------------------------------------------- field specs
# key, label, input type, required, self_edit (the person themselves), staff_edit (teacher with authority),
# admin_only (protected: only a School Admin may change), max length
def _f(key, label, kind="text", required=False, self_edit=False, staff_edit=True, admin_only=False, maxlen=120, **kw):
    d = dict(key=key, label=label, kind=kind, required=required, self_edit=self_edit,
             staff_edit=staff_edit, admin_only=admin_only, maxlen=maxlen)
    d.update(kw)
    return d


STUDENT_SPECS = [
    _f("first_name", "First Name", "name", True),
    _f("last_name", "Surname", "name", True),
    _f("other_names", "Other Names", "name", False),
    _f("admission_no", "Admission No. / Register No.", "text", True, False, False, admin_only=True, maxlen=40),
    _f("date_of_birth", "Date of Birth", "dob_student", True),
    _f("gender", "Gender", "gender", True),
    _f("state", "State", "place", True, True, True, maxlen=60, datalist="states"),
    _f("lga", "Local Government Area (LGA)", "place", True, True, True, maxlen=60),
    _f("tribe", "Tribe", "place", False, True, True, maxlen=60),
    _f("religion", "Religion", "place", False, True, True, maxlen=40),
    _f("date_of_admission", "Date of Admission", "admission_date", False),
    _f("email", "Email", "email", False, True, True),
    _f("phone", "Phone Number", "phone", False, True, True),
    _f("address", "Address", "address", True, True, True, maxlen=300),
    _f("parent_name", "Parent/Guardian Name", "name", True, True, True),
    _f("parent_relationship", "Relationship to Student", "place", False, True, True, maxlen=40),
    _f("parent_phone", "Parent/Guardian Phone", "phone", True, True, True),
    _f("parent_email", "Parent/Guardian Email", "email", False, True, True),
    _f("parent_address", "Parent/Guardian Address", "address", False, True, True, maxlen=300),
]
STUDENT_PROTECTED = {"admission_no", "class_id", "school_id", "tenant_id", "status", "is_active", "username",
                     "password_hash", "user_id", "register_no", "account_status", "signup_status", "id"}

STAFF_SPECS = [
    _f("first_name", "First Name", "name", True, True, True),
    _f("surname", "Surname", "name", True, True, True),
    _f("other_names", "Other Names", "name", False, True, True),
    _f("username", "Username", "username", True, False, False, admin_only=True, maxlen=40),
    _f("phone", "Phone Number", "phone", True, True, True),
    _f("email", "Email", "email", False, True, True),
    _f("date_of_birth", "Date of Birth", "dob_staff", False, True, True),
    _f("gender", "Gender", "gender", False, True, True),
    _f("state", "State", "place", False, True, True, maxlen=60, datalist="states"),
    _f("lga", "LGA", "place", False, True, True, maxlen=60),
    _f("address", "Address", "address", False, True, True, maxlen=300),
    _f("qualifications", "Qualification", "text", False, True, True, maxlen=200),
    _f("subjects_taught", "Subjects Taught (as declared)", "text", False, True, True, maxlen=300),
    _f("staff_id", "Staff / Employee ID", "text", False, False, False, admin_only=True, maxlen=40),
]
STAFF_PROTECTED = {"role", "position", "rbac_role", "school_id", "tenant_id", "is_active", "password_hash",
                   "security_question", "security_answer_hash", "account_status", "signup_status",
                   "activation_status", "first_login_required", "signup_name", "id", "client_uuid"}

SYSTEM_LABEL_WORDS = {
    "admission no", "admission number", "register no", "register number", "username", "staff id", "employee id",
    "role", "school", "school id", "tenant", "tenant id", "password", "position", "permissions",
}

FIELD_TYPES = [
    ("short_text", "Short Text"), ("long_text", "Long Text"), ("number", "Number"), ("date", "Date"),
    ("select", "Dropdown / Select"), ("multiselect", "Multiple Select"), ("yes_no", "Yes / No"),
    ("phone", "Phone Number"), ("email", "Email"), ("file", "File Upload"),
]
FIELD_TYPE_KEYS = {k for k, _ in FIELD_TYPES}
UNIQUE_CAPABLE = {"short_text", "number", "date", "phone", "email"}
OPTION_TYPES = {"select", "multiselect"}


# --------------------------------------------------------------------------- primitives
def clean(value):
    return " ".join(str(value or "").split())


def clean_multiline(value):
    return str(value or "").replace("\r\n", "\n").strip()


def norm_phone(value):
    return re.sub(r"[\s\-().]", "", str(value or ""))


def parse_date(value):
    v = str(value or "").strip()
    if not v:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.datetime.strptime(v, fmt).date()
        except ValueError:
            continue
    return None


def _today():
    return datetime.date.today()


def check_value(spec, raw, *, dob_context=None):
    """Validate one system field. Returns (clean_value_or_None, error_or_None)."""
    kind, label, required = spec["kind"], spec["label"], spec["required"]
    maxlen = spec["maxlen"]
    if kind == "address":
        v = clean_multiline(raw)
    else:
        v = clean(raw)
    if not v:
        return None, (f"{label} is required." if required else None)
    if len(v) > maxlen:
        return None, f"{label} must be at most {maxlen} characters."
    if kind == "name":
        letters = sum(ch.isalpha() for ch in v)
        if letters < 2 or any(not (ch.isalpha() or ch in " '-.") for ch in v):
            return None, f"{label} may contain only letters, spaces, hyphens, apostrophes and full stops (at least 2 letters)."
    elif kind == "place":
        if any(ch in "<>{}[];|\\`" for ch in v) or not any(ch.isalpha() for ch in v):
            return None, f"{label} contains invalid characters."
    elif kind == "text":
        if any(ch in "<>" for ch in v):
            return None, f"{label} contains invalid characters."
    elif kind == "address":
        if len(v) < 5:
            return None, f"{label} looks too short."
        if "<" in v or ">" in v:
            return None, f"{label} contains invalid characters."
    elif kind == "email":
        if not EMAIL_RE.match(v):
            return None, f"{label}: enter a valid email address such as name@example.com."
        v = v.lower()
    elif kind == "phone":
        v = norm_phone(v)
        if not PHONE_RE.match(v):
            return None, f"{label}: enter digits only, 7 to 15 long, optionally starting with +."
    elif kind == "username":
        v = v.lower()
        if not re.fullmatch(r"[a-z0-9._\-]{3,40}", v):
            return None, f"{label} must be 3-40 characters: letters, numbers, dot, underscore or hyphen."
    elif kind == "gender":
        v = v.upper()[:1] if v.upper() in ("M", "F", "MALE", "FEMALE") else v
        if v not in ("M", "F"):
            return None, f"{label}: choose Male or Female."
    elif kind in ("dob_student", "dob_staff", "admission_date"):
        d = parse_date(v)
        if d is None:
            return None, f"{label}: enter a valid date (YYYY-MM-DD)."
        if d > _today():
            return None, f"{label} cannot be in the future."
        if kind == "dob_student" and not (2 <= (_today() - d).days / 365.25 <= 40):
            return None, f"{label}: the student's age must be between 2 and 40 years."
        if kind == "dob_staff" and not (16 <= (_today() - d).days / 365.25 <= 90):
            return None, f"{label}: staff age must be between 16 and 90 years."
        if kind == "admission_date" and dob_context and d < dob_context:
            return None, f"{label} cannot be before the date of birth."
        v = d.isoformat()
    return v, None


def read_image_upload(file_storage, limit, label):
    """Validate an uploaded image on the server: size, extension AND real image content.
    Returns (bytes, ext, error)."""
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None, None, None
    name = file_storage.filename
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in IMAGE_EXTS:
        return None, None, f"{label} must be a PNG, JPG or GIF image."
    data = file_storage.stream.read(limit + 1)
    if len(data) > limit:
        return None, None, f"{label} must not exceed {limit // 1024} KB."
    if not data:
        return None, None, f"{label} file is empty."
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            fmt = (im.format or "").upper()
            w, h = im.size
            im.verify()
    except Exception:
        return None, None, f"{label} is not a valid image file."
    if fmt not in IMAGE_FORMATS:
        return None, None, f"{label} must be a PNG, JPG or GIF image."
    if w > 6000 or h > 6000 or w < 20 or h < 20:
        return None, None, f"{label} dimensions are not acceptable."
    ext = "jpg" if fmt == "JPEG" else fmt.lower()
    return data, ext, None


def read_custom_file(file_storage, label):
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None, None, None
    name = file_storage.filename
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in CUSTOM_FILE_EXTS:
        return None, None, f"{label}: allowed file types are PDF, PNG and JPG."
    data = file_storage.stream.read(DOCUMENT_MAX + 1)
    if len(data) > DOCUMENT_MAX:
        return None, None, f"{label} must not exceed 1 MB."
    if not data:
        return None, None, f"{label} file is empty."
    head = data[:8]
    ok = (ext == "pdf" and head.startswith(b"%PDF")) or (ext == "png" and head.startswith(b"\x89PNG")) \
        or (ext in ("jpg", "jpeg") and head.startswith(b"\xff\xd8"))
    if not ok:
        return None, None, f"{label}: file content does not match its type."
    return data, ext, None


# --------------------------------------------------------------------------- audit
def audit(conn, actor, action, entity_type=None, entity_id=None, changes=None, school_id=None, tenant_id=None, ip=None):
    """Append to the protected audit history. Runs inside the caller's transaction and never
    commits, so a change and its audit record are stored together or not at all."""
    conn.execute(
        "INSERT INTO rbac_audit_log(actor_type,actor_id,actor_name,actor_role,school_id,tenant_id,action,entity_type,entity_id,changes,ip_address) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (actor.get("type"), actor.get("id"), actor.get("name"), actor.get("role"),
         school_id if school_id is not None else actor.get("school_id"),
         tenant_id if tenant_id is not None else actor.get("tenant_id"),
         action, entity_type, None if entity_id is None else str(entity_id),
         json.dumps(changes, default=str, ensure_ascii=False) if changes is not None else None, ip),
    )


def diff(old, new, keys):
    out = {}
    for k in keys:
        o, n = (old[k] if old is not None and k in old.keys() else None), new.get(k)
        if (o or None) != (n or None):
            out[k] = [o, n]
    return out


# --------------------------------------------------------------------------- custom fields: read
def slugify_key(label):
    s = re.sub(r"[^a-z0-9]+", "_", clean(label).lower()).strip("_")
    return ("cf_" + (s or "field"))[:60]


def unique_key(conn, school_id, applies_to, label):
    base = slugify_key(label)
    key, n = base, 2
    while conn.execute("SELECT 1 FROM custom_fields WHERE school_id=? AND applies_to=? AND field_key=?",
                       (school_id, applies_to, key)).fetchone():
        key = f"{base}_{n}"
        n += 1
    return key


def load_fields(conn, school_id, tenant_id, applies_to, include_inactive=False, include_archived=False):
    q = "SELECT * FROM custom_fields WHERE school_id=? AND tenant_id=? AND applies_to=?"
    if not include_archived:
        q += " AND is_archived=0"
    if not include_inactive:
        q += " AND is_active=1"
    q += " ORDER BY display_order, id"
    fields = []
    for f in conn.execute(q, (school_id, tenant_id, applies_to)).fetchall():
        d = dict(f)
        d["options"] = [dict(o) for o in conn.execute(
            "SELECT * FROM custom_field_options WHERE field_id=? AND school_id=? ORDER BY display_order,id",
            (f["id"], school_id)).fetchall()] if f["field_type"] in OPTION_TYPES else []
        fields.append(d)
    return fields


def load_values(conn, school_id, entity_type, entity_id):
    rows = conn.execute("SELECT field_id,value FROM custom_field_values WHERE school_id=? AND entity_type=? AND entity_id=?",
                        (school_id, entity_type, entity_id)).fetchall()
    return {r["field_id"]: r["value"] for r in rows}


def decode_value(field, stored):
    """Turn a stored value into something the template can show."""
    if stored is None or stored == "":
        return "" if field["field_type"] != "multiselect" else []
    if field["field_type"] == "multiselect":
        try:
            v = json.loads(stored)
            return v if isinstance(v, list) else [str(v)]
        except (ValueError, TypeError):
            return [stored]
    if field["field_type"] == "file":
        try:
            return json.loads(stored)
        except (ValueError, TypeError):
            return {}
    return stored


# --------------------------------------------------------------------------- custom fields: validate
def collect_custom(fields, form, files, existing, can_edit_all):
    """Validate submitted custom-field values.

    Only fields defined for THIS school (the list passed in) are ever read, so a value for another
    school's field key is ignored. Returns (updates, errors, echo)
      updates: {field_id: (stored_value_or_None, unique_value_or_None, file_blob_or_None)}
      errors : {"cf_<id>": message}
      echo   : {field_id: value to re-display}
    """
    updates, errors, echo = {}, {}, {}
    for f in fields:
        fid = f["id"]
        name = f"cf_{fid}"
        editable = can_edit_all or bool(f["is_editable"])
        stored = existing.get(fid)
        if not editable:
            echo[fid] = decode_value(f, stored)
            continue
        label, ftype = f["label"], f["field_type"]
        required = bool(f["is_required"])
        if ftype == "multiselect":
            raw = [clean(x) for x in form.getlist(name) if clean(x)]
        elif ftype == "file":
            raw = None
        else:
            raw = clean_multiline(form.get(name, "")) if ftype == "long_text" else clean(form.get(name, ""))
        err, val, uniq, blob = None, None, None, None

        if ftype == "file":
            data, ext, ferr = read_custom_file(files.get(name), label)
            if ferr:
                err = ferr
            elif data:
                val = json.dumps({"name": os.path.basename(files[name].filename)[:120], "ext": ext,
                                  "stored": f"{uuid.uuid4().hex}.{ext}", "size": len(data)})
                blob = data
            elif form.get(name + "__remove") == "1" and not required:
                val = None
            else:
                val = stored
                if required and not stored:
                    err = f"{label} is required."
            echo[fid] = decode_value(f, val if val is not None else stored)
        elif ftype == "multiselect":
            allowed = {o["option_value"] for o in f["options"] if o["is_active"]}
            keep = set(decode_value(f, stored)) if stored else set()
            bad = [x for x in raw if x not in allowed and x not in keep]
            if bad:
                err = f"{label}: choose only from the listed options."
            elif required and not raw:
                err = f"{label} is required."
            elif raw:
                val = json.dumps(sorted(set(raw), key=raw.index), ensure_ascii=False)
            echo[fid] = raw
        else:
            v = raw
            if v == "" and f.get("default_value") and stored is None and not required:
                v = ""      # a blank field stays blank; defaults only pre-fill new forms
            if v == "":
                if required:
                    err = f"{label} is required."
            elif ftype == "short_text":
                if len(v) > 200:
                    err = f"{label} must be at most 200 characters."
                else:
                    val = v
            elif ftype == "long_text":
                if len(v) > 2000:
                    err = f"{label} must be at most 2000 characters."
                else:
                    val = v
            elif ftype == "number":
                try:
                    dv = decimal.Decimal(v)
                    if not dv.is_finite() or abs(dv) > decimal.Decimal("1e15"):
                        raise decimal.InvalidOperation
                    val = format(dv.normalize(), "f") if dv != 0 else "0"
                except decimal.InvalidOperation:
                    err = f"{label}: enter a valid number."
            elif ftype == "date":
                d = parse_date(v)
                if d is None:
                    err = f"{label}: enter a valid date (YYYY-MM-DD)."
                else:
                    val = d.isoformat()
            elif ftype == "select":
                allowed = {o["option_value"] for o in f["options"] if o["is_active"]}
                if v not in allowed and v != stored:
                    err = f"{label}: choose one of the listed options."
                else:
                    val = v
            elif ftype == "yes_no":
                if v.lower() not in ("yes", "no"):
                    err = f"{label}: choose Yes or No."
                else:
                    val = v.capitalize()
            elif ftype == "phone":
                pv = norm_phone(v)
                if not PHONE_RE.match(pv):
                    err = f"{label}: enter a valid phone number (7 to 15 digits)."
                else:
                    val = pv
            elif ftype == "email":
                if not EMAIL_RE.match(v):
                    err = f"{label}: enter a valid email address."
                else:
                    val = v.lower()
            echo[fid] = v if err else (val or "")
        if err:
            errors[name] = err
            continue
        if f["is_unique"] and val is not None:
            uniq = val.lower()
        updates[fid] = (val, uniq, blob)
    return updates, errors, echo


def default_echo(fields, existing):
    """Values to show on a fresh form: stored value, otherwise the field's default."""
    echo = {}
    for f in fields:
        if f["id"] in existing:
            echo[f["id"]] = decode_value(f, existing[f["id"]])
        elif f["field_type"] == "multiselect":
            dv = f.get("default_value") or ""
            echo[f["id"]] = [x for x in dv.split("|") if x] if dv else []
        elif f["field_type"] == "file":
            echo[f["id"]] = {}
        else:
            echo[f["id"]] = f.get("default_value") or ""
    return echo


def save_custom(conn, school_id, tenant_id, entity_type, entity_id, updates, fields, actor_id, files_dir):
    """Write validated custom values inside the caller's transaction.
    Returns (errors, written_files, replaced_files) — errors is empty on success."""
    errors, written, replaced = {}, [], []
    by_id = {f["id"]: f for f in fields}
    for fid, (val, uniq, blob) in updates.items():
        f = by_id[fid]
        row = conn.execute("SELECT id,value FROM custom_field_values WHERE field_id=? AND entity_id=?", (fid, entity_id)).fetchone()
        if val is None:
            if row:
                if f["field_type"] == "file":
                    replaced.append(row["value"])
                conn.execute("DELETE FROM custom_field_values WHERE id=?", (row["id"],))
            continue
        try:
            if row:
                if f["field_type"] == "file" and blob is not None:
                    replaced.append(row["value"])
                conn.execute("UPDATE custom_field_values SET value=?,unique_value=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                             (val, uniq, actor_id, row["id"]))
            else:
                conn.execute("INSERT INTO custom_field_values(field_id,school_id,tenant_id,entity_type,entity_id,value,unique_value,updated_by) VALUES(?,?,?,?,?,?,?,?)",
                             (fid, school_id, tenant_id, entity_type, entity_id, val, uniq, actor_id))
        except sqlite3.IntegrityError:
            errors[f"cf_{fid}"] = f"{f['label']}: this value is already used by another {entity_type} in your school."
            continue
        if blob is not None:
            os.makedirs(files_dir, exist_ok=True)
            stored = json.loads(val)["stored"]
            with open(os.path.join(files_dir, stored), "wb") as fh:
                fh.write(blob)
            written.append(os.path.join(files_dir, stored))
    return errors, written, replaced


def check_custom_unique_preflight(conn, fields, updates, entity_id):
    """Friendly pre-check (the DB unique index remains the real guarantee)."""
    errors = {}
    by_id = {f["id"]: f for f in fields}
    for fid, (val, uniq, _b) in updates.items():
        if uniq is None:
            continue
        clash = conn.execute("SELECT 1 FROM custom_field_values WHERE field_id=? AND unique_value=? AND entity_id<>?",
                             (fid, uniq, entity_id)).fetchone()
        if clash:
            errors[f"cf_{fid}"] = f"{by_id[fid]['label']}: this value is already used in your school."
    return errors


def system_label_clash(label):
    norm = re.sub(r"[^a-z0-9 ]+", " ", clean(label).lower()).strip()
    norm = re.sub(r"\s+", " ", norm)
    if norm in SYSTEM_LABEL_WORDS:
        return True
    all_labels = {re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", s["label"].lower())).strip()
                  for s in STUDENT_SPECS + STAFF_SPECS}
    return norm in all_labels or norm in {"passport", "passport photograph", "signature", "photo", "class", "class arm"}
