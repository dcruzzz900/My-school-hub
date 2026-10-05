"""V63: Registrar / Admissions Officer tools and class registers.

* Student registration with automatic admission numbers, register numbers, class/arm and admission details.
* Student status management (Active, Transferred, Withdrawn, Suspended, Graduated, Expelled + school-defined statuses)
  with an append-only history, and transfers that keep the student's records.
* Class registers: a Class Teacher / Form Teacher sees and numbers only their own class.

Every query is scoped by the school stored in the authenticated session; ids from URLs/forms are always combined with it.
"""
import datetime
import os
import re
import sqlite3

from school.core import flash, redirect, render_template, request, session, url_for

REGISTRAR_ROLE = "Registrar / Admissions Officer"
BUILTIN_STATUSES = ("Active", "Suspended", "Transferred", "Withdrawn", "Graduated", "Expelled")
ACTIVE_LIKE = {"Active", "Suspended"}          # still enrolled: stay on class lists; every other status leaves the active roll
CLEAN = re.compile(r"[<>]")


def register_registrar_routes(app, h):
    get_db = h["get_db"]; login_required = h["login_required"]; current_school_id = h["current_school_id"]
    current_tenant_id = h["current_tenant_id"]; session_roles = h["session_roles"]; school_today = h["school_today"]
    form_teacher_class_ids = h["form_teacher_class_ids"]; class_in_school = h["class_in_school"]
    plan_limit_check = h["plan_limit_check"]; upsert_enrollment = h["upsert_enrollment"]
    student_full_name = h["student_full_name"]; recorder_role_label = h["recorder_role_label"]
    verify_image = h["verify_image"]; reject_oversize = h["reject_oversize"]
    photos_dir = h["photos_dir"]; allowed_ext = h["allowed_ext"]; log_audit = h["log_audit"]

    def is_registrar():
        if session.get("role") in ("admin", "sub_admin"):
            return True
        return session.get("role") == "teacher" and REGISTRAR_ROLE in session_roles()

    def registrar_only(f):
        from functools import wraps

        @wraps(f)
        @login_required()
        def wrapped(*a, **k):
            if not is_registrar():
                flash("Only the Registrar / Admissions Officer or a School Admin can do that.", "error")
                return redirect(url_for("dashboard"))
            return f(*a, **k)
        return wrapped

    def clean(v, n=120):
        v = (v or "").strip()[:n]
        return v

    def status_options(conn, school_id):
        extra = [r["label"] for r in conn.execute("SELECT label FROM student_status_options WHERE school_id=? ORDER BY label", (school_id,)).fetchall()]
        return list(BUILTIN_STATUSES) + [x for x in extra if x not in BUILTIN_STATUSES]

    def is_active_like(conn, school_id, status):
        if status in ACTIVE_LIKE:
            return True
        r = conn.execute("SELECT active_like FROM student_status_options WHERE school_id=? AND label=?", (school_id, status)).fetchone()
        return bool(r and r["active_like"])

    def next_admission_no(conn, school_id):
        year = school_today(conn, school_id)[:4]
        stem = f"ADM/{year}/"
        hi = 0
        for r in conn.execute("SELECT admission_no FROM students WHERE school_id=? AND admission_no LIKE ?", (school_id, stem + "%")).fetchall():
            m = re.fullmatch(re.escape(stem) + r"(\d+)", (r["admission_no"] or "").strip())
            if m:
                hi = max(hi, int(m.group(1)))
        n = hi + 1
        while True:
            cand = f"{stem}{n:04d}"
            if not conn.execute("SELECT 1 FROM students WHERE school_id=? AND LOWER(TRIM(admission_no))=LOWER(?)", (school_id, cand)).fetchone():
                return cand
            n += 1

    def class_stem(name):
        return re.sub(r"[^A-Za-z0-9]+", "", name or "").upper() or "CLS"

    def next_register_no(conn, school_id, class_row):
        stem = class_stem(class_row["name"]) + "/"
        hi = 0
        for r in conn.execute("SELECT register_no FROM students WHERE school_id=? AND register_no LIKE ?", (school_id, stem + "%")).fetchall():
            m = re.fullmatch(re.escape(stem) + r"(\d+)", (r["register_no"] or "").strip().upper())
            if m:
                hi = max(hi, int(m.group(1)))
        n = hi + 1
        while True:
            cand = f"{stem}{n:02d}"
            if not conn.execute("SELECT 1 FROM students WHERE school_id=? AND LOWER(TRIM(register_no))=LOWER(?)", (school_id, cand)).fetchone():
                return cand
            n += 1

    def record_status(conn, school_id, student, new_status, effective, reason=None, destination=None, previous_school=None):
        conn.execute(
            "INSERT INTO student_status_history(school_id,tenant_id,student_id,old_status,new_status,effective_date,reason,destination_school,previous_school,actor_id,actor_name,actor_role) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (school_id, current_tenant_id(), student["id"], student["status"] if student and "status" in student.keys() else None, new_status,
             effective, reason, destination, previous_school, session.get("user_id"), session.get("name"), recorder_role_label()))

    # ------------------------------------------------------------------ dashboard
    @app.route("/registrar")
    @registrar_only
    def registrar_dashboard():
        conn = get_db()
        try:
            sid = current_school_id()
            counts = {r["status"]: r["n"] for r in conn.execute("SELECT COALESCE(status,'Active') status, COUNT(*) n FROM students WHERE school_id=? GROUP BY 1", (sid,)).fetchall()}
            recent = conn.execute("SELECT s.*, c.name class_name FROM students s JOIN classes c ON c.id=s.class_id WHERE s.school_id=? ORDER BY s.id DESC LIMIT 8", (sid,)).fetchall()
            moves = conn.execute("SELECT h.*, st.first_name, st.last_name FROM student_status_history h JOIN students st ON st.id=h.student_id WHERE h.school_id=? ORDER BY h.id DESC LIMIT 8", (sid,)).fetchall()
            return render_template("registrar_dashboard.html", counts=counts, statuses=status_options(conn, sid), recent=recent, moves=moves, student_full_name=student_full_name)
        finally:
            conn.close()

    # ------------------------------------------------------------------ registration
    @app.route("/registrar/register", methods=["GET", "POST"])
    @registrar_only
    def registrar_register():
        conn = get_db()
        try:
            sid = current_school_id()
            classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (sid,)).fetchall()
            today = school_today(conn, sid)
            form = {}
            if request.method == "POST":
                f = form = request.form
                errors = []
                class_id = f.get("class_id", type=int)
                crow = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, sid)).fetchone() if class_id else None
                if not crow:
                    errors.append("Select a class/arm.")
                first, last = clean(f.get("first_name"), 60), clean(f.get("last_name"), 60)
                if not first: errors.append("First name is required.")
                if not last: errors.append("Last name is required.")
                if f.get("gender") not in ("M", "F"): errors.append("Gender is required.")
                if any(CLEAN.search(f.get(k, "")) for k in f):
                    errors.append("Angle brackets are not allowed in any field.")
                dob = clean(f.get("date_of_birth"), 10) or None
                if dob and (not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dob) or dob > today):
                    errors.append("Date of birth is not valid.")
                adm_date = clean(f.get("admission_date"), 10) or today
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", adm_date) or adm_date > today:
                    errors.append("Admission date cannot be in the future.")
                admission = clean(f.get("admission_no"), 40)
                if f.get("auto_admission") or not admission:
                    admission = next_admission_no(conn, sid)
                elif conn.execute("SELECT 1 FROM students WHERE school_id=? AND LOWER(TRIM(admission_no))=LOWER(?)", (sid, admission)).fetchone():
                    errors.append(f"Admission number {admission} is already used in this school.")
                register_no = clean(f.get("register_no"), 40)
                if crow and (f.get("auto_register") or not register_no):
                    register_no = next_register_no(conn, sid, crow) if f.get("auto_register") else None
                if register_no and conn.execute("SELECT 1 FROM students WHERE school_id=? AND LOWER(TRIM(register_no))=LOWER(?)", (sid, register_no)).fetchone():
                    errors.append(f"Register number {register_no} is already used in this school.")
                parent_email = clean(f.get("parent_email"), 120) or None
                if parent_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", parent_email):
                    errors.append("Parent/guardian email is not valid.")
                if not errors:
                    allowed, message, _ = plan_limit_check(conn, sid, "students", 1)
                    if not allowed:
                        errors.append(message)
                if errors:
                    for e in errors: flash(e, "error")
                else:
                    try:
                        tenant = conn.execute("SELECT tenant_id FROM schools WHERE id=?", (sid,)).fetchone()["tenant_id"]
                        cur = conn.execute(
                            "INSERT INTO students (school_id,tenant_id,admission_no,register_no,first_name,last_name,other_names,gender,class_id,date_of_birth,religion,"
                            "parent_name,parent_address,parent_email,parent_phone,status,admission_date,previous_school,admission_notes) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'Active',?,?,?)",
                            (sid, tenant, admission, register_no, first, last, clean(f.get("other_names"), 60) or None, f.get("gender"), class_id, dob,
                             clean(f.get("religion"), 40) or None, clean(f.get("parent_name"), 100) or None, clean(f.get("parent_address"), 200) or None,
                             parent_email, clean(f.get("parent_phone"), 30) or None, adm_date, clean(f.get("previous_school"), 120) or None,
                             clean(f.get("admission_notes"), 300) or None))
                        stid = cur.lastrowid
                        upsert_enrollment(conn, stid, class_id)
                        photo = request.files.get("photo")
                        if photo and photo.filename:
                            err = reject_oversize(photo, "passport") or verify_image(photo, 500 * 1024, "Passport photograph")
                            ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
                            if not err and ext not in allowed_ext:
                                err = "Passport photo must be a PNG, JPG, or GIF image."
                            if err:
                                raise ValueError(err)
                            os.makedirs(photos_dir, exist_ok=True)
                            fn = f"student_{stid}.{ext}"
                            photo.save(os.path.join(photos_dir, fn))
                            conn.execute("UPDATE students SET photo_filename=? WHERE id=? AND school_id=?", (fn, stid, sid))
                        record_status(conn, sid, {"id": stid, "status": None}, "Active", adm_date, reason="Admitted", previous_school=clean(f.get("previous_school"), 120) or None)
                        log_audit(conn, session.get("role"), session.get("name"), "student_registered", f"{first} {last} — {admission}", school_id=sid)
                        conn.commit()
                        flash(f"{first} {last} registered. Admission No. {admission}" + (f", Register No. {register_no}" if register_no else "") + ".", "success")
                        return redirect(url_for("registrar_register"))
                    except ValueError as exc:
                        conn.rollback(); flash(str(exc), "error")
                    except sqlite3.IntegrityError:
                        conn.rollback(); flash("That admission or register number was just taken. Please try again.", "error")
            return render_template("registrar_register.html", classes=classes, today=today, form=form, next_adm=next_admission_no(conn, sid))
        finally:
            conn.close()

    # ------------------------------------------------------------------ list / manage
    @app.route("/registrar/students")
    @registrar_only
    def registrar_students():
        conn = get_db()
        try:
            sid = current_school_id()
            q = clean(request.args.get("q"), 60).lower(); st = clean(request.args.get("status"), 40); cl = request.args.get("class_id", type=int)
            sql = "SELECT s.*, c.name class_name FROM students s JOIN classes c ON c.id=s.class_id WHERE s.school_id=? AND c.school_id=?"; args = [sid, sid]
            if q:
                sql += " AND (LOWER(s.first_name||' '||s.last_name) LIKE ? OR LOWER(s.admission_no) LIKE ? OR LOWER(COALESCE(s.register_no,'')) LIKE ?)"; args += [f"%{q}%"] * 3
            if st:
                sql += " AND COALESCE(s.status,'Active')=?"; args.append(st)
            if cl:
                sql += " AND s.class_id=?"; args.append(cl)
            rows = conn.execute(sql + " ORDER BY c.name, s.last_name LIMIT 500", args).fetchall()
            classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (sid,)).fetchall()
            return render_template("registrar_students.html", students=rows, classes=classes, statuses=status_options(conn, sid), q=q, status=st, class_id=cl, student_full_name=student_full_name)
        finally:
            conn.close()

    def load_student(conn, sid, student_id):
        return conn.execute("SELECT s.*, c.name class_name FROM students s JOIN classes c ON c.id=s.class_id WHERE s.id=? AND s.school_id=? AND c.school_id=?", (student_id, sid, sid)).fetchone()

    @app.route("/registrar/students/<int:student_id>")
    @registrar_only
    def registrar_student(student_id):
        conn = get_db()
        try:
            sid = current_school_id()
            stu = load_student(conn, sid, student_id)
            if not stu:
                flash("Student not found.", "error"); return redirect(url_for("registrar_students"))
            hist = conn.execute("SELECT * FROM student_status_history WHERE school_id=? AND student_id=? ORDER BY id DESC", (sid, student_id)).fetchall()
            classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY name", (sid,)).fetchall()
            return render_template("registrar_student.html", s=stu, history=hist, statuses=status_options(conn, sid), classes=classes, today=school_today(conn, sid), student_full_name=student_full_name)
        finally:
            conn.close()

    @app.route("/registrar/students/<int:student_id>/status", methods=["POST"])
    @registrar_only
    def registrar_set_status(student_id):
        conn = get_db()
        try:
            sid = current_school_id()
            stu = load_student(conn, sid, student_id)
            if not stu:
                flash("Student not found.", "error"); return redirect(url_for("registrar_students"))
            new = clean(request.form.get("status"), 40)
            if new not in status_options(conn, sid):
                flash("Choose a valid status.", "error"); return redirect(url_for("registrar_student", student_id=student_id))
            today = school_today(conn, sid)
            eff = clean(request.form.get("effective_date"), 10) or today
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", eff) or eff > today:
                flash("The effective date cannot be in the future.", "error"); return redirect(url_for("registrar_student", student_id=student_id))
            reason = clean(request.form.get("reason"), 300) or None
            destination = clean(request.form.get("destination_school"), 120) or None
            if new == "Transferred" and not destination:
                flash("Enter the school the student is transferring to.", "error"); return redirect(url_for("registrar_student", student_id=student_id))
            old = stu["status"] or "Active"
            if new == old:
                flash("The student already has that status.", "error"); return redirect(url_for("registrar_student", student_id=student_id))
            active = 1 if is_active_like(conn, sid, new) else 0
            record_status(conn, sid, stu, new, eff, reason, destination)
            conn.execute("UPDATE students SET status=?, is_active=?, transfer_date=?, transfer_destination=? WHERE id=? AND school_id=?",
                         (new, active, eff if new == "Transferred" else None, destination if new == "Transferred" else None, student_id, sid))
            log_audit(conn, session.get("role"), session.get("name"), "student_status", f"{student_full_name(stu)}: {old} → {new}", school_id=sid)
            conn.commit()
            flash(f"{student_full_name(stu)} is now {new}. Their results, attendance and history are kept.", "success")
            return redirect(url_for("registrar_student", student_id=student_id))
        finally:
            conn.close()

    @app.route("/registrar/statuses", methods=["POST"])
    @registrar_only
    def registrar_add_status():
        conn = get_db()
        try:
            sid = current_school_id()
            label = clean(request.form.get("label"), 30)
            if not label or CLEAN.search(label):
                flash("Enter a status name.", "error")
            elif label.lower() in {x.lower() for x in status_options(conn, sid)}:
                flash("That status already exists.", "error")
            else:
                conn.execute("INSERT INTO student_status_options(school_id,tenant_id,label,active_like) VALUES (?,?,?,?)", (sid, current_tenant_id(), label, 1 if request.form.get("active_like") else 0))
                conn.commit(); flash(f"Status “{label}” added.", "success")
            return redirect(url_for("registrar_dashboard"))
        finally:
            conn.close()

    # ------------------------------------------------------------------ class registers (Class Teacher / Form Teacher)
    def own_class(conn, sid, class_id):
        crow = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, sid)).fetchone()
        if not crow:
            return None
        if session.get("role") in ("admin", "sub_admin") or is_registrar():
            return crow
        if "Class Teacher / Form Teacher" in session_roles() and class_id in form_teacher_class_ids(conn, session.get("user_id")):
            return crow
        return None

    @app.route("/my-class/<int:class_id>/register", methods=["GET", "POST"])
    @login_required()
    def class_register(class_id):
        conn = get_db()
        try:
            sid = current_school_id()
            crow = own_class(conn, sid, class_id)
            if not crow:
                flash("You can open the register only for your own class.", "error"); return redirect(url_for("dashboard"))
            if request.method == "POST":
                action = request.form.get("action")
                students = conn.execute("SELECT * FROM students WHERE class_id=? AND school_id=? AND COALESCE(status,'Active')='Active' ORDER BY last_name, first_name", (class_id, sid)).fetchall()
                if action == "auto":
                    n = 0
                    for s in students:
                        if not (s["register_no"] or "").strip():
                            conn.execute("UPDATE students SET register_no=? WHERE id=? AND school_id=?", (next_register_no(conn, sid, crow), s["id"], sid)); n += 1
                    conn.commit(); flash(f"{n} register number(s) assigned." if n else "Every student already has a register number.", "success")
                else:
                    taken_err = []
                    for s in students:
                        key = f"register_no_{s['id']}"
                        if key not in request.form:
                            continue
                        val = clean(request.form.get(key), 40) or None
                        if CLEAN.search(val or ""):
                            taken_err.append("Angle brackets are not allowed."); continue
                        if (val or "") == (s["register_no"] or ""):
                            continue
                        if val and conn.execute("SELECT 1 FROM students WHERE school_id=? AND LOWER(TRIM(register_no))=LOWER(?) AND id<>?", (sid, val, s["id"])).fetchone():
                            taken_err.append(f"Register number {val} is already used by another student."); continue
                        conn.execute("UPDATE students SET register_no=? WHERE id=? AND school_id=?", (val, s["id"], sid))
                    conn.commit()
                    for e in taken_err: flash(e, "error")
                    if not taken_err: flash("Register saved.", "success")
                return redirect(url_for("class_register", class_id=class_id))
            students = conn.execute("SELECT * FROM students WHERE class_id=? AND school_id=? ORDER BY COALESCE(status,'Active')<>'Active', last_name, first_name", (class_id, sid)).fetchall()
            return render_template("class_register.html", class_row=crow, students=students, student_full_name=student_full_name)
        finally:
            conn.close()
