"""Student / Staff profile management, custom fields and audit views (V60).

Registered from app.py with register_profile_routes(app, helpers). Every route resolves the school and
tenant from the authenticated session; a school or tenant id in a URL/form is never trusted.
"""
import json
import os
import sqlite3
import uuid
from functools import wraps

from school.core import (abort, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for, HTTPException)

import profile_core as pc


def register_profile_routes(app, h):
    get_db = h["get_db"]
    login_required = h["login_required"]
    student_login_required = h["student_login_required"]
    platform_admin_required = h["platform_admin_required"]
    student_full_name = h["student_full_name"]
    STUDENT_PHOTOS_DIR = h["STUDENT_PHOTOS_DIR"]
    STAFF_PHOTOS_DIR = h["STAFF_PHOTOS_DIR"]
    SIGNATURES_DIR = h["SIGNATURES_DIR"]
    CUSTOM_FILES_DIR = h["CUSTOM_FILES_DIR"]
    form_teacher_class_ids = h["form_teacher_class_ids"]
    active_role_assignments = h["active_role_assignments"]
    security_event = h["security_event"]
    POSITION_LABELS = h["POSITION_LABELS"]

    # ------------------------------------------------------------------ small helpers
    def school_id():
        return session.get("school_id")

    def tenant_id():
        return session.get("tenant_id")

    def actor():
        if session.get("student_id") and session.get("role") == "student":
            return {"type": "student", "id": session["student_id"], "name": session.get("name") or "student",
                    "role": "student", "school_id": school_id(), "tenant_id": tenant_id()}
        return {"type": "staff", "id": session.get("user_id"), "name": session.get("name"),
                "role": session.get("role"), "school_id": school_id(), "tenant_id": tenant_id()}

    def ip():
        return request.headers.get("X-Forwarded-For", request.remote_addr or "")[:64].split(",")[0].strip()

    def deny(conn=None, what="profile"):
        """403 Forbidden, with the attempt recorded."""
        try:
            c = conn or get_db()
            security_event(c, "profile_access_denied", "denied", f"{request.method} {request.path}", what)
            c.commit()
            if conn is None:
                c.close()
        except Exception:
            app.logger.exception("Could not record denied access")
        abort(403)

    def is_school_admin():
        return session.get("role") == "admin"

    def has_registrar_role(conn):
        try:
            rows = active_role_assignments(conn, session.get("user_id"), school_id())
        except Exception:
            return False
        return any(r["role"] == "Registrar / Admissions Officer" for r in rows)

    def student_row(conn, student_id):
        """Tenant-resolved student lookup: the class must belong to the caller's school AND tenant."""
        return conn.execute(
            "SELECT s.* FROM students s JOIN classes c ON c.id=s.class_id JOIN schools sc ON sc.id=c.school_id "
            "WHERE s.id=? AND c.school_id=? AND sc.tenant_id=?", (student_id, school_id(), tenant_id())).fetchone()

    def staff_student_level(conn, student):
        """'admin' | 'staff' | None — what this logged-in staff member may do to this student's profile."""
        if session.get("role") in ("admin", "sub_admin"):
            return "admin"
        if student["class_id"] in form_teacher_class_ids(conn, session["user_id"]) or has_registrar_role(conn):
            return "staff"
        return None

    def render_error_page(msg, code):
        return render_template("profile_denied.html", message=msg), code

    @app.errorhandler(403)
    def _forbidden(_e):
        return render_error_page("You do not have permission to do that.", 403)

    def img_url_student_self():
        return url_for("student_self_photo")

    # ------------------------------------------------------------------ shared form model
    def build_rows(specs, values, editable_fn, errors=None):
        rows = []
        for sp in specs:
            r = dict(sp)
            r["value"] = values.get(sp["key"], "") if values.get(sp["key"]) is not None else ""
            r["editable"] = editable_fn(sp)
            r["error"] = (errors or {}).get(sp["key"])
            rows.append(r)
        return rows

    def custom_rows(fields, echo, can_edit_all, errors=None):
        rows = []
        for f in fields:
            r = dict(f)
            r["value"] = echo.get(f["id"], "")
            r["editable"] = can_edit_all or bool(f["is_editable"])
            r["error"] = (errors or {}).get(f"cf_{f['id']}")
            rows.append(r)
        return rows

    def cleaned_specs(specs, form, editable_fn, current, dob_hint=None):
        """Validate every editable system field. Returns (new_values, errors)."""
        new, errors = {}, {}
        for sp in specs:
            k = sp["key"]
            if not editable_fn(sp):
                new[k] = current[k] if current is not None and k in current.keys() else None
                continue
            ctx = dob_hint if sp["kind"] == "admission_date" else None
            v, err = pc.check_value(sp, form.get(k, ""), dob_context=ctx)
            if err:
                errors[k] = err
            new[k] = v
            if k in ("date_of_birth",) and v:
                dob_hint = pc.parse_date(v)
        return new, errors

    def verify_persisted(conn, table, row_id, expected, keys):
        row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (row_id,)).fetchone()
        if not row:
            return False
        for k in keys:
            if (row[k] or None) != (expected.get(k) or None):
                return False
        return True

    def cleanup(paths):
        for p in paths:
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass

    # ================================================================== STUDENT PROFILE
    def student_editable_fn(mode):
        if mode == "admin":
            return lambda sp: True
        if mode == "staff":
            return lambda sp: sp["staff_edit"] and not sp["admin_only"]
        return lambda sp: sp["self_edit"]

    def process_student(conn, student, mode, form, files):
        """Validate then save a student profile atomically.
        Returns (ok, errors, echo_values, custom_echo)."""
        sid = student["id"]
        editable = student_editable_fn(mode)
        new, errors = cleaned_specs(pc.STUDENT_SPECS, form, editable, student)
        # uniqueness pre-checks (friendly messages; the database triggers/indexes are the guarantee)
        if "admission_no" not in errors and editable({"key": "admission_no", "self_edit": False, "staff_edit": False, "admin_only": True}) \
                and new.get("admission_no"):
            clash = conn.execute(
                "SELECT 1 FROM students s JOIN classes c ON c.id=s.class_id WHERE c.school_id=? AND s.id<>? "
                "AND LOWER(TRIM(s.admission_no))=LOWER(?)", (school_id(), sid, new["admission_no"])).fetchone()
            if clash:
                errors["admission_no"] = "Admission No. / Register No. is already used by another student in this school."
        if new.get("email") and "email" not in errors:
            if conn.execute("SELECT 1 FROM students WHERE school_id=? AND id<>? AND LOWER(email)=LOWER(?)",
                            (student["school_id"], sid, new["email"])).fetchone():
                errors["email"] = "Email is already used by another student in this school."
        # passport photograph
        blob = ext = None
        if files.get("photo") and files["photo"].filename:
            blob, ext, perr = pc.read_image_upload(files["photo"], pc.PASSPORT_MAX, "Passport photograph")
            if perr:
                errors["photo"] = perr
        # custom fields
        fields = pc.load_fields(conn, school_id(), tenant_id(), "student")
        existing = pc.load_values(conn, school_id(), "student", sid)
        updates, cerrors, cecho = pc.collect_custom(fields, form, files, existing, mode in ("admin", "staff"))
        errors.update(cerrors)
        if not cerrors:
            errors.update(pc.check_custom_unique_preflight(conn, fields, updates, sid))
        echo = dict(new)
        for k in echo:
            if echo[k] is None:
                echo[k] = form.get(k, "") if editable({"key": k, "self_edit": True, "staff_edit": True, "admin_only": False}) else (student[k] if k in student.keys() else "")
        if errors:
            return False, errors, echo, cecho

        written, new_photo_path, old_photo_path = [], None, None
        try:
            keys = [sp["key"] for sp in pc.STUDENT_SPECS if editable(sp)]
            sets = ", ".join(f"{k}=?" for k in keys)
            vals = [new[k] for k in keys]
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"UPDATE students SET {sets}, profile_updated_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=?",
                         vals + [sid, student["school_id"]])
            photo_changed = False
            if blob is not None:
                os.makedirs(STUDENT_PHOTOS_DIR, exist_ok=True)
                fname = f"student_{sid}_{uuid.uuid4().hex[:8]}.{ext}"
                new_photo_path = os.path.join(STUDENT_PHOTOS_DIR, fname)
                with open(new_photo_path, "wb") as fh:
                    fh.write(blob)
                conn.execute("UPDATE students SET photo_filename=? WHERE id=?", (fname, sid))
                if student["photo_filename"]:
                    old_photo_path = os.path.join(STUDENT_PHOTOS_DIR, student["photo_filename"])
                photo_changed = True
            elif form.get("remove_photo") == "1" and student["photo_filename"]:
                conn.execute("UPDATE students SET photo_filename=NULL WHERE id=?", (sid,))
                old_photo_path = os.path.join(STUDENT_PHOTOS_DIR, student["photo_filename"])
                photo_changed = True
            cerr2, written, replaced = pc.save_custom(conn, school_id(), tenant_id(), "student", sid, updates, fields,
                                                       session.get("user_id"), CUSTOM_FILES_DIR)
            if cerr2:
                raise sqlite3.IntegrityError("custom unique")
            changes = pc.diff(student, new, keys)
            if photo_changed:
                changes["passport_photo"] = "changed"
            changed_custom = [f["label"] for f in fields if f["id"] in updates and updates[f["id"]][0] != existing.get(f["id"])]
            if changed_custom:
                changes["custom_fields"] = changed_custom
            pc.audit(conn, actor(), f"student_profile_updated_by_{mode}", "student", sid, changes, ip=ip())
            if not verify_persisted(conn, "students", sid, new, keys):
                raise RuntimeError("Saved data could not be read back")
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            cleanup([new_photo_path] + list(written))
            app.logger.warning("Student profile save rejected by database: %s", exc)
            msg = str(exc).lower()
            if "admission" in msg:
                errors["admission_no"] = "Admission No. / Register No. is already used by another student in this school."
            elif "email" in msg:
                errors["email"] = "Email is already used by another student in this school."
            else:
                for f in fields:
                    errors[f"cf_{f['id']}"] = errors.get(f"cf_{f['id']}") or None
                errors = {k: v for k, v in errors.items() if v}
                errors["_form"] = "A value you entered is already used by another record in your school."
            return False, errors, echo, cecho
        except Exception:
            conn.rollback()
            cleanup([new_photo_path] + list(written))
            app.logger.exception("Student profile save failed")
            errors["_form"] = "The profile could not be saved because of a server error. Your entries are kept — please try again."
            return False, errors, echo, cecho
        cleanup([old_photo_path] + [os.path.join(CUSTOM_FILES_DIR, json.loads(r)["stored"]) for r in replaced if r])
        return True, {}, echo, cecho

    def student_form_context(conn, student, mode, echo=None, cecho=None, errors=None):
        editable = student_editable_fn(mode)
        values = dict(echo) if echo is not None else {sp["key"]: student[sp["key"]] for sp in pc.STUDENT_SPECS}
        fields = pc.load_fields(conn, school_id(), tenant_id(), "student")
        existing = pc.load_values(conn, school_id(), "student", student["id"])
        if cecho is None:
            cecho = pc.default_echo(fields, existing)
        cls = conn.execute("SELECT name FROM classes WHERE id=?", (student["class_id"],)).fetchone()
        can_all = mode in ("admin", "staff")
        return dict(
            title="My Profile" if mode == "self" else f"Edit Profile — {student_full_name(student)}",
            kind="student",
            rows=build_rows(pc.STUDENT_SPECS, values, editable, errors),
            custom=custom_rows(fields, cecho, can_all, errors),
            errors=errors or {}, form_error=(errors or {}).get("_form"),
            action=url_for("student_self_profile") if mode == "self" else url_for("student_profile_edit", student_id=student["id"]),
            cancel=url_for("student_dashboard") if mode == "self" else url_for("student_profile", student_id=student["id"]),
            photo_url=(url_for("student_self_photo") if mode == "self" else url_for("student_photo", student_id=student["id"])) if student["photo_filename"] else None,
            photo_error=(errors or {}).get("photo"),
            readonly=[("Class / Arm", cls["name"] if cls else "—"), ("Status", student["status"] or "Active")],
            states=pc.NIGERIAN_STATES, mode=mode, has_signature=False,
            entity_id=student["id"], today=pc._today().isoformat(),
        )

    @app.route("/student/profile", methods=["GET", "POST"])
    @student_login_required
    def student_self_profile():
        conn = get_db()
        try:
            student = student_row(conn, session["student_id"])
            if not student:
                session.clear()
                flash("Your account could not be linked to a school record. Please contact your school.", "error")
                return redirect(url_for("student_login"))
            session["name"] = student_full_name(student)
            if request.method == "POST":
                ok, errors, echo, cecho = process_student(conn, student, "self", request.form, request.files)
                if ok:
                    flash("Profile saved successfully.", "success")
                    return redirect(url_for("student_self_profile"))
                ctx = student_form_context(conn, student, "self", echo, cecho, errors)
                return render_template("profile_form.html", **ctx), 422
            return render_template("profile_form.html", **student_form_context(conn, student, "self"))
        finally:
            conn.close()

    @app.route("/student/profile/photo")
    @student_login_required
    def student_self_photo():
        conn = get_db()
        try:
            student = student_row(conn, session["student_id"])
        finally:
            conn.close()
        if not student or not student["photo_filename"]:
            return "", 404
        return send_from_directory(STUDENT_PHOTOS_DIR, student["photo_filename"])

    @app.route("/students/<int:student_id>/profile/edit", methods=["GET", "POST"])
    @login_required()
    def student_profile_edit(student_id):
        conn = get_db()
        try:
            student = student_row(conn, student_id)
            if not student:
                abort(404)
            mode = staff_student_level(conn, student)
            if not mode:
                deny(conn, "student_profile")
            if request.method == "POST":
                ok, errors, echo, cecho = process_student(conn, student, mode, request.form, request.files)
                if ok:
                    flash("Profile saved successfully.", "success")
                    return redirect(url_for("student_profile_edit", student_id=student_id))
                return render_template("profile_form.html", **student_form_context(conn, student, mode, echo, cecho, errors)), 422
            return render_template("profile_form.html", **student_form_context(conn, student, mode))
        finally:
            conn.close()

    # ================================================================== STAFF PROFILE
    def staff_row(conn, user_id):
        return conn.execute("SELECT * FROM users WHERE id=? AND school_id=? AND tenant_id=?",
                            (user_id, school_id(), tenant_id())).fetchone()

    def staff_mode(target):
        if target["id"] == session.get("user_id"):
            return "self"
        if session.get("role") == "admin":
            return "admin"
        return None

    def staff_editable_fn(mode):
        if mode == "admin":
            return lambda sp: True
        return lambda sp: sp["self_edit"]

    def process_staff(conn, target, mode, form, files):
        uid = target["id"]
        editable = staff_editable_fn(mode)
        new, errors = cleaned_specs(pc.STAFF_SPECS, form, editable, target)
        new = dict(new)
        if new.get("username") and "username" not in errors and editable({"key": "username", "self_edit": False, "admin_only": True}):
            if conn.execute("SELECT 1 FROM users WHERE id<>? AND LOWER(username)=LOWER(?)", (uid, new["username"])).fetchone():
                errors["username"] = "Username is already taken."
        if new.get("email") and "email" not in errors:
            if conn.execute("SELECT 1 FROM users WHERE id<>? AND LOWER(email)=LOWER(?)", (uid, new["email"])).fetchone():
                errors["email"] = "Email is already used by another account."
        if new.get("phone") and "phone" not in errors:
            if conn.execute("SELECT 1 FROM users WHERE id<>? AND phone=?", (uid, new["phone"])).fetchone():
                errors["phone"] = "Phone number is already used by another account."
        if new.get("staff_id") and "staff_id" not in errors and editable({"key": "staff_id", "self_edit": False, "admin_only": True}):
            if conn.execute("SELECT 1 FROM users WHERE id<>? AND school_id=? AND LOWER(staff_id)=LOWER(?)",
                            (uid, school_id(), new["staff_id"])).fetchone():
                errors["staff_id"] = "Staff / Employee ID is already used by another staff member in this school."
        pblob = pext = sblob = sext = None
        if files.get("photo") and files["photo"].filename:
            pblob, pext, e = pc.read_image_upload(files["photo"], pc.PASSPORT_MAX, "Passport photograph")
            if e:
                errors["photo"] = e
        if files.get("signature") and files["signature"].filename:
            sblob, sext, e = pc.read_image_upload(files["signature"], pc.SIGNATURE_MAX, "Signature")
            if e:
                errors["signature"] = e
        fields = pc.load_fields(conn, school_id(), tenant_id(), "staff")
        existing = pc.load_values(conn, school_id(), "staff", uid)
        # Staff edit custom values only where the field is marked editable; School Admin may edit all.
        updates, cerrors, cecho = pc.collect_custom(fields, form, files, existing, mode == "admin")
        errors.update(cerrors)
        if not cerrors:
            errors.update(pc.check_custom_unique_preflight(conn, fields, updates, uid))
        echo = dict(new)
        for k in echo:
            if echo[k] is None:
                echo[k] = form.get(k, "") if editable({"key": k, "self_edit": True, "admin_only": False}) else (target[k] if k in target.keys() else "")
        if errors:
            return False, errors, echo, cecho

        written, made, olds = [], [], []
        try:
            keys = [sp["key"] for sp in pc.STAFF_SPECS if editable(sp)]
            full_name = " ".join(x for x in (new.get("first_name"), new.get("surname"), new.get("other_names")) if x)
            conn.execute("BEGIN IMMEDIATE")
            sets = ", ".join(f"{k}=?" for k in keys)
            conn.execute(f"UPDATE users SET {sets}, name=?, profile_updated_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=? AND tenant_id=?",
                         [new[k] for k in keys] + [full_name or target["name"], uid, school_id(), tenant_id()])
            media = {}
            if pblob is not None:
                os.makedirs(STAFF_PHOTOS_DIR, exist_ok=True)
                fn = f"staff_{uid}_{uuid.uuid4().hex[:8]}.{pext}"
                with open(os.path.join(STAFF_PHOTOS_DIR, fn), "wb") as fh:
                    fh.write(pblob)
                made.append(os.path.join(STAFF_PHOTOS_DIR, fn))
                conn.execute("UPDATE users SET photo_filename=? WHERE id=?", (fn, uid))
                if target["photo_filename"]:
                    olds.append(os.path.join(STAFF_PHOTOS_DIR, target["photo_filename"]))
                media["passport_photo"] = "changed"
            if sblob is not None:
                os.makedirs(SIGNATURES_DIR, exist_ok=True)
                fn = f"signature_{uid}_{uuid.uuid4().hex[:8]}.{sext}"
                with open(os.path.join(SIGNATURES_DIR, fn), "wb") as fh:
                    fh.write(sblob)
                made.append(os.path.join(SIGNATURES_DIR, fn))
                conn.execute("UPDATE users SET signature_filename=? WHERE id=?", (fn, uid))
                if target["signature_filename"]:
                    olds.append(os.path.join(SIGNATURES_DIR, target["signature_filename"]))
                media["signature"] = "changed"
            # Name changes are never silent: previous and new values, who, when, plus a notice to the School Admin.
            old_parts = (target["first_name"], target["surname"], target["other_names"])
            new_parts = (new.get("first_name"), new.get("surname"), new.get("other_names"))
            name_changed = bool(full_name) and (target["name"] or "").strip() != full_name.strip()
            if name_changed and mode in ("self", "admin"):
                conn.execute(
                    "INSERT INTO staff_name_history(school_id,tenant_id,user_id,previous_first_name,previous_surname,previous_other_names,previous_name,"
                    "new_first_name,new_surname,new_other_names,new_name,changed_by,changed_by_name,admin_notified) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                    (school_id(), tenant_id(), uid, *old_parts, target["name"], *new_parts, full_name, session.get("user_id"), session.get("name")))
                if mode == "self":
                    conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",
                                 ("System", school_id(), "admin", "Staff name changed",
                                  f"{target['name']} changed their name to {full_name} on {pc._today().isoformat()}. See the staff profile history."))
                pc.audit(conn, actor(), "staff_name_changed", "staff", uid, {"name": [target["name"], full_name], "changed_by": session.get("name")}, ip=ip())
            cerr2, written, replaced = pc.save_custom(conn, school_id(), tenant_id(), "staff", uid, updates, fields,
                                                       session.get("user_id"), CUSTOM_FILES_DIR)
            if cerr2:
                raise sqlite3.IntegrityError("custom unique")
            changes = pc.diff(target, new, keys)
            changes.update(media)
            changed_custom = [f["label"] for f in fields if f["id"] in updates and updates[f["id"]][0] != existing.get(f["id"])]
            if changed_custom:
                changes["custom_fields"] = changed_custom
            pc.audit(conn, actor(), f"staff_profile_updated_by_{mode}", "staff", uid, changes, ip=ip())
            if not verify_persisted(conn, "users", uid, new, keys):
                raise RuntimeError("Saved data could not be read back")
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            cleanup(made + list(written))
            app.logger.warning("Staff profile save rejected by database: %s", exc)
            errors["_form"] = "Username, email, phone, Staff ID or a unique custom value is already used by another record."
            return False, errors, echo, cecho
        except Exception:
            conn.rollback()
            cleanup(made + list(written))
            app.logger.exception("Staff profile save failed")
            errors["_form"] = "The profile could not be saved because of a server error. Your entries are kept — please try again."
            return False, errors, echo, cecho
        cleanup(olds + [os.path.join(CUSTOM_FILES_DIR, json.loads(r)["stored"]) for r in replaced if r])
        if mode == "self":
            session["name"] = full_name or session.get("name")
        return True, {}, echo, cecho

    def staff_form_context(conn, target, mode, echo=None, cecho=None, errors=None):
        editable = staff_editable_fn(mode)
        values = dict(echo) if echo is not None else {sp["key"]: target[sp["key"]] for sp in pc.STAFF_SPECS}
        fields = pc.load_fields(conn, school_id(), tenant_id(), "staff")
        existing = pc.load_values(conn, school_id(), "staff", target["id"])
        if cecho is None:
            cecho = pc.default_echo(fields, existing)
        form_classes = conn.execute("SELECT name FROM classes WHERE form_teacher_id=? AND school_id=? ORDER BY name",
                                    (target["id"], school_id())).fetchall()
        subjects = conn.execute("SELECT DISTINCT s.name FROM class_subjects cs JOIN subjects s ON s.id=cs.subject_id "
                                "WHERE cs.teacher_id=? ORDER BY s.name", (target["id"],)).fetchall()
        return dict(
            title="My Profile" if mode == "self" else f"Edit Profile — {target['name']}",
            kind="staff",
            rows=build_rows(pc.STAFF_SPECS, values, editable, errors),
            custom=custom_rows(fields, cecho, mode == "admin", errors),
            errors=errors or {}, form_error=(errors or {}).get("_form"),
            action=url_for("staff_profile_edit", user_id=target["id"]),
            cancel=url_for("staff_profile", user_id=target["id"]),
            photo_url=url_for("staff_photo", user_id=target["id"]) if target["photo_filename"] else None,
            photo_error=(errors or {}).get("photo"),
            signature_url=url_for("staff_signature", user_id=target["id"]) if target["signature_filename"] else None,
            signature_error=(errors or {}).get("signature"),
            readonly=[
                ("Name used at signup", target["signup_name"] or target["name"]),
                ("Role / Position", POSITION_LABELS.get(target["position"], target["position"] or (target["role"] or "").title())),
                ("Assigned Class / Form", ", ".join(r["name"] for r in form_classes) or "—"),
                ("Subjects assigned by the school", ", ".join(r["name"] for r in subjects) or "—"),
            ],
            states=pc.NIGERIAN_STATES, mode=mode, has_signature=True,
            entity_id=target["id"], today=pc._today().isoformat(),
        )

    @app.route("/staff/<int:user_id>/edit", methods=["GET", "POST"])
    @login_required()
    def staff_profile_edit(user_id):
        conn = get_db()
        try:
            target = staff_row(conn, user_id)
            if not target:
                # A missing row and a row in another school look the same to the caller.
                abort(404)
            mode = staff_mode(target)
            if not mode:
                deny(conn, "staff_profile")
            if request.method == "POST":
                ok, errors, echo, cecho = process_staff(conn, target, mode, request.form, request.files)
                if ok:
                    flash("Profile saved successfully.", "success")
                    return redirect(url_for("staff_profile_edit", user_id=user_id))
                return render_template("profile_form.html", **staff_form_context(conn, target, mode, echo, cecho, errors)), 422
            return render_template("profile_form.html", **staff_form_context(conn, target, mode))
        finally:
            conn.close()

    # ================================================================== custom-field files
    @app.route("/custom-files/<int:field_id>/<entity_type>/<int:entity_id>")
    def custom_field_file(field_id, entity_type, entity_id):
        if "school_id" not in session or entity_type not in ("student", "staff"):
            abort(404)
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT v.value FROM custom_field_values v JOIN custom_fields f ON f.id=v.field_id "
                "WHERE v.field_id=? AND v.entity_type=? AND v.entity_id=? AND v.school_id=? AND v.tenant_id=? AND f.field_type='file'",
                (field_id, entity_type, entity_id, school_id(), tenant_id())).fetchone()
            if not row:
                abort(404)
            allowed = False
            if entity_type == "student":
                if session.get("role") == "student":
                    allowed = session.get("student_id") == entity_id
                elif "user_id" in session:
                    st = student_row(conn, entity_id)
                    allowed = bool(st and staff_student_level(conn, st))
            else:
                allowed = "user_id" in session and (session.get("user_id") == entity_id or session.get("role") == "admin")
            if not allowed:
                deny(conn, "custom_file")
        finally:
            conn.close()
        meta = json.loads(row["value"])
        return send_from_directory(CUSTOM_FILES_DIR, meta["stored"], as_attachment=True, download_name=meta.get("name") or "file")

    # ================================================================== CUSTOM FIELD ADMIN
    def admin_only(f):
        @wraps(f)
        @login_required()
        def wrapped(*a, **kw):
            if session.get("role") != "admin":
                deny(None, "custom_fields")
            return f(*a, **kw)
        return wrapped

    def field_or_404(conn, fid):
        f = conn.execute("SELECT * FROM custom_fields WHERE id=? AND school_id=? AND tenant_id=?",
                         (fid, school_id(), tenant_id())).fetchone()
        if not f:
            abort(404)
        return f

    def renumber(conn, applies_to):
        rows = conn.execute("SELECT id FROM custom_fields WHERE school_id=? AND applies_to=? AND is_archived=0 ORDER BY display_order,id",
                            (school_id(), applies_to)).fetchall()
        for i, r in enumerate(rows, 1):
            conn.execute("UPDATE custom_fields SET display_order=? WHERE id=?", (i, r["id"]))

    def usage_count(conn, fid):
        return conn.execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=? AND value IS NOT NULL AND value<>''", (fid,)).fetchone()[0]

    def validate_default(ftype, value, options):
        v = pc.clean(value)
        if not v:
            return None, None
        if ftype == "short_text":
            return (v, None) if len(v) <= 200 else (None, "Default value is too long.")
        if ftype == "long_text":
            return (v, None) if len(v) <= 2000 else (None, "Default value is too long.")
        if ftype == "number":
            import decimal
            try:
                decimal.Decimal(v)
                return v, None
            except decimal.InvalidOperation:
                return None, "Default value must be a number."
        if ftype == "date":
            d = pc.parse_date(v)
            return (d.isoformat(), None) if d else (None, "Default value must be a valid date.")
        if ftype == "yes_no":
            return (v.capitalize(), None) if v.lower() in ("yes", "no") else (None, "Default must be Yes or No.")
        if ftype == "phone":
            pv = pc.norm_phone(v)
            return (pv, None) if pc.PHONE_RE.match(pv) else (None, "Default value is not a valid phone number.")
        if ftype == "email":
            return (v.lower(), None) if pc.EMAIL_RE.match(v) else (None, "Default value is not a valid email.")
        if ftype == "select":
            return (v, None) if v in options else (None, "Default must be one of the options.")
        if ftype == "multiselect":
            parts = [x.strip() for x in v.split("|") if x.strip()]
            return ("|".join(parts), None) if all(p in options for p in parts) else (None, "Default values must be from the options.")
        return None, "Defaults are not supported for this type."

    def parse_option_rows(form):
        """Rows: opt_id[], opt_text[], opt_remove[] (indexes). Order = row order."""
        ids, texts = form.getlist("opt_id"), form.getlist("opt_text")
        removes = set(form.getlist("opt_remove"))
        out = []
        for i, t in enumerate(texts):
            rid = ids[i] if i < len(ids) else ""
            out.append({"id": int(rid) if rid.isdigit() else None, "text": pc.clean(t), "remove": str(i) in removes})
        return out

    def field_actor_diff(old, new, keys):
        return pc.diff(old, new, keys)

    @app.route("/admin/custom-fields")
    @admin_only
    def admin_custom_fields():
        tab = "staff" if request.args.get("tab") == "staff" else "student"
        show_archived = request.args.get("archived") == "1"
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM custom_fields WHERE school_id=? AND tenant_id=? AND applies_to=? "
                + ("" if show_archived else "AND is_archived=0 ") + "ORDER BY is_archived, display_order, id",
                (school_id(), tenant_id(), tab)).fetchall()
            fields = [dict(r, usage=usage_count(conn, r["id"])) for r in rows]
        finally:
            conn.close()
        return render_template("admin_custom_fields.html", tab=tab, fields=fields, show_archived=show_archived,
                               type_labels=dict(pc.FIELD_TYPES))

    @app.route("/admin/custom-fields/new", methods=["GET", "POST"])
    @admin_only
    def admin_custom_field_new():
        applies_to = request.values.get("applies_to", "student")
        if applies_to not in ("student", "staff"):
            abort(400)
        form_data, errors = {"applies_to": applies_to, "is_active": "1", "is_editable": "1", "field_type": "short_text"}, {}
        options_rows = [{"id": None, "text": ""}]
        if request.method == "POST":
            form_data = request.form.to_dict()
            form_data["applies_to"] = applies_to
            conn = get_db()
            try:
                label = pc.clean(request.form.get("label"))
                ftype = request.form.get("field_type", "")
                desc = pc.clean_multiline(request.form.get("description"))[:300]
                is_req = 1 if request.form.get("is_required") else 0
                is_uniq = 1 if request.form.get("is_unique") else 0
                is_edit = 1 if request.form.get("is_editable") else 0
                is_act = 1 if request.form.get("is_active") else 0
                if len(label) < 2 or len(label) > 60:
                    errors["label"] = "Field name must be 2 to 60 characters."
                elif pc.system_label_clash(label):
                    errors["label"] = "That name is reserved for a protected system field. Choose a different name."
                elif conn.execute("SELECT 1 FROM custom_fields WHERE school_id=? AND applies_to=? AND LOWER(label)=LOWER(?) AND is_archived=0",
                                  (school_id(), applies_to, label)).fetchone():
                    errors["label"] = "A field with this name already exists. Use a clearly different name."
                if ftype not in pc.FIELD_TYPE_KEYS:
                    errors["field_type"] = "Choose a field type."
                if is_uniq and ftype not in pc.UNIQUE_CAPABLE:
                    errors["is_unique"] = "This field type cannot be marked Unique."
                orows = [r for r in parse_option_rows(request.form) if r["text"]]
                options_rows = orows or [{"id": None, "text": ""}]
                if ftype in pc.OPTION_TYPES:
                    lowered = [r["text"].lower() for r in orows]
                    if not orows:
                        errors["options"] = "Add at least one option."
                    elif len(set(lowered)) != len(lowered):
                        errors["options"] = "Options must be different from each other."
                    elif any(len(r["text"]) > 100 or "|" in r["text"] for r in orows):
                        errors["options"] = "Options must be under 100 characters and cannot contain the | symbol."
                default, derr = validate_default(ftype, request.form.get("default_value"), [r["text"] for r in orows]) if ftype in pc.FIELD_TYPE_KEYS and ftype != "file" else (None, None)
                if derr:
                    errors["default_value"] = derr
                if not errors:
                    key = pc.unique_key(conn, school_id(), applies_to, label)
                    nxt = conn.execute("SELECT COALESCE(MAX(display_order),0)+1 FROM custom_fields WHERE school_id=? AND applies_to=?",
                                       (school_id(), applies_to)).fetchone()[0]
                    order_in = request.form.get("display_order", "").strip()
                    order = int(order_in) if order_in.isdigit() and 0 < int(order_in) < 10000 else nxt
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        cur = conn.execute(
                            "INSERT INTO custom_fields(school_id,tenant_id,applies_to,field_key,label,description,field_type,is_required,is_unique,is_editable,default_value,is_active,display_order,created_by,created_by_name,updated_by,updated_by_name) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (school_id(), tenant_id(), applies_to, key, label, desc or None, ftype, is_req, is_uniq, is_edit, default, is_act,
                             order, session["user_id"], session.get("name"), session["user_id"], session.get("name")))
                        fid = cur.lastrowid
                        if ftype in pc.OPTION_TYPES:
                            for i, r in enumerate(orows, 1):
                                conn.execute("INSERT INTO custom_field_options(field_id,school_id,tenant_id,option_value,display_order) VALUES(?,?,?,?,?)",
                                             (fid, school_id(), tenant_id(), r["text"], i))
                        pc.audit(conn, actor(), "custom_field_created", "custom_field", fid,
                                 {"label": label, "key": key, "applies_to": applies_to, "type": ftype, "required": is_req,
                                  "unique": is_uniq, "editable": is_edit, "active": is_act,
                                  "options": [r["text"] for r in orows] or None}, ip=ip())
                        renumber(conn, applies_to)
                        conn.commit()
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        errors["label"] = "A field with this name already exists."
                    else:
                        flash(f"Custom field '{label}' created.", "success")
                        return redirect(url_for("admin_custom_fields", tab=applies_to))
            finally:
                conn.close()
        return render_template("admin_custom_field_form.html", mode="new", data=form_data, errors=errors, options=options_rows,
                               applies_to=applies_to, field_types=pc.FIELD_TYPES, unique_capable=sorted(pc.UNIQUE_CAPABLE),
                               option_types=sorted(pc.OPTION_TYPES), key_preview=None, field=None, usage=0), (422 if errors else 200)

    @app.route("/admin/custom-fields/<int:fid>/edit", methods=["GET", "POST"])
    @admin_only
    def admin_custom_field_edit(fid):
        conn = get_db()
        try:
            f = field_or_404(conn, fid)
            ftype = f["field_type"]
            cur_opts = [dict(o) for o in conn.execute("SELECT * FROM custom_field_options WHERE field_id=? ORDER BY display_order,id", (fid,))]
            usage = usage_count(conn, fid)
            data = dict(f)
            options_rows = [{"id": o["id"], "text": o["option_value"], "inactive": not o["is_active"]} for o in cur_opts] or [{"id": None, "text": ""}]
            errors = {}
            if request.method == "POST":
                data = dict(f)
                data.update(request.form.to_dict())
                label = pc.clean(request.form.get("label"))
                desc = pc.clean_multiline(request.form.get("description"))[:300]
                is_req = 1 if request.form.get("is_required") else 0
                is_edit = 1 if request.form.get("is_editable") else 0
                is_act = 1 if request.form.get("is_active") else 0
                is_uniq = 1 if request.form.get("is_unique") else 0
                if len(label) < 2 or len(label) > 60:
                    errors["label"] = "Field name must be 2 to 60 characters."
                elif pc.system_label_clash(label):
                    errors["label"] = "That name is reserved for a protected system field."
                elif conn.execute("SELECT 1 FROM custom_fields WHERE school_id=? AND applies_to=? AND LOWER(label)=LOWER(?) AND id<>? AND is_archived=0",
                                  (school_id(), f["applies_to"], label, fid)).fetchone():
                    errors["label"] = "Another field already has this name."
                if is_uniq != f["is_unique"]:
                    if ftype not in pc.UNIQUE_CAPABLE:
                        errors["is_unique"] = "This field type cannot be Unique."
                    elif is_uniq and conn.execute(
                            "SELECT 1 FROM custom_field_values WHERE field_id=? AND value IS NOT NULL GROUP BY LOWER(value) HAVING COUNT(*)>1 LIMIT 1", (fid,)).fetchone():
                        errors["is_unique"] = "Cannot make this field Unique: existing profiles already share the same value."
                orows = parse_option_rows(request.form) if ftype in pc.OPTION_TYPES else []
                live = [r for r in orows if r["text"] and not r["remove"]]
                if ftype in pc.OPTION_TYPES:
                    lowered = [r["text"].lower() for r in live]
                    if not live:
                        errors["options"] = "Keep at least one option."
                    elif len(set(lowered)) != len(lowered):
                        errors["options"] = "Options must be different from each other."
                    elif any(len(r["text"]) > 100 or "|" in r["text"] for r in live):
                        errors["options"] = "Options must be under 100 characters and cannot contain the | symbol."
                    options_rows = [{"id": r["id"], "text": r["text"]} for r in orows if r["text"]] or options_rows
                default, derr = (None, None)
                if ftype != "file":
                    default, derr = validate_default(ftype, request.form.get("default_value"), [r["text"] for r in live])
                if derr:
                    errors["default_value"] = derr
                order_in = request.form.get("display_order", "").strip()
                order = int(order_in) if order_in.isdigit() and 0 < int(order_in) < 10000 else f["display_order"]
                if not errors:
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        conn.execute(
                            "UPDATE custom_fields SET label=?,description=?,is_required=?,is_unique=?,is_editable=?,default_value=?,is_active=?,display_order=?,"
                            "updated_by=?,updated_by_name=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=? AND tenant_id=?",
                            (label, desc or None, is_req, is_uniq, is_edit, default, is_act, order, session["user_id"], session.get("name"),
                             fid, school_id(), tenant_id()))
                        if is_uniq != f["is_unique"]:
                            if is_uniq:
                                conn.execute("UPDATE custom_field_values SET unique_value=LOWER(value) WHERE field_id=? AND value IS NOT NULL", (fid,))
                            else:
                                conn.execute("UPDATE custom_field_values SET unique_value=NULL WHERE field_id=?", (fid,))
                        opt_changes = []
                        if ftype in pc.OPTION_TYPES:
                            by_id = {o["id"]: o for o in cur_opts}
                            pos = 0
                            for r in orows:
                                if not r["text"] and r["id"] is None:
                                    continue
                                pos += 1
                                if r["id"] and r["id"] in by_id:
                                    old = by_id[r["id"]]
                                    used = conn.execute("SELECT 1 FROM custom_field_values WHERE field_id=? AND (value=? OR value LIKE ?) LIMIT 1",
                                                        (fid, old["option_value"], "%" + json.dumps(old["option_value"], ensure_ascii=False)[1:-1] + "%")).fetchone()
                                    if r["remove"] or not r["text"]:
                                        if used:
                                            conn.execute("UPDATE custom_field_options SET is_active=0,display_order=? WHERE id=?", (pos, old["id"]))
                                            opt_changes.append(f"deactivated (in use): {old['option_value']}")
                                        else:
                                            conn.execute("DELETE FROM custom_field_options WHERE id=?", (old["id"],))
                                            opt_changes.append(f"removed: {old['option_value']}")
                                        continue
                                    if r["text"] != old["option_value"]:
                                        conn.execute("UPDATE custom_field_options SET option_value=?,display_order=?,is_active=1 WHERE id=?", (r["text"], pos, old["id"]))
                                        if ftype == "select":
                                            conn.execute("UPDATE custom_field_values SET value=? WHERE field_id=? AND value=?", (r["text"], fid, old["option_value"]))
                                        else:
                                            for v in conn.execute("SELECT id,value FROM custom_field_values WHERE field_id=?", (fid,)).fetchall():
                                                try:
                                                    lst = json.loads(v["value"])
                                                except (ValueError, TypeError):
                                                    continue
                                                if old["option_value"] in lst:
                                                    lst = [r["text"] if x == old["option_value"] else x for x in lst]
                                                    conn.execute("UPDATE custom_field_values SET value=? WHERE id=?", (json.dumps(lst, ensure_ascii=False), v["id"]))
                                        opt_changes.append(f"renamed: {old['option_value']} -> {r['text']}")
                                    else:
                                        conn.execute("UPDATE custom_field_options SET display_order=?,is_active=1 WHERE id=?", (pos, old["id"]))
                                elif r["text"] and not r["remove"]:
                                    conn.execute("INSERT INTO custom_field_options(field_id,school_id,tenant_id,option_value,display_order) VALUES(?,?,?,?,?)",
                                                 (fid, school_id(), tenant_id(), r["text"], pos))
                                    opt_changes.append(f"added: {r['text']}")
                        new = {"label": label, "description": desc or None, "is_required": is_req, "is_unique": is_uniq,
                               "is_editable": is_edit, "default_value": default, "is_active": is_act, "display_order": order}
                        ch = pc.diff(f, new, list(new.keys()))
                        if opt_changes:
                            ch["options"] = opt_changes
                        if ch:
                            action = "custom_field_modified"
                            if "is_required" in ch or "is_unique" in ch:
                                action = "custom_field_rules_changed"
                            pc.audit(conn, actor(), action, "custom_field", fid, ch, ip=ip())
                            if "is_active" in ch:
                                pc.audit(conn, actor(), "custom_field_activated" if is_act else "custom_field_deactivated", "custom_field", fid, {"label": label}, ip=ip())
                            if "display_order" in ch:
                                pc.audit(conn, actor(), "custom_field_reordered", "custom_field", fid, {"display_order": ch["display_order"]}, ip=ip())
                        renumber(conn, f["applies_to"])
                        conn.commit()
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        errors["label"] = "Another field already has this name."
                    else:
                        flash(f"Custom field '{label}' updated.", "success")
                        return redirect(url_for("admin_custom_field_detail", fid=fid))
            return render_template("admin_custom_field_form.html", mode="edit", data=data, errors=errors, options=options_rows,
                                   applies_to=f["applies_to"], field_types=pc.FIELD_TYPES, unique_capable=sorted(pc.UNIQUE_CAPABLE),
                                   option_types=sorted(pc.OPTION_TYPES), field=f, usage=usage), (422 if errors else 200)
        finally:
            conn.close()

    @app.route("/admin/custom-fields/<int:fid>")
    @admin_only
    def admin_custom_field_detail(fid):
        conn = get_db()
        try:
            f = field_or_404(conn, fid)
            opts = conn.execute("SELECT * FROM custom_field_options WHERE field_id=? ORDER BY display_order,id", (fid,)).fetchall()
            usage = usage_count(conn, fid)
            history = conn.execute("SELECT * FROM rbac_audit_log WHERE entity_type='custom_field' AND entity_id=? AND school_id=? ORDER BY id DESC LIMIT 25",
                                   (str(fid), school_id())).fetchall()
        finally:
            conn.close()
        return render_template("admin_custom_field_detail.html", f=f, options=opts, usage=usage, history=history,
                               type_labels=dict(pc.FIELD_TYPES))

    def _post_action(fid, fn):
        conn = get_db()
        try:
            f = field_or_404(conn, fid)
            msg = fn(conn, f)
            conn.commit()
            if msg:
                flash(msg, "success")
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            app.logger.exception("Custom field action failed")
            flash("The change could not be saved. Please try again.", "error")
        finally:
            conn.close()
        return redirect(request.referrer or url_for("admin_custom_fields"))

    @app.route("/admin/custom-fields/<int:fid>/toggle", methods=["POST"])
    @admin_only
    def admin_custom_field_toggle(fid):
        def go(conn, f):
            new = 0 if f["is_active"] else 1
            conn.execute("UPDATE custom_fields SET is_active=?,updated_by=?,updated_by_name=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (new, session["user_id"], session.get("name"), fid))
            pc.audit(conn, actor(), "custom_field_activated" if new else "custom_field_deactivated", "custom_field", fid, {"label": f["label"]}, ip=ip())
            return f"'{f['label']}' " + ("activated." if new else "deactivated. Existing values are kept.")
        return _post_action(fid, go)

    @app.route("/admin/custom-fields/<int:fid>/move", methods=["POST"])
    @admin_only
    def admin_custom_field_move(fid):
        direction = request.form.get("direction")
        def go(conn, f):
            renumber(conn, f["applies_to"])
            rows = conn.execute("SELECT id,display_order FROM custom_fields WHERE school_id=? AND applies_to=? AND is_archived=0 ORDER BY display_order,id",
                                (school_id(), f["applies_to"])).fetchall()
            ids = [r["id"] for r in rows]
            if fid not in ids:
                return None
            i = ids.index(fid)
            j = i - 1 if direction == "up" else i + 1
            if j < 0 or j >= len(ids):
                return None
            ids[i], ids[j] = ids[j], ids[i]
            for pos, x in enumerate(ids, 1):
                conn.execute("UPDATE custom_fields SET display_order=? WHERE id=?", (pos, x))
            pc.audit(conn, actor(), "custom_field_reordered", "custom_field", fid, {"label": f["label"], "moved": direction}, ip=ip())
            return None
        return _post_action(fid, go)

    @app.route("/admin/custom-fields/<int:fid>/archive", methods=["POST"])
    @admin_only
    def admin_custom_field_archive(fid):
        def go(conn, f):
            restore = f["is_archived"]
            conn.execute("UPDATE custom_fields SET is_archived=?,is_active=?,updated_by=?,updated_by_name=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (0 if restore else 1, 1 if restore else 0, session["user_id"], session.get("name"), fid))
            pc.audit(conn, actor(), "custom_field_restored" if restore else "custom_field_archived", "custom_field", fid, {"label": f["label"]}, ip=ip())
            renumber(conn, f["applies_to"])
            return f"'{f['label']}' " + ("restored." if restore else "archived. Its values are preserved.")
        return _post_action(fid, go)

    @app.route("/admin/custom-fields/<int:fid>/delete", methods=["POST"])
    @admin_only
    def admin_custom_field_delete(fid):
        conn = get_db()
        try:
            f = field_or_404(conn, fid)
            if usage_count(conn, fid) > 0:
                flash("This field already holds profile data, so it cannot be deleted. Archive it instead — the data is kept.", "error")
                return redirect(url_for("admin_custom_fields", tab=f["applies_to"]))
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM custom_field_options WHERE field_id=?", (fid,))
            conn.execute("DELETE FROM custom_field_values WHERE field_id=?", (fid,))
            conn.execute("DELETE FROM custom_fields WHERE id=? AND school_id=? AND tenant_id=?", (fid, school_id(), tenant_id()))
            pc.audit(conn, actor(), "custom_field_deleted", "custom_field", fid, {"label": f["label"], "key": f["field_key"]}, ip=ip())
            renumber(conn, f["applies_to"])
            conn.commit()
            flash(f"Custom field '{f['label']}' deleted.", "success")
            return redirect(url_for("admin_custom_fields", tab=f["applies_to"]))
        except Exception:
            conn.rollback()
            app.logger.exception("Custom field delete failed")
            flash("The field could not be deleted.", "error")
            return redirect(url_for("admin_custom_fields"))
        finally:
            conn.close()

    # ================================================================== AUDIT VIEWS
    @app.route("/admin/audit-history")
    @admin_only
    def admin_audit_history():
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM rbac_audit_log WHERE school_id=? AND tenant_id=? ORDER BY id DESC LIMIT 300",
                                (school_id(), tenant_id())).fetchall()
        finally:
            conn.close()
        return render_template("admin_audit_history.html", rows=rows, scope="school")

    @app.route("/platform/audit-history")
    @platform_admin_required
    def platform_audit_history():
        conn = get_db()
        try:
            rows = conn.execute("SELECT a.*, s.name AS school_name FROM rbac_audit_log a LEFT JOIN schools s ON s.id=a.school_id ORDER BY a.id DESC LIMIT 500").fetchall()
        finally:
            conn.close()
        return render_template("admin_audit_history.html", rows=rows, scope="platform")

    @app.route("/platform/custom-fields")
    @platform_admin_required
    def platform_custom_fields():
        conn = get_db()
        try:
            rows = conn.execute("SELECT f.*, s.name AS school_name, (SELECT COUNT(*) FROM custom_field_values v WHERE v.field_id=f.id) AS usage "
                                "FROM custom_fields f JOIN schools s ON s.id=f.school_id ORDER BY s.name, f.applies_to, f.display_order").fetchall()
        finally:
            conn.close()
        return render_template("platform_custom_fields.html", fields=rows, type_labels=dict(pc.FIELD_TYPES))
