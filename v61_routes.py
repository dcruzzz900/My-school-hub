"""V61 features: class login codes, student account page, dashboard search, school-wide score history,
educational domains, result-sheet settings, automatic term/session creation and Super Admin subscriptions.

Registered from app.py with register_v61_routes(app, globals()). Every query is scoped by the school/tenant
stored in the authenticated session; ids in URLs or forms are only ever used together with that scope.
"""
import datetime
import json
import re
import secrets
import sqlite3

from school.core import abort, flash, jsonify, redirect, render_template, request, session, url_for
from school.compat import check_password_hash, generate_password_hash

import profile_core as pc

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I to avoid misreading
CODE_LENGTH = 8


def ordinal(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if 10 <= n % 100 <= 20:
        suf = "th"
    else:
        suf = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suf}"


def register_v61_routes(app, h):
    get_db = h["get_db"]
    login_required = h["login_required"]
    student_login_required = h["student_login_required"]
    platform_admin_required = h["platform_admin_required"]
    current_school_id = h["current_school_id"]
    form_teacher_class_ids = h["form_teacher_class_ids"]
    active_role_assignments = h["active_role_assignments"]
    validate_password_policy = h["validate_password_policy"]
    student_full_name = h["student_full_name"]
    security_event = h["security_event"]
    all_terms_for_school = h["all_terms_for_school"]
    log_audit = h["log_audit"]
    actor_role_label = h["_actor_role_label"]
    app.jinja_env.filters["ordinal"] = ordinal

    def sid():
        return session.get("school_id")

    def tid():
        return session.get("tenant_id")

    def actor():
        if session.get("role") == "student":
            return {"type": "student", "id": session.get("student_id"), "name": session.get("name") or "student",
                    "role": "student", "school_id": sid(), "tenant_id": tid()}
        return {"type": "staff", "id": session.get("user_id"), "name": session.get("name"),
                "role": actor_role_label(), "school_id": sid(), "tenant_id": tid()}

    def ip():
        return (request.headers.get("X-Forwarded-For", request.remote_addr or "")[:64].split(",")[0]).strip()

    def is_admin():
        return session.get("role") in ("admin", "sub_admin")

    def forbid(conn=None):
        try:
            c = conn or get_db()
            security_event(c, "access_denied", "denied", f"{request.method} {request.path}", "v61")
            c.commit()
            if conn is None:
                c.close()
        except Exception:
            app.logger.exception("Could not record denied access")
        abort(403)

    # ===================================================================== CLASS LOGIN CODES
    def manageable_classes(conn):
        """Classes whose login code this staff member may manage: admins -> all in school; teachers -> only
        the classes they are the assigned Form/Class Teacher of."""
        if is_admin():
            return conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY level, name, arm", (sid(),)).fetchall()
        ids = form_teacher_class_ids(conn, session.get("user_id")) or []
        if not ids:
            return []
        q = ",".join("?" * len(ids))
        return conn.execute(f"SELECT * FROM classes WHERE school_id=? AND id IN ({q}) ORDER BY name", (sid(), *ids)).fetchall()

    def class_for_code_action(conn, class_id):
        cls = conn.execute("SELECT * FROM classes WHERE id=? AND school_id=?", (class_id, sid())).fetchone()
        if not cls:
            abort(404)
        if not is_admin() and class_id not in (form_teacher_class_ids(conn, session.get("user_id")) or []):
            forbid(conn)
        return cls

    def new_code(conn):
        for _ in range(20):
            code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
            if not conn.execute("SELECT 1 FROM class_login_codes WHERE code=?", (code,)).fetchone():
                return code
        raise RuntimeError("Could not generate a unique class code")

    def retire_active(conn, class_id, status, reason):
        conn.execute("UPDATE class_login_codes SET status=?, ended_at=CURRENT_TIMESTAMP, ended_by=?, ended_by_name=?, end_reason=? "
                     "WHERE class_id=? AND school_id=? AND status='active'",
                     (status, session.get("user_id"), session.get("name"), reason, class_id, sid()))

    def create_code(conn, cls, days):
        code = new_code(conn)
        expires = None
        if days:
            expires = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat(timespec="seconds")
        cur = conn.execute("INSERT INTO class_login_codes(school_id,tenant_id,class_id,code,expires_at,created_by,created_by_name) VALUES(?,?,?,?,?,?,?)",
                           (sid(), tid(), cls["id"], code, expires, session.get("user_id"), session.get("name")))
        return cur.lastrowid, code, expires

    def parse_days():
        v = request.form.get("valid_days", "30")
        return int(v) if v in ("7", "14", "30", "90") else 30

    def code_audit(conn, action, cls, code_id, code, extra=None):
        ch = {"class": cls["name"], "code_id": code_id, "code_suffix": code[-3:] if code else None}
        if extra:
            ch.update(extra)
        pc.audit(conn, actor(), action, "class_login_code", code_id, ch, ip=ip())

    @app.route("/class-login-codes")
    @login_required()
    def class_login_codes():
        conn = get_db()
        try:
            classes = manageable_classes(conn)
            if not classes and not is_admin():
                forbid(conn)
            rows = []
            for c in classes:
                active = conn.execute("SELECT * FROM class_login_codes WHERE class_id=? AND school_id=? AND status='active'", (c["id"], sid())).fetchone()
                if active and active["expires_at"] and active["expires_at"] < datetime.datetime.utcnow().isoformat(timespec="seconds"):
                    conn.execute("UPDATE class_login_codes SET status='expired', ended_at=CURRENT_TIMESTAMP, end_reason='expired' WHERE id=?", (active["id"],))
                    conn.commit()
                    active = None
                pending = conn.execute(
                    "SELECT COUNT(*) FROM students WHERE class_id=? AND is_active=1 AND password_hash IS NOT NULL AND password_hash<>'' AND first_login_completed_at IS NULL",
                    (c["id"],)).fetchone()[0]
                total = conn.execute("SELECT COUNT(*) FROM students WHERE class_id=? AND is_active=1", (c["id"],)).fetchone()[0]
                rows.append({"cls": c, "active": active, "pending": pending, "total": total,
                             "display": (active["code"][:4] + "-" + active["code"][4:]) if active else None})
            history = conn.execute(
                "SELECT h.*, c.name AS class_name FROM class_login_codes h JOIN classes c ON c.id=h.class_id WHERE h.school_id=? "
                + ("" if is_admin() else f"AND h.class_id IN ({','.join('?'*len(classes))}) ") + "ORDER BY h.id DESC LIMIT 40",
                (sid(), *([] if is_admin() else [c['id'] for c in classes]))).fetchall()
        finally:
            conn.close()
        return render_template("class_login_codes.html", rows=rows, history=history)

    @app.route("/classes/<int:class_id>/login-code/generate", methods=["POST"])
    @login_required()
    def class_code_generate(class_id):
        conn = get_db()
        try:
            cls = class_for_code_action(conn, class_id)
            if conn.execute("SELECT 1 FROM class_login_codes WHERE class_id=? AND status='active' AND (expires_at IS NULL OR expires_at>=?)",
                            (class_id, datetime.datetime.utcnow().isoformat(timespec="seconds"))).fetchone():
                flash("This class already has an active code. Use Regenerate to replace it.", "error")
                return redirect(url_for("class_login_codes"))
            conn.execute("BEGIN IMMEDIATE")
            retire_active(conn, class_id, "expired", "expired before new code")
            cid, code, exp = create_code(conn, cls, parse_days())
            code_audit(conn, "class_login_code_created", cls, cid, code, {"expires_at": exp})
            conn.commit()
            flash(f"Class Login Code for {cls['name']} created.", "success")
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("A code could not be created (it may have just been created by someone else). Please check below.", "error")
        finally:
            conn.close()
        return redirect(url_for("class_login_codes"))

    @app.route("/classes/<int:class_id>/login-code/rotate", methods=["POST"])
    @login_required()
    def class_code_rotate(class_id):
        conn = get_db()
        try:
            cls = class_for_code_action(conn, class_id)
            old = conn.execute("SELECT * FROM class_login_codes WHERE class_id=? AND school_id=? AND status='active'", (class_id, sid())).fetchone()
            conn.execute("BEGIN IMMEDIATE")
            retire_active(conn, class_id, "rotated", "replaced by a new code")
            cid, code, exp = create_code(conn, cls, parse_days())
            code_audit(conn, "class_login_code_regenerated", cls, cid, code,
                       {"replaced_code_id": old["id"] if old else None, "expires_at": exp})
            conn.commit()
            flash(f"New Class Login Code generated for {cls['name']}. The old code no longer works.", "success")
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("The code could not be regenerated. Please try again.", "error")
        finally:
            conn.close()
        return redirect(url_for("class_login_codes"))

    @app.route("/classes/<int:class_id>/login-code/revoke", methods=["POST"])
    @login_required()
    def class_code_revoke(class_id):
        conn = get_db()
        try:
            cls = class_for_code_action(conn, class_id)
            old = conn.execute("SELECT * FROM class_login_codes WHERE class_id=? AND school_id=? AND status='active'", (class_id, sid())).fetchone()
            if not old:
                flash("There is no active code to revoke for this class.", "error")
                return redirect(url_for("class_login_codes"))
            conn.execute("BEGIN IMMEDIATE")
            retire_active(conn, class_id, "revoked", (request.form.get("reason") or "revoked by staff")[:200])
            code_audit(conn, "class_login_code_revoked", cls, old["id"], old["code"])
            conn.commit()
            flash(f"The Class Login Code for {cls['name']} has been revoked.", "success")
        finally:
            conn.close()
        return redirect(url_for("class_login_codes"))

    # ===================================================================== STUDENT ACCOUNT
    @app.route("/student/account", methods=["GET", "POST"])
    @student_login_required
    def student_account():
        conn = get_db()
        try:
            st = conn.execute("SELECT * FROM students WHERE id=? AND school_id=? AND tenant_id=?", (session["student_id"], sid(), tid())).fetchone()
            if not st:
                session.clear()
                return redirect(url_for("student_login"))
            errors = {}
            if request.method == "POST":
                which = request.form.get("action")
                if which == "username":
                    new = pc.clean(request.form.get("username")).lower()
                    if not re.fullmatch(r"[a-z0-9._\-]{3,40}", new):
                        errors["username"] = "Username must be 3-40 characters: letters, numbers, dot, underscore or hyphen."
                    elif new != (st["username"] or "").lower():
                        # A username must never collide with someone else's username, nor with an admission/register number
                        # of another student in this school (that would make login ambiguous).
                        if conn.execute("SELECT 1 FROM students WHERE id<>? AND LOWER(username)=?", (st["id"], new)).fetchone():
                            errors["username"] = "That username is already taken."
                        elif conn.execute("SELECT 1 FROM students WHERE id<>? AND school_id=? AND (LOWER(TRIM(admission_no))=? OR LOWER(TRIM(COALESCE(register_no,'')))=?)",
                                          (st["id"], sid(), new, new)).fetchone():
                            errors["username"] = "That username is not available."
                    if not errors:
                        old = st["username"]
                        try:
                            conn.execute("BEGIN IMMEDIATE")
                            conn.execute("UPDATE students SET username=?, username_changed_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=?", (new, st["id"], sid()))
                            pc.audit(conn, actor(), "student_username_changed", "student", st["id"], {"username": [old, new]}, ip=ip())
                            conn.commit()
                            flash("Username updated. Your Admission/Register No. is unchanged.", "success")
                            return redirect(url_for("student_account"))
                        except sqlite3.IntegrityError:
                            conn.rollback()
                            errors["username"] = "That username is already taken."
                elif which == "password":
                    cur, new, conf = request.form.get("current_password", ""), request.form.get("new_password", ""), request.form.get("confirm_password", "")
                    if not st["password_hash"] or not check_password_hash(st["password_hash"], cur):
                        errors["current_password"] = "Your current password is not correct."
                    else:
                        pol = validate_password_policy(new, st["username"])
                        if pol:
                            errors["new_password"] = " ".join(pol)
                        elif new != conf:
                            errors["confirm_password"] = "The new password and confirmation do not match."
                        elif check_password_hash(st["password_hash"], new):
                            errors["new_password"] = "Choose a password different from your current one."
                    if not errors:
                        conn.execute("BEGIN IMMEDIATE")
                        conn.execute("UPDATE students SET password_hash=?, failed_logins=0, locked_until=NULL WHERE id=? AND school_id=?",
                                     (generate_password_hash(new), st["id"], sid()))
                        pc.audit(conn, actor(), "student_password_changed", "student", st["id"], {"changed": True}, ip=ip())
                        conn.commit()
                        flash("Password changed successfully.", "success")
                        return redirect(url_for("student_account"))
                else:
                    abort(400)
            return render_template("student_account.html", st=st, errors=errors, form=request.form), (422 if errors else 200)
        finally:
            conn.close()

    # ===================================================================== SEARCH
    def like(q):
        return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def visible_student_scope(conn):
        """None = every student of the school; list = those class ids only; [] = no students at all."""
        role = session.get("role")
        if role in ("admin", "sub_admin"):
            return None
        if role == "teacher":
            try:
                for a in active_role_assignments(conn, session.get("user_id"), sid()):
                    if a["role"] == "Registrar / Admissions Officer":
                        return None
            except Exception:
                pass
            ids = set(form_teacher_class_ids(conn, session.get("user_id")) or [])
            ids |= {r[0] for r in conn.execute("SELECT DISTINCT class_id FROM class_subjects WHERE teacher_id=?", (session.get("user_id"),))}
            return sorted(ids)
        return []

    def feature_links():
        role = session.get("role")
        items = []
        def add(label, endpoint, roles=None, **kw):
            if roles and role not in roles:
                return
            try:
                items.append({"label": label, "url": url_for(endpoint, **kw)})
            except Exception:
                pass
        if role == "student":
            add("My Dashboard", "student_dashboard"); add("My Profile", "student_self_profile"); add("Account (username & password)", "student_account")
            add("Learning Materials", "student_materials")
        else:
            add("Dashboard", "dashboard")
            if session.get("user_id"):
                add("My Profile", "staff_profile", user_id=session["user_id"])
            add("Students", "admin_students", ("admin", "sub_admin")); add("Teachers", "admin_teachers", ("admin", "sub_admin"))
            add("Classes", "admin_classes", ("admin", "sub_admin")); add("Subjects", "admin_subjects", ("admin", "sub_admin"))
            add("School Setup", "admin_school", ("admin", "sub_admin")); add("Custom Fields", "admin_custom_fields", ("admin",))
            add("Result Display Settings", "result_settings", ("admin", "sub_admin")); add("Additional School Info", "school_info_fields", ("admin",)); add("Custom Result Fields", "result_custom_fields_page", ("admin", "sub_admin")); add("Educational Domains", "admin_domains", ("admin", "sub_admin"))
            add("Class Login Codes", "class_login_codes", ("admin", "sub_admin", "teacher"))
            add("Score Change History", "score_history_all", ("admin", "sub_admin"))
            add("Audit History", "admin_audit_history", ("admin",)); add("Timetable", "timetable_hub")
        return items

    def run_search(q):
        q = pc.clean(q)[:60]
        out = {"q": q, "students": [], "staff": [], "classes": [], "features": []}
        if len(q) < 2:
            return out
        pat = like(q)
        ql = q.lower()
        out["features"] = [f for f in feature_links() if ql in f["label"].lower()][:6]
        if session.get("role") == "student":
            return out
        conn = get_db()
        try:
            scope = visible_student_scope(conn)
            if scope is None or scope:
                sql = ("SELECT st.id, st.first_name, st.last_name, st.other_names, st.admission_no, c.name AS class_name FROM students st "
                       "JOIN classes c ON c.id=st.class_id WHERE c.school_id=? AND st.is_active=1 AND "
                       "(st.first_name LIKE ? ESCAPE '\\' OR st.last_name LIKE ? ESCAPE '\\' OR st.other_names LIKE ? ESCAPE '\\' "
                       "OR st.admission_no LIKE ? ESCAPE '\\' OR COALESCE(st.register_no,'') LIKE ? ESCAPE '\\' "
                       "OR (st.first_name||' '||st.last_name) LIKE ? ESCAPE '\\' OR (st.last_name||' '||st.first_name) LIKE ? ESCAPE '\\')")
                args = [sid(), pat, pat, pat, pat, pat, pat, pat]
                if scope:
                    sql += f" AND st.class_id IN ({','.join('?'*len(scope))})"
                    args += scope
                sql += " ORDER BY st.last_name, st.first_name LIMIT 12"
                for r in conn.execute(sql, args):
                    out["students"].append({"name": student_full_name(r), "sub": f"{r['admission_no']} · {r['class_name']}",
                                            "url": url_for("student_profile", student_id=r["id"])})
            if is_admin():
                for r in conn.execute(
                        "SELECT id,name,username,staff_id,position FROM users WHERE school_id=? AND role IN ('teacher','sub_admin','admin') AND "
                        "(name LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR COALESCE(staff_id,'') LIKE ? ESCAPE '\\') ORDER BY name LIMIT 10",
                        (sid(), pat, pat, pat)):
                    out["staff"].append({"name": r["name"], "sub": r["staff_id"] or r["username"], "url": url_for("staff_profile", user_id=r["id"])})
            elif session.get("user_id") and ql in (session.get("name") or "").lower():
                out["staff"].append({"name": session.get("name"), "sub": "You", "url": url_for("staff_profile", user_id=session["user_id"])})
            if is_admin():
                cls_rows = conn.execute("SELECT id,name FROM classes WHERE school_id=? AND name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 8", (sid(), pat)).fetchall()
            elif scope:
                cls_rows = conn.execute(f"SELECT id,name FROM classes WHERE school_id=? AND name LIKE ? ESCAPE '\\' AND id IN ({','.join('?'*len(scope))}) ORDER BY name LIMIT 8",
                                        (sid(), pat, *scope)).fetchall()
            else:
                cls_rows = []
            for r in cls_rows:
                out["classes"].append({"name": r["name"], "sub": "Class", "url": url_for("my_class_roster", class_id=r["id"]) if not is_admin() else url_for("admin_students", class_id=r["id"])})
        finally:
            conn.close()
        return out

    @app.route("/api/search")
    def api_search():
        if not (session.get("user_id") or session.get("student_id")) or not sid():
            return jsonify({"error": "auth"}), 401
        return jsonify(run_search(request.args.get("q", "")))

    @app.route("/search")
    def search_page():
        if not (session.get("user_id") or session.get("student_id")) or not sid():
            return redirect(url_for("login"))
        res = run_search(request.args.get("q", ""))
        total = sum(len(res[k]) for k in ("students", "staff", "classes", "features"))
        return render_template("search_results.html", res=res, total=total, short=len(res["q"]) < 2)

    # ===================================================================== SCORE HISTORY (school-wide)
    @app.route("/scores/history")
    @login_required("admin", "sub_admin")
    def score_history_all():
        conn = get_db()
        try:
            f = {"term_id": request.args.get("term_id", type=int), "class_id": request.args.get("class_id", type=int),
                 "subject_id": request.args.get("subject_id", type=int), "q": pc.clean(request.args.get("q", ""))[:60]}
            sql = "SELECT * FROM score_audit WHERE school_id=? AND tenant_id=?"
            args = [sid(), tid()]
            for col in ("term_id", "class_id", "subject_id"):
                if f[col]:
                    sql += f" AND {col}=?"
                    args.append(f[col])
            if f["q"]:
                sql += " AND (student_name LIKE ? ESCAPE '\\' OR admission_no LIKE ? ESCAPE '\\')"
                args += [like(f["q"]), like(f["q"])]
            sql += " ORDER BY id DESC LIMIT 501"
            rows = conn.execute(sql, args).fetchall()
            truncated = len(rows) > 500
            classes = conn.execute("SELECT id,name FROM classes WHERE school_id=? ORDER BY name", (sid(),)).fetchall()
            subjects = conn.execute("SELECT id,name FROM subjects WHERE school_id=? ORDER BY name", (sid(),)).fetchall()
            terms = all_terms_for_school(conn)
        finally:
            conn.close()
        return render_template("score_history_all.html", history=rows[:500], truncated=truncated, f=f, classes=classes, subjects=subjects, all_terms=terms)

    # ===================================================================== EDUCATIONAL DOMAINS
    def domain_key(label):
        return re.sub(r"[^a-z0-9]+", "_", pc.clean(label).lower()).strip("_")[:40]

    @app.route("/admin/domains", methods=["GET", "POST"])
    @login_required("admin", "sub_admin")
    def admin_domains():
        conn = get_db()
        try:
            h["ensure_school_v61_defaults"](conn, sid())
            if request.method == "POST":
                act = request.form.get("action")
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    if act == "add_domain":
                        label = pc.clean(request.form.get("label"))
                        key = domain_key(label)
                        if len(label) < 3 or len(label) > 60 or not key:
                            raise ValueError("Domain name must be 3-60 characters.")
                        order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM educational_domains WHERE school_id=?", (sid(),)).fetchone()[0]
                        conn.execute("INSERT INTO educational_domains(school_id,tenant_id,domain_key,label,sort_order) VALUES(?,?,?,?,?)", (sid(), tid(), key, label, order))
                        pc.audit(conn, actor(), "educational_domain_created", "educational_domain", key, {"label": label}, ip=ip())
                    elif act in ("toggle_domain", "rename_domain"):
                        d = conn.execute("SELECT * FROM educational_domains WHERE id=? AND school_id=?", (request.form.get("domain_id", type=int), sid())).fetchone()
                        if not d:
                            raise ValueError("Domain not found.")
                        if act == "toggle_domain":
                            conn.execute("UPDATE educational_domains SET is_active=? WHERE id=?", (0 if d["is_active"] else 1, d["id"]))
                            pc.audit(conn, actor(), "educational_domain_toggled", "educational_domain", d["domain_key"], {"active": 0 if d["is_active"] else 1}, ip=ip())
                        else:
                            label = pc.clean(request.form.get("label"))
                            if len(label) < 3 or len(label) > 60:
                                raise ValueError("Domain name must be 3-60 characters.")
                            conn.execute("UPDATE educational_domains SET label=? WHERE id=?", (label, d["id"]))
                            pc.audit(conn, actor(), "educational_domain_renamed", "educational_domain", d["domain_key"], {"label": [d["label"], label]}, ip=ip())
                    elif act == "add_trait":
                        name = pc.clean(request.form.get("name"))
                        d = conn.execute("SELECT * FROM educational_domains WHERE domain_key=? AND school_id=?", (request.form.get("domain_key", ""), sid())).fetchone()
                        if not d:
                            raise ValueError("Choose a domain.")
                        if len(name) < 2 or len(name) > 60 or any(c in name for c in "<>"):
                            raise ValueError("Skill / behaviour name must be 2-60 characters.")
                        if conn.execute("SELECT 1 FROM skill_traits WHERE school_id=? AND LOWER(name)=LOWER(?)", (sid(), name)).fetchone():
                            raise ValueError("A skill or behaviour with that name already exists.")
                        order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM skill_traits WHERE school_id=?", (sid(),)).fetchone()[0]
                        conn.execute("INSERT INTO skill_traits(school_id,tenant_id,name,category,sort_order) VALUES(?,?,?,?,?)", (sid(), tid(), name, d["domain_key"], order))
                        pc.audit(conn, actor(), "educational_trait_created", "skill_trait", name, {"domain": d["label"]}, ip=ip())
                    elif act in ("toggle_trait", "rename_trait"):
                        t = conn.execute("SELECT * FROM skill_traits WHERE id=? AND school_id=?", (request.form.get("trait_id", type=int), sid())).fetchone()
                        if not t:
                            raise ValueError("Item not found.")
                        if act == "toggle_trait":
                            conn.execute("UPDATE skill_traits SET is_active=? WHERE id=?", (0 if t["is_active"] else 1, t["id"]))
                            pc.audit(conn, actor(), "educational_trait_toggled", "skill_trait", t["name"], {"active": 0 if t["is_active"] else 1}, ip=ip())
                        else:
                            name = pc.clean(request.form.get("name"))
                            if len(name) < 2 or len(name) > 60 or any(c in name for c in "<>"):
                                raise ValueError("Name must be 2-60 characters.")
                            if conn.execute("SELECT 1 FROM skill_traits WHERE school_id=? AND LOWER(name)=LOWER(?) AND id<>?", (sid(), name, t["id"])).fetchone():
                                raise ValueError("A skill or behaviour with that name already exists.")
                            conn.execute("UPDATE skill_traits SET name=? WHERE id=?", (name, t["id"]))
                            pc.audit(conn, actor(), "educational_trait_renamed", "skill_trait", t["id"], {"name": [t["name"], name]}, ip=ip())
                    else:
                        raise ValueError("Unknown action.")
                    conn.commit()
                    flash("Saved.", "success")
                except ValueError as exc:
                    conn.rollback()
                    flash(str(exc), "error")
                except sqlite3.IntegrityError:
                    conn.rollback()
                    flash("That name already exists.", "error")
                return redirect(url_for("admin_domains"))
            domains = conn.execute("SELECT * FROM educational_domains WHERE school_id=? ORDER BY sort_order, id", (sid(),)).fetchall()
            traits = conn.execute("SELECT * FROM skill_traits WHERE school_id=? ORDER BY sort_order, name", (sid(),)).fetchall()
        finally:
            conn.close()
        by = {d["domain_key"]: [t for t in traits if t["category"] == d["domain_key"]] for d in domains}
        return render_template("admin_domains.html", domains=domains, by=by)

    # ===================================================================== RESULT SETTINGS
    TEMPLATES = [("classic", "Classic", "Traditional bordered table, all score columns."),
                 ("modern", "Modern", "Coloured header band, rounded cards, passport beside the identity panel."),
                 ("compact", "Compact", "Tight rows so a long subject list fits one page."),
                 ("detailed", "Detailed", "Adds remarks, class statistics and the grading key.")]
    COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

    @app.route("/admin/result-display", methods=["GET", "POST"])
    @login_required("admin", "sub_admin")
    def result_settings():
        """School Setup -> Result Display Settings: the ONE place that controls what a result sheet shows
        (HTML preview, print page and PDF all read these values). Scoped to the signed-in admin's own school."""
        import result_display as RD
        conn = get_db()
        try:
            school = conn.execute("SELECT * FROM schools WHERE id=?", (sid(),)).fetchone()
            errors = {}
            if request.method == "POST":
                f = request.form
                tmpl = f.get("result_template", "classic")
                if tmpl not in RD.TEMPLATE_KEYS:
                    errors["result_template"] = "Choose one of the available templates."
                prim, sec = f.get("result_accent_color", "").strip(), f.get("result_secondary_color", "").strip()
                if prim and not COLOR_RE.match(prim):
                    errors["result_accent_color"] = "Use a colour like #1f3a5f."
                if sec and not COLOR_RE.match(sec):
                    errors["result_secondary_color"] = "Use a colour like #c9a227."
                title = pc.clean(f.get("result_title"))[:80]
                footer = pc.clean_multiline(f.get("result_footer_text"))[:300]
                wm = pc.clean(f.get("result_watermark_text"))[:40]
                address = pc.clean_multiline(f.get("school_address"))[:200]
                sig = f.get("result_signature_layout", "split")
                if sig not in ("split", "stacked", "right"):
                    errors["result_signature_layout"] = "Choose a signature placement."
                logo_align = f.get("logo_align", "left")
                text_align = f.get("name_align", "center")
                if logo_align not in ("left", "center", "right") or text_align not in ("left", "center", "right"):
                    errors["logo_align"] = "Choose left, center or right."
                if any(c in (title + footer + wm + address) for c in "<>"):
                    errors["result_title"] = "Angle brackets are not allowed."
                if not errors:
                    before = dict(school)
                    vals = RD.form_values(f)
                    vals.update(result_template=tmpl, result_title=title or None, result_footer_text=footer or None,
                                result_watermark_text=wm or None,
                                result_accent_color=prim or school["result_accent_color"], result_secondary_color=sec or None,
                                result_signature_layout=sig, logo_align=logo_align, name_align=text_align, school_address=address or None)
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        conn.execute("UPDATE schools SET " + ",".join(f"{k}=?" for k in vals) + " WHERE id=?", [*vals.values(), sid()])
                        ch = pc.diff(before, vals, list(vals))
                        if ch:
                            pc.audit(conn, actor(), "result_settings_changed", "school", sid(), ch, ip=ip())
                        conn.commit()
                        flash("Result Display Settings saved. They apply to the preview, printing and PDF.", "success")
                        return redirect(url_for("result_settings"))
                    except Exception:
                        conn.rollback()
                        app.logger.exception("Result settings save failed")
                        errors["_form"] = "The settings could not be saved. Please try again."
                merged = dict(school)
                merged.update({k: v for k, v in request.form.items() if not k.startswith("d_")})
                school = merged
                checked = {k: bool(request.form.get("d_" + k)) for k in RD.KEYS}
            else:
                checked = RD.display_settings(school)
            return render_template("result_settings.html", s=school, templates=RD.TEMPLATES, errors=errors,
                                   groups=RD.groups(), checked=checked), (422 if errors else 200)
        finally:
            conn.close()

    @app.route("/admin/result-settings")
    @login_required("admin", "sub_admin")
    def result_settings_legacy():
        return redirect(url_for("result_settings"))

    @app.route("/admin/school-info", methods=["GET", "POST"])
    @login_required("admin")
    def school_info_fields():
        """School Setup -> Additional School Information: custom label/value pairs (e.g. Education Domain)
        that the School Admin manages without any developer change. Always scoped to the signed-in school."""
        conn = get_db()
        try:
            school_id = sid()
            school = conn.execute("SELECT tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()
            if request.method == "POST":
                action = request.form.get("action", "")
                label = pc.clean(request.form.get("label"))[:60]
                value = pc.clean_multiline(request.form.get("value"))[:300]
                fid = request.form.get("field_id", type=int)
                if any(c in (label + value) for c in "<>"):
                    flash("Angle brackets are not allowed.", "error")
                    return redirect(url_for("school_info_fields"))
                if action == "add":
                    if not label:
                        flash("Give the field a name, e.g. Education Domain.", "error")
                    elif conn.execute("SELECT 1 FROM school_info_fields WHERE school_id=? AND LOWER(label)=LOWER(?)", (school_id, label)).fetchone():
                        flash(f"A field called “{label}” already exists.", "error")
                    else:
                        n = conn.execute("SELECT COALESCE(MAX(display_order),0)+1 FROM school_info_fields WHERE school_id=?", (school_id,)).fetchone()[0]
                        conn.execute("INSERT INTO school_info_fields(school_id,tenant_id,label,value,display_order,show_on_result) VALUES(?,?,?,?,?,?)",
                                     (school_id, school["tenant_id"] if school else None, label, value or None, n, 1 if request.form.get("show_on_result") else 0))
                        pc.audit(conn, actor(), "school_info_field_added", "school_info_field", None, {"label": label}, ip=ip())
                        conn.commit(); flash("Field added.", "success")
                elif action in ("save", "delete") and fid:
                    row = conn.execute("SELECT * FROM school_info_fields WHERE id=? AND school_id=?", (fid, school_id)).fetchone()
                    if not row:
                        flash("Field not found.", "error")
                    elif action == "delete":
                        conn.execute("DELETE FROM school_info_fields WHERE id=? AND school_id=?", (fid, school_id))
                        pc.audit(conn, actor(), "school_info_field_removed", "school_info_field", fid, {"label": row["label"]}, ip=ip())
                        conn.commit(); flash("Field removed.", "success")
                    else:
                        if not label:
                            flash("A field needs a name.", "error")
                        elif conn.execute("SELECT 1 FROM school_info_fields WHERE school_id=? AND LOWER(label)=LOWER(?) AND id!=?", (school_id, label, fid)).fetchone():
                            flash(f"A field called “{label}” already exists.", "error")
                        else:
                            conn.execute("UPDATE school_info_fields SET label=?, value=?, show_on_result=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=?",
                                         (label, value or None, 1 if request.form.get("show_on_result") else 0, fid, school_id))
                            pc.audit(conn, actor(), "school_info_field_changed", "school_info_field", fid, {"label": label}, ip=ip())
                            conn.commit(); flash("Field saved.", "success")
                return redirect(url_for("school_info_fields"))
            fields = conn.execute("SELECT * FROM school_info_fields WHERE school_id=? ORDER BY display_order, id", (school_id,)).fetchall()
            return render_template("school_info_fields.html", fields=fields)
        finally:
            conn.close()

    # ===================================================================== CUSTOM RESULT FIELDS
    FIELD_TYPES = (("text", "Short text"), ("number", "Number"), ("date", "Date"), ("choice", "Choice list"), ("yesno", "Yes / No"))

    @app.route("/admin/result-fields", methods=["GET", "POST"])
    @login_required("admin", "sub_admin")
    def result_custom_fields_page():
        """School Setup -> Custom Result Fields. Add / edit / enable-disable / delete fields that are not on the default
        result sheet and choose where each one appears. Always scoped to the signed-in school."""
        conn = get_db()
        try:
            school_id = sid()
            tenant = conn.execute("SELECT tenant_id FROM schools WHERE id=?", (school_id,)).fetchone()
            if request.method == "POST":
                act = request.form.get("action", "")
                fid = request.form.get("field_id", type=int)
                label = pc.clean(request.form.get("label"))[:40]
                ftype = request.form.get("field_type", "text")
                scope = request.form.get("scope", "term")
                options = ", ".join(x.strip() for x in pc.clean(request.form.get("options")).split(",") if x.strip())[:300]
                flags = {k: 1 if request.form.get(k) else 0 for k in ("enabled", "show_on_result", "show_on_profile")}
                if any(c in (label + options) for c in "<>"):
                    flash("Angle brackets are not allowed.", "error"); return redirect(url_for("result_custom_fields_page"))
                if act in ("add", "save"):
                    if not label:
                        flash("Give the field a name, e.g. House.", "error")
                    elif ftype not in dict(FIELD_TYPES) or scope not in ("student", "term"):
                        flash("Choose a valid field type and scope.", "error")
                    elif ftype == "choice" and not options:
                        flash("A choice field needs at least one option (comma separated).", "error")
                    elif conn.execute("SELECT 1 FROM result_custom_fields WHERE school_id=? AND LOWER(label)=LOWER(?) AND id!=?", (school_id, label, fid or 0)).fetchone():
                        flash(f"A field called “{label}” already exists.", "error")
                    elif act == "add":
                        n = conn.execute("SELECT COALESCE(MAX(display_order),0)+1 FROM result_custom_fields WHERE school_id=?", (school_id,)).fetchone()[0]
                        conn.execute("INSERT INTO result_custom_fields(school_id,tenant_id,label,field_type,options,scope,enabled,show_on_result,show_on_profile,display_order) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                     (school_id, tenant["tenant_id"], label, ftype, options or None, scope, flags["enabled"] if "enabled" in request.form else 1,
                                      flags["show_on_result"], flags["show_on_profile"], n))
                        pc.audit(conn, actor(), "result_field_added", "result_field", None, {"label": label}, ip=ip())
                        conn.commit(); flash("Field added.", "success")
                    else:
                        row = conn.execute("SELECT * FROM result_custom_fields WHERE id=? AND school_id=?", (fid, school_id)).fetchone()
                        if not row:
                            flash("Field not found.", "error")
                        else:
                            conn.execute("UPDATE result_custom_fields SET label=?, field_type=?, options=?, scope=?, enabled=?, show_on_result=?, show_on_profile=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND school_id=?",
                                         (label, ftype, options or None, scope, flags["enabled"], flags["show_on_result"], flags["show_on_profile"], fid, school_id))
                            pc.audit(conn, actor(), "result_field_changed", "result_field", fid, {"label": label}, ip=ip())
                            conn.commit(); flash("Field saved.", "success")
                elif act == "delete" and fid:
                    row = conn.execute("SELECT * FROM result_custom_fields WHERE id=? AND school_id=?", (fid, school_id)).fetchone()
                    if not row:
                        flash("Field not found.", "error")
                    elif conn.execute("SELECT 1 FROM student_custom_values WHERE field_id=? AND school_id=? AND COALESCE(value,'')<>'' LIMIT 1", (fid, school_id)).fetchone():
                        flash("This field already holds student data, so it can't be deleted safely. Switch it off instead and it will disappear from every screen.", "error")
                    else:
                        conn.execute("DELETE FROM student_custom_values WHERE field_id=? AND school_id=?", (fid, school_id))
                        conn.execute("DELETE FROM result_custom_fields WHERE id=? AND school_id=?", (fid, school_id))
                        pc.audit(conn, actor(), "result_field_removed", "result_field", fid, {"label": row["label"]}, ip=ip())
                        conn.commit(); flash("Field deleted.", "success")
                return redirect(url_for("result_custom_fields_page"))
            fields = conn.execute("SELECT * FROM result_custom_fields WHERE school_id=? ORDER BY display_order, id", (school_id,)).fetchall()
            return render_template("result_custom_fields.html", fields=fields, field_types=FIELD_TYPES)
        finally:
            conn.close()

    # ===================================================================== SUBSCRIPTION MANAGEMENT (Super Admin)
    def eff_status(sch):
        """Normalise a school's subscription into Active / Trial / Expired / Suspended for display."""
        now = datetime.datetime.utcnow().date().isoformat()
        if sch["is_suspended"]:
            return "Suspended"
        st = (sch["subscription_status"] or "").lower()
        end = (sch["subscription_ends_at"] or sch["trial_ends_at"] or "")[:10]
        if st in ("suspended",):
            return "Suspended"
        if st in ("expired", "cancelled", "canceled"):
            return "Expired"
        if end and end < now:
            return "Expired"
        if st == "trial":
            return "Trial"
        return "Active" if st in ("active", "paid") else (st.title() or "Trial")

    app.jinja_env.globals["subscription_label"] = eff_status

    def record_sub(conn, school, action, new_status, new_plan, new_end, note, admin_name):
        conn.execute("INSERT INTO subscription_history(school_id,tenant_id,action,previous_status,new_status,previous_plan,new_plan,previous_ends_at,new_ends_at,note,actor_id,actor_name) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                     (school["id"], school["tenant_id"], action, eff_status(school), new_status, school["subscription_plan"], new_plan,
                      school["subscription_ends_at"] or school["trial_ends_at"], new_end, note, session.get("platform_admin_id"), admin_name))
        log_audit(conn, "platform_admin", admin_name, f"subscription_{action}", details=f"school={school['id']} {eff_status(school)}->{new_status} until {new_end}", school_id=school["id"])

    @app.route("/platform/subscription-manager")
    @platform_admin_required
    def platform_subscription_manager():
        conn = get_db()
        try:
            schools = conn.execute("SELECT * FROM schools ORDER BY name").fetchall()
            rows = [{"s": s, "status": eff_status(s)} for s in schools]
            counts = {k: sum(1 for r in rows if r["status"] == k) for k in ("Active", "Trial", "Expired", "Suspended")}
            plans = conn.execute("SELECT * FROM subscription_plans ORDER BY 1").fetchall() if h["table_exists"](conn, "subscription_plans") else []
        finally:
            conn.close()
        return render_template("platform_subscription_manager.html", rows=rows, counts=counts, plans=plans)

    @app.route("/platform/schools/<int:school_id>/subscription-action", methods=["POST"])
    @platform_admin_required
    def platform_subscription_action(school_id):
        conn = get_db()
        try:
            school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
            if not school:
                abort(404)
            act = request.form.get("action")
            note = pc.clean(request.form.get("note"))[:200] or None
            admin_name = session.get("platform_admin_name")
            today = datetime.date.today()
            cur_end = (school["subscription_ends_at"] or school["trial_ends_at"] or "")[:10]
            try:
                conn.execute("BEGIN IMMEDIATE")
                if act == "activate":
                    plan = pc.clean(request.form.get("plan")) or school["subscription_plan"] or "standard"
                    months = request.form.get("months", type=int) or 12
                    if not 1 <= months <= 60:
                        raise ValueError("Choose between 1 and 60 months.")
                    start = today
                    end = (start + datetime.timedelta(days=30 * months)).isoformat()
                    record_sub(conn, school, "activated", "Active", plan, end, note, admin_name)
                    conn.execute("UPDATE schools SET subscription_status='active', subscription_plan=?, subscription_started_at=?, subscription_ends_at=?, is_suspended=0 WHERE id=?",
                                 (plan, start.isoformat(), end, school_id))
                elif act == "extend":
                    days = request.form.get("days", type=int)
                    if not days or not 1 <= days <= 1825:
                        raise ValueError("Enter a number of days between 1 and 1825.")
                    try:
                        base = max(datetime.date.fromisoformat(cur_end), today) if cur_end else today
                    except ValueError:
                        base = today
                    end = (base + datetime.timedelta(days=days)).isoformat()
                    was_trial = (school["subscription_status"] or "").lower() == "trial"
                    record_sub(conn, school, "extended", "Trial" if was_trial else "Active", school["subscription_plan"], end, note, admin_name)
                    col = "trial_ends_at" if was_trial else "subscription_ends_at"
                    conn.execute(f"UPDATE schools SET {col}=?, subscription_status=? WHERE id=?", (end, "trial" if was_trial else "active", school_id))
                elif act == "suspend":
                    record_sub(conn, school, "suspended", "Suspended", school["subscription_plan"], cur_end, note, admin_name)
                    conn.execute("UPDATE schools SET is_suspended=1 WHERE id=?", (school_id,))
                elif act == "unsuspend":
                    record_sub(conn, school, "reinstated", "Active", school["subscription_plan"], cur_end, note, admin_name)
                    conn.execute("UPDATE schools SET is_suspended=0 WHERE id=?", (school_id,))
                elif act == "expire":
                    record_sub(conn, school, "deactivated", "Expired", school["subscription_plan"], today.isoformat(), note, admin_name)
                    conn.execute("UPDATE schools SET subscription_status='expired', subscription_ends_at=? WHERE id=?", (today.isoformat(), school_id))
                else:
                    raise ValueError("Unknown action.")
                conn.commit()
                flash(f"Subscription updated for {school['name']}.", "success")
            except ValueError as exc:
                conn.rollback()
                flash(str(exc), "error")
        finally:
            conn.close()
        return redirect(request.form.get("next") if (request.form.get("next") or "").startswith("/platform/") else url_for("platform_subscription_manager"))

    @app.route("/platform/schools/<int:school_id>/subscription-history")
    @platform_admin_required
    def platform_subscription_history(school_id):
        conn = get_db()
        try:
            school = conn.execute("SELECT * FROM schools WHERE id=?", (school_id,)).fetchone()
            if not school:
                abort(404)
            rows = conn.execute("SELECT * FROM subscription_history WHERE school_id=? ORDER BY id DESC LIMIT 200", (school_id,)).fetchall()
        finally:
            conn.close()
        return render_template("platform_subscription_history.html", school=school, rows=rows, status=eff_status(school))

    # ===================================================================== AUTOMATIC TERM / SESSION
    def next_session_name(name):
        m = re.fullmatch(r"\s*(\d{4})\s*/\s*(\d{4})\s*", name or "")
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            return f"{a + 1}/{b + 1}"
        m = re.fullmatch(r"\s*(\d{4})\s*", name or "")
        return str(int(m.group(1)) + 1) if m else None

    h["_next_session_name"] = next_session_name

    def auto_advance(conn, term_id):
        """Called when a term's results are published. Creates the NEXT term (or, after the last term of a session,
        the next session with its first term) as inactive drafts. Never touches students, staff, subjects or
        existing results and never duplicates an existing term/session. Returns a short description or None."""
        t = conn.execute("SELECT t.*, se.school_id, se.name AS session_name FROM terms t JOIN sessions se ON se.id=t.session_id WHERE t.id=?", (term_id,)).fetchone()
        if not t or t["school_id"] != current_school_id():
            return None
        terms = conn.execute("SELECT * FROM terms WHERE session_id=? ORDER BY id", (t["session_id"],)).fetchall()
        names = [x["name"] for x in terms]
        m = re.search(r"(\d+)", t["name"] or "")
        if re.search(r"third|3", t["name"] or "", re.I) or (m and int(m.group(1)) >= 3):
            # end of session -> next session + first term
            nn = next_session_name(t["session_name"])
            if not nn:
                return None
            existing = conn.execute("SELECT * FROM sessions WHERE school_id=? AND name=?", (current_school_id(), nn)).fetchone()
            if existing:
                return None
            cur = conn.execute("INSERT INTO sessions(school_id,name,is_active,tenant_id,is_auto_created,created_from_session_id) VALUES(?,?,0,?,1,?)",
                               (current_school_id(), nn, session.get("tenant_id"), t["session_id"]))
            # Carry the term structure forward (same term names), all inactive and editable. No students, staff, subjects or results are copied:
            # those belong to the school and simply continue into the new session.
            carried = names or ["First Term", "Second Term", "Third Term"]
            for nm in carried:
                conn.execute("INSERT INTO terms(name,session_id,is_active,is_published,is_auto_created,created_from_term_id) VALUES(?,?,0,0,1,?)", (nm, cur.lastrowid, t["id"]))
            pc.audit(conn, actor(), "academic_session_auto_created", "session", cur.lastrowid, {"name": nn, "from": t["session_name"], "terms": carried}, ip=ip())
            for nm in carried:
                pc.audit(conn, actor(), "term_auto_created", "term", None, {"name": nm, "session": nn}, ip=ip())
            conn.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES (?,?,?,?,?)",
                         ("System", current_school_id(), "admin", "New academic session created",
                          f"{nn} was created automatically after {t['session_name']} ended. Review its dates and activate it when ready."))
            return f"Session {nn} was created automatically with {len(carried)} term(s). Review the dates and activate it when ready."
        ordered = ["First Term", "Second Term", "Third Term"]
        nxt = None
        if m:
            nxt_no = int(m.group(1)) + 1
            has_suffix = re.search(r"\d+\s*(st|nd|rd|th)\b", t["name"], re.I)
            repl = ordinal(nxt_no) if has_suffix else str(nxt_no)
            nxt = re.sub(r"\d+\s*(st|nd|rd|th)?\b", repl, t["name"], count=1, flags=re.I)
        if not nxt:
            low = (t["name"] or "").lower()
            for i, nm in enumerate(ordered[:-1]):
                if nm.split()[0].lower() in low:
                    nxt = ordered[i + 1]
                    break
        if not nxt or nxt in names or any(x["name"].lower() == nxt.lower() for x in terms):
            return None
        cur = conn.execute("INSERT INTO terms(name,session_id,is_active,is_published,is_auto_created,created_from_term_id) VALUES(?,?,0,0,1,?)", (nxt, t["session_id"], t["id"]))
        pc.audit(conn, actor(), "term_auto_created", "term", cur.lastrowid, {"name": nxt, "session": t["session_name"], "from_term": t["name"]}, ip=ip())
        return f"{nxt} was created automatically. Review its dates and activate it when ready."

    h["auto_advance_after_publish"] = auto_advance


    # ===================================================================== SUPER ADMIN HUB PAGES (simple navigation)
    def hub(title, intro, items):
        links = []
        for label, desc, ep in items:
            try:
                links.append({"label": label, "desc": desc, "url": url_for(ep)})
            except Exception:
                pass
        return render_template("platform_hub.html", title=title, intro=intro, links=links)

    @app.route("/platform/reports")
    @platform_admin_required
    def platform_reports_hub():
        return hub("Reports", "Platform-wide reports. Individual school data stays inside that school.", [
            ("Billing analytics", "Revenue and subscription trends", "platform_billing_analytics"),
            ("Billing reports", "Downloadable billing reports", "platform_billing_reports"),
            ("Billing overview", "Invoices, payments and balances", "platform_billing"),
            ("Net revenue", "Revenue after refunds and credits", "billing_finalization.net_revenue"),
            ("Reconciliation", "Match payments to invoices", "billing_finalization.reconciliation"),
            ("Refunds & credits", "Adjustments made to accounts", "billing_finalization.adjustments"),
            ("Renewal recovery", "Schools due or overdue to renew", "billing_finalization.renewal_recovery"),
            ("Fraud controls", "Payment risk checks", "billing_finalization.fraud_controls"),
            ("Production readiness", "Deployment health", "billing_finalization.readiness")])

    @app.route("/platform/audit-logs")
    @platform_admin_required
    def platform_audit_hub():
        return hub("Audit Logs", "Append-only history of important actions.", [
            ("Platform activity", "Logins and platform actions", "platform_audit"),
            ("Profile & configuration changes", "Profile, custom-field, term and result-setting changes in all schools", "platform_audit_history"),
            ("Security events", "Denied access and security checks", "platform_security_audit"),
            ("Billing audit", "Billing and subscription audit trail", "platform_billing_audit")])

    @app.route("/platform/settings")
    @platform_admin_required
    def platform_settings_hub():
        return hub("Settings", "Platform configuration and maintenance.", [
            ("Subscription plans", "Plans, prices and limits", "platform_plans"),
            ("Roles & permissions", "Platform-level role assignments", "platform_roles"),
            ("Activation requests", "Schools waiting for approval", "platform_activation_requests"),
            ("Notifications", "Send notices to schools", "platform_notifications"),
            ("Backups", "Create and download backups", "platform_backups"),
            ("Billing operations", "Scheduled billing jobs", "platform_billing_operations")])


    # ===================================================================== PRINTABLE RESULT SHEET (staff / student / parent)
    build_result_data = h["build_result_data"]

    def render_print(conn, student_id, term, pdf_url, back_url):
        data = build_result_data(conn, student_id, term["id"])
        return render_template("result_print.html", term=term, student_full_name=student_full_name, pdf_url=pdf_url, back_url=back_url,
                               autoprint=request.args.get("auto") == "1", **data)

    @app.route("/result/<int:student_id>/print")
    @login_required()
    def result_print(student_id):
        conn = get_db()
        try:
            if not h["student_in_school"](conn, student_id):
                flash("Student not found.", "error")
                return redirect(url_for("dashboard"))
            term = h["resolve_term"](conn, request.args.get("term_id", type=int))
            if not term:
                flash("No term set yet.", "error")
                return redirect(url_for("dashboard"))
            cls = h["student_class_for_term"](conn, student_id, term["id"])
            denied = h["require_class_result_access"](conn, cls)
            if denied:
                return denied
            return render_print(conn, student_id, term, url_for("result_pdf", student_id=student_id, term_id=term["id"]),
                                url_for("result", student_id=student_id, term_id=term["id"]))
        finally:
            conn.close()

    @app.route("/student/result/<int:term_id>/print")
    @student_login_required
    def student_result_print(term_id):
        conn = get_db()
        try:
            term = conn.execute("SELECT t.*, se.name AS session_name FROM terms t JOIN sessions se ON se.id=t.session_id WHERE t.id=? AND se.school_id=? AND t.is_published=1",
                                (term_id, sid())).fetchone()
            enrolled = term and conn.execute("SELECT 1 FROM enrollments WHERE student_id=? AND session_id=?", (session["student_id"], term["session_id"])).fetchone()
            if not term or not enrolled:
                flash("That term's result isn't available.", "error")
                return redirect(url_for("student_dashboard"))
            return render_print(conn, session["student_id"], term, url_for("student_result_pdf", term_id=term_id), url_for("student_result", term_id=term_id))
        finally:
            conn.close()

    @app.route("/parent/children/<int:student_id>/result/<int:term_id>/print")
    @h["parent_login_required"]
    def parent_result_print(student_id, term_id):
        conn = get_db()
        try:
            child = h["parent_child"](conn, session["parent_id"], student_id)
            term = conn.execute("SELECT t.*, se.name AS session_name FROM terms t JOIN sessions se ON se.id=t.session_id WHERE t.id=? AND se.school_id=? AND t.is_published=1",
                                (term_id, sid())).fetchone()
            if not child or not term:
                flash("That published result is not available.", "error")
                return redirect(url_for("parent_children_page"))
            return render_print(conn, student_id, term, url_for("parent_result_pdf", student_id=student_id, term_id=term_id),
                                url_for("parent_result", student_id=student_id, term_id=term_id))
        finally:
            conn.close()


    # ===================================================================== REPORTS & ANALYTICS (tenant-isolated)
    import charts as ch
    TOTAL = "(COALESCE(sc.ca1,0)+COALESCE(sc.ca2,0)+COALESCE(sc.ca3,0)+COALESCE(sc.exam,0))"

    def term_avg_rows(conn, term_ids):
        out = {}
        for tid_ in term_ids:
            r = conn.execute(
                f"SELECT AVG({TOTAL}) a FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id "
                "WHERE sc.term_id=? AND c.school_id=?", (tid_, sid())).fetchone()
            out[tid_] = r["a"]
        return out

    @app.route("/reports/analytics")
    @login_required("admin", "sub_admin")
    def reports_analytics():
        conn = get_db()
        try:
            school = sid()
            term = h["resolve_term"](conn, request.args.get("term_id", type=int)) or h["current_term"](conn)
            class_id = request.args.get("class_id", type=int)
            subject_id = request.args.get("subject_id", type=int)
            if class_id and not conn.execute("SELECT 1 FROM classes WHERE id=? AND school_id=?", (class_id, school)).fetchone():
                class_id = None
            if subject_id and not conn.execute("SELECT 1 FROM subjects WHERE id=? AND school_id=?", (subject_id, school)).fetchone():
                subject_id = None
            classes = conn.execute("SELECT * FROM classes WHERE school_id=? ORDER BY level, name, arm", (school,)).fetchall()
            subjects = conn.execute("SELECT * FROM subjects WHERE school_id=? ORDER BY name", (school,)).fetchall()
            terms = all_terms_for_school(conn)
            cf = " AND c.id=:cid" if class_id else ""
            sf = " AND sc.subject_id=:sjid" if subject_id else ""
            P = {"sid": school, "tid": term["id"] if term else -1, "cid": class_id, "sjid": subject_id}

            def q(sql, **extra):
                return conn.execute(sql, {**P, **extra}).fetchall()

            def one(sql):
                return conn.execute(sql, P).fetchone()[0]

            n_students = one("SELECT COUNT(*) FROM students st JOIN classes c ON c.id=st.class_id WHERE c.school_id=:sid AND st.is_active=1" + cf)
            n_staff = one("SELECT COUNT(*) FROM users WHERE school_id=:sid AND role IN ('teacher','sub_admin') AND COALESCE(is_active,1)=1")
            n_classes = one("SELECT COUNT(*) FROM classes c WHERE c.school_id=:sid" + cf)
            gender = q("SELECT COALESCE(NULLIF(st.gender,''),'Not set') g, COUNT(*) n FROM students st JOIN classes c ON c.id=st.class_id "
                       "WHERE c.school_id=:sid AND st.is_active=1" + cf + " GROUP BY 1")
            gmap = {"M": "Male", "F": "Female"}
            enrol = q("SELECT c.name, COUNT(st.id) n FROM classes c LEFT JOIN students st ON st.class_id=c.id AND st.is_active=1 WHERE c.school_id=:sid" + cf + " GROUP BY c.id ORDER BY c.level, c.name, c.arm")
            subj_perf = q(f"SELECT sub.name, AVG({TOTAL}) a FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id JOIN subjects sub ON sub.id=sc.subject_id "
                          f"WHERE sc.term_id=:tid AND c.school_id=:sid AND sub.school_id=:sid{cf}{sf} GROUP BY sub.id ORDER BY sub.name")
            class_perf = q(f"SELECT c.name, AVG({TOTAL}) a FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id "
                           f"WHERE sc.term_id=:tid AND c.school_id=:sid{cf}{sf} GROUP BY c.id ORDER BY c.level, c.name, c.arm")
            scale = conn.execute("SELECT grade, min_score, max_score FROM grade_scale WHERE school_id=? ORDER BY min_score DESC", (school,)).fetchall()
            totals = [r[0] for r in q(f"SELECT {TOTAL} t FROM scores sc JOIN students st ON st.id=sc.student_id JOIN classes c ON c.id=st.class_id WHERE sc.term_id=:tid AND c.school_id=:sid{cf}{sf}")]
            grade_counts = {g["grade"]: 0 for g in scale}
            for t_ in totals:
                for g in scale:
                    if g["min_score"] <= t_ <= g["max_score"] + 0.999:
                        grade_counts[g["grade"]] += 1
                        break
            fail_grade = scale[-1]["grade"] if scale else None
            failed = grade_counts.get(fail_grade, 0) if fail_grade else 0
            passed = len(totals) - failed
            pass_rate = round(passed * 100 / len(totals), 1) if totals else None
            avg_all = round(sum(totals) / len(totals), 1) if totals else None
            ordered_terms = sorted(terms, key=lambda t_: t_["id"])
            avgs = term_avg_rows(conn, [t_["id"] for t_ in ordered_terms])
            trend = [(f"{t_['session_name']} {t_['name']}"[-18:], avgs[t_["id"]]) for t_ in ordered_terms if avgs[t_["id"]] is not None][-8:]
            delta = None
            if term and len(trend) >= 2:
                idx = [t_["id"] for t_ in ordered_terms if avgs[t_["id"]] is not None]
                if term["id"] in idx and idx.index(term["id"]) > 0:
                    prev = avgs[idx[idx.index(term["id"]) - 1]]
                    delta = round((avgs[term["id"]] or 0) - prev, 1)
            att = q("SELECT ar.date d, SUM(CASE WHEN ar.status='present' THEN 1 ELSE 0 END) p, COUNT(*) n FROM attendance_records ar JOIN classes c ON c.id=ar.class_id "
                    "WHERE c.school_id=:sid AND ar.term_id=:tid" + cf + " GROUP BY ar.date ORDER BY ar.date DESC LIMIT 30")
            att = list(reversed(att))
            att_total = sum(r["n"] for r in att)
            att_rate = round(sum(r["p"] for r in att) * 100 / att_total, 1) if att_total else None
            staff_att = q("SELECT status, COUNT(*) n FROM staff_attendance WHERE school_id=:sid AND COALESCE(is_deleted,0)=0 AND date>=date('now','-30 day') GROUP BY status")
            completion = []
            for c in classes:
                if class_id and c["id"] != class_id:
                    continue
                n_st = conn.execute("SELECT COUNT(*) FROM students WHERE class_id=? AND is_active=1", (c["id"],)).fetchone()[0]
                n_sub = conn.execute("SELECT COUNT(*) FROM class_subjects WHERE class_id=?", (c["id"],)).fetchone()[0]
                expected = n_st * n_sub
                done = conn.execute("SELECT COUNT(*) FROM scores sc JOIN students st ON st.id=sc.student_id WHERE st.class_id=? AND st.is_active=1 AND sc.term_id=? "
                                    "AND sc.subject_id IN (SELECT subject_id FROM class_subjects WHERE class_id=?)", (c["id"], P["tid"], c["id"])).fetchone()[0]
                if expected:
                    completion.append((c["name"], round(min(done, expected) * 100 / expected, 1)))
            pub = conn.execute("SELECT SUM(CASE WHEN t.is_published=1 THEN 1 ELSE 0 END) p, SUM(CASE WHEN t.is_published=1 THEN 0 ELSE 1 END) u FROM terms t JOIN sessions se ON se.id=t.session_id WHERE se.school_id=?", (school,)).fetchone()
            top_classes = sorted(((r["name"], r["a"]) for r in class_perf if r["a"] is not None), key=lambda x: -x[1])
            charts = {
                "gender": ch.donut_chart([(gmap.get(r["g"], r["g"]), r["n"]) for r in gender], "Gender distribution", "students"),
                "enrol": ch.bar_chart([(r["name"], r["n"]) for r in enrol], "Class enrollment"),
                "subject": ch.bar_chart([(r["name"], r["a"]) for r in subj_perf if r["a"] is not None], "Subject performance", max_value=100, horizontal=True),
                "class": ch.bar_chart([(r["name"], r["a"]) for r in class_perf if r["a"] is not None], "Class performance comparison", max_value=100),
                "grades": ch.bar_chart(list(grade_counts.items()), "Grade distribution"),
                "passfail": ch.donut_chart([("Passed", passed), ("Failed", failed)], "Pass / fail", "scores"),
                "trend": ch.line_chart(trend, "Term-to-term performance", max_value=100),
                "attendance": ch.line_chart([(r["d"], r["p"] * 100 / r["n"]) for r in att], "Student attendance trend", "%", max_value=100),
                "staff_att": ch.bar_chart([(r["status"], r["n"]) for r in staff_att], "Staff attendance (30 days)"),
                "completion": ch.bar_chart(completion, "Result completion", "%", max_value=100, horizontal=True),
                "published": ch.donut_chart([("Published", pub["p"] or 0), ("Unpublished", pub["u"] or 0)], "Published vs unpublished", "terms"),
            }
            kpis = [("Students", n_students, None), ("Staff", n_staff, None), ("Classes", n_classes, None),
                    ("Average score", avg_all, delta), ("Pass rate", f"{pass_rate}%" if pass_rate is not None else "—", None),
                    ("Attendance", f"{att_rate}%" if att_rate is not None else "—", None)]
            return render_template("reports_analytics.html", term=term, terms=terms, classes=classes, subjects=subjects, class_id=class_id, subject_id=subject_id,
                                   charts=charts, kpis=kpis, top_classes=top_classes, grade_counts=grade_counts, class_perf=class_perf, subj_perf=subj_perf,
                                   completion=completion, has_scores=bool(totals))
        finally:
            conn.close()
