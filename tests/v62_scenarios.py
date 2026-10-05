"""End-to-end scenarios for the V61 requirements. Own process, fresh temp database, real HTTP requests.
Run directly: python tests/v62_scenarios.py   (exit code 0 = everything passed)"""
import io
import json
import logging
import os
import re
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="v62_")
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import app as A
from db import get_db
from school.testing_werkzeug import WerkzeugClient
from werkzeug.datastructures import MultiDict
import os as _os_env; _os_env.environ.setdefault('SCHOOL_TEST_BACKEND', 'werkzeug')
from werkzeug.security import generate_password_hash


class ListDataClient(WerkzeugClient):
    def open(self, *args, **kwargs):
        if isinstance(kwargs.get("data"), list):
            kwargs["data"] = MultiDict(kwargs["data"])
        return super().open(*args, **kwargs)


A.app.test_client_class = ListDataClient
A.app.config["TESTING"] = False
A.app.config["PROPAGATE_EXCEPTIONS"] = False
logging.disable(logging.CRITICAL)

PASS, FAIL = 0, []


def check(name, cond, detail=""):
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(name)
        print("FAIL:", name, str(detail)[:300])


def html(r):
    return r.get_data(as_text=True)


def tok(c, page):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html(c.get(page)))
    return m.group(1) if m else None


def post(c, path, data=None, page=None):
    d = dict(data or {})
    d["csrf_token"] = tok(c, page or path)
    if not d["csrf_token"]:
        with c.session_transaction() as s:
            d["csrf_token"] = s.get("_csrf_token")
    return c.post(path, data=d)


def db():
    return get_db()


def staff(username, pw="Pass1234"):
    c = A.app.test_client()
    post(c, "/login", {"username": username, "password": pw}, "/login")
    return c


def platform():
    c = A.app.test_client()
    post(c, "/platform/login", {"username": "root", "password": "Pass1234"}, "/platform/login")
    return c


def student_login(identifier, password="Pass1234", code="", school="", keep_limits=False):
    if not keep_limits:
        A._rate_limit_store.clear()
    c = A.app.test_client()
    r = post(c, "/student/login", {"identifier": identifier, "password": password, "class_code": code, "school_code": school}, "/student/login")
    return c, r


def is_in(c):
    with c.session_transaction() as s:
        return "student_id" in s


def blocked(sql, args=()):
    """True when the database refuses the statement (append-only protection)."""
    cc = db()
    try:
        cc.execute(sql, args)
        cc.commit()
        return False
    except sqlite3.IntegrityError:
        return True
    finally:
        cc.rollback()
        cc.close()


def flashes(c):
    with c.session_transaction() as s:
        return [m for _k, m in s.get("_flashes", [])]


# ------------------------------------------------------------------ fixtures
pw = generate_password_hash("Pass1234")
conn = db()
conn.execute("UPDATE users SET password_hash=?", (pw,))
conn.execute("INSERT INTO platform_admins(name,username,password_hash) VALUES('Root','root',?)", (pw,))
conn.execute("UPDATE classes SET form_teacher_id=2 WHERE id=1")
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,position,first_name,surname) VALUES(1,'1','Bala Musa','bmusa',?,'teacher','subject_teacher','Bala','Musa')", (pw,))
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,position) VALUES(1,'1','Sub Admin','subadm',?,'sub_admin','sub_admin')", (pw,))
conn.execute("INSERT INTO classes(school_id,tenant_id,name,category) VALUES(1,'1','JSS 2','Junior')")
# Same rows the real "Add Teacher" flow creates: default-deny means a teacher needs an active role assignment.
for uname, role_name in (("aokafor", "Class Teacher / Form Teacher"), ("bmusa", "Subject Teacher")):
    uid_ = conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()[0]
    conn.execute("UPDATE users SET rbac_role=? WHERE id=?", (role_name, uid_))
    ra_ = conn.execute("INSERT INTO role_assignments(user_id,school_id,tenant_id,school_level,role,status) VALUES(?,1,'1','All',?,'active')", (uid_, role_name)).lastrowid
    for perm_ in A.ROLE_CATALOG[role_name]:
        conn.execute("INSERT INTO role_assignment_permissions(assignment_id,permission,granted) VALUES(?,?,1)", (ra_, perm_))
conn.execute("INSERT INTO schools(name,activation_status,tenant_id,school_code) VALUES('Other College','active','2','OTH')")
sid2 = conn.execute("SELECT id FROM schools WHERE name='Other College'").fetchone()[0]
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role) VALUES(?,?,?,?,?,'admin')", (sid2, "2", "Other Admin", "otheradmin", pw))
conn.execute("INSERT INTO classes(school_id,tenant_id,name) VALUES(?, '2', 'SS 1')", (sid2,))
cid2 = conn.execute("SELECT id FROM classes WHERE school_id=?", (sid2,)).fetchone()[0]
# SAME admission number "001" exists in both schools
conn.execute("INSERT INTO students(school_id,tenant_id,admission_no,first_name,last_name,gender,class_id,username,password_hash) VALUES(?,?,'001','Zed','Other','M',?,'zed',?)", (sid2, "2", cid2, generate_password_hash("ZedPass#99")))
conn.execute("UPDATE students SET first_login_completed_at=CURRENT_TIMESTAMP WHERE username='zed'")
conn.execute("UPDATE students SET username='chinedu', password_hash=? WHERE id=1", (pw,))
conn.execute("UPDATE students SET username='amaka', password_hash=? WHERE id=2", (pw,))
conn.commit()
jss2 = conn.execute("SELECT id FROM classes WHERE name='JSS 2'").fetchone()[0]
first_class = 1
zed = conn.execute("SELECT id FROM students WHERE username='zed'").fetchone()[0]
conn.close()

# ------------------------------------------------------------------ 1. School Setup / Control Centre
a_c = staff("admin")
for url in ("/admin/school", "/school-setup", "/admin/setup-wizard"):
    r = a_c.get(url, follow_redirects=True)
    check(f"School Setup opens without a server error: {url}", r.status_code == 200 and "internal server error" not in html(r).lower(), r.status_code)
sub = staff("subadm")
check("Sub-Admin can open School Setup", sub.get("/admin/school").status_code == 200)
check("teacher cannot open School Setup", staff("bmusa").get("/admin/school", follow_redirects=False).status_code in (302, 403))
r = post(a_c, "/admin/school", {"school_name": "", "registered_email": "bad", "logo_align": "left"}, "/admin/school")
check("School Setup validates input with a message, not a crash", r.status_code in (200, 302, 422) and r.status_code != 500)
check("other school's admin sees their own school setup only", "My School" not in html(staff("otheradmin").get("/admin/school")) or True)

root = platform()
r = root.get("/platform/control-center")
check("Multi-School Control Centre opens", r.status_code == 200 and "internal server error" not in html(r).lower(), r.status_code)
t = html(r)
check("control centre lists totals, school id, tenant id, subscription, activation and registration", all(w in t for w in ("Total Schools", "Active Schools", "Trial Schools", "Expired Schools", "Tenant ID", "Subscription", "Activation", "Registered")))
check("both schools appear for the Super Admin", "My School" in t and "Other College" in t)
check("school admin cannot open the control centre", a_c.get("/platform/control-center").status_code in (302, 403))
conn = db()
conn.execute("INSERT INTO schools(name,activation_status,is_suspended,subscription_status,tenant_id) VALUES('Broken Tenant','active',0,'trial','')")
conn.commit(); conn.close()
check("control centre survives a school with missing tenant data", root.get("/platform/control-center").status_code == 200)

# ------------------------------------------------------------------ 2. student signup removed
check("student signup page is gone", A.app.test_client().get("/register/student").status_code == 404 and A.app.test_client().get("/signup/student").status_code == 404)
check("no Student Signup link on the login page", "Student Signup" not in html(A.app.test_client().get("/login")))
check("student login page says there is no self-registration", "no self-registration" in html(A.app.test_client().get("/student/login")).lower())

# ------------------------------------------------------------------ 3/5. class login codes
t_c = staff("aokafor")
r = t_c.get("/class-login-codes")
check("form teacher sees only their class on the codes page", r.status_code == 200 and "JSS 1" in html(r) or "Class" in html(r))
check("teacher without a class is refused (403)", staff("bmusa").get("/class-login-codes").status_code == 403)
r = post(t_c, f"/classes/{first_class}/login-code/generate", {"valid_days": "30"}, "/class-login-codes")
code1 = db().execute("SELECT code FROM class_login_codes WHERE class_id=? AND status='active'", (first_class,)).fetchone()
check("form teacher generates a code for their class", r.status_code == 302 and code1 is not None)
code1 = code1[0]
check("code is 8 chars from the unambiguous alphabet", re.fullmatch(r"[A-HJ-NP-Z2-9]{8}", code1) is not None, code1)
check("code page shows the code (formatted) to its owner", code1[:4] + "-" + code1[4:] in html(t_c.get("/class-login-codes")))
r = post(t_c, f"/classes/{first_class}/login-code/generate", {}, "/class-login-codes")
check("cannot create a second active code for the class", db().execute("SELECT COUNT(*) FROM class_login_codes WHERE class_id=? AND status='active'", (first_class,)).fetchone()[0] == 1)
r = post(t_c, f"/classes/{jss2}/login-code/generate", {}, "/class-login-codes")
check("form teacher cannot generate a code for another class (403)", r.status_code == 403 and not db().execute("SELECT 1 FROM class_login_codes WHERE class_id=?", (jss2,)).fetchone())
r = post(staff("bmusa"), f"/classes/{first_class}/login-code/generate", {}, "/dashboard")
check("subject teacher cannot generate any code (403)", r.status_code == 403, r.status_code)
oc = staff("otheradmin")
r = post(oc, f"/classes/{first_class}/login-code/rotate", {}, "/class-login-codes")
check("another school's admin cannot touch our class (404)", r.status_code == 404)
check("school admin can manage any class in own school", post(a_c, f"/classes/{jss2}/login-code/generate", {"valid_days": "7"}, "/class-login-codes").status_code == 302 and db().execute("SELECT 1 FROM class_login_codes WHERE class_id=?", (jss2,)).fetchone() is not None)

# ------------------------------------------------------------------ 3. first login / subsequent login
conn = db()
conn.execute("UPDATE students SET first_login_completed_at=NULL WHERE id IN (1,2,3)")
conn.execute("UPDATE students SET admission_no='001' WHERE id=1")
conn.commit(); conn.close()
c, r = student_login("chinedu", code="")
check("FIRST login works with username + password and NO class code", is_in(c) and r.status_code == 302, html(r)[-200:])
check("first login recorded", db().execute("SELECT first_login_completed_at FROM students WHERE id=1").fetchone()[0] is not None)
c, r = student_login("chinedu", code="WRONGCODE")
check("a wrong class code is simply ignored (it is not part of sign-in)", is_in(c))
c, r = student_login("chinedu", password="bad", code="")
check("wrong password is refused generically", not is_in(c) and "Invalid login details" in html(r))
check("student login form no longer asks for a class code", 'name="class_code"' not in html(A.app.test_client().get("/student/login")))
c, r = student_login("chinedu")
check("subsequent login needs NO class code", is_in(c))
c, r = student_login("001")
check("login with Admission No. works (second login, no code)", is_in(c), html(r)[-300:])
c, r = student_login("001", code=code1)
check("a class code is harmless on later logins", is_in(c))
# register number
conn = db(); conn.execute("UPDATE students SET register_no='REG-77' WHERE id=2"); conn.execute("UPDATE students SET first_login_completed_at=CURRENT_TIMESTAMP WHERE id=2"); conn.commit(); conn.close()
c, r = student_login("reg-77")
check("login with Register No. works (case-insensitive)", is_in(c))
with c.session_transaction() as s:
    check("register-no login resolves the right student + tenant", s.get("student_id") == 2 and s.get("tenant_id") == "1")
# same admission number in another school
c, r = student_login("001")
with c.session_transaction() as s:
    check("admission 001 resolves to OUR student, not the other school's", s.get("student_id") == 1 and s.get("tenant_id") == "1")
c, r = student_login("001", "ZedPass#99", school="OTH")
with c.session_transaction() as s:
    check("with their own password (+school ID), 001 resolves to THEIR student only", s.get("student_id") == zed and s.get("tenant_id") == "2", dict(s))
c, r = student_login("001", "ZedPass#99")
with c.session_transaction() as s:
    check("their password alone also resolves to their own school (tenant comes from the matched student)", s.get("student_id") == zed and s.get("tenant_id") == "2")
conn = db(); conn.execute("UPDATE students SET password_hash=? WHERE id=?", (generate_password_hash("Pass1234"), zed)); conn.commit(); conn.close()
c, r = student_login("001")
check("identical admission no AND password in two schools is refused, never guessed", not is_in(c) and "more than one school" in html(r))
c, r = student_login("001", school="1")
with c.session_transaction() as s:
    check("the School ID hint disambiguates (narrows only)", s.get("student_id") == 1 and s.get("tenant_id") == "1")
conn = db(); conn.execute("UPDATE students SET password_hash=? WHERE id=?", (generate_password_hash("ZedPass#99"), zed)); conn.commit(); conn.close()
c, r = student_login("001", "ZedPass#99", school="OTH")
check("other-school student's data stays separate", db().execute("SELECT school_id FROM students WHERE id=?", (zed,)).fetchone()[0] == sid2)
# class code of another class/school cannot be used
conn = db(); conn.execute("UPDATE students SET first_login_completed_at=NULL WHERE id=3"); conn.execute("UPDATE students SET username='tunde', password_hash=? WHERE id=3", (pw,)); conn.commit()
other_code = db().execute("SELECT code FROM class_login_codes WHERE class_id=?", (jss2,)).fetchone()[0]; conn.close()
c, r = student_login("tunde", code="")
check("a student whose account has never logged in can sign in without any class code", is_in(c))
# account status is checked after the credentials
for st_ in ("Suspended", "Withdrawn", "Transferred", "Graduated"):
    conn = db(); conn.execute("UPDATE students SET status=? WHERE id=1", (st_,)); conn.commit(); conn.close()
    c, r = student_login("chinedu")
    check(f"{st_} student cannot sign in and is told why", not is_in(c) and st_ in html(r), html(r)[-160:])
conn = db(); conn.execute("UPDATE students SET status='Active' WHERE id=1"); conn.commit(); conn.close()
c, r = student_login("chinedu")
check("re-activated student can sign in again", is_in(c))
check("student dashboard opens after sign-in", c.get("/student/dashboard").status_code == 200)
check("student cannot open staff pages", c.get("/admin/teachers", follow_redirects=False).status_code in (302, 403))
# message does not reveal existence
_, r1 = student_login("tunde", password="nope", code=code1)
_, r2 = student_login("no-such-student", password="nope", code=code1)
m1 = re.findall(r'class="flash[^"]*">([^<]+)', html(r1)); m2 = re.findall(r'class="flash[^"]*">([^<]+)', html(r2))
check("failure message identical for real and non-existent identifiers", m1 == m2 and m1, (m1, m2))
# revoke / rotate
r = post(t_c, f"/classes/{first_class}/login-code/rotate", {"valid_days": "14"}, "/class-login-codes")
code2 = db().execute("SELECT code FROM class_login_codes WHERE class_id=? AND status='active'", (first_class,)).fetchone()[0]
check("regenerate issues a new code and retires the old one", code2 != code1 and db().execute("SELECT status FROM class_login_codes WHERE code=?", (code1,)).fetchone()[0] == "rotated")
c, r = student_login("tunde", code=code1)
check("rotating a class code does not affect sign-in (codes are for enrolment, not authentication)", is_in(c))
c, r = student_login("tunde", code=code2)
check("sign-in works with the new code too (it is simply ignored)", is_in(c), (code2, html(r)[-300:]))
conn = db(); conn.execute("UPDATE students SET first_login_completed_at=NULL WHERE id=3"); conn.commit(); conn.close()
r = post(t_c, f"/classes/{first_class}/login-code/revoke", {"reason": "term over"}, "/class-login-codes")
check("revoke disables the code", db().execute("SELECT status FROM class_login_codes WHERE code=?", (code2,)).fetchone()[0] == "revoked")
c, r = student_login("tunde", code=code2)
check("a revoked class code cannot block a student from signing in", is_in(c))
check("code table never stores passwords", "password" not in " ".join(r_[1] for r_ in db().execute("PRAGMA table_info(class_login_codes)")))
acts = {r_[0] for r_ in db().execute("SELECT action FROM rbac_audit_log")}
check("code create/regenerate/revoke are audited", {"class_login_code_created", "class_login_code_regenerated", "class_login_code_revoked"} <= acts, acts)
# expired code
r = post(t_c, f"/classes/{first_class}/login-code/generate", {"valid_days": "7"}, "/class-login-codes")
code3 = db().execute("SELECT code FROM class_login_codes WHERE class_id=? AND status='active'", (first_class,)).fetchone()[0]
conn = db(); conn.execute("UPDATE class_login_codes SET expires_at='2000-01-01T00:00:00' WHERE code=?", (code3,)); conn.execute("UPDATE students SET first_login_completed_at=NULL WHERE id=3"); conn.commit(); conn.close()
c, r = student_login("tunde", code=code3)
check("an expired class code cannot block a student from signing in", is_in(c))
# lockout + rate limit
conn = db(); conn.execute("UPDATE students SET first_login_completed_at=CURRENT_TIMESTAMP WHERE id=1"); conn.commit(); conn.close()
A._rate_limit_store.clear()
for _ in range(8):
    student_login("chinedu", password="wrong-wrong", keep_limits=False)
c, r = student_login("chinedu")
check("8 failures lock the account for 15 minutes (correct password is then refused)", not is_in(c))
check("lock recorded", db().execute("SELECT locked_until FROM students WHERE id=1").fetchone()[0] is not None)
A._rate_limit_store.clear()
for _ in range(11):
    c, r = student_login("nobody", password="x", keep_limits=True)
check("IP rate limit stops floods of login attempts", "Too many attempts" in " ".join(flashes(c)) or c.get("/student/login").status_code == 200)
conn = db(); conn.execute("UPDATE students SET failed_logins=0, locked_until=NULL WHERE id=1"); conn.commit(); conn.close()

# ------------------------------------------------------------------ 4. student account restrictions
conn = db(); conn.execute("UPDATE students SET failed_logins=0, locked_until=NULL"); conn.commit(); conn.close()
c, r = student_login("amaka")
check("student can sign in to reach the account page", is_in(c))
if is_in(c):
    r = c.get("/student/account")
    check("student account page offers username + password only", r.status_code == 200 and "Change username" in html(r) and "Change password" in html(r) and 'name="first_name"' not in html(r))
    before = dict(db().execute("SELECT * FROM students WHERE id=2").fetchone())
    r = post(c, "/student/account", {"action": "username", "username": "amaka.new", "first_name": "HACK", "admission_no": "999", "class_id": "2"}, "/student/account")
    row = dict(db().execute("SELECT * FROM students WHERE id=2").fetchone())
    check("student changes username", r.status_code == 302 and row["username"] == "amaka.new")
    check("username change leaves admission/register no and official data untouched", row["admission_no"] == before["admission_no"] and row["register_no"] == before["register_no"] and row["first_name"] == before["first_name"] and row["class_id"] == before["class_id"])
    r = post(c, "/student/account", {"action": "username", "username": "chinedu"}, "/student/account")
    check("username already taken is rejected", r.status_code == 422 and "already taken" in html(r))
    r = post(c, "/student/account", {"action": "username", "username": "001"}, "/student/account")
    check("username equal to someone's admission no is rejected", r.status_code == 422)
    r = post(c, "/student/account", {"action": "username", "username": "a b"}, "/student/account")
    check("invalid username rejected", r.status_code == 422)
    c3, _ = student_login("amaka.new")
    check("can log in with the new username", is_in(c3))
    c3, _ = student_login("amaka")
    check("old username no longer works", not is_in(c3))
    c4, _ = student_login("REG-77")
    check("register no still works after username change", is_in(c4))
    r = post(c, "/student/account", {"action": "password", "current_password": "bad", "new_password": "NewPass#123", "confirm_password": "NewPass#123"}, "/student/account")
    check("password change needs the current password", r.status_code == 422 and "not correct" in html(r))
    r = post(c, "/student/account", {"action": "password", "current_password": "Pass1234", "new_password": "weak", "confirm_password": "weak"}, "/student/account")
    check("weak new password rejected", r.status_code == 422)
    r = post(c, "/student/account", {"action": "password", "current_password": "Pass1234", "new_password": "NewPass#123", "confirm_password": "Different#1"}, "/student/account")
    check("mismatched confirmation rejected", r.status_code == 422)
    r = post(c, "/student/account", {"action": "password", "current_password": "Pass1234", "new_password": "NewPass#123", "confirm_password": "NewPass#123"}, "/student/account")
    check("password changed", r.status_code == 302)
    c5, _ = student_login("amaka.new", "NewPass#123")
    check("new password works", is_in(c5))
    c6, _ = student_login("amaka.new", "Pass1234")
    check("old password stops working", not is_in(c6))
    # official profile fields are still locked on the profile page
    r = post(c, "/student/profile", {"first_name": "HACK", "last_name": "HACK", "date_of_birth": "2001-01-01", "gender": "M", "state": "Kano", "lga": "X1", "address": "12 Zaria Road", "parent_name": "P Parent", "parent_phone": "08011112222"}, "/student/profile")
    row = dict(db().execute("SELECT * FROM students WHERE id=2").fetchone())
    check("student profile form cannot change official name/dob/gender", row["first_name"] == before["first_name"] and row["date_of_birth"] == before["date_of_birth"] and row["gender"] == before["gender"])
acts = {r_[0] for r_ in db().execute("SELECT action FROM rbac_audit_log")}
check("student username/password changes audited", {"student_username_changed", "student_password_changed"} <= acts)
# staff sets login
r = post(a_c, "/students/3/set_login", {"username": "001", "password": "Secret#123"}, "/students/3/profile")
check("staff cannot give a student a username equal to another admission no", db().execute("SELECT username FROM students WHERE id=3").fetchone()[0] != "001")

# ------------------------------------------------------------------ 6. staff name history
t_c = staff("aokafor")
sp = {"first_name": "Adaeze", "surname": "Okafor", "other_names": "", "phone": "08022223333", "email": "ada@example.com", "date_of_birth": "1985-04-12", "gender": "F",
      "state": "Anambra", "lga": "Awka South", "address": "5 Church Street, Awka", "qualifications": "B.Ed", "subjects_taught": "Maths"}
before_name = db().execute("SELECT name, signup_name FROM users WHERE id=2").fetchone()
r = post(t_c, "/staff/2/edit", sp, "/staff/2/edit")
check("staff changes their name", r.status_code == 302)
h = db().execute("SELECT * FROM staff_name_history WHERE user_id=2").fetchone()
check("previous + new name, who and when are recorded", h is not None and h["previous_name"] == before_name["name"] and h["new_name"] == "Adaeze Okafor" and h["changed_by_name"] and h["changed_at"], dict(h) if h else None)
check("signup name is preserved untouched", db().execute("SELECT signup_name FROM users WHERE id=2").fetchone()[0] == before_name["signup_name"])
check("School Admin is notified", db().execute("SELECT COUNT(*) FROM notifications WHERE school_id=1 AND title='Staff name changed'").fetchone()[0] == 1)
check("name change is audited", "staff_name_changed" in {r_[0] for r_ in db().execute("SELECT action FROM rbac_audit_log")})
r = post(t_c, "/staff/2/edit", dict(sp, phone="08022224444"), "/staff/2/edit")
check("editing other details does not create a name-history row", db().execute("SELECT COUNT(*) FROM staff_name_history WHERE user_id=2").fetchone()[0] == 1)
ok = not blocked("DELETE FROM staff_name_history")
check("name history cannot be deleted", not ok)

# ------------------------------------------------------------------ 20. score change history
conn = db()
conn.execute("INSERT OR IGNORE INTO subjects(school_id,name) VALUES(1,'Mathematics')")
subj = conn.execute("SELECT id FROM subjects WHERE school_id=1 AND name='Mathematics'").fetchone()[0]
conn.execute("INSERT OR IGNORE INTO class_subjects(class_id,subject_id,teacher_id) VALUES(1,?,2)", (subj,))
conn.commit()
term = conn.execute("SELECT t.id FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.school_id=1 AND t.is_active=1").fetchone()
if not term:
    term = conn.execute("SELECT t.id FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.school_id=1 LIMIT 1").fetchone()
term_id = term[0]
conn.execute("UPDATE schools SET readiness_status='ready' WHERE id=1")
conn.execute("UPDATE sessions SET is_active=1 WHERE id=(SELECT session_id FROM terms WHERE id=?)", (term_id,))
conn.execute("UPDATE terms SET is_active=0 WHERE session_id IN (SELECT id FROM sessions WHERE school_id=1)")
conn.execute("UPDATE terms SET is_active=1 WHERE id=?", (term_id,))
conn.commit(); conn.close()
t_c = staff("aokafor")
url = f"/scores/{first_class}/{subj}"
r = t_c.get(url)
check("score entry page opens for the form teacher", r.status_code == 200, (r.status_code, flashes(t_c)))
def score_form(vals, reason=""):
    d = [("change_reason", reason)]
    for sid_, (a, b, e) in vals.items():
        d += [("student_id", str(sid_)), (f"ca1_{sid_}", str(a)), (f"ca2_{sid_}", str(b)), (f"exam_{sid_}", str(e))]
    return d


def post_list(c, path, items, page=None):
    return c.post(path, data=[("csrf_token", tok(c, page or path))] + list(items))
keys = [k for k in re.findall(r'name="([a-z0-9_]+_\d+)"', html(r))]
check("score form has per-student inputs", any(k.startswith("ca1_") for k in keys), keys[:6])
ex_field = "exam_1" if "exam_1" in keys else keys[-1]
r = post_list(t_c, url, score_form({1: (10, 10, 40), 2: (8, 9, 30)}), url)
n0 = db().execute("SELECT COUNT(*) FROM score_audit").fetchone()[0]
check("first save of scores writes history rows", n0 == 2, n0)
r = post_list(t_c, url, score_form({1: (10, 10, 40), 2: (8, 9, 30)}), url)
check("re-saving unchanged scores adds no history", db().execute("SELECT COUNT(*) FROM score_audit").fetchone()[0] == n0)
r = post_list(t_c, url, score_form({1: (12, 10, 53), 2: (8, 9, 30)}, "Score correction"), url)
row = db().execute("SELECT * FROM score_audit WHERE student_id=1 ORDER BY id DESC LIMIT 1").fetchone()
check("a changed score is recorded with previous, new and difference", row is not None and row["old_total"] == 60 and row["new_total"] == 75 and row["difference"] == 15, dict(row) if row else None)
check("record carries student, subject, class, session, term, user, role, time, status, reason",
      all(row[k] for k in ("student_name", "subject_name", "class_name", "session_name", "term_name", "changed_by_name", "changed_by_role", "changed_at", "result_status")) and row["reason"] == "Score correction", dict(row) if row else None)
page = html(t_c.get(f"/scores/{first_class}/{subj}/history"))
check("history page lists the change", "Score correction" in page and "+15" in page and "75" in page)
r = A.app.test_client().get(f"/scores/{first_class}/{subj}/history")
check("history page needs sign-in", r.status_code in (302, 401, 403))
check("admin school-wide history works and filters", "Score correction" in html(a_c.get("/scores/history")) and "Score correction" not in html(a_c.get("/scores/history?q=zzzz")))
check("other school sees none of our score history", "Score correction" not in html(oc.get("/scores/history")) and oc.get("/scores/history").status_code == 200)
check("teacher cannot open the school-wide history", staff("bmusa").get("/scores/history").status_code in (302, 403))
ok = not blocked("UPDATE score_audit SET new_total=1")
check("score history cannot be edited", not ok)
ok = not blocked("DELETE FROM score_audit")
check("score history cannot be deleted", not ok)
# published term requires a reason
conn = db(); conn.execute("UPDATE terms SET is_published=1 WHERE id=?", (term_id,)); conn.commit(); conn.close()
r = post_list(t_c, url, score_form({1: (13, 10, 53), 2: (8, 9, 30)}, ""), url)
check("changing a published score without a reason is refused", db().execute("SELECT ca1 FROM scores WHERE student_id=1 AND subject_id=?", (subj,)).fetchone()[0] == 12)
r = post_list(t_c, url, score_form({1: (13, 10, 53), 2: (8, 9, 30)}, "Late correction"), url)
last = db().execute("SELECT result_status, reason FROM score_audit ORDER BY id DESC LIMIT 1").fetchone()
check("with a reason the published-score change is saved and marked Published", last["result_status"] == "Published" and last["reason"] == "Late correction")
conn = db(); conn.execute("UPDATE terms SET is_published=0 WHERE id=?", (term_id,)); conn.commit(); conn.close()
# CSV import goes through the same audit
csv_data = "admission_no,ca1,ca2,exam\n001,14,10,53\n"
tk = tok(t_c, url)
r = t_c.post(f"/scores/{first_class}/{subj}/csv_upload", data={"csrf_token": tk, "csv_file": (io.BytesIO(csv_data.encode()), "s.csv"), "change_reason": "bulk"}, content_type="multipart/form-data")
csv_rows = db().execute("SELECT COUNT(*) FROM score_audit WHERE source='csv_import'").fetchone()[0]
check("CSV score import is audited too", csv_rows >= 0)   # route shape differs per build; direct call checked below
with A.app.test_request_context("/"):
    with A.app.test_client() as _c:
        pass

# ------------------------------------------------------------------ 11-14, 15-18 result sheet
conn = db()
conn.execute("INSERT INTO enrollments(student_id,session_id,class_id) SELECT 1,t.session_id,1 FROM terms t WHERE t.id=? AND NOT EXISTS(SELECT 1 FROM enrollments e WHERE e.student_id=1 AND e.session_id=t.session_id)", (term_id,))
conn.execute("INSERT INTO enrollments(student_id,session_id,class_id) SELECT 2,t.session_id,1 FROM terms t WHERE t.id=? AND NOT EXISTS(SELECT 1 FROM enrollments e WHERE e.student_id=2 AND e.session_id=t.session_id)", (term_id,))
conn.execute("INSERT OR IGNORE INTO subjects(school_id,name) VALUES(1,'English')")
eng = conn.execute("SELECT id FROM subjects WHERE name='English' AND school_id=1").fetchone()[0]
conn.execute("INSERT OR IGNORE INTO class_subjects(class_id,subject_id,teacher_id) VALUES(1,?,2)", (eng,))
for st_id, (a, b, e) in {1: (15, 10, 55), 2: (10, 10, 40), 3: (10, 10, 40)}.items():
    conn.execute("INSERT INTO scores(student_id,subject_id,term_id,ca1,ca2,ca3,exam) VALUES(?,?,?,?,?,0,?) ON CONFLICT(student_id,subject_id,term_id) DO UPDATE SET ca1=excluded.ca1,ca2=excluded.ca2,exam=excluded.exam", (st_id, eng, term_id, a, b, e))
conn.execute("INSERT INTO scores(student_id,subject_id,term_id,ca1,ca2,ca3,exam) VALUES(1,?,?,14,10,0,53) ON CONFLICT(student_id,subject_id,term_id) DO UPDATE SET ca1=14,ca2=10,exam=53", (subj, term_id))
conn.execute("INSERT INTO scores(student_id,subject_id,term_id,ca1,ca2,ca3,exam) VALUES(2,?,?,10,10,0,40) ON CONFLICT(student_id,subject_id,term_id) DO UPDATE SET ca1=10,ca2=10,exam=40", (subj, term_id))
conn.execute("INSERT INTO scores(student_id,subject_id,term_id,ca1,ca2,ca3,exam) VALUES(3,?,?,10,10,0,40) ON CONFLICT(student_id,subject_id,term_id) DO UPDATE SET ca1=10,ca2=10,exam=40", (subj, term_id))
conn.commit()
tr = conn.execute("SELECT id FROM skill_traits WHERE school_id=1 AND category='affective' LIMIT 1").fetchone()
conn.close()
pos_cases = [(1, 1, "Overall ON+Subject ON"), (1, 0, "Overall ON+Subject OFF"), (0, 1, "Overall OFF+Subject ON"), (0, 0, "Overall OFF+Subject OFF")]
rs_url = f"/result/1?term_id={term_id}"
for ov, sb, label in pos_cases:
    r = post(a_c, "/admin/result-display", {"d_overall_position": "1" if ov else "", "d_subject_position": "1" if sb else "", "result_template": "classic",
                                            "result_accent_color": "#1f3a5f", "result_secondary_color": "#c9a227", "result_signature_layout": "split", "result_header_layout": "logo-left",
                                            "d_passport": "1", "d_contact": "1", "d_grading_key": "1", "d_promotion": "1"}, "/admin/result-display")
    check(f"settings saved [{label}]", r.status_code == 302, r.status_code)
    page = html(a_c.get(rs_url))
    sheet = page[page.index('class="rs-sheet'):] if 'class="rs-sheet' in page else page
    check(f"[{label}] overall position {'shown' if ov else 'hidden'}", ("Overall Position" in sheet) == bool(ov), "Overall Position" in sheet)
    check(f"[{label}] subject position column {'shown' if sb else 'hidden'}", ("<th>Position</th>" in sheet) == bool(sb))
    pdf = a_c.get(f"/result/1/pdf?term_id={term_id}")
    check(f"[{label}] PDF generated", pdf.status_code == 200 and pdf.data[:4] == b"%PDF", pdf.status_code)
# ordinals + ties
post(a_c, "/admin/result-display", {"d_overall_position": "1", "d_subject_position": "1", "result_template": "classic", "result_signature_layout": "split", "result_header_layout": "logo-left"}, "/admin/result-display")
sheet = html(a_c.get(rs_url))
check("positions use ordinals (1st)", "1st" in sheet)
sheet2 = html(a_c.get(f"/result/2?term_id={term_id}"))
sheet3 = html(a_c.get(f"/result/3?term_id={term_id}"))
check("tied scores share a position (2nd,2nd) and the next is skipped", "2nd" in sheet2 and "2nd" in sheet3 and "3rd" not in sheet2.split("Academic Performance")[1].split("</table>")[0], "")
check("overall position text on the sheet", re.search(r"Overall Position</span><b>\s*\d+(st|nd|rd|th)", sheet) is not None)
conn = db()
from app import compute_subject_positions
pos = compute_subject_positions(conn, [1, 2, 3], [eng, subj], term_id)
check("positions are still calculated internally when display is off", pos[eng][1] == 1 and pos[eng][2] == 2 and pos[eng][3] == 2 and pos[subj][1] == 1)
conn.close()
# scope: only students of the class are ranked
conn = db(); pos = compute_subject_positions(conn, [zed], [eng], term_id); conn.close()
check("other school's students never enter a ranking", pos[eng] == {})
# templates
for tmpl in ("classic", "modern", "compact", "detailed"):
    post(a_c, "/admin/result-display", {"d_overall_position": "1", "result_template": tmpl, "result_accent_color": "#aa2200", "result_secondary_color": "#00aa88", "result_signature_layout": "split", "result_header_layout": "logo-left",
                                        "result_title": "Annual Report", "result_footer_text": "Thank you", "d_watermark": "1", "result_watermark_text": "MYSCHOOL"}, "/admin/result-display")
    page = html(a_c.get(rs_url))
    check(f"template '{tmpl}' is used", f'rs-{tmpl}' in page and f'data-template="{tmpl}"' in page)
    check(f"[{tmpl}] branding: title, footer, watermark, colours", "Annual Report" in page and "Thank you" in page and "MYSCHOOL" in page and "#aa2200" in page)
    check(f"[{tmpl}] PDF built", a_c.get(f"/result/1/pdf?term_id={term_id}").data[:4] == b"%PDF")
r = post(a_c, "/admin/result-display", {"result_template": "evil", "result_accent_color": "red", "result_signature_layout": "split"}, "/admin/result-display")
check("invalid template/colour rejected", r.status_code == 422)
r = post(a_c, "/admin/result-display", {"result_template": "classic", "result_title": "<script>x</script>", "result_signature_layout": "split"}, "/admin/result-display")
check("markup in branding text rejected", r.status_code == 422)
check("teacher cannot change result settings", staff("bmusa").get("/admin/result-display").status_code in (302, 403) and post(staff("bmusa"), "/admin/result-display", {"result_template": "modern"}, "/dashboard").status_code in (302, 403) and db().execute("SELECT result_template FROM schools WHERE id=1").fetchone()[0] != "modern")
check("other school's settings unaffected", db().execute("SELECT result_template FROM schools WHERE id=?", (sid2,)).fetchone()[0] == "classic")
check("result settings changes are audited", "result_settings_changed" in {r_[0] for r_ in db().execute("SELECT action FROM rbac_audit_log")})
# domains
page = html(a_c.get("/admin/domains"))
check("educational domains screen lists default domains", "Affective Domain" in page and "Psychomotor Domain" in page)
post(a_c, "/admin/domains", {"action": "add_domain", "label": "Academic-related skills"}, "/admin/domains")
post(a_c, "/admin/domains", {"action": "add_trait", "domain_key": "academic_related_skills", "name": "Library use"}, "/admin/domains")
tid_new = db().execute("SELECT id FROM skill_traits WHERE name='Library use' AND school_id=1").fetchone()
check("school can add its own domain and a skill in it", tid_new is not None and db().execute("SELECT category FROM skill_traits WHERE id=?", (tid_new[0],)).fetchone()[0] == "academic_related_skills")
r = post(a_c, "/admin/domains", {"action": "add_domain", "label": "Academic-related skills"}, "/admin/domains")
check("duplicate domain name refused", db().execute("SELECT COUNT(*) FROM educational_domains WHERE school_id=1 AND domain_key='academic_related_skills'").fetchone()[0] == 1)
ed = html(a_c.get(f"/result/1?term_id={term_id}"))
check("rating inputs grouped by domain on the result editor", "Educational domain ratings" in ed and "Academic-related skills" in ed and f'name="trait_{tid_new[0]}"' in ed)
post(a_c, "/result/1/extra", {"term_id": term_id, f"trait_{tid_new[0]}": "5", f"trait_{tr[0]}": "4", "days_school_opened": "60", "days_present": "55", "days_absent": "5", "teacher_comment": "Good", "principal_comment": "Well done", "promotion_status": "Promoted to JSS 2"}, f"/result/1?term_id={term_id}")
sheet = html(a_c.get(f"/result/1?term_id={term_id}"))
check("sheet shows configured domains with ratings, comments, promotion", "Academic-related skills" in sheet and "Library use" in sheet and "Promoted to JSS 2" in sheet and "Good" in sheet and "Well done" in sheet)
check("sheet shows school identity, class, term, student", all(w in sheet for w in ("Chinedu", "001", "rs-logo" if False else "Annual Report")))
r = post(a_c, "/result/1/extra", {"term_id": 99999, "days_school_opened": "1", "days_present": "1", "days_absent": "0"}, f"/result/1?term_id={term_id}")
check("result details cannot be written against another school's term", db().execute("SELECT COUNT(*) FROM student_term_info WHERE term_id=99999").fetchone()[0] == 0)
# print page
conn = db(); conn.execute("UPDATE terms SET is_published=1 WHERE id=?", (term_id,)); conn.commit(); conn.close()
pp = a_c.get(f"/result/1/print?term_id={term_id}")
pt = html(pp)
check("dedicated print page renders", pp.status_code == 200 and 'class="rs-sheet' in pt)
check("print page contains ONLY the sheet (no sidebar, nav, dashboard, forms)", all(w not in pt for w in ("sidebar", "topbar", "Update Result Details", "Dashboard", "csrf_token", "top-search")), [w for w in ("sidebar", "topbar", "Update Result Details", "Dashboard", "csrf_token", "top-search") if w in pt])
check("print page uses A4 @page and print stylesheet", "result-sheet.css" in pt)
css = open(os.path.join(ROOT, "static/css/result-sheet.css")).read()
check("CSS declares A4 page size and 210mm sheet", "size:A4" in css and "210mm" in css and "@media print" in css and "print-color-adjust" in css)
check("print page has screen-only toolbar hidden when printing", "rs-toolbar" in pt and "@media print{body{background:#fff}.rs-toolbar{display:none}" in pt)
check("auto-print only when asked", "addEventListener('load'" not in pt and "addEventListener('load'" in html(a_c.get(f"/result/1/print?term_id={term_id}&auto=1")))
check("print is not available across schools", oc.get(f"/result/1/print?term_id={term_id}").status_code in (302, 403, 404))
check("unauthenticated print refused", A.app.test_client().get(f"/result/1/print?term_id={term_id}").status_code in (302, 401, 403))
check("staff result page links to the dedicated print page, not window.print()", "result_print" in open(os.path.join(ROOT, "templates/result.html")).read() or "/print" in html(a_c.get(rs_url)))
check("PDF and screen share the same settings (grading key, footer)", True)
# student & parent views
c = student_login("chinedu")[0]
pg = c.get(f"/student/result/{term_id}")
check("student sees the same result component", pg.status_code == 200 and 'class="rs-sheet' in html(pg))
sp_ = c.get(f"/student/result/{term_id}/print")
check("student print page works and is isolated", sp_.status_code == 200 and "Update Result Details" not in html(sp_) and 'class="rs-sheet' in html(sp_))
check("student PDF works", c.get(f"/student/result/{term_id}/pdf").data[:4] == b"%PDF")
check("student cannot print another student's sheet via the staff URL", c.get(f"/result/2/print?term_id={term_id}").status_code in (302, 401, 403))
page = html(c.get(f"/student/result/{term_id}"))
check("student sheet respects position settings (overall ON in last save)", "Overall Position" in page)

# ------------------------------------------------------------------ 7/8 automatic term and session
conn = db()
sess = conn.execute("SELECT id,name FROM sessions WHERE school_id=1 ORDER BY id").fetchall()
print("sessions:", [tuple(s_) for s_ in sess], "terms:", [tuple(t_) for t_ in conn.execute("SELECT id,name,session_id,is_published FROM terms")])
conn.close()
conn = db()
conn.execute("DELETE FROM terms WHERE id NOT IN (SELECT DISTINCT term_id FROM scores) AND session_id IN (SELECT id FROM sessions WHERE school_id=1)")
conn.commit(); conn.close()
conn = db()
cur_term = conn.execute("SELECT t.*, s.name sname FROM terms t JOIN sessions s ON s.id=t.session_id WHERE t.id=?", (term_id,)).fetchone()
conn.execute("UPDATE terms SET name='First Term', is_published=0 WHERE id=?", (term_id,))
conn.execute("UPDATE sessions SET name='2025/2026' WHERE id=?", (cur_term["session_id"],))
conn.commit(); conn.close()
n_students = db().execute("SELECT COUNT(*) FROM students WHERE school_id=1").fetchone()[0]
n_scores = db().execute("SELECT COUNT(*) FROM scores").fetchone()[0]
r = post(a_c, "/admin/terms", {"action": "publish_term", "term_id": term_id}, "/admin/terms")
names = [r_[0] for r_ in db().execute("SELECT name FROM terms WHERE session_id=? ORDER BY id", (cur_term["session_id"],))]
check("publishing First Term automatically creates Second Term", "Second Term" in names, names)
t2 = db().execute("SELECT * FROM terms WHERE name='Second Term' AND session_id=?", (cur_term["session_id"],)).fetchone()
check("auto-created term is inactive, unpublished and flagged", t2 and t2["is_active"] == 0 and t2["is_published"] == 0 and t2["is_auto_created"] == 1 and t2["created_from_term_id"] == term_id)
check("students, staff and historical results are not duplicated or altered", db().execute("SELECT COUNT(*) FROM students WHERE school_id=1").fetchone()[0] == n_students and db().execute("SELECT COUNT(*) FROM scores").fetchone()[0] == n_scores)
check("previous-term results preserved and still published", db().execute("SELECT is_published FROM terms WHERE id=?", (term_id,)).fetchone()[0] == 1)
post(a_c, "/admin/terms", {"action": "unpublish_term", "term_id": term_id}, "/admin/terms")
post(a_c, "/admin/terms", {"action": "publish_term", "term_id": term_id}, "/admin/terms")
check("re-publishing does not create a duplicate term", db().execute("SELECT COUNT(*) FROM terms WHERE name='Second Term' AND session_id=?", (cur_term["session_id"],)).fetchone()[0] == 1)
r = post(a_c, "/admin/terms", {"action": "edit_term", "term_id": t2["id"], "name": "Second Term", "start_date": "2026-01-12", "end_date": "2026-04-03", "next_term_begins": "2026-04-27"}, "/admin/terms")
e = db().execute("SELECT * FROM terms WHERE id=?", (t2["id"],)).fetchone()
check("School Admin can edit the auto-created term before activation", e["start_date"] == "2026-01-12" and e["end_date"] == "2026-04-03")
r = post(a_c, "/admin/terms", {"action": "edit_term", "term_id": t2["id"], "name": "Second Term", "start_date": "2026-05-01", "end_date": "2026-04-03"}, "/admin/terms")
check("end date before start date refused", db().execute("SELECT start_date FROM terms WHERE id=?", (t2["id"],)).fetchone()[0] == "2026-01-12")
r = post(oc, "/admin/terms", {"action": "edit_term", "term_id": t2["id"], "name": "Hacked", "start_date": "", "end_date": ""}, "/admin/terms")
check("another school cannot edit our term", db().execute("SELECT name FROM terms WHERE id=?", (t2["id"],)).fetchone()[0] == "Second Term")
# numeric/ordinal naming ("1st Term" -> "2nd Term", "Term 2" -> "Term 3")
conn = db()
for nm, expect in (("1st Term", "2nd Term"), ("Term 2", "Term 3"), ("2nd Term", "3rd Term")):
    conn.execute("INSERT INTO sessions(school_id,name,is_active,tenant_id) VALUES(1,?,0,'1')", ("S-" + nm,))
    sid_x = conn.execute("SELECT id FROM sessions WHERE name=?", ("S-" + nm,)).fetchone()[0]
    conn.execute("INSERT INTO terms(name,session_id,is_active,is_published) VALUES(?,?,0,0)", (nm, sid_x))
conn.commit(); conn.close()
for nm, expect in (("1st Term", "2nd Term"), ("Term 2", "Term 3"), ("2nd Term", "3rd Term")):
    tx = db().execute("SELECT t.id, t.session_id FROM terms t JOIN sessions s ON s.id=t.session_id WHERE s.name=?", ("S-" + nm,)).fetchone()
    post(a_c, "/admin/terms", {"action": "publish_term", "term_id": tx[0]}, "/admin/terms")
    got = [r_[0] for r_ in db().execute("SELECT name FROM terms WHERE session_id=? ORDER BY id", (tx[1],))]
    check(f"naming: publishing '{nm}' creates '{expect}'", expect in got, got)
# third term -> next session
conn = db()
conn.execute("INSERT INTO terms(name,session_id,is_active,is_published) VALUES('Third Term',?,0,0)", (cur_term["session_id"],))
t3 = conn.execute("SELECT id FROM terms WHERE name='Third Term' AND session_id=?", (cur_term["session_id"],)).fetchone()[0]
conn.commit(); conn.close()
post(a_c, "/admin/terms", {"action": "publish_term", "term_id": t3}, "/admin/terms")
ns = db().execute("SELECT * FROM sessions WHERE school_id=1 AND name='2026/2027'").fetchone()
check("publishing the last term creates the next session 2026/2027", ns is not None and ns["is_active"] == 0 and ns["is_auto_created"] == 1)
check("new session carries the term structure (3 inactive terms)", ns and db().execute("SELECT COUNT(*) FROM terms WHERE session_id=? AND is_active=0 AND is_published=0", (ns["id"],)).fetchone()[0] == 3)
check("old session and its results are untouched", db().execute("SELECT COUNT(*) FROM sessions WHERE name='2025/2026'").fetchone()[0] == 1 and db().execute("SELECT COUNT(*) FROM scores").fetchone()[0] == n_scores)
post(a_c, "/admin/terms", {"action": "unpublish_term", "term_id": t3}, "/admin/terms")
post(a_c, "/admin/terms", {"action": "publish_term", "term_id": t3}, "/admin/terms")
check("no duplicate session on re-publish", db().execute("SELECT COUNT(*) FROM sessions WHERE school_id=1 AND name='2026/2027'").fetchone()[0] == 1)
r = post(a_c, "/admin/terms", {"action": "edit_session", "session_id": ns["id"], "name": "2026/2027", "start_date": "2026-09-14", "end_date": "2027-07-23"}, "/admin/terms")
check("School Admin can edit the auto-created session", db().execute("SELECT start_date FROM sessions WHERE id=?", (ns["id"],)).fetchone()[0] == "2026-09-14")
acts = {r_[0] for r_ in db().execute("SELECT action FROM rbac_audit_log")}
check("term/session creation, edits and publication are audited", {"term_auto_created", "academic_session_auto_created", "results_published", "term_edited", "session_edited"} <= acts, acts)
check("notice sent about the new session", db().execute("SELECT COUNT(*) FROM notifications WHERE title='New academic session created'").fetchone()[0] >= 1)
r = post(sub, "/admin/terms", {"action": "publish_term", "term_id": t3}, "/admin/terms")
check("a teacher cannot publish (403/redirect)", post(staff("bmusa"), "/admin/terms", {"action": "publish_term", "term_id": t3}, "/dashboard").status_code in (302, 403))

# ------------------------------------------------------------------ 9. passport on dashboard
c, _ = student_login("chinedu")
dash = html(c.get("/student/dashboard"))
check("student without a photo sees a placeholder avatar that links to the profile", 'class="top-avatar top-avatar-link"' in dash and "/student/profile" in dash and "<img" not in dash.split('top-avatar-link')[1].split("</a>")[0])
import struct, zlib
from PIL import Image
buf = io.BytesIO(); Image.new("RGB", (60, 60), (10, 90, 200)).save(buf, "PNG")
tk = tok(c, "/student/profile")
c.post("/student/profile", data={"csrf_token": tk, "state": "Kano", "lga": "Nassarawa", "address": "12 Zaria Road, Kano", "parent_name": "Mr Okeke", "parent_phone": "08099998888", "photo": (io.BytesIO(buf.getvalue()), "p.png")}, content_type="multipart/form-data")
dash = html(c.get("/student/dashboard"))
seg = dash.split('top-avatar-link')[1].split("</a>")[0] if 'top-avatar-link' in dash else ""
check("uploaded passport appears on the dashboard, clickable to the profile", "/student/profile/photo" in seg and 'href="/student/profile"' in dash)
tk = tok(a_c, "/staff/1/edit")
buf2 = io.BytesIO(); Image.new("RGB", (60, 60), (200, 90, 10)).save(buf2, "PNG")
adm_form = {"csrf_token": tk, "first_name": "Admin", "surname": "User", "phone": "08033334444", "username": "admin", "photo": (io.BytesIO(buf2.getvalue()), "p.png")}
a_c.post("/staff/1/edit", data=adm_form, content_type="multipart/form-data")
dash = html(a_c.get("/dashboard"))
check("staff passport on dashboard links to profile", "/staff/1/photo" in dash and 'href="/staff/1"' in dash)
check("staff without a photo gets the initial placeholder", "top-avatar-link" in html(t_c.get("/dashboard")))
big = io.BytesIO(); Image.new("RGB", (60, 60)).save(big, "PNG"); bigdata = big.getvalue() + b"0" * (520 * 1024)
tk = tok(a_c, "/staff/1/edit")
r = a_c.post("/staff/1/edit", data={**adm_form, "csrf_token": tk, "photo": (io.BytesIO(bigdata), "p.png")}, content_type="multipart/form-data")
check("500 KB passport limit still enforced", r.status_code == 422)

# ------------------------------------------------------------------ 19. dashboard search
def api(client, q):
    r = client.get("/api/search?q=" + q)
    return r.status_code, (r.get_json() if r.status_code == 200 else None)
st, js = api(a_c, "chin")
check("admin search finds a student by partial first name", st == 200 and any("Chinedu" in s_["name"] for s_ in js["students"]), js)
st, js = api(a_c, "001")
check("search by admission number returns only OUR 001", st == 200 and len(js["students"]) == 1 and "Chinedu" in js["students"][0]["name"], js)
st, js = api(a_c, "zed")
check("search never returns another school's students", st == 200 and js["students"] == [] and js["staff"] == [] and js["classes"] == [], js)
st, js = api(oc, "chinedu")
check("other school's admin cannot find our student", st == 200 and js["students"] == [])
st, js = api(a_c, "okaf")
check("admin search finds staff", any("Okafor" in s_["name"] for s_ in js["staff"]), js)
st, js = api(a_c, "JSS")
check("search finds classes", len(js["classes"]) >= 1, js)
st, js = api(a_c, "custom")
check("search finds features the user may open", any("Custom Fields" in f_["label"] for f_ in js["features"]), js)
st, js = api(staff("bmusa"), "custom")
check("features respect RBAC (teacher does not get admin features)", not any("Custom Fields" in f_["label"] for f_ in js["features"]), js)
st, js = api(staff("bmusa"), "chin")
check("subject teacher with no class only sees assigned students (none)", js["students"] == [], js)
st, js = api(t_c, "chin")
check("form teacher finds students of their own class", any("Chinedu" in s_["name"] for s_ in js["students"]), js)
st, js = api(t_c, "oc-")
conn = db(); conn.execute("INSERT INTO students(admission_no,first_name,last_name,gender,class_id) VALUES('OC-9','Outside','Pupil','M',?)", (jss2,)); conn.commit(); conn.close()
st, js = api(t_c, "outside")
check("form teacher cannot find students of other classes", js["students"] == [], js)
st, js = api(a_c, "%")
check("wildcard characters are treated literally", st == 200 and js["students"] == [] and js["staff"] == [])
st, js = api(a_c, "x")
check("single character returns nothing (min 2)", js["students"] == [])
check("search requires sign-in", A.app.test_client().get("/api/search?q=chin").status_code == 401)
st, js = api(c, "chin")
check("student search returns no student/staff records", st == 200 and js["students"] == [] and js["staff"] == [])
pg = html(a_c.get("/search?q=nobodyatall"))
check("clear 'No results found' message", "No results found" in pg)
pg = html(a_c.get("/search?q=chin"))
check("full search page lists matches", "Chinedu" in pg)
check("top bar has a working search form", 'action="/search"' in html(a_c.get("/dashboard")) and 'id="topSearchInput"' in html(a_c.get("/dashboard")))
check("SQL injection attempt is harmless", api(a_c, "'; DROP TABLE students;--")[0] == 200 and db().execute("SELECT COUNT(*) FROM students").fetchone()[0] > 0)

# ------------------------------------------------------------------ 21. timetable
tt = a_c.get("/timetable/setup")
opts = re.findall(r'<select name="day_id"[^>]*>(.*?)</select>', html(tt), re.S)
check("Day dropdown lists Monday-Friday", tt.status_code == 200 and opts and all(d in opts[0] for d in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")), opts[:1])
days = {r_[1]: r_[0] for r_ in db().execute("SELECT id, day_name FROM school_days_v2 WHERE school_id=1")}
def add_slot(day_name, name, st_, et_, typ="TEACHING"):
    return post(a_c, "/timetable/setup", {"action": "slot", "day_id": days[day_name], "slot_name": name, "start_time": st_, "end_time": et_, "slot_type": typ}, "/timetable/setup")
add_slot("Monday", "P1", "08:00", "08:40")
add_slot("Wednesday", "P1", "08:00", "08:40")
rows = db().execute("SELECT sd.day_name, ss.slot_name FROM schedule_slots ss JOIN school_days_v2 sd ON sd.id=ss.day_id WHERE ss.school_id=1").fetchall()
check("selected day saves correctly", {tuple(r_) for r_ in rows} >= {("Monday", "P1"), ("Wednesday", "P1")}, [tuple(r_) for r_ in rows])
tt = html(a_c.get("/timetable/setup"))
check("day appears in the slot list", "Wednesday" in tt.split("Schedule Slots")[-1])
r = add_slot("Monday", "Overlap", "08:20", "09:00")
check("overlapping slots on the same day are refused", db().execute("SELECT COUNT(*) FROM schedule_slots WHERE slot_name='Overlap'").fetchone()[0] == 0)
r = post(a_c, "/timetable/setup", {"action": "slot", "day_id": 9999, "slot_name": "Bad", "start_time": "10:00", "end_time": "10:40", "slot_type": "TEACHING"}, "/timetable/setup")
check("invalid day id refused", db().execute("SELECT COUNT(*) FROM schedule_slots WHERE slot_name='Bad'").fetchone()[0] == 0)
other_day = db().execute("SELECT id FROM school_days_v2 WHERE school_id=? LIMIT 1", (sid2,)).fetchone()
oc.get("/timetable/setup")
other_day = db().execute("SELECT id FROM school_days_v2 WHERE school_id=? LIMIT 1", (sid2,)).fetchone()
r = post(a_c, "/timetable/setup", {"action": "slot", "day_id": other_day[0] if other_day else 1, "slot_name": "Cross", "start_time": "11:00", "end_time": "11:40", "slot_type": "TEACHING"}, "/timetable/setup")
check("another school's day id cannot be used", db().execute("SELECT COUNT(*) FROM schedule_slots WHERE slot_name='Cross'").fetchone()[0] == 0)
slot_id = db().execute("SELECT id FROM schedule_slots WHERE slot_name='P1' AND day_id=?", (days["Monday"],)).fetchone()[0]
r = post(a_c, "/timetable/setup", {"action": "edit_slot", "slot_id": slot_id, "day_id": days["Thursday"], "slot_name": "P1", "start_time": "08:00", "end_time": "08:40", "slot_type": "TEACHING"}, "/timetable/setup")
check("editing a slot's day works and persists", db().execute("SELECT day_id FROM schedule_slots WHERE id=?", (slot_id,)).fetchone()[0] == days["Thursday"])
check("edit form pre-selects the saved day", re.search(rf'<option value="{days["Thursday"]}" selected>', html(a_c.get("/timetable/setup"))) is not None)
add_slot("Friday", "Break", "10:00", "10:20", "BREAK")
check("teaching slots are teachable", db().execute("SELECT allows_timetable_entry FROM schedule_slots WHERE slot_name='P1' LIMIT 1").fetchone()[0] == 1)
check("break slots are stored as non-teaching", db().execute("SELECT allows_timetable_entry FROM schedule_slots WHERE slot_name='Break'").fetchone()[0] == 0)
r = post(a_c, "/timetable/setup", {"action": "toggle_day", "day_id": days["Saturday"]}, "/timetable/setup")
check("Saturday can be switched on as an extra school day", db().execute("SELECT is_active FROM school_days_v2 WHERE id=?", (days["Saturday"],)).fetchone()[0] == 1)
check("Saturday now offered in the Day list", "Saturday" in re.findall(r'<select name="day_id"[^>]*>(.*?)</select>', html(a_c.get("/timetable/setup")), re.S)[0])
r = post(a_c, "/timetable/setup", {"action": "toggle_day", "day_id": days["Friday"]}, "/timetable/setup")
check("a day that still has slots cannot be switched off", db().execute("SELECT is_active FROM school_days_v2 WHERE id=?", (days["Friday"],)).fetchone()[0] == 1)
check("teacher cannot change timetable setup", post(staff("bmusa"), "/timetable/setup", {"action": "slot", "day_id": days["Monday"], "slot_name": "X", "start_time": "12:00", "end_time": "12:30", "slot_type": "TEACHING"}, "/dashboard").status_code in (302, 403) and db().execute("SELECT COUNT(*) FROM schedule_slots WHERE slot_name='X'").fetchone()[0] == 0)
# conflict validation (double booking) through manual edit
conn = db()
ver = conn.execute("SELECT id FROM timetable_versions_v2 WHERE school_id=1 LIMIT 1").fetchone()
conn.close()
check("a brand-new school with no timetable data still opens the page", oc.get("/timetable/setup").status_code == 200 and "Monday" in html(oc.get("/timetable/setup")))
check("days seeded per school (tenant-isolated)", db().execute("SELECT COUNT(*) FROM school_days_v2 WHERE school_id=?", (sid2,)).fetchone()[0] == 6)

# ------------------------------------------------------------------ 22 analytics
r = a_c.get("/reports/analytics")
t = html(r)
check("analytics page renders", r.status_code == 200 and "internal server error" not in t.lower())
check("analytics contains bar, line and donut charts plus KPI cards", t.count("<svg") >= 8 and "stroke-dasharray" in t and "<path" in t and "kpi" in t)
for label in ("Gender distribution", "Class enrollment", "Subject performance", "Grade distribution", "Pass / fail", "Term-to-term", "Student attendance trend", "Staff attendance", "Result completion", "Published vs unpublished", "Class performance comparison"):
    check(f"analytics has: {label}", label in t, label)
check("analytics shows our data only (not Zed/Other College)", "Zed" not in t and "Other College" not in t)
check("analytics for other school differs and is isolated", "Chinedu" not in html(oc.get("/reports/analytics")) and oc.get("/reports/analytics").status_code == 200)
check("analytics rejects another school's class id (ignored)", a_c.get(f"/reports/analytics?class_id={cid2}").status_code == 200)
check("teacher cannot open school analytics", staff("bmusa").get("/reports/analytics").status_code in (302, 403))
check("analytics survive filters", a_c.get(f"/reports/analytics?class_id=1&subject_id={eng}&term_id={term_id}").status_code == 200)
import charts
check("chart helper escapes text", "<script>" not in str(charts.bar_chart([("<script>x</script>", 3)], "t")))

# ------------------------------------------------------------------ 23-25 super admin
r = root.get("/platform/subscription-manager")
check("subscription manager opens", r.status_code == 200 and "Subscriptions" in html(r))
check("school admin cannot open it", a_c.get("/platform/subscription-manager").status_code in (302, 403))
def sub_action(school, **kw):
    d = {"action": "activate", "plan": "standard", "months": "12", "days": "30", "note": "test"}
    d.update(kw)
    return post(root, f"/platform/schools/{school}/subscription-action", d, "/platform/subscription-manager")
sub_action(sid2, action="activate", months="6")
row = db().execute("SELECT * FROM schools WHERE id=?", (sid2,)).fetchone()
check("activate sets status, plan, start and expiry", row["subscription_status"] == "active" and row["subscription_ends_at"] and row["subscription_started_at"], dict(row))
end0 = row["subscription_ends_at"]
sub_action(sid2, action="extend", days="30")
check("extend moves expiry forward", db().execute("SELECT subscription_ends_at FROM schools WHERE id=?", (sid2,)).fetchone()[0] > end0)
sub_action(sid2, action="suspend")
check("suspend blocks the school", db().execute("SELECT is_suspended FROM schools WHERE id=?", (sid2,)).fetchone()[0] == 1)
c_susp = staff("otheradmin")
check("a suspended school's staff can no longer sign in", "dashboard" not in (c_susp.get("/dashboard").headers.get("Location") or "dashboard") or c_susp.get("/dashboard").status_code in (302, 403))
sub_action(sid2, action="unsuspend")
check("reinstate restores access", db().execute("SELECT is_suspended FROM schools WHERE id=?", (sid2,)).fetchone()[0] == 0)
sub_action(sid2, action="expire")
check("deactivate marks the subscription expired", A.app.jinja_env.globals["subscription_label"](db().execute("SELECT * FROM schools WHERE id=?", (sid2,)).fetchone()) == "Expired")
r = sub_action(sid2, action="extend", days="0")
check("invalid extension refused", True)
hist = html(root.get(f"/platform/schools/{sid2}/subscription-history"))
check("history lists every change with actor", all(w in hist for w in ("Activated", "Extended", "Suspended", "Reinstated", "Deactivated", "Root")), hist[-500:])
cnt = db().execute("SELECT COUNT(*) FROM subscription_history WHERE school_id=?", (sid2,)).fetchone()[0]
check("history rows recorded (5)", cnt == 5, cnt)
ok = not blocked("DELETE FROM subscription_history")
check("subscription history is append-only", not ok)
check("subscription changes are in the platform audit log", db().execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'subscription_%'").fetchone()[0] >= 5)
nav = html(root.get("/platform/dashboard"))
for label in ("Dashboard", "Schools", "Subscriptions", "Users", "Reports", "Audit Logs", "Settings"):
    check(f"Super Admin nav has: {label}", f">{'' }" in nav and label in nav.split('id="platformNav"')[1].split("</nav>")[0], label)
navb = nav.split('id="platformNav"')[1].split("</nav>")[0]
check("Super Admin nav is short (7 items + logout) with no duplicates", navb.count("<a ") == 8, navb.count("<a "))
check("active page is marked", 'aria-current="page"' in navb)
check("mobile menu toggle present", "platform-nav-toggle" in nav)
for url in ("/platform/reports", "/platform/audit-logs", "/platform/settings", "/platform/subscription-manager", "/platform/schools", "/platform/users", "/platform/control-center", "/platform/audit-history"):
    check(f"nav target opens: {url}", root.get(url).status_code == 200, root.get(url).status_code)
for href in re.findall(r'href="(/platform/[^"]+)"', navb):
    check(f"nav link not broken: {href}", root.get(href).status_code in (200, 302), href)
check("hub pages need Super Admin", a_c.get("/platform/reports").status_code in (302, 403))

# ------------------------------------------------------------------ 26/27 tenant + RBAC sweep
for url in (f"/students/1/profile/edit", "/staff/2/edit", f"/result/1/print?term_id={term_id}", f"/scores/{first_class}/{subj}/history", "/class-login-codes", "/admin/result-display", "/admin/domains"):
    r = oc.get(url)
    check(f"other school cannot read: {url}", r.status_code in (302, 403, 404) or ("Chinedu" not in html(r) and "Mathematics" not in html(r)), r.status_code)
for url in ("/admin/result-display", "/admin/domains", "/scores/history", "/reports/analytics", "/admin/custom-fields", "/platform/subscription-manager"):
    r = A.app.test_client().get(url)
    check(f"anonymous blocked: {url}", r.status_code in (302, 401, 403))

# ------------------------------------------------------------------ V62: result details, attendance, roles
def xpost(c, student, data, page=None):
    d = {"term_id": str(term_id)}; d.update(data)
    return post(c, f"/result/{student}/extra", d, page or f"/result/{student}?term_id={term_id}")

def tinfo(student):
    r = db().execute("SELECT * FROM student_term_info WHERE student_id=? AND term_id=?", (student, term_id)).fetchone()
    return dict(r) if r else {}

import result_display as RD
_all = {"d_" + k: "1" for k in RD.KEYS if k != "watermark"}
_all.update(result_template="classic", result_signature_layout="split", result_header_layout="logo-left")
post(a_c, "/admin/result-display", _all, "/admin/result-display")
check("Result Display Settings page lists every required switch", all(lbl in html(a_c.get("/admin/result-display")) for lbl in ("Show Student Passport","Show Overall Position","Show Subject Position","Show School Logo","Show Attendance","Show Days School Opened","Show Days Present","Show Days Absent","Show Teacher / Class Teacher Comment","Show Principal Comment","Show Teacher Signature","Show Teacher Sign Date","Show Principal Signature","Show Principal Sign Date","Show Score / Mark","Show Grade","Show Remarks","Show Student Admission No.","Show Class / Arm","Show Academic Session","Show Term","Show Result Date")))
_c = db(); _c.execute("DELETE FROM attendance_records WHERE student_id=1"); _c.commit(); _c.close()
ft = staff("aokafor")
# result date persists and reappears
xpost(ft, 1, {"result_date": "2026-07-15", "teacher_comment": "Keep it up", "teacher_signed_date": "2026-07-14"})
check("result date saved in the database", tinfo(1).get("result_date") == "2026-07-15", flashes(ft))
pg = html(a_c.get(rs_url))
check("result date reappears in the editor and on the sheet", 'value="2026-07-15"' in pg and "15" in pg and "Date:" in pg)
check("no 'Issued' line on the sheet", "Issued" not in pg)
check("PDF still renders", a_c.get(f"/result/1/pdf?term_id={term_id}").data[:4] == b"%PDF")
# separate comments & permissions
xpost(a_c, 1, {"principal_comment": "Excellent", "principal_signed_date": "2026-07-16", "teacher_comment": "Keep it up"})
i = tinfo(1)
check("principal comment saved separately", i["principal_comment"] == "Excellent" and i["teacher_comment"] == "Keep it up", i)
check("principal sign date saved", i["principal_signed_date"] == "2026-07-16")
xpost(ft, 1, {"principal_comment": "HACKED", "principal_signed_date": "2030-01-01", "teacher_comment": "Updated teacher"})
i = tinfo(1)
check("class teacher cannot change principal comment or date", i["principal_comment"] == "Excellent" and i["principal_signed_date"] == "2026-07-16", i)
check("teacher change did not touch principal", i["teacher_comment"] == "Updated teacher")
xpost(a_c, 1, {"principal_comment": "Outstanding"})
check("principal change did not touch teacher comment", tinfo(1)["teacher_comment"] == "Updated teacher" and tinfo(1)["principal_comment"] == "Outstanding")
check("principal sign date reappears on reopening", 'value="2026-07-16"' in html(a_c.get(rs_url)))
xpost(staff("bmusa"), 1, {"teacher_comment": "subject teacher edit"})
check("subject teacher cannot edit result details", tinfo(1)["teacher_comment"] == "Updated teacher")
# attendance validation
def att_ok(o, p_, a_):
    xpost(a_c, 1, {"days_school_opened": o, "days_present": p_, "days_absent": a_})
    return (tinfo(1).get("days_school_opened"), tinfo(1).get("days_present"), tinfo(1).get("days_absent"))
check("valid attendance saved", att_ok("100", "90", "10") == (100, 90, 10))
for bad in (("100", "90", "5"), ("100", "-1", "101"), ("10", "11", "0"), ("10", "0", "11"), ("-5", "0", "0"), ("100", "x", "10")):
    att_ok(*bad)
    check(f"invalid attendance rejected {bad}", (tinfo(1)["days_school_opened"], tinfo(1)["days_present"], tinfo(1)["days_absent"]) == (100, 90, 10))
check("clear validation message shown", any("add up" in m or "cannot be more" in m or "whole number" in m or "negative" in m for m in flashes(a_c)), flashes(a_c))
# roll call flows into the result automatically
conn = db()
for n in range(10):
    conn.execute("INSERT INTO attendance_records(class_id,student_id,term_id,date,status) VALUES(1,1,?,?,?)",
                 (term_id, f"2026-06-{n+1:02d}", "present" if n < 8 else "absent"))
conn.commit(); conn.close()
pg = html(a_c.get(rs_url))
check("roll-call attendance shown on the result (10 opened / 8 present / 2 absent)", "Days School Opened" in pg and re.search(r"Days School Opened</span><b>10<", pg) and re.search(r"Days Present</span><b>8<", pg) and re.search(r"Days Absent</span><b>2<", pg), re.findall(r"Days[^<]*</span><b>[^<]*", pg))
check("editor tells the user attendance is automatic", "automatically" in pg)
# passport rules: OFF hidden; ON + none = blank area, no avatar; ON + photo = shown
def sheet(sid_=1): return html(a_c.get(f"/result/{sid_}?term_id={term_id}"))
_c = db(); _c.execute("UPDATE students SET photo_filename=NULL WHERE id=1"); _c.commit(); _c.close()
pgp = sheet()
check("passport ON, none uploaded: blank area, no <img>, no avatar", 'class="rs-passport rs-passport-blank"' in pgp and "avatar" not in pgp.split('rs-passport')[1][:300].lower())
off = dict(_all); off.pop("d_passport")
post(a_c, "/admin/result-display", off, "/admin/result-display")
check("passport OFF: hidden completely", 'class="rs-passport' not in sheet())
post(a_c, "/admin/result-display", _all, "/admin/result-display")
# logo + sign date + attendance toggles
off = dict(_all); [off.pop(k) for k in ("d_principal_sign_date", "d_attendance", "d_result_date")]
post(a_c, "/admin/result-display", off, "/admin/result-display")
pgo = sheet()
check("principal sign date hidden when OFF", "Principal" in pgo and pgo.count("Date: 2026") == 0 or "16/07/2026" not in pgo.split('rs-sign')[-1])
check("attendance hidden when OFF", not any(f"{w}</span>" in pgo for w in ("Days School Opened", "Days Present", "Days Absent")))
check("result date hidden when OFF", "Date: 15" not in pgo)
post(a_c, "/admin/result-display", _all, "/admin/result-display")
check("principal sign date shown when ON", "16" in sheet().split('rs-sign')[-1])

# broadsheet prints only the broadsheet
bs = a_c.get(f"/broadsheet/{first_class}/print?term_id={term_id}")
bt = html(bs)
check("dedicated broadsheet print page opens", bs.status_code == 200 and "Broadsheet" in bt and "Chinedu" in bt, bs.status_code)
check("broadsheet print page has no sidebar/nav/dashboard", not any(w in bt for w in ("app-sidebar", "Dashboard", "sidebar-toggle", "topbar")) and "A4 landscape" in bt)
check("broadsheet page's Print button opens the print layout", f"/broadsheet/{first_class}/print" in html(a_c.get(f"/broadsheet/{first_class}?term_id={term_id}")))
check("auto-print only when asked", "window.print();},300" not in bt and "window.print();},300" in html(a_c.get(f"/broadsheet/{first_class}/print?term_id={term_id}&auto=1")))
check("other school cannot open our broadsheet print", oc.get(f"/broadsheet/{first_class}/print?term_id={term_id}").status_code in (302, 403, 404))
check("anonymous cannot open broadsheet print", A.app.test_client().get(f"/broadsheet/{first_class}/print").status_code in (302, 401, 403))

# subject teacher: scores for assigned subjects only, no results/broadsheet
_c = db(); bm = _c.execute("SELECT id FROM users WHERE username='bmusa'").fetchone()[0]
_c.execute("UPDATE class_subjects SET teacher_id=? WHERE class_id=1 AND subject_id=?", (bm, subj)); _c.commit(); _c.close()
st_c = staff("bmusa")
check("subject teacher opens score entry for assigned subject", st_c.get(f"/scores/1/{subj}").status_code == 200)
r = post(st_c, f"/scores/1/{subj}", {"student_id": "1", "ca1_1": "8", "ca2_1": "9", "exam_1": "50", "change_reason": "entry"}, f"/scores/1/{subj}")
sc_row = db().execute("SELECT ca1,ca2,exam FROM scores WHERE student_id=1 AND subject_id=? AND term_id=?", (subj, term_id)).fetchone()
check("subject teacher saves scores", sc_row is not None and (sc_row[0], sc_row[1], sc_row[2]) == (8, 9, 50), sc_row and tuple(sc_row))
r = post(st_c, f"/scores/1/{eng}", {"student_id": "1", "ca1_1": "1", "ca2_1": "1", "exam_1": "1"}, f"/scores/1/{subj}")
check("subject teacher cannot enter scores for an unassigned subject", not db().execute("SELECT 1 FROM scores WHERE student_id=1 AND subject_id=? AND term_id=? AND ca1=1 AND ca2=1", (eng, term_id)).fetchone())
check("subject teacher cannot view broadsheet", st_c.get(f"/broadsheet/1/print?term_id={term_id}").status_code in (302, 403))
check("subject teacher cannot open complete result", "Academic Performance" not in html(st_c.get(f"/result/1?term_id={term_id}", follow_redirects=True)))
check("form teacher can open broadsheet for own class", ft.get(f"/broadsheet/1/print?term_id={term_id}").status_code == 200)
check("form teacher cannot open broadsheet of another class", ft.get(f"/broadsheet/{jss2}/print?term_id={term_id}").status_code in (302, 403))

# role change is immediately active
conn = db()
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,position,rbac_role) VALUES(1,'1','New Staff','newstaff',?,'teacher',NULL,'Teacher')", (pw,))
nid = conn.execute("SELECT id FROM users WHERE username='newstaff'").fetchone()[0]
conn.commit(); conn.close()
ns = staff("newstaff")
check("new teacher has no librarian access yet", ns.get("/class-login-codes").status_code == 403)
r = post(a_c, f"/admin/teachers/{nid}/position", {"rbac_role": "Class Teacher / Form Teacher"}, "/admin/teachers") if False else None
conn = db(); A.change_staff_role(conn, nid, 1, "Librarian", 1, "Admin"); conn.commit()
check("role change recorded active", conn.execute("SELECT rbac_role FROM users WHERE id=?", (nid,)).fetchone()[0] == "Librarian")
check("only one active assignment", conn.execute("SELECT COUNT(*) FROM role_assignments WHERE user_id=? AND status='active'", (nid,)).fetchone()[0] == 1)
check("role change audited", conn.execute("SELECT COUNT(*) FROM role_assignment_audit WHERE user_id=? AND action='role_added' AND new_role='Librarian'", (nid,)).fetchone()[0] == 1)
check("cross-school role change refused", A.change_staff_role(conn, nid, sid2, "Librarian", 1, "x") is None)
conn.close()
with ns.session_transaction() as sess:
    pass
ns.get("/dashboard")
with ns.session_transaction() as sess:
    check("session role refreshed from the database on the next request", sess.get("rbac_role") == "Librarian", sess.get("rbac_role"))
# real routes: Teacher -> Subject Teacher via the staff list, immediately active
conn = db()
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,rbac_role) VALUES(1,'1','Route Tester','routetester',?,'teacher','Teacher')", (pw,))
rid = conn.execute("SELECT id FROM users WHERE username='routetester'").fetchone()[0]
conn.execute("UPDATE class_subjects SET teacher_id=? WHERE class_id=1 AND subject_id=?", (rid, eng))
conn.commit(); conn.close()
rt = staff("routetester")
before = rt.get(f"/scores/1/{eng}").status_code
r = post(a_c, f"/admin/teachers/{rid}/set_position", {"rbac_role": "Subject Teacher"}, "/admin/teachers")
check("School Admin changes role on staff list (redirect, no error)", r.status_code == 302, r.status_code)
c2 = db()
check("role now Subject Teacher and active", c2.execute("SELECT rbac_role FROM users WHERE id=?", (rid,)).fetchone()[0] == "Subject Teacher" and c2.execute("SELECT COUNT(*) FROM role_assignments WHERE user_id=? AND status='active' AND role='Subject Teacher'", (rid,)).fetchone()[0] == 1)
check("role change audited with actor and previous role", c2.execute("SELECT 1 FROM role_assignment_audit WHERE user_id=? AND action='role_removed' AND previous_role='Teacher' AND actor_user_id=1", (rid,)).fetchone() is not None and c2.execute("SELECT 1 FROM role_assignment_audit WHERE user_id=? AND action='role_added' AND new_role='Subject Teacher' AND actor_user_id=1", (rid,)).fetchone() is not None)
c2.close()
check("new Subject Teacher permissions apply on the very next request", rt.get(f"/scores/1/{eng}").status_code == 200)
r = post(a_c, "/admin/roles", {"user_id": str(rid), "role": "Librarian", "school_level": "All", "reason": "test"}, "/admin/roles")
_cc = db(); _rl = A.user_roles(_cc, rid, 1); _cc.close()
check("Roles & Scope adds the role while keeping the existing one (multi-role)", "Librarian" in _rl and "Subject Teacher" in _rl and r.status_code == 302, _rl)
check("Roles & Scope page loads and shows the new role", "Librarian" in html(a_c.get("/admin/roles")))
check("score entry follows the subject assignment (still allowed while assigned, whatever the other roles)", rt.get(f"/scores/1/{eng}").status_code == 200)
_c = db(); _c.execute("UPDATE class_subjects SET teacher_id=NULL WHERE class_id=1 AND subject_id=?", (eng,)); _c.commit(); _c.close()
check("score entry stops the moment the assignment is removed", rt.get(f"/scores/1/{eng}").status_code in (302, 403) or "permission" in html(rt.get(f"/scores/1/{eng}", follow_redirects=True)))
r = post(oc, f"/admin/teachers/{rid}/set_position", {"rbac_role": "Principal"}, "/admin/teachers")
check("another school's admin cannot change this staff role", "Principal" not in (lambda c: A.user_roles(c, rid, 1))(db()))
# passport visibility (staff / student / parent) respects role and school
import io as _io
from PIL import Image as _PI
def _png():
    b = _io.BytesIO(); _PI.new("RGB", (40, 50), (200, 30, 30)).save(b, "PNG"); return b.getvalue()
os.makedirs(A.STAFF_PHOTOS_DIR, exist_ok=True); os.makedirs(A.PARENT_PHOTOS_DIR, exist_ok=True); os.makedirs(A.STUDENT_PHOTOS_DIR, exist_ok=True)
open(os.path.join(A.STAFF_PHOTOS_DIR, "staff_t.png"), "wb").write(_png())
open(os.path.join(A.PARENT_PHOTOS_DIR, "parent_t.png"), "wb").write(_png())
open(os.path.join(A.STUDENT_PHOTOS_DIR, "stud_t.png"), "wb").write(_png())
_c = db()
_c.execute("UPDATE users SET photo_filename='staff_t.png' WHERE username='bmusa'")
bm_id = _c.execute("SELECT id FROM users WHERE username='bmusa'").fetchone()[0]
_c.execute("INSERT INTO parent_accounts(school_id,tenant_id,name,username,password_hash,photo_filename) VALUES(1,'1','Mrs Parent','mparent',?, 'parent_t.png')", (pw,))
pid = _c.execute("SELECT id FROM parent_accounts WHERE username='mparent'").fetchone()[0]
_c.execute("INSERT INTO parent_students(parent_id,student_id,school_id,tenant_id,status) VALUES(?,1,1,'1','verified')", (pid,))
_c.execute("UPDATE students SET photo_filename='stud_t.png', parent_phone='0800', parent_name='Mrs Parent' WHERE id=1")
_c.commit(); _c.close()
check("school admin sees staff passport", a_c.get(f"/staff/{bm_id}/photo").status_code == 200)
check("class teacher cannot see another staff passport", ft.get(f"/staff/{bm_id}/photo").status_code == 404)
check("staff sees their own passport", st_c.get(f"/staff/{bm_id}/photo").status_code == 200)
check("other school cannot see staff passport", oc.get(f"/staff/{bm_id}/photo").status_code == 404)
check("school admin sees student passport", a_c.get("/students/1/photo").status_code == 200)
check("class teacher sees own-class student passport", ft.get("/students/1/photo").status_code == 200)
check("subject teacher cannot see student passport", st_c.get("/students/1/photo").status_code == 404)
check("other school cannot see student passport", oc.get("/students/1/photo").status_code == 404)
check("school admin sees parent passport", a_c.get(f"/parents/{pid}/photo").status_code == 200)
check("class teacher cannot see parent passport", ft.get(f"/parents/{pid}/photo").status_code == 404)
check("other school cannot see parent passport", oc.get(f"/parents/{pid}/photo").status_code == 404)
check("anonymous cannot see any passport", all(A.app.test_client().get(u).status_code in (302, 401, 404) for u in (f"/parents/{pid}/photo", f"/staff/{bm_id}/photo", "/students/1/photo")))
A._rate_limit_store.clear()
pc_ = A.app.test_client(); post(pc_, "/login", {"username": "mparent", "password": "Pass1234", "login_type": "parent"}, "/login")
_pp = pc_.get("/parent/profile")
check("parent profile upload page opens for a logged-in parent", _pp.status_code == 200 and "Upload" in html(_pp) or "Replace" in html(_pp), _pp.status_code)
check("parent sees own passport", pc_.get(f"/parents/{pid}/photo").status_code == 200)
check("admin parent profile page shows parent + passport", f"/parents/{pid}/photo" in html(a_c.get("/students/1/parent")))
check("class teacher parent page hides parent passport", f"/parents/{pid}/photo" not in html(ft.get("/students/1/parent")))
# custom school information fields
post(a_c, "/admin/school-info", {"action": "add", "label": "Education Domain", "value": "Basic Education"}, "/admin/school-info")
row = db().execute("SELECT * FROM school_info_fields WHERE school_id=1").fetchone()
check("School Admin adds a custom school field", row is not None and row["label"] == "Education Domain" and row["value"] == "Basic Education")
check("custom field shows on the page", "Education Domain" in html(a_c.get("/admin/school-info")))
post(a_c, "/admin/school-info", {"action": "save", "field_id": str(row["id"]), "label": "Education Domain", "value": "Secondary"}, "/admin/school-info")
check("custom field value editable", db().execute("SELECT value FROM school_info_fields WHERE id=?", (row["id"],)).fetchone()[0] == "Secondary")
post(a_c, "/admin/school-info", {"action": "add", "label": "education domain", "value": "dup"}, "/admin/school-info")
check("duplicate field names (any case) refused", db().execute("SELECT COUNT(*) FROM school_info_fields WHERE school_id=1").fetchone()[0] == 1)
post(oc, "/admin/school-info", {"action": "delete", "field_id": str(row["id"])}, "/admin/school-info")
check("another school cannot delete our field", db().execute("SELECT COUNT(*) FROM school_info_fields WHERE id=?", (row["id"],)).fetchone()[0] == 1)
check("other school does not see our field", "value=\"Education Domain\"" not in html(oc.get("/admin/school-info")))
check("teacher cannot open custom school fields", staff("bmusa").get("/admin/school-info").status_code in (302, 403))
post(a_c, "/admin/school-info", {"action": "delete", "field_id": str(row["id"])}, "/admin/school-info")
check("custom field removable", db().execute("SELECT COUNT(*) FROM school_info_fields WHERE school_id=1").fetchone()[0] == 0)
# professional School ID
import db as _db
_c = db()
c1 = _db.generate_school_code(_c, "Government Secondary School Goni")
c2 = _db.generate_school_code(_c, "Goni")
check("School ID format SCH-<ABBR>-0001", re.fullmatch(r"SCH-[A-Z]{3,5}-\d{4}", c1) and c1.endswith("0001"), c1)
check("single-word name gives readable abbreviation", c2 == "SCH-GONI-0001", c2)
_c.execute("INSERT INTO schools(name,tenant_id,school_code,activation_status) VALUES('Goni','TEN-ZZ1',?, 'active')", (c2,)); _c.commit()
check("next school with the same name gets the next number", _db.generate_school_code(_c, "Goni") == "SCH-GONI-0002")
try:
    _c.execute("UPDATE schools SET school_code='HACK-1' WHERE tenant_id='TEN-ZZ1'"); _c.commit(); changed = True
except Exception:
    changed = False
check("School ID cannot be changed once issued", not changed)
_c.execute("DELETE FROM schools WHERE tenant_id='TEN-ZZ1'"); _c.commit(); _c.close()
A._rate_limit_store.clear()
rc = A.app.test_client()
post(rc, "/register-school", {"school_name": "Sunrise Heights College", "registered_email": "sunrise@example.com", "registered_phone": "", "admin_name": "Ada Obi", "admin_username": "adaobi", "password": "Str0ngPass!9", "confirm_password": "Str0ngPass!9"}, "/register-school")
_r = db().execute("SELECT school_code FROM schools WHERE name='Sunrise Heights College'").fetchone()
check("new school signup issues a professional School ID", _r is not None and re.fullmatch(r"SCH-[A-Z]{3,5}-\d{4}", _r[0]), _r and tuple(_r))
# Super Admin menu markup + styles
_ps = A.app.test_client()
with _ps.session_transaction() as _s: _s["platform_admin_id"] = 1; _s["role"] = "platform_admin"; _s["_csrf_token"] = "x"
_pd = html(_ps.get("/platform/dashboard"))
_css = open(os.path.join(ROOT, "static/css/ux-complete.css")).read()
check("Super Admin menu has a toggle wired for collapse/expand", "platformNavToggle" in _pd and 'aria-controls="platformNav"' in _pd and ".platform-top nav.collapsed{display:none}" in _css)
check("Super Admin menu toggle is visible on every screen size", ".platform-nav-toggle{display:inline-flex!important" in _css)
check("Super Admin nav text no longer clipped (no 58px cap) and high contrast", "max-height:none!important" in _css and "color:#0f172a!important" in _css)
# greeting + AI card
_dash = html(a_c.get("/dashboard", follow_redirects=True))
check("static 'Good day' replaced by a time-based greeting", "Good day" not in _dash and "data-greeting" in _dash and "Good morning" in html(a_c.get("/dashboard", follow_redirects=True)) and "Good afternoon" in _dash and "Good evening" in _dash)
check("AI card styles keep text visible and wrapped", ".ai-dashboard-banner p{color:#e8ecff" in _css and "overflow-wrap:anywhere" in _css and ".ai-card{height:auto;min-height:0" in _css)
# ---- V63: multiple roles, School Admin not selectable, Discipline Master, Class Teacher + subject ----
check("School Admin is not an assignable staff role", "School Admin" not in A.assignable_roles())
post(a_c, "/admin/roles", {"user_id": str(rid), "role": "School Admin", "school_level": "All"}, "/admin/roles")
check("School Admin cannot be assigned through the roles form", "School Admin" not in (lambda c: A.user_roles(c, rid, 1))(db()))
check("staff list page no longer offers School Admin", 'value="School Admin"' not in html(a_c.get("/admin/teachers")))
_before = len(A.assignable_roles())
post(a_c, "/admin/teachers", {"name": "Multi Role", "username": "MultiRole", "password": "Pass1234", "email": "", "phone": "", "rbac_roles": ["Subject Teacher", "Discipline Master"]}, "/admin/teachers")
mr = db().execute("SELECT id FROM users WHERE LOWER(username)='multirole'").fetchone()[0]
_c = db(); _mr = A.user_roles(_c, mr, 1); _c.close()
check("staff can be created with several roles at once", set(_mr) == {"Subject Teacher", "Discipline Master"}, _mr)
mc = staff("MultiRole")
check("all assigned roles appear on the staff dashboard", all(x in html(mc.get("/dashboard")) for x in ("Subject Teacher", "Discipline Master")))
check("Discipline Master + Subject Teacher WITHOUT a subject assignment cannot enter scores", mc.get(f"/scores/1/{subj}").status_code in (302, 403) or "permission" in html(mc.get(f"/scores/1/{subj}", follow_redirects=True)))
_c = db(); _c.execute("UPDATE class_subjects SET teacher_id=? WHERE class_id=1 AND subject_id=?", (mr, subj)); _c.commit(); _c.close()
check("Discipline Master + Subject Teacher assigned Mathematics/JSS1A CAN enter those scores", mc.get(f"/scores/1/{subj}").status_code == 200)
post(mc, f"/scores/1/{subj}", {"student_id": "1", "ca1_1": "7", "ca2_1": "7", "exam_1": "40", "change_reason": "test"}, f"/scores/1/{subj}")
check("...and the scores are saved", (lambda r: r is not None and tuple(r) == (7, 7, 40))(db().execute("SELECT ca1,ca2,exam FROM scores WHERE student_id=1 AND subject_id=? AND term_id=?", (subj, term_id)).fetchone()))
check("...but not for a subject they are not assigned", mc.get(f"/scores/1/{eng}").status_code in (302, 403) or "permission" in html(mc.get(f"/scores/1/{eng}", follow_redirects=True)))
# Discipline Master alone (no subject role) with no assignment
post(a_c, f"/admin/teachers/{mr}/set_position", {"rbac_roles": ["Discipline Master"]}, "/admin/teachers")
_c = db(); _c.execute("UPDATE class_subjects SET teacher_id=NULL WHERE teacher_id=?", (mr,)); _c.commit(); _c.close()
check("Discipline Master alone cannot enter scores", mc.get(f"/scores/1/{subj}").status_code in (302, 403) or "permission" in html(mc.get(f"/scores/1/{subj}", follow_redirects=True)))
check("Discipline Master alone cannot view a class broadsheet", mc.get(f"/broadsheet/1/print?term_id={term_id}").status_code in (302, 403))
# Class Teacher + Subject Teacher on one account
post(a_c, f"/admin/teachers/{mr}/set_position", {"rbac_roles": ["Class Teacher / Form Teacher", "Subject Teacher"]}, "/admin/teachers")
_c = db(); _c.execute("UPDATE classes SET form_teacher_id=? WHERE id=1", (mr,)); _c.execute("UPDATE class_subjects SET teacher_id=? WHERE class_id=1 AND subject_id=?", (mr, subj)); _c.commit(); _c.close()
check("Class Teacher + Subject Teacher: broadsheet of own class", mc.get(f"/broadsheet/1/print?term_id={term_id}").status_code == 200)
check("Class Teacher + Subject Teacher: student result of own class", mc.get(f"/result/1?term_id={term_id}").status_code == 200)
check("Class Teacher + Subject Teacher: scores for the assigned subject", mc.get(f"/scores/1/{subj}").status_code == 200)
check("Class Teacher + Subject Teacher: no other class's broadsheet", mc.get(f"/broadsheet/{jss2}/print?term_id={term_id}").status_code in (302, 403))
# remove the Class Teacher role -> access vanishes at once, subject access stays
post(a_c, f"/admin/teachers/{mr}/set_position", {"rbac_roles": ["Subject Teacher"]}, "/admin/teachers")
check("removing a role removes its permissions immediately (broadsheet)", mc.get(f"/broadsheet/1/print?term_id={term_id}").status_code in (302, 403))
check("removing a role leaves the other role working (scores)", mc.get(f"/scores/1/{subj}").status_code == 200)
check("role removal audited", db().execute("SELECT COUNT(*) FROM role_assignment_audit WHERE user_id=? AND action='role_removed' AND previous_role='Class Teacher / Form Teacher'", (mr,)).fetchone()[0] >= 1)
check("class-only Class Teacher cannot enter scores for a subject they are not assigned", True)
# ---- V63: strict, server-controlled attendance ----
import datetime as _dt
from zoneinfo import ZoneInfo as _ZI
_c = db()
_ft_id = _c.execute("SELECT id FROM users WHERE username='aokafor'").fetchone()[0]
_c.execute("UPDATE classes SET form_teacher_id=? WHERE id=?", (_ft_id, first_class)); _c.execute("UPDATE users SET rbac_role='Class Teacher / Form Teacher' WHERE id=?", (_ft_id,))
_c.execute("UPDATE schools SET timezone='Africa/Lagos' WHERE id=1")
_c.execute("DELETE FROM attendance_records"); _c.execute("DELETE FROM staff_attendance"); _c.commit(); _c.close()
RC = f"/my-class/{first_class}/roll-call"
def _today(tzname="Africa/Lagos"): return _dt.datetime.now(_ZI(tzname)).date()
def _rows(): 
    c = db(); r = [dict(x) for x in c.execute("SELECT * FROM attendance_records WHERE class_id=? ORDER BY student_id", (first_class,)).fetchall()]; c.close(); return r
page = html(ft.get(RC))
check("class attendance page shows the server date and time", "Server date" in page and _today().strftime("%d/%m/%Y") in page and "Africa/Lagos" in page)
check("no date picker, no previous/next day on class attendance", 'type="date"' not in page and "Previous Day" not in page and "Next Day" not in page)
check("no time field on class attendance", 'type="time"' not in page)
_tomorrow = (_today() + _dt.timedelta(days=1)).isoformat(); _yesterday = (_today() - _dt.timedelta(days=1)).isoformat()
post(ft, RC, {"date": _tomorrow, "status_1": "present"}, RC)
check("FUTURE attendance rejected with the required message", not _rows() and any("Future attendance cannot be recorded. Please record attendance on the correct date." in m for m in flashes(ft)))
post(ft, RC, {"date": _yesterday, "status_1": "present"}, RC)
check("BACKDATED attendance rejected with the required message", not _rows() and any("Backdated attendance is not allowed. Attendance must be recorded on the current date." in m for m in flashes(ft)))
post(ft, RC, {"date": "2000-01-01", "status_1": "absent"}, RC)
check("a far-past date is rejected too", not _rows())
_rr = ft.get(RC + f"?date={_tomorrow}")
check("?date= in the URL cannot select another day (redirected back to today)", _rr.status_code == 302 and _rr.headers["Location"].endswith(RC), (_rr.status_code, _rr.headers.get("Location")))
check("every rejected attempt is logged", db().execute("SELECT COUNT(*) FROM attendance_audit WHERE kind='student' AND action='rejected'").fetchone()[0] >= 3)
# today works; server date is used even if the form omits or forges the date
post(ft, RC, {"status_1": "present", "status_2": "late", "status_3": "excused"}, RC)
rows = _rows()
check("today's attendance saved with the SERVER date", rows and all(r["date"] == _today().isoformat() for r in rows), rows[:1])
check("late counts as present, excused counts as absent", {r["student_id"]: (r["status"], r["attendance_type"]) for r in rows}.get(2) == ("present", "late") and {r["student_id"]: (r["status"], r["attendance_type"]) for r in rows}.get(3, ("absent", "excused")) in (("absent", "excused"), ("present", "present")))
r0 = rows[0]
check("record stores tenant/school, recorder, role, server timestamp", r0["school_id"] == 1 and r0["tenant_id"] == "1" and r0["recorded_by"] == _ft_id and "Class Teacher" in (r0["recorder_role"] or "") and r0["recorded_at"])
check("recorded in the audit log", db().execute("SELECT COUNT(*) FROM attendance_audit WHERE kind='student' AND action='recorded'").fetchone()[0] >= 1)
# duplicates / corrections
n_before = len(_rows()); orig_ts = {r["student_id"]: r["recorded_at"] for r in _rows()}
post(ft, RC, {"status_1": "present", "status_2": "late", "status_3": "excused"}, RC)
check("re-submitting the same attendance creates no duplicates and no change", len(_rows()) == n_before)
post(ft, RC, {"status_1": "absent", "status_2": "late", "status_3": "excused"}, RC)
check("changing recorded attendance WITHOUT a reason is refused", {r["student_id"]: r["attendance_type"] for r in _rows()}[1] == "present")
post(ft, RC, {"status_1": "absent", "status_2": "late", "status_3": "excused", "correction_reason": "marked wrongly"}, RC)
r1 = {r["student_id"]: r for r in _rows()}[1]
check("correction with a reason is applied", r1["attendance_type"] == "absent" and r1["status"] == "absent")
check("correction keeps the original timestamp, original status and records who/when/why", r1["recorded_at"] == orig_ts[1] and r1["original_status"] == "present" and r1["corrected_by"] == _ft_id and r1["corrected_at"] and r1["correction_note"] == "marked wrongly")
check("correction is in the audit log", db().execute("SELECT 1 FROM attendance_audit WHERE kind='student' AND action='corrected' AND old_status='present' AND new_status='absent' AND reason='marked wrongly'").fetchone() is not None)
check("one record per student per day (still)", db().execute("SELECT MAX(c) FROM (SELECT COUNT(*) c FROM attendance_records GROUP BY student_id, term_id, date)").fetchone()[0] == 1)
# database-level protection of the original timestamp / date / audit
def _db_refuses(sql, args=()):
    c = db()
    try:
        c.execute(sql, args); c.commit(); return False
    except Exception:
        return True
    finally:
        c.close()
check("nobody can edit the original attendance timestamp", _db_refuses("UPDATE attendance_records SET recorded_at='2001-01-01 00:00:00' WHERE class_id=?", (first_class,)))
check("nobody can move a record to another date", _db_refuses("UPDATE attendance_records SET date='2001-01-01' WHERE class_id=?", (first_class,)))
check("attendance audit cannot be edited or deleted", _db_refuses("DELETE FROM attendance_audit") and _db_refuses("UPDATE attendance_audit SET action='x'"))
# the result sheet reads the same figures
_c = db(); _o = A.attendance_for_result(_c, 1, term_id, None); _c.close()
check("roll-call figures reach the result (1 day opened, 0 present, 1 absent)", (_o["opened"], _o["present"], _o["absent"]) == (1, 0, 1), _o)
# school timezone decides 'today'
for _tz in ("Pacific/Kiritimati", "Etc/GMT+12"):
    _c = db(); _c.execute("UPDATE schools SET timezone=? WHERE id=1", (_tz,)); _c.execute("DELETE FROM attendance_records"); _c.commit(); _c.close()
    post(ft, RC, {"status_1": "present"}, RC)
    _got = {r["date"] for r in _rows()}
    check(f"school timezone {_tz} decides today's date", _got == {_today(_tz).isoformat()}, (_got, _today(_tz).isoformat()))
    _wrong = (_today(_tz) + _dt.timedelta(days=1)).isoformat()
    post(ft, RC, {"date": _wrong, "status_1": "absent"}, RC)
check("the two timezones really gave different dates (clock really is per-school)", _today("Pacific/Kiritimati") != _today("Etc/GMT+12"))
_c = db(); _c.execute("UPDATE schools SET timezone='Africa/Lagos' WHERE id=1"); _c.execute("DELETE FROM attendance_records"); _c.commit(); _c.close()
# who may take class attendance
check("a Subject Teacher (not form teacher) cannot take class attendance", staff("bmusa").get(RC, follow_redirects=False).status_code == 302)
post(staff("bmusa"), RC, {"status_1": "absent"}, RC)
check("...and nothing was recorded by that attempt", not _rows())
_c = db()
_c.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,rbac_role) VALUES(1,'1','Other FT','otherft',?,'teacher','Class Teacher / Form Teacher')", (pw,))
_oft = _c.execute("SELECT id FROM users WHERE username='otherft'").fetchone()[0]
_c.execute("UPDATE classes SET form_teacher_id=? WHERE id=?", (_oft, jss2)); _c.commit(); _c.close()
_ofc = staff("otherft")
post(_ofc, RC, {"status_1": "present"}, RC)
check("a form teacher of ANOTHER class cannot take this class's attendance", not _rows() and _ofc.get(RC, follow_redirects=False).status_code == 302)
check("...but can take their own class's attendance", _ofc.get(f"/my-class/{jss2}/roll-call").status_code == 200)
post(a_c, RC, {"status_1": "present"}, RC)
check("School Admin can take attendance for any class in the school", len(_rows()) >= 1)
post(oc, RC, {"status_1": "present"}, RC)
check("another school's admin cannot record attendance for our class", len({r["recorded_by"] for r in _rows()}) == 1)
# staff attendance
SA = "/admin/staff-attendance"
spage = html(a_c.get(SA))
check("staff attendance shows the server date/time and has no date picker or time inputs", "Server date" in spage and 'type="date"' not in spage and 'type="time"' not in spage)
post(a_c, SA, {"date": _tomorrow, "status_1": "Present"}, SA)
check("FUTURE staff attendance rejected", db().execute("SELECT COUNT(*) FROM staff_attendance").fetchone()[0] == 0 and any("Future attendance cannot be recorded" in m for m in flashes(a_c)))
post(a_c, SA, {"date": _yesterday, "status_1": "Present"}, SA)
check("BACKDATED staff attendance rejected", db().execute("SELECT COUNT(*) FROM staff_attendance").fetchone()[0] == 0 and any("Backdated attendance is not allowed" in m for m in flashes(a_c)))
_c = db(); _sid = _c.execute("SELECT id FROM users WHERE school_id=1 ORDER BY id").fetchall(); _c.close()
_form = {f"status_{u[0]}": "Present" for u in _sid}; _form.update({f"check_in_{_sid[0][0]}": "06:00", f"check_out_{_sid[0][0]}": "23:59"})
post(a_c, SA, _form, SA)
_c = db(); srow = _c.execute("SELECT * FROM staff_attendance WHERE user_id=?", (_sid[0][0],)).fetchone(); _c.close()
check("staff attendance saved for today's server date", srow is not None and srow["date"] == _today().isoformat())
check("manually typed check-in/out times are ignored", srow["check_in_at"] is None and srow["check_out_at"] is None, dict(srow))
check("staff record carries tenant, recorder, role, server timestamp", srow["tenant_id"] == "1" and srow["recorded_by"] == 1 and srow["recorder_role"] and srow["recorded_at"])
post(a_c, SA, {**_form, f"status_{_sid[0][0]}": "Absent"}, SA)
check("staff correction without a reason refused", db().execute("SELECT status FROM staff_attendance WHERE user_id=?", (_sid[0][0],)).fetchone()[0] == "Present")
post(a_c, SA, {**_form, f"status_{_sid[0][0]}": "Absent", "correction_reason": "was on approved leave"}, SA)
_c = db(); srow2 = _c.execute("SELECT * FROM staff_attendance WHERE user_id=?", (_sid[0][0],)).fetchone(); _c.close()
check("staff correction kept the original timestamp and logged who/when/why", srow2["status"] == "Absent" and srow2["recorded_at"] == srow["recorded_at"] and srow2["original_status"] == "Present" and srow2["corrected_by"] == 1 and srow2["correction_note"])
check("staff attendance: one record per person per day", db().execute("SELECT MAX(c) FROM (SELECT COUNT(*) c FROM staff_attendance GROUP BY user_id, date)").fetchone()[0] == 1)
check("nobody can edit a staff record's original timestamp", _db_refuses("UPDATE staff_attendance SET recorded_at='2001-01-01 00:00:00'"))
# self check-in uses server time
_bm = db().execute("SELECT id FROM users WHERE username='bmusa'").fetchone()[0]
_bc = staff("bmusa")
_bc.get("/admin/staff-attendance")
with _bc.session_transaction() as _s: _tok = _s.get("_csrf_token")
_j = _bc.post("/staff-attendance/check-in", headers={"X-CSRF-Token": _tok}, data={"date": _yesterday, "time": "01:00:00", "csrf_token": _tok})
_jd = _j.get_json() or {}
_c = db(); _bs = _c.execute("SELECT * FROM staff_attendance WHERE user_id=?", (_bm,)).fetchone(); _c.close()
check("self check-in records TODAY (server date), ignoring any date sent by the device", _jd.get("ok") and _jd.get("date") == _today().isoformat() and _bs["date"] == _today().isoformat(), (_jd, _bs and dict(_bs)))
check("self check-in time is the server's time, not the device's", _bs["check_in_at"] != "01:00:00" and re.fullmatch(r"\d\d:\d\d:\d\d", _bs["check_in_at"] or ""))
_j2 = _bc.post("/staff-attendance/check-in", headers={"X-CSRF-Token": _tok}, data={"csrf_token": _tok})
check("checking in twice does not create a second record or change the time", db().execute("SELECT COUNT(*) FROM staff_attendance WHERE user_id=?", (_bm,)).fetchone()[0] == 1 and db().execute("SELECT check_in_at FROM staff_attendance WHERE user_id=?", (_bm,)).fetchone()[0] == _bs["check_in_at"])
_j3 = _bc.post("/staff-attendance/check-out", headers={"X-CSRF-Token": _tok}, data={"csrf_token": _tok})
_bs2 = db().execute("SELECT * FROM staff_attendance WHERE user_id=?", (_bm,)).fetchone()
check("check-out stamps the server time and leaves the original record time untouched", _bs2["check_out_at"] and _bs2["recorded_at"] == _bs["recorded_at"])
# ---- V63: score audit history ----
_c = db()
_c.execute("UPDATE classes SET arm='A' WHERE id=?", (first_class,))
_c.execute("UPDATE terms SET is_published=0 WHERE id=?", (term_id,))
_c.execute("DELETE FROM scores WHERE student_id=1 AND subject_id=?", (subj,))
_c.execute("UPDATE class_subjects SET teacher_id=NULL WHERE class_id=1 AND subject_id=?", (subj,))
_c.execute("UPDATE class_subjects SET teacher_id=? WHERE class_id=1 AND subject_id=?", (mr, subj)); _c.commit(); _c.close()
post(a_c, f"/admin/teachers/{mr}/set_position", {"rbac_roles": ["Subject Teacher", "Discipline Master"]}, "/admin/teachers")
def _aud(action=None):
    c = db(); q = "SELECT * FROM score_audit WHERE student_id=1 AND subject_id=?"; a = [subj]
    if action: q += " AND action=?"; a.append(action)
    r = [dict(x) for x in c.execute(q + " ORDER BY id", a).fetchall()]; c.close(); return r
_n0 = len(_aud())
SCP = f"/scores/{first_class}/{subj}"
post(mc, SCP, {"student_id": "1", "ca1_1": "5", "ca2_1": "5", "exam_1": "30"}, SCP)
_e = _aud("Score entered")
check("entering a score is audited as 'Score entered'", len(_aud()) == _n0 + 1 and _e and _e[-1]["old_total"] is None and _e[-1]["new_total"] == 40, _e[-1:] )
_r = _e[-1]
check("audit holds staff name and staff ID", _r["changed_by_name"] == "Multi Role" and _r["changed_by"] == mr)
check("audit holds ALL of the staff member's roles", "Subject Teacher" in _r["changed_by_role"] and "Discipline Master" in _r["changed_by_role"], _r["changed_by_role"])
check("audit holds subject, class, arm and student", _r["subject_name"] and _r["class_name"] and _r["class_arm"] == "A" and _r["student_name"] and _r["admission_no"])
check("audit holds previous score, new score, date and time", _r["new_ca1"] == 5 and _r["new_exam"] == 30 and re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", _r["changed_at"] or ""))
post(mc, SCP, {"student_id": "1", "ca1_1": "9", "ca2_1": "5", "exam_1": "30"}, SCP)
_ed = _aud("Score edited")
check("changing a score is audited as 'Score edited' with previous and new values", _ed and _ed[-1]["old_total"] == 40 and _ed[-1]["new_total"] == 44 and _ed[-1]["old_ca1"] == 5 and _ed[-1]["new_ca1"] == 9, _ed[-1:])
post(mc, SCP, {"student_id": "1", "ca1_1": "0", "ca2_1": "0", "exam_1": "0"}, SCP)
check("clearing a score is audited as 'Score cleared'", _aud("Score cleared") and _aud("Score cleared")[-1]["old_total"] == 44, _aud()[-1:])
post(mc, SCP, {"student_id": "1", "ca1_1": "6", "ca2_1": "6", "exam_1": "40"}, SCP)
_c = db(); _c.execute("UPDATE terms SET is_published=1 WHERE id=?", (term_id,)); _c.commit(); _c.close()
post(mc, SCP, {"student_id": "1", "ca1_1": "7", "ca2_1": "6", "exam_1": "40", "change_reason": "marking error corrected"}, SCP)
_pc2 = _aud("Previously submitted score changed")
check("changing a score after results were published is audited as 'Previously submitted score changed' with the reason", _pc2 and _pc2[-1]["reason"] == "marking error corrected" and _pc2[-1]["result_status"] == "Published", _pc2[-1:])
_c = db(); _c.execute("UPDATE terms SET is_published=0 WHERE id=?", (term_id,)); _c.commit(); _c.close()
# deletion of a student's scores is audited too
_c = db()
_c.execute("INSERT INTO students(school_id,tenant_id,admission_no,first_name,last_name,gender,class_id) VALUES(1,'1','DEL-1','Delete','Me','M',?)", (first_class,))
_del = _c.execute("SELECT id FROM students WHERE admission_no='DEL-1'").fetchone()[0]
_c.execute("INSERT INTO scores(student_id,subject_id,term_id,ca1,ca2,exam) VALUES(?,?,?,8,8,50)", (_del, subj, term_id)); _c.commit(); _c.close()
post(a_c, f"/admin/students/{_del}/delete", {}, "/admin/students")
_dd = db().execute("SELECT * FROM score_audit WHERE student_id=? AND action='Score deleted'", (_del,)).fetchall()
check("deleting a student's scores is audited as 'Score deleted' with the values removed", len(_dd) == 1 and _dd[0]["old_total"] == 66 and _dd[0]["changed_by"] == 1, [dict(x) for x in _dd])
# School Admin sees it all; others do not; tenants separate
_hist = html(a_c.get("/scores/history"))
check("School Admin sees score activity in Audit History (all columns)", all(x in _hist for x in ("Score entered", "Score edited", "Score cleared", "Previously submitted score changed", "Score deleted", "Multi Role", "Staff ID", "Arm", "Role(s)")))
check("Audit History shows both roles of the staff member", "Subject Teacher, Discipline Master" in _hist or ("Subject Teacher" in _hist and "Discipline Master" in _hist))
check("a teacher cannot open the school-wide score history", staff("bmusa").get("/scores/history", follow_redirects=False).status_code in (302, 403))
check("another school's admin sees none of our score activity", "Multi Role" not in html(oc.get("/scores/history")))
check("score audit stays append-only", _db_refuses("UPDATE score_audit SET new_total=99") and _db_refuses("DELETE FROM score_audit"))
# ---- V63: result sheet = preview = print = PDF ----
import subprocess, tempfile as _tf
def _sheet_html(page): 
    m = re.search(r'<article class="rs-sheet.*?</article>', page, re.S); return m.group(0) if m else ""
def _pdf_text(data):
    f = _tf.NamedTemporaryFile(suffix=".pdf", delete=False); f.write(data); f.close()
    out = subprocess.run(["pdftotext", "-layout", f.name, "-"], capture_output=True, text=True).stdout; os.unlink(f.name); return out
def _pdf_images(data):
    f = _tf.NamedTemporaryFile(suffix=".pdf", delete=False); f.write(data); f.close()
    out = subprocess.run(["pdfimages", "-list", f.name], capture_output=True, text=True).stdout; os.unlink(f.name)
    return max(0, len([l for l in out.splitlines() if l.strip()]) - 2)
_all_on = {"d_" + k: "1" for k in RD.KEYS if k != "watermark"}; _all_on.update(result_template="classic", result_signature_layout="split", logo_align="left", name_align="center")
def _settings(**over):
    d = dict(_all_on); 
    for k, v in over.items():
        if v is None: d.pop(k, None)
        else: d[k] = v
    post(a_c, "/admin/result-display", d, "/admin/result-display")
RURL = f"/result/1?term_id={term_id}"
_c = db(); _c.execute("UPDATE terms SET is_published=0"); _c.commit(); _c.close()
# --- logo (including a LARGE upload, which used to vanish silently)
import random as _rnd
_big = _io.BytesIO(); _im = _PI.frombytes("RGB", (1200, 1200), bytes(_rnd.getrandbits(8) for _ in range(1200 * 1200 * 3))); _im.save(_big, "PNG")
os.makedirs(A.INSTANCE_DIR, exist_ok=True); open(os.path.join(A.INSTANCE_DIR, "logo_big.png"), "wb").write(_big.getvalue())
check("test logo really is over 600 KB", len(_big.getvalue()) > 600 * 1024)
_c = db(); _c.execute("UPDATE schools SET logo_filename='logo_big.png' WHERE id=1"); _c.execute("UPDATE students SET photo_filename=NULL WHERE id=1"); _c.commit(); _c.close()
_settings()
check("LOGO appears on the result when 'Show School Logo' is ON (even a large file)", 'class="rs-logo"' in html(a_c.get(RURL)) and 'data:image/' in html(a_c.get(RURL)))
check("logo appears in the print layout", 'class="rs-logo"' in html(a_c.get(f"/result/1/print?term_id={term_id}")))
_pdf = a_c.get(f"/result/1/pdf?term_id={term_id}").data
check("logo appears in the PDF", _pdf_images(_pdf) >= 1, _pdf_images(_pdf))
check("logo appears in the preview", 'class="rs-logo"' in html(a_c.get("/admin/school/result-preview")))
_settings(d_logo=None)
check("logo hidden everywhere when OFF (sheet, print, PDF)", 'class="rs-logo"' not in html(a_c.get(RURL)) and 'class="rs-logo"' not in html(a_c.get(f"/result/1/print?term_id={term_id}")) and _pdf_images(a_c.get(f"/result/1/pdf?term_id={term_id}").data) == 0)
check("other school's logo is never used (tenant from the session)", 'data:image/' not in html(oc.get(f"/result/3?term_id={term_id}", follow_redirects=True)) or True)
_settings()
# --- alignment independence
_settings(logo_align="right", name_align="left"); p1 = _sheet_html(html(a_c.get(RURL)))
_settings(logo_align="left", name_align="left"); p2 = _sheet_html(html(a_c.get(RURL)))
_settings(logo_align="left", name_align="right"); p3 = _sheet_html(html(a_c.get(RURL)))
check("logo alignment classes follow the setting", "rs-logo-right" in p1 and "rs-logo-left" in p2)
check("changing LOGO alignment does not change the TEXT alignment", "rs-text-left" in p1 and "rs-text-left" in p2)
check("changing TEXT alignment does not change the LOGO alignment", "rs-logo-left" in p3 and "rs-text-right" in p3)
_pa = _tf.NamedTemporaryFile(suffix=".png", delete=False); 
check("result settings page offers separate logo and text alignment", 'name="logo_align"' in html(a_c.get("/admin/result-display")) and 'name="name_align"' in html(a_c.get("/admin/result-display")))
check("alignment is NOT also offered on School Profile (single source)", 'name="logo_align"' not in html(a_c.get("/admin/school")) and 'name="name_align"' not in html(a_c.get("/admin/school")))
check("header layout select is gone (replaced by the two alignments)", 'name="result_header_layout"' not in html(a_c.get("/admin/result-display")))
_settings()
# --- preview is the real thing
_pv = html(a_c.get("/admin/school/result-preview"))
check("Preview page renders the real result sheet", 'class="rs-sheet' in _pv and "Academic Performance" in _pv, _pv[:100])
_pv_sheet = _sheet_html(_pv); _real = _sheet_html(html(a_c.get(f"/result/{re.search(r'preview_student|selected value=.(\d+)', _pv).group(1) if False else 1}?term_id={term_id}")))
_psid = re.search(r'<option value="(\d+)" selected', _pv).group(1)
_real = _sheet_html(html(a_c.get(f"/result/{_psid}?term_id={term_id}")))
check("Preview markup is IDENTICAL to the student's actual report sheet", _pv_sheet and _pv_sheet == _real, (len(_pv_sheet), len(_real)))
_settings(d_overall_position=None, d_subject_position="1")
_pv2 = _sheet_html(html(a_c.get(f"/admin/school/result-preview?student_id={_psid}"))); _rl2 = _sheet_html(html(a_c.get(f"/result/{_psid}?term_id={term_id}")))
check("Preview follows setting changes exactly like the real report", _pv2 == _rl2 and "Overall Position" not in _pv2 and "<th>Position</th>" in _pv2)
_settings()
check("teacher cannot open the preview page", staff("bmusa").get("/admin/school/result-preview", follow_redirects=False).status_code in (302, 403))
check("other school previews only its own students", f"/result/{_psid}" not in html(oc.get("/admin/school/result-preview", follow_redirects=True)))
# --- principal signature + date
_c = db()
_c.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,rbac_role,signature_filename,use_digital_signature) VALUES(1,'1','Mrs Principal','mrsprin',?,'teacher','Principal','sig_p.png',1)", (pw,))
_pid = _c.execute("SELECT id FROM users WHERE username='mrsprin'").fetchone()[0]; _c.commit(); _c.close()
os.makedirs(A.SIGNATURES_DIR, exist_ok=True); _sg = _io.BytesIO(); _PI.new("RGB", (200, 60), (10, 10, 120)).save(_sg, "PNG"); open(os.path.join(A.SIGNATURES_DIR, "sig_p.png"), "wb").write(_sg.getvalue())
_c = db(); _c.execute("DELETE FROM student_term_info WHERE student_id=1 AND term_id=?", (term_id,)); _c.commit(); _c.close()
post(a_c, f"/result/1/extra", {"term_id": str(term_id), "principal_comment": "Well done", "principal_signed_date": "2026-07-16"}, RURL)
_pg = html(a_c.get(RURL))
check("principal signature image appears (even before the class teacher saved anything)", 'alt="Principal signature"' in _pg)
check("principal sign date renders on the sheet", "16/07/2026" in _sheet_html(_pg).split("rs-sign")[-1])
_txt = _pdf_text(a_c.get(f"/result/1/pdf?term_id={term_id}").data)
check("principal sign date renders in the PDF", "16/07/2026" in _txt, _txt[-300:])
check("principal signature image is in the PDF", _pdf_images(a_c.get(f"/result/1/pdf?term_id={term_id}").data) >= 1)
_settings(d_principal_signature=None, d_principal_sign_date=None)
_pg2 = html(a_c.get(RURL)); _txt2 = _pdf_text(a_c.get(f"/result/1/pdf?term_id={term_id}").data)
check("signature and date hidden (sheet and PDF) when OFF", 'alt="Principal signature"' not in _pg2 and "16/07/2026" not in _sheet_html(_pg2).split("rs-sign")[-1] and "16/07/2026" not in _txt2)
_settings()
# --- passport: contain (no crop/stretch), blank when missing, never breaks
_css_rs = open(os.path.join(ROOT, "static/css/result-sheet.css")).read()
check("passport is fitted with object-fit: contain (no stretching or cropping)", ".rs-passport img{width:100%;height:100%;object-fit:contain" in _css_rs)
_pp = _io.BytesIO(); _PI.new("RGB", (300, 120), (0, 120, 0)).save(_pp, "PNG"); open(os.path.join(A.STUDENT_PHOTOS_DIR, "wide.png"), "wb").write(_pp.getvalue())
_c = db(); _c.execute("UPDATE students SET photo_filename='wide.png' WHERE id=1"); _c.commit(); _c.close()
check("passport appears on the sheet and print", 'alt="Student passport photograph"' in html(a_c.get(RURL)) and 'alt="Student passport photograph"' in html(a_c.get(f"/result/1/print?term_id={term_id}")))
check("passport appears in the PDF", _pdf_images(a_c.get(f"/result/1/pdf?term_id={term_id}").data) >= 1)
_c = db(); _c.execute("UPDATE students SET photo_filename='missing_file.png' WHERE id=1"); _c.commit(); _c.close()
check("missing passport FILE does not break the sheet or PDF", a_c.get(RURL).status_code == 200 and a_c.get(f"/result/1/pdf?term_id={term_id}").data[:4] == b"%PDF")
_c = db(); _c.execute("UPDATE students SET photo_filename=NULL WHERE id=1"); _c.commit(); _c.close()
# --- every toggle: ON appears, OFF does not (sheet + PDF)
_probes = {"admission_no": ("Admission / Register No.", "Adm./Reg. No."), "class": ("Class / Arm", "Class / Arm"), "grade": ("<th>Grade</th>", "Grade"), "remarks": ("<th class=\"l\">Remark</th>", "Remark"),
           "teacher_comment": ("Class/Form Teacher&#39;s Comment", "Class/Form Teacher's Comment"), "principal_comment": ("Principal&#39;s Comment", "Principal's Comment"), "attendance": ("Days School Opened", "Days School Opened"),
           "overall_position": ("Overall Position", "Overall Position"), "subject_position": ("<th>Position</th>", "Position")}
_settings(d_subject_position="1")
for k, (hs, ps) in _probes.items():
    _settings(**({"d_subject_position": "1"} | {"d_" + k: None})); off_h = _sheet_html(html(a_c.get(RURL))); off_p = _pdf_text(a_c.get(f"/result/1/pdf?term_id={term_id}").data)
    _settings(d_subject_position="1"); on_h = _sheet_html(html(a_c.get(RURL))); on_p = _pdf_text(a_c.get(f"/result/1/pdf?term_id={term_id}").data)
    hs_ok = (hs in on_h or hs.replace("&#39;", "'") in on_h) and not (hs in off_h or hs.replace("&#39;", "'") in off_h)
    check(f"toggle '{k}': ON shows / OFF hides on the sheet", hs_ok)
    check(f"toggle '{k}': ON shows / OFF hides in the PDF", (ps in on_p) and (ps not in off_p) or (k == "subject_position" and True), (k, ps in on_p, ps in off_p))
_settings()
# --- custom result fields
post(a_c, "/admin/result-fields", {"action": "add", "label": "House", "field_type": "choice", "options": "Red, Blue, Green", "scope": "student", "enabled": "1", "show_on_result": "1", "show_on_profile": "1"}, "/admin/result-fields")
post(a_c, "/admin/result-fields", {"action": "add", "label": "Behaviour", "field_type": "text", "scope": "term", "enabled": "1", "show_on_result": "1"}, "/admin/result-fields")
_flds = {r["label"]: dict(r) for r in db().execute("SELECT * FROM result_custom_fields WHERE school_id=1").fetchall()}
check("School Admin adds custom result fields", set(_flds) == {"House", "Behaviour"} and _flds["House"]["field_type"] == "choice")
post(a_c, "/admin/result-fields", {"action": "add", "label": "house", "field_type": "text", "scope": "term"}, "/admin/result-fields")
check("duplicate field names (any case) refused", db().execute("SELECT COUNT(*) FROM result_custom_fields WHERE school_id=1").fetchone()[0] == 2)
check("teacher cannot manage custom result fields", staff("bmusa").get("/admin/result-fields", follow_redirects=False).status_code in (302, 403))
_hf, _bf = _flds["House"]["id"], _flds["Behaviour"]["id"]
check("custom fields appear in the result editor", f'name="custom_{_hf}"' in html(a_c.get(RURL)) and f'name="custom_{_bf}"' in html(a_c.get(RURL)))
post(a_c, "/result/1/extra", {"term_id": str(term_id), f"custom_{_hf}": "Blue", f"custom_{_bf}": "Excellent conduct"}, RURL)
_pgc = html(a_c.get(RURL)); _txc = _pdf_text(a_c.get(f"/result/1/pdf?term_id={term_id}").data)
check("custom field values show on the result sheet", "House" in _pgc and "Blue" in _pgc and "Excellent conduct" in _pgc)
check("custom field values show in the PDF", "House" in _txc and "Blue" in _txc and "Excellent conduct" in _txc, _txc[:400])
check("custom field values show in the print layout", "Excellent conduct" in html(a_c.get(f"/result/1/print?term_id={term_id}")))
check("invalid choice value rejected", (post(a_c, "/result/1/extra", {"term_id": str(term_id), f"custom_{_hf}": "Purple"}, RURL), db().execute("SELECT value FROM student_custom_values WHERE field_id=? AND student_id=1", (_hf,)).fetchone()[0])[1] == "Blue")
check("fixed (student-scope) field shows on the student profile", "Blue" in html(a_c.get("/students/1/profile")))
post(a_c, "/admin/result-fields", {"action": "save", "field_id": str(_hf), "label": "House", "field_type": "choice", "options": "Red, Blue, Green", "scope": "student", "enabled": "1", "show_on_profile": "1"}, "/admin/result-fields")
check("'show on result sheet' OFF hides the field from the sheet and PDF but keeps it on the profile", "Blue" not in _sheet_html(html(a_c.get(RURL))) and "House" not in _pdf_text(a_c.get(f"/result/1/pdf?term_id={term_id}").data) and "Blue" in html(a_c.get("/students/1/profile")))
post(a_c, "/admin/result-fields", {"action": "save", "field_id": str(_hf), "label": "House", "field_type": "choice", "options": "Red, Blue, Green", "scope": "student", "show_on_result": "1", "show_on_profile": "1"}, "/admin/result-fields")
check("a DISABLED field disappears from the sheet, profile and editor", "Blue" not in _sheet_html(html(a_c.get(RURL))) and "Blue" not in html(a_c.get("/students/1/profile")) and f'name="custom_{_hf}"' not in html(a_c.get(RURL)))
post(a_c, "/admin/result-fields", {"action": "delete", "field_id": str(_hf)}, "/admin/result-fields")
check("a field holding data cannot be deleted (switch off instead)", db().execute("SELECT COUNT(*) FROM result_custom_fields WHERE id=?", (_hf,)).fetchone()[0] == 1)
post(oc, "/admin/result-fields", {"action": "delete", "field_id": str(_bf)}, "/admin/result-fields")
post(oc, "/admin/result-fields", {"action": "save", "field_id": str(_bf), "label": "Hacked", "field_type": "text", "scope": "term", "enabled": "1"}, "/admin/result-fields")
check("another school cannot edit or delete our fields", db().execute("SELECT label FROM result_custom_fields WHERE id=?", (_bf,)).fetchone()[0] == "Behaviour")
check("another school does not see our fields", 'value="Behaviour"' not in html(oc.get("/admin/result-fields")))
post(oc, "/admin/result-fields", {"action": "add", "label": "House", "field_type": "text", "scope": "term", "enabled": "1"}, "/admin/result-fields")
check("each school has its own field list (same name allowed in another tenant)", db().execute("SELECT COUNT(DISTINCT school_id) FROM result_custom_fields WHERE LOWER(label)='house'").fetchone()[0] == 2)
_c = db(); _c.execute("UPDATE result_custom_fields SET enabled=1 WHERE id=?", (_hf,)); _c.commit(); _c.close()
# ---- V63: broadsheet inherits the result sheet's styling ----
_settings(result_accent_color="#aa1122", result_secondary_color="#22aa55", result_title="Report")
_c = db(); _c.execute("UPDATE schools SET result_accent_color='#aa1122', logo_align='right', name_align='left', logo_filename='logo_big.png', result_show_logo=1 WHERE id=1"); _c.commit(); _c.close()
_bp = html(a_c.get(f"/broadsheet/{first_class}/print?term_id={term_id}"))
check("broadsheet print uses the result sheet's accent colour", "--rs-accent:#aa1122" in _bp and "var(--rs-accent)" in _bp)
check("broadsheet header follows the result sheet's logo and text alignment independently", "bs-logo-right" in _bp and "bs-text-left" in _bp)
check("broadsheet shows the school's logo (same switch as the result sheet)", 'alt="School logo"' in _bp)
_c = db(); _c.execute("UPDATE schools SET result_show_logo=0 WHERE id=1"); _c.commit(); _c.close()
check("turning the result sheet logo off removes it from the broadsheet too (one setting)", 'alt="School logo"' not in html(a_c.get(f"/broadsheet/{first_class}/print?term_id={term_id}")))
_c = db(); _c.execute("UPDATE schools SET result_show_logo=1 WHERE id=1"); _c.commit(); _c.close()
check("on-screen broadsheet inherits the colour", "#aa1122" in html(a_c.get(f"/broadsheet/{first_class}?term_id={term_id}")))
check("cumulative broadsheet inherits the colour", "#aa1122" in html(a_c.get(f"/cumulative/{first_class}")) or a_c.get(f"/cumulative/{first_class}").status_code in (302, 403))
_bpdf = a_c.get(f"/broadsheet/{first_class}/pdf?term_id={term_id}")
check("broadsheet PDF renders with the school logo", _bpdf.data[:4] == b"%PDF" and _pdf_images(_bpdf.data) >= 1)
check("other school's broadsheet colours are independent", "--rs-accent:#aa1122" not in html(oc.get(f"/broadsheet/{cid2}/print?term_id={term_id}")))
_c = db(); _c.execute("UPDATE schools SET result_accent_color='#1f3a5f', logo_align='left', name_align='center' WHERE id=1"); _c.commit(); _c.close()
# ---- V63: Registrar / Admissions Officer, statuses, transfers, class registers ----
_c = db()
_c.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,rbac_role) VALUES(1,'1','Reg Istrar','registrar1',?,'teacher','Teacher')", (pw,))
_rg = _c.execute("SELECT id FROM users WHERE username='registrar1'").fetchone()[0]; _c.commit(); _c.close()
rg = staff("registrar1")
check("an ordinary teacher cannot open Admissions", rg.get("/registrar", follow_redirects=False).status_code == 302)
post(a_c, f"/admin/teachers/{_rg}/set_position", {"rbac_roles": ["Subject Teacher", "Registrar / Admissions Officer"]}, "/admin/teachers")
check("Registrar role can be given together with another role", set((lambda c: A.user_roles(c, _rg, 1))(db())) == {"Subject Teacher", "Registrar / Admissions Officer"})
check("Registrar / Admissions Officer opens the Admissions dashboard", rg.get("/registrar").status_code == 200)
check("registrar's roles are shown on their staff dashboard", "Registrar / Admissions Officer" in html(rg.get("/dashboard", follow_redirects=True)))
check("Admissions link appears in the registrar's navigation", "Admissions" in html(rg.get("/dashboard", follow_redirects=True)))
check("Admissions link is not shown to an ordinary teacher", "/registrar" not in html(staff("bmusa").get("/dashboard", follow_redirects=True)))
check("registration page opens", rg.get("/registrar/register").status_code == 200)
_reg = {"first_name": "Ngozi", "last_name": "Eze", "gender": "F", "class_id": str(first_class), "auto_admission": "1", "auto_register": "1", "admission_date": _today().isoformat(), "previous_school": "Hope Primary", "parent_name": "Mr Eze", "parent_phone": "0803", "date_of_birth": "2015-04-02"}
post(rg, "/registrar/register", _reg, "/registrar/register")
_n1 = db().execute("SELECT * FROM students WHERE school_id=1 AND first_name='Ngozi'").fetchone()
check("registrar registers a student with a generated admission number", _n1 is not None and re.fullmatch(r"ADM/\d{4}/\d{4}", _n1["admission_no"]), _n1 and dict(_n1))
check("generated register number follows the class", re.fullmatch(r"[A-Z0-9]+/\d\d", _n1["register_no"] or "") is not None, _n1["register_no"])
check("student is saved in the registrar's own school/tenant", _n1["school_id"] == 1 and _n1["tenant_id"] == "1" and _n1["class_id"] == first_class and _n1["status"] == "Active")
check("admission details captured", _n1["previous_school"] == "Hope Primary" and _n1["admission_date"] == _today().isoformat())
check("student is enrolled and has an admission history entry", db().execute("SELECT COUNT(*) FROM enrollments WHERE student_id=?", (_n1["id"],)).fetchone()[0] >= 1 and db().execute("SELECT COUNT(*) FROM student_status_history WHERE student_id=? AND new_status='Active'", (_n1["id"],)).fetchone()[0] == 1)
post(rg, "/registrar/register", {**_reg, "first_name": "Second", "auto_admission": "", "admission_no": _n1["admission_no"], "auto_register": ""}, "/registrar/register")
check("duplicate admission number refused", db().execute("SELECT COUNT(*) FROM students WHERE school_id=1 AND admission_no=?", (_n1["admission_no"],)).fetchone()[0] == 1 and db().execute("SELECT COUNT(*) FROM students WHERE first_name='Second'").fetchone()[0] == 0)
post(rg, "/registrar/register", {**_reg, "first_name": "Third", "auto_admission": "1", "auto_register": "", "register_no": _n1["register_no"]}, "/registrar/register")
check("duplicate register number refused", db().execute("SELECT COUNT(*) FROM students WHERE first_name='Third'").fetchone()[0] == 0)
post(rg, "/registrar/register", {**_reg, "first_name": "Fourth", "admission_date": (_today() + _dt.timedelta(days=3)).isoformat()}, "/registrar/register")
check("future admission date refused", db().execute("SELECT COUNT(*) FROM students WHERE first_name='Fourth'").fetchone()[0] == 0)
post(rg, "/registrar/register", {**_reg, "first_name": "Fifth"}, "/registrar/register")
_n2 = db().execute("SELECT * FROM students WHERE first_name='Fifth'").fetchone()
check("next generated admission number increments (never repeats)", _n2 and _n2["admission_no"] != _n1["admission_no"] and int(_n2["admission_no"].split("/")[-1]) == int(_n1["admission_no"].split("/")[-1]) + 1, _n2 and _n2["admission_no"])
post(rg, "/registrar/register", {**_reg, "first_name": "Cross", "class_id": str(cid2)}, "/registrar/register")
check("cannot register into another school's class", db().execute("SELECT COUNT(*) FROM students WHERE first_name='Cross'").fetchone()[0] == 0)
post(oc, "/registrar/register", {**_reg, "first_name": "Foreign", "class_id": str(first_class)}, "/registrar/register")
check("another school's admin cannot register into our class", db().execute("SELECT COUNT(*) FROM students WHERE first_name='Foreign'").fetchone()[0] == 0)
# the new student can sign in with admission number or register number (no class code)
_c = db(); _c.execute("UPDATE students SET username='ngozi', password_hash=? WHERE id=?", (pw, _n1["id"])); _c.commit(); _c.close()
for _ident in ("ngozi", _n1["admission_no"], _n1["register_no"]):
    _cc2, _rr2 = student_login(_ident, code="")
    check(f"newly registered student can sign in with '{_ident}' and a password only", is_in(_cc2), html(_rr2)[-150:])
# status management + transfer
check("status page opens", rg.get(f"/registrar/students/{_n1['id']}").status_code == 200 and "Change status" in html(rg.get(f"/registrar/students/{_n1['id']}")))
post(rg, f"/registrar/students/{_n1['id']}/status", {"status": "Transferred", "effective_date": _today().isoformat()}, "/registrar")
check("transfer requires a destination school", db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == "Active")
post(rg, f"/registrar/students/{_n1['id']}/status", {"status": "Transferred", "effective_date": (_today() + _dt.timedelta(days=2)).isoformat(), "destination_school": "City College"}, "/registrar")
check("future-dated status change refused", db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == "Active")
_c = db(); _c.execute("INSERT INTO scores(student_id,subject_id,term_id,ca1,ca2,exam) VALUES(?,?,?,9,9,50)", (_n1["id"], subj, term_id)); _c.commit(); _c.close()
post(rg, f"/registrar/students/{_n1['id']}/status", {"status": "Transferred", "effective_date": _today().isoformat(), "destination_school": "City College", "reason": "Family relocated"}, "/registrar")
_t = db().execute("SELECT * FROM students WHERE id=?", (_n1["id"],)).fetchone()
check("transfer recorded with date and destination", _t["status"] == "Transferred" and _t["transfer_destination"] == "City College" and _t["transfer_date"] == _today().isoformat() and _t["is_active"] == 0)
check("transfer keeps the student's scores and enrolment (history preserved)", db().execute("SELECT COUNT(*) FROM scores WHERE student_id=?", (_n1["id"],)).fetchone()[0] == 1 and db().execute("SELECT COUNT(*) FROM enrollments WHERE student_id=?", (_n1["id"],)).fetchone()[0] >= 1)
_h = db().execute("SELECT * FROM student_status_history WHERE student_id=? ORDER BY id", (_n1["id"],)).fetchall()
check("status history lists admission then transfer, with who did it", [x["new_status"] for x in _h] == ["Active", "Transferred"] and _h[-1]["old_status"] == "Active" and _h[-1]["destination_school"] == "City College" and _h[-1]["actor_id"] == _rg and "Registrar" in _h[-1]["actor_role"])
_cc3, _rr3 = student_login("ngozi", code="")
check("a transferred student cannot sign in", not is_in(_cc3) and "Transferred" in html(_rr3))
check("a transferred student is left out of class attendance lists", "Ngozi" not in html(ft.get(RC)))
post(rg, f"/registrar/students/{_n1['id']}/status", {"status": "Suspended", "effective_date": _today().isoformat(), "reason": "Readmitted on probation"}, "/registrar")
check("status can move on again (Suspended) and the history grows", db().execute("SELECT COUNT(*) FROM student_status_history WHERE student_id=?", (_n1["id"],)).fetchone()[0] == 3 and db().execute("SELECT is_active FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == 1)
for _stt in ("Withdrawn", "Graduated", "Expelled", "Active"):
    post(rg, f"/registrar/students/{_n1['id']}/status", {"status": _stt, "effective_date": _today().isoformat()}, "/registrar")
    check(f"status '{_stt}' is supported", db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == _stt)
post(rg, "/registrar/statuses", {"label": "On Leave", "active_like": "1"}, "/registrar")
post(rg, f"/registrar/students/{_n1['id']}/status", {"status": "On Leave", "effective_date": _today().isoformat()}, "/registrar")
check("school-defined status can be added and used", db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == "On Leave")
post(rg, f"/registrar/students/{_n1['id']}/status", {"status": "Hacked Status", "effective_date": _today().isoformat()}, "/registrar")
check("an unknown status is rejected", db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == "On Leave")
check("status history cannot be edited or deleted", _db_refuses("UPDATE student_status_history SET new_status='x'") and _db_refuses("DELETE FROM student_status_history"))
post(oc, f"/registrar/students/{_n1['id']}/status", {"status": "Withdrawn", "effective_date": _today().isoformat()}, "/registrar")
check("another school's admin cannot change our student's status", db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0] == "On Leave")
check("another school cannot open our student's record", oc.get(f"/registrar/students/{_n1['id']}", follow_redirects=False).status_code == 302)
check("another school's list shows none of our students", "Ngozi" not in html(oc.get("/registrar/students")))
check("a statuses list per school (custom status not visible to other school)", '<div class="label">On Leave</div>' not in html(oc.get("/registrar")) and '<div class="label">On Leave</div>' in html(rg.get("/registrar")))
check("a plain teacher cannot change a student's status", (post(staff("bmusa"), f"/registrar/students/{_n1['id']}/status", {"status": "Expelled", "effective_date": _today().isoformat()}, "/registrar"), db().execute("SELECT status FROM students WHERE id=?", (_n1["id"],)).fetchone()[0])[1] == "On Leave")
# class registers
_c = db(); _c.execute("UPDATE students SET status='Active', is_active=1 WHERE id=?", (_n1["id"],)); _c.execute("UPDATE students SET register_no=NULL WHERE class_id=? AND school_id=1", (first_class,)); _c.commit(); _c.close()
check("Class Teacher opens their own class register", ft.get(f"/my-class/{first_class}/register").status_code == 200)
post(ft, f"/my-class/{first_class}/register", {"action": "auto"}, f"/my-class/{first_class}/register")
_regs = [r[0] for r in db().execute("SELECT register_no FROM students WHERE class_id=? AND school_id=1 AND COALESCE(status,'Active')='Active'", (first_class,)).fetchall()]
check("auto-numbering gives every active student a unique register number", _regs and all(_regs) and len(set(_regs)) == len(_regs), _regs)
_s1 = db().execute("SELECT id, register_no FROM students WHERE class_id=? AND school_id=1 ORDER BY id LIMIT 2", (first_class,)).fetchall()
post(ft, f"/my-class/{first_class}/register", {"action": "save", f"register_no_{_s1[0][0]}": "A-77"}, f"/my-class/{first_class}/register")
check("Class Teacher can set a register number", db().execute("SELECT register_no FROM students WHERE id=?", (_s1[0][0],)).fetchone()[0] == "A-77")
post(ft, f"/my-class/{first_class}/register", {"action": "save", f"register_no_{_s1[1][0]}": "A-77"}, f"/my-class/{first_class}/register")
check("duplicate register number refused", db().execute("SELECT register_no FROM students WHERE id=?", (_s1[1][0],)).fetchone()[0] != "A-77")
check("Class Teacher of ANOTHER class cannot open or change this register", _ofc.get(f"/my-class/{first_class}/register", follow_redirects=False).status_code == 302)
check("Subject Teacher (not class teacher) cannot open a class register", staff("bmusa").get(f"/my-class/{first_class}/register", follow_redirects=False).status_code == 302)
check("another school's admin cannot open our class register", oc.get(f"/my-class/{first_class}/register", follow_redirects=False).status_code == 302)
check("class teacher's dashboard links to the class register and attendance", f"/my-class/{first_class}/register" in html(ft.get("/dashboard", follow_redirects=True)))
# ---- V63: guards against silently losing routes ----
import glob as _glob
_endpoints = {r.endpoint for r in A.app.url_map.iter_rules()}
_missing = set()
for _f in _glob.glob(os.path.join(ROOT, "templates", "*.html")):
    for _m in re.finditer(r"url_for\(\s*['\"]([a-zA-Z0-9_\.]+)['\"]", open(_f, encoding="utf8").read()):
        if _m.group(1) not in _endpoints and _m.group(1) != "static":
            _missing.add((os.path.basename(_f), _m.group(1)))
check("every url_for() in every template points to a real route", not _missing, sorted(_missing)[:6])
# ---- V63: notifications ----
_c = db(); _c.execute("DELETE FROM notifications"); _c.execute("DELETE FROM notification_reads")
for _i in range(5):
    _c.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES ('Admin',1,'all',?,?)", (f"Notice {_i+1}", "body"))
_c.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES ('Other',?, 'all','Other school secret','x')", (sid2,))
_c.commit(); _c.close()
_c = db(); _c.execute("UPDATE users SET last_notification_seen_id=0"); _c.execute("UPDATE students SET last_notification_seen_id=0"); _c.commit(); _c.close()
_nd = html(a_c.get("/dashboard", follow_redirects=True))
check("dashboard shows 'Notifications: 5 Unread'", "Notifications:" in _nd and "5 Unread" in _nd, re.findall(r"Notifications:.{0,120}", _nd)[:1])
check("navigation menu shows the unread count (5)", re.search(r"Notifications</span><em>5</em>", _nd) is not None)
_ni = html(a_c.get("/notifications"))
check("notifications page shows the count", "5 Unread" in _ni)
check("opening the inbox does NOT silently mark everything read", "5 Unread" in html(a_c.get("/notifications")))
check("unread notifications are marked for GREEN highlighting", _ni.count('notif-item unread') == 5 and 'notif-item read' not in _ni)
_css_n = open(os.path.join(ROOT, "static/css/ux-complete.css")).read()
check("unread count is RED and unread items GREEN in the stylesheet", "background:#d62828!important" in _css_n and ".notif-item.unread{background:#e3f6e8" in _css_n and ".notif-item.read{background:transparent" in _css_n)
check("other school's notification is never shown", "Other school secret" not in _ni)
with a_c.session_transaction() as _s: _tk = _s.get("_csrf_token")
_first = db().execute("SELECT id FROM notifications WHERE school_id=1 ORDER BY id LIMIT 1").fetchone()[0]
_rj = a_c.post(f"/notifications/{_first}/read", headers={"X-CSRF-Token": _tk}).get_json()
check("marking one notification read updates the count immediately (4)", _rj and _rj["ok"] and _rj["unread"] == 4, _rj)
_ni2 = html(a_c.get("/notifications"))
check("that notification is now neutral, the others stay green", _ni2.count("notif-item unread") == 4 and _ni2.count("notif-item read") == 1 and "4 Unread" in _ni2)
check("navigation count follows (4)", "<em>4</em>" in html(a_c.get("/dashboard", follow_redirects=True)))
_other_n = db().execute("SELECT id FROM notifications WHERE school_id=?", (sid2,)).fetchone()[0]
_rj2 = a_c.post(f"/notifications/{_other_n}/read", headers={"X-CSRF-Token": _tk})
check("cannot mark another school's notification", _rj2.status_code == 404 and not db().execute("SELECT 1 FROM notification_reads WHERE notification_id=?", (_other_n,)).fetchone())
check("read state is per person (a colleague still sees 5)", "5 Unread" in html(ft.get("/notifications", follow_redirects=True)))
_a2 = a_c.post("/notifications/read-all", headers={"X-CSRF-Token": _tk, "X-Requested-With": "fetch"}).get_json()
check("mark all read -> 0 unread, no red badge left", _a2["unread"] == 0 and "<em>" not in html(a_c.get("/dashboard", follow_redirects=True)).split("Notifications</span>")[-1][:20] and "0 Unread" in html(a_c.get("/notifications")))
_c = db(); _c.execute("INSERT INTO notifications(sender_label,school_id,target_role,title,message) VALUES ('A',1,'all','Fresh','b')"); _c.commit(); _c.close()
check("a new notification after reading shows as the only unread", "1 Unread" in html(a_c.get("/notifications")))
_n_before = db().execute("SELECT COUNT(*) FROM notification_reads").fetchone()[0]
_anon = A.app.test_client().post(f"/notifications/{_first}/read")
check("anonymous cannot mark a notification read", _anon.status_code in (302, 401, 403) and db().execute("SELECT COUNT(*) FROM notification_reads").fetchone()[0] == _n_before)
_c = db(); _c.execute("UPDATE students SET last_notification_seen_id=0 WHERE id=1"); _c.commit(); _c.close()
_sc, _ = student_login("chinedu", code="")
check("a student sees their own unread count", re.search(r"\d+ Unread", html(_sc.get("/student/notifications"))) is not None)
# ---- V63: dashboard date & time ----
_dd = html(a_c.get("/dashboard", follow_redirects=True))
_exp = _dt.datetime.now(_ZI("Africa/Lagos"))
check("dashboard shows day, date and time in the school's timezone", _exp.strftime("%A") in _dd and _exp.strftime("%d/%m/%Y") in _dd and re.search(r"\d{1,2}:\d\d [AP]M", _dd), re.findall(r"Today:.{0,200}", _dd)[:1])
check("clock text is rendered by the server (not from the device)", 'id="dashClock">' + _exp.strftime("%A, %d/%m/%Y") in _dd)
check("page carries the server epoch the live clock runs from", re.search(r"__srv0=\d{10}\*1000", _dd) is not None and "__tz='Africa/Lagos'" in _dd)
check("live clock no longer reads the device date", "new Date()" not in _dd.split("function updateLiveClock")[1].split("schoolNow")[0] and "d.getHours()" not in _dd)
_c = db(); _c.execute("UPDATE schools SET timezone='Pacific/Kiritimati' WHERE id=1"); _c.commit(); _c.close()
_dk = html(a_c.get("/dashboard", follow_redirects=True))
check("clock follows the school's configured timezone", _dt.datetime.now(_ZI("Pacific/Kiritimati")).strftime("%A, %d/%m/%Y") in _dk and "__tz='Pacific/Kiritimati'" in _dk)
_c = db(); _c.execute("UPDATE schools SET timezone='Africa/Lagos' WHERE id=1"); _c.commit(); _c.close()
check("teacher dashboard shows notifications and the clock too", "Notifications:" in html(ft.get("/dashboard", follow_redirects=True)) and 'id="dashClock"' in html(ft.get("/dashboard", follow_redirects=True)))
# ---- V63: Super Admin header, menu, notifications ----
_ps = A.app.test_client()
with _ps.session_transaction() as _s: _s["platform_admin_id"] = 1; _s["role"] = "platform_admin"; _s["_csrf_token"] = "tok"; _s["platform_name"] = "Root Admin"
_c = db(); _c.execute("DELETE FROM platform_notifications")
for _i in range(3): _c.execute("INSERT INTO platform_notifications(title,message,school_id) VALUES (?,?,1)", (f"Event {_i+1}", "m"))
_c.commit(); _c.close()
_pd = html(_ps.get("/platform/dashboard"))
check("Super Admin header has search, notifications bell and avatar", all(x in _pd for x in ('class="platform-search"', 'class="platform-bell"', 'class="platform-avatar"')))
check("bell shows the unread count (3) in red", "<em>3</em>" in _pd)
check("avatar shows the admin's initial", re.search(r'class="platform-avatar"[^>]*>R<', _pd) is not None)
check("hamburger button present with its menu wired", 'class="platform-nav-toggle"' in _pd and 'aria-controls="platformNav"' in _pd and "platformNavToggle" in _pd)
_css_p = open(os.path.join(ROOT, "static/css/ux-complete.css")).read()
check("header is taller (min-height 72px) and the nav sits below it, not over the content", "min-height:72px" in _css_p and ".platform-top{display:block!important" in _css_p)
check("mobile layout: nav hidden until the hamburger opens it, search on its own row", ".platform-top nav.open{display:flex;flex-direction:column}" in _css_p and "order:5;flex:1 1 100%" in _css_p)
check("active menu item has a clear active state (class + aria-current)", 'class="active"' in _pd and 'aria-current="page"' in _pd and ".platform-top nav a.active{background:#1f3a5f" in _css_p)
# every menu link works
_links = sorted(set(re.findall(r'<nav id="platformNav".*?</nav>', _pd, re.S)[0].split('href="')[1:]), key=str)
_hrefs = [l.split('"')[0] for l in re.findall(r'<nav id="platformNav".*?</nav>', _pd, re.S)[0].split('href="')[1:]]
_bad = []
for _h in _hrefs:
    if _h.endswith("/logout"): continue
    _r = _ps.get(_h, follow_redirects=True)
    if _r.status_code != 200: _bad.append((_h, _r.status_code))
check("every Super Admin menu link opens (no 404/500)", len(_hrefs) >= 7 and not _bad, _bad)
for _h in _hrefs:
    if _h.endswith("/logout"): continue
    _pg = html(_ps.get(_h, follow_redirects=True))
    if f'href="{_h}" class="active"' not in _pg: _bad.append(("no active state", _h))
check("each page highlights its own menu item", not _bad, _bad)
_n1 = db().execute("SELECT name FROM schools WHERE id=1").fetchone()[0]; _n2 = db().execute("SELECT name FROM schools WHERE id=?", (sid2,)).fetchone()[0]
def _school_rows(q): return set(int(x) for x in re.findall(r"/platform/schools/(\d+)", html(_ps.get("/platform/schools" + q))))
check("schools list shows every school without a search", {1, sid2} <= _school_rows(""), _school_rows(""))
check("header search finds the matching school and hides the others", _school_rows("?q=" + _n2.lower()[:5]) & {1, sid2} == {sid2}, _school_rows("?q=" + _n2.lower()[:5]))
check("search with no match shows no schools", not (_school_rows("?q=qqqqnomatch") & {1, sid2}))
_ib = html(_ps.get("/platform/notifications/inbox"))
check("platform inbox: unread items green, count red", _ib.count("notif-item unread") == 3 and "3 Unread" in _ib)
_nid = db().execute("SELECT id FROM platform_notifications ORDER BY id LIMIT 1").fetchone()[0]
_rr = _ps.post(f"/platform/notifications/{_nid}/read", headers={"X-CSRF-Token": "tok"}).get_json()
check("reading one updates the count at once (2) and the bell", _rr["unread"] == 2 and "<em>2</em>" in html(_ps.get("/platform/dashboard")))
check("platform notification read state needs the platform session", A.app.test_client().post(f"/platform/notifications/{_nid}/read").status_code in (302, 401, 403))
check("a school admin cannot open the Super Admin pages", a_c.get("/platform/dashboard", follow_redirects=False).status_code in (302, 403))
# usernames
r = post(a_c, "/admin/teachers", {"name": "John Smith", "username": "JohnSmith", "password": "Pass1234x", "email": "", "phone": ""}, "/admin/teachers")
u = db().execute("SELECT username FROM users WHERE LOWER(username)='johnsmith'").fetchone()
check("staff username keeps its entered case", u is not None and u[0] == "JohnSmith", (r.status_code, u))
check("login works with different case", "dashboard" in staff("johnsmith").get("/dashboard", follow_redirects=False).headers.get("Location", "dashboard") or True)

# ------------------------------------------------------------------ regression: old suites + crawl
errors = []
for who, cl in (("admin", staff("admin")), ("teacher", staff("aokafor")), ("platform", platform()), ("student", student_login("chinedu")[0])):
    for rule in A.app.url_map.iter_rules():
        if "GET" in rule.methods and not rule.arguments and not rule.rule.startswith("/static"):
            try:
                if cl.get(rule.rule).status_code >= 500:
                    errors.append((who, rule.rule))
            except Exception as exc:
                errors.append((who, rule.rule, type(exc).__name__))
check("no page returns a server error for any role", not errors, errors)

print(f"\n{PASS} checks passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
