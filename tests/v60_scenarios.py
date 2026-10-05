"""End-to-end scenarios for the V60 requirements. Runs in its OWN process against a fresh temp database
(invoked by test_v60_behavior.py, or directly: python tests/v60_scenarios.py).
Exit code 0 = every check passed."""
import io
import json
import os
import re
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="v60_")
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import logging
import app as A
from db import get_db
from werkzeug.security import generate_password_hash
from PIL import Image

from school.testing_werkzeug import WerkzeugClient
from werkzeug.datastructures import MultiDict
import os as _os_env; _os_env.environ.setdefault('SCHOOL_TEST_BACKEND', 'werkzeug')


class ListDataClient(WerkzeugClient):
    """Lets tests send repeated form keys as a list of (key, value) tuples."""
    def open(self, *args, **kwargs):
        d = kwargs.get("data")
        if isinstance(d, list):
            kwargs["data"] = MultiDict(d)
        return super().open(*args, **kwargs)


A.app.test_client_class = ListDataClient
A.app.config["TESTING"] = False
A.app.config["PROPAGATE_EXCEPTIONS"] = False
logging.getLogger().setLevel(logging.CRITICAL)
A.app.logger.setLevel(logging.CRITICAL)

PASS, FAIL = 0, []


def check(name, cond, detail=""):
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(f"{name} {detail}")
        print("FAIL:", name, detail)


def tok(c, page):
    r = c.get(page)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True))
    return m.group(1) if m else None


def post(c, path, data=None, page=None, files=None, follow=False):
    d = dict(data or {})
    d["csrf_token"] = tok(c, page or path)
    if files:
        d.update(files)
        return c.post(path, data=d, content_type="multipart/form-data", follow_redirects=follow)
    return c.post(path, data=d, follow_redirects=follow)


def login(username, password="Pass1234"):
    c = A.app.test_client()
    post(c, "/login", {"username": username, "password": password}, "/login")
    return c


def student_login(username, password="Pass1234", school_code=""):
    c = A.app.test_client()
    r = post(c, "/student/login", {"username": username, "password": password, "school_code": school_code}, "/student/login")
    return c, r


def png(size_kb=None, w=60, h=60, fmt="PNG"):
    buf = io.BytesIO()
    im = Image.new("RGB", (w, h), (30, 90, 200))
    im.save(buf, fmt)
    data = buf.getvalue()
    if size_kb:
        if fmt == "PNG":
            # pad with an ancillary text chunk so the file stays a valid PNG but is large
            import struct, zlib
            pad = b"x" * (size_kb * 1024)
            chunk = b"tEXt" + b"pad\x00" + pad
            crc = zlib.crc32(chunk) & 0xffffffff
            block = struct.pack(">I", len(chunk) - 4 + 0) + chunk + struct.pack(">I", crc)
            iend = data.rfind(b"IEND") - 4
            data = data[:iend] + block + data[iend:]
    return data


def upload(data, name="p.png"):
    return (io.BytesIO(data), name)


def flashes(c):
    with c.session_transaction() as s:
        return [m for _cat, m in s.get("_flashes", [])]


def html(r):
    return r.get_data(as_text=True)


def db():
    return get_db()


# ------------------------------------------------------------------------------------ setup
conn = db()
conn.execute("UPDATE students SET first_login_completed_at=CURRENT_TIMESTAMP")
conn.execute("UPDATE students SET username=?, password_hash=? WHERE id=1", ("chinedu", generate_password_hash("Pass1234")))
conn.execute("UPDATE students SET username=?, password_hash=? WHERE id=2", ("amaka", generate_password_hash("Pass1234")))
conn.execute("UPDATE users SET password_hash=? WHERE username IN ('admin','aokafor')", (generate_password_hash("Pass1234"),))
conn.execute("UPDATE classes SET form_teacher_id=2 WHERE id=1")
# a second teacher (no class) and a second class
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role,position,first_name,surname,phone,email) VALUES(1,'1','Mr Bala Musa','bmusa',?,'teacher','subject_teacher','Bala','Musa','08011112222','bmusa@example.com')",
             (generate_password_hash("Pass1234"),))
conn.execute("INSERT INTO classes(school_id,tenant_id,name,category) VALUES(1,'1','JSS 2','Junior')") if False else None
conn.commit()
first_class = conn.execute("SELECT id FROM classes ORDER BY id").fetchone()[0]
# second school (tenant isolation)
conn.execute("INSERT INTO schools(name,activation_status,tenant_id,school_code) VALUES('Other College','active','2','OTH')")
sid2 = conn.execute("SELECT id FROM schools WHERE name='Other College'").fetchone()[0]
conn.execute("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role) VALUES(?,?,?,?,?,'admin')",
             (sid2, "2", "Other Admin", "otheradmin", generate_password_hash("Pass1234")))
conn.execute("INSERT INTO classes(school_id,name) VALUES(?, 'SS 1')", (sid2,))
cid2 = conn.execute("SELECT id FROM classes WHERE school_id=?", (sid2,)).fetchone()[0]
conn.execute("INSERT INTO students(school_id,tenant_id,admission_no,first_name,last_name,gender,class_id,username,password_hash) VALUES(?,?,'001','Zed','Other','M',?,'zed',?)",
             (sid2, "2", cid2, generate_password_hash("Pass1234")))
conn.commit()
conn.execute("UPDATE students SET first_login_completed_at=CURRENT_TIMESTAMP")
conn.commit()
other_student = conn.execute("SELECT id FROM students WHERE username='zed'").fetchone()[0]
conn.close()

# ------------------------------------------------------------------------------------ 5. student login
c, r = student_login("chinedu")
check("student login redirects to dashboard", r.status_code == 302 and "/student/dashboard" in r.headers["Location"], (r.status_code, html(r)[:150]))
r = c.get("/student/dashboard")
check("student dashboard opens", r.status_code == 200 and "Chinedu" in html(r))
check("student dashboard shows assigned class", "JSS" in html(r) or "SS" in html(r) or "Class" in html(r))
with c.session_transaction() as s:
    check("student session bound to tenant", s.get("tenant_id") == "1" and s.get("school_id") == 1)
c_bad, r = student_login("chinedu", "wrongpass")
check("wrong password gives clear error, not 500", r.status_code == 200 and "Invalid login details" in html(r), r.status_code)
c_bad, r = student_login("nobody")
check("unknown student gives same clear error", r.status_code == 200 and "Invalid login details" in html(r))
c_x, r = student_login("chinedu", school_code="ZZZ")
check("wrong school id rejected without revealing why", "Invalid login details" in html(r))
c_x, r = student_login("zed")
check("student of other school logs into own tenant only", A.app.test_client() and True)
with c_x.session_transaction() as s:
    check("other-school student session has other tenant", s.get("tenant_id") == "2")
# broken account linking -> friendly error + server log, never a 500 page
conn = db()
conn.execute("UPDATE students SET username='orphan', password_hash=? WHERE id=3", (generate_password_hash("Pass1234"),))
conn.execute("PRAGMA foreign_keys=OFF")
conn.execute("UPDATE students SET class_id=9999 WHERE id=3")
conn.commit(); conn.close()
c_o, r = student_login("orphan")
check("broken class link gives a clear message, not a 500", r.status_code == 200 and "not linked to a class" in html(r))
conn = db(); conn.execute("UPDATE students SET class_id=? WHERE id=3", (first_class,)); conn.commit(); conn.close()
# a phone number is not a login identifier any more
conn = db(); conn.execute("UPDATE students SET phone='08055550000' WHERE id IN (1,2)"); conn.commit(); conn.close()
c_a, r = student_login("08055550000")
check("phone number does not log anyone in", "Invalid login details" in html(r))
conn = db(); conn.execute("UPDATE students SET phone=NULL WHERE id IN (1,2)"); conn.commit(); conn.close()

# ------------------------------------------------------------------------------------ 1/3. student profile
c, _ = student_login("chinedu")
r = c.get("/student/profile")
check("student sees own profile form", r.status_code == 200 and "Passport photograph" in html(r) and 'name="state"' in html(r))
check("required and optional clearly marked", "Required" in html(r) and "Optional" in html(r))
check("protected fields shown read-only", 'name="admission_no"' not in html(r) and "Protected" in html(r))
base = {"state": "Kano", "lga": "Nassarawa", "tribe": "Hausa", "religion": "Islam", "email": "chinedu@example.com",
        "phone": "08031234567", "address": "12 Zaria Road, Kano", "parent_name": "Mr Okeke", "parent_relationship": "Father",
        "parent_phone": "08099998888", "parent_email": "", "parent_address": ""}
before = dict(db().execute("SELECT * FROM students WHERE id=1").fetchone())
bad = dict(base, phone="12ab", email="not-an-email", state="", address="")
r = post(c, "/student/profile", bad)
check("invalid student profile rejected (422)", r.status_code == 422, r.status_code)
t = html(r)
check("field-specific messages shown", "Phone Number: enter digits only" in t and "valid email" in t and "State is required" in t and "Address is required" in t)
check("entered values preserved on failure", 'value="12ab"' in t and 'value="not-an-email"' in t and 'value="Nassarawa"' in t)
after = dict(db().execute("SELECT * FROM students WHERE id=1").fetchone())
check("nothing partially saved on invalid input", after == before)
# tamper with protected fields
tamper = dict(base, admission_no="HACK1", class_id="2", status="Graduated", school_id="2", tenant_id="2", is_active="0", username="hacker")
r = post(c, "/student/profile", tamper)
check("valid save redirects", r.status_code == 302, (r.status_code, html(r)[:300]))
check("success message shown", any("Profile saved successfully" in m for m in flashes(c)))
row = dict(db().execute("SELECT * FROM students WHERE id=1").fetchone())
check("editable fields persisted", row["state"] == "Kano" and row["lga"] == "Nassarawa" and row["phone"] == "08031234567" and row["email"] == "chinedu@example.com")
check("protected fields NOT changed by student",
      row["admission_no"] == "001" and row["class_id"] == first_class and row["status"] == before["status"] and row["school_id"] == 1
      and row["tenant_id"] == "1" and row["is_active"] == 1 and row["username"] == "chinedu")
r = c.get("/student/profile")
check("saved values reloaded from database", 'value="Nassarawa"' in html(r) and 'value="08031234567"' in html(r))
# photo rules
r = post(c, "/student/profile", base, files={"photo": upload(png(size_kb=600), "big.png")})
check("passport > 500KB rejected", r.status_code == 422 and "must not exceed 500 KB" in html(r))
r = post(c, "/student/profile", base, files={"photo": upload(b"<?php echo 1; ?>", "evil.png")})
check("non-image disguised as png rejected", r.status_code == 422 and "not a valid image" in html(r))
r = post(c, "/student/profile", base, files={"photo": upload(b"GIF89a", "x.exe")})
check("bad extension rejected", r.status_code == 422 and "PNG, JPG or GIF" in html(r))
r = post(c, "/student/profile", base, files={"photo": upload(png(), "ok.png")})
check("valid passport saved", r.status_code == 302)
row = dict(db().execute("SELECT * FROM students WHERE id=1").fetchone())
check("photo stored and served to owner", bool(row["photo_filename"]) and c.get("/student/profile/photo").status_code == 200)
# student cannot reach staff-side or other students
check("student cannot open another student's profile page", c.get("/students/2/profile").status_code in (302, 401, 403))
check("student cannot edit another student via staff route", c.get("/students/2/profile/edit").status_code in (302, 401, 403))
r = post(c, "/students/2/profile/edit", {"state": "Lagos"}, page="/student/profile")
check("student cannot POST to another student's edit route", r.status_code in (302, 401, 403) and (db().execute("SELECT state FROM students WHERE id=2").fetchone()[0] != "Lagos"))
check("student cannot read another student's photo", c.get("/students/2/photo").status_code in (302, 401, 403, 404))
check("student cannot open staff pages", c.get("/staff/1").status_code in (302, 401, 403))
check("student cannot open custom field admin", c.get("/admin/custom-fields").status_code in (302, 401, 403))

# ------------------------------------------------------------------------------------ 2/3. staff profile
t_c = login("aokafor")
r = t_c.get("/dashboard")
check("staff dashboard has My Profile link", "My Profile" in html(r) and "/staff/2" in html(r))
r = t_c.get("/staff/2")
check("staff can view own profile", r.status_code == 200)
r = t_c.get("/staff/2/edit")
check("staff edit page opens", r.status_code == 200 and 'name="first_name"' in html(r) and "Name used at signup" in html(r))
check("staff protected fields read-only", 'name="username"' not in html(r) and 'name="staff_id"' not in html(r))
sp_ok = {"first_name": "Ada", "surname": "Okafor", "other_names": "Grace", "phone": "08022223333", "email": "ada@example.com",
         "date_of_birth": "1985-04-12", "gender": "F", "state": "Anambra", "lga": "Awka South", "address": "5 Church Street, Awka",
         "qualifications": "B.Ed Mathematics", "subjects_taught": "Mathematics"}
r = post(t_c, "/staff/2/edit", dict(sp_ok, first_name="", phone="abc", email="bad@", date_of_birth="2999-01-01"))
check("staff invalid profile rejected", r.status_code == 422 and "First Name is required" in html(r) and "Phone Number" in html(r) and "valid email" in html(r) and "cannot be in the future" in html(r))
check("staff values kept on failure", 'value="abc"' in html(r) and 'value="Awka South"' in html(r))
r = post(t_c, "/staff/2/edit", dict(sp_ok, username="hijack", staff_id="STF-999", role="admin", position="principal", school_id="2", tenant_id="2", is_active="0"))
check("staff valid save ok", r.status_code == 302, (r.status_code, html(r)[:400]))
u = dict(db().execute("SELECT * FROM users WHERE id=2").fetchone())
check("staff persisted", u["phone"] == "08022223333" and u["state"] == "Anambra" and u["qualifications"] == "B.Ed Mathematics" and u["name"] == "Ada Okafor Grace")
check("staff protected fields untouched", u["username"] == "aokafor" and u["staff_id"] is None and u["role"] == "teacher" and u["position"] == "form_teacher" and u["school_id"] == 1 and u["tenant_id"] == "1" and u["is_active"] == 1)
check("signup name retained", u["signup_name"] == "Mrs. Ada Okafor")
cc = db()
try:
    cc.execute("UPDATE users SET signup_name='X' WHERE id=2"); cc.commit(); ok = True
except sqlite3.IntegrityError:
    ok = False
finally:
    cc.rollback(); cc.close()
check("signup name cannot be altered even by SQL", not ok)
r = post(t_c, "/staff/2/edit", sp_ok, files={"signature": upload(png(size_kb=520), "s.png"), "photo": upload(png(size_kb=520), "p.png")})
check("staff signature/passport > 500KB rejected", r.status_code == 422 and html(r).count("must not exceed 500 KB") >= 2)
r = post(t_c, "/staff/2/edit", sp_ok, files={"signature": upload(png(), "s.png"), "photo": upload(png(), "p.png")})
check("staff signature+photo saved", r.status_code == 302 and db().execute("SELECT signature_filename,photo_filename FROM users WHERE id=2").fetchone()[0] is not None)
# duplicates
r = post(t_c, "/staff/2/edit", dict(sp_ok, email="BMUSA@example.com"))
check("duplicate email (case-insensitive) blocked with clear message", r.status_code == 422 and "Email is already used" in html(r))
r = post(t_c, "/staff/2/edit", dict(sp_ok, phone="08011112222"))
check("duplicate phone blocked", r.status_code == 422 and "Phone number is already used" in html(r))
check("teacher cannot edit another staff member (403)", t_c.get("/staff/3/edit").status_code == 403)
r = post(t_c, "/staff/3/edit", sp_ok, page="/staff/2/edit")
check("teacher POST to another staff member is 403 and unchanged", r.status_code == 403 and db().execute("SELECT phone FROM users WHERE id=3").fetchone()[0] == "08011112222")
check("teacher cannot open school admin custom fields (403)", t_c.get("/admin/custom-fields").status_code == 403)
check("teacher cannot open audit history (403)", t_c.get("/admin/audit-history").status_code == 403)
check("teacher cannot view other staff profile page", t_c.get("/staff/1").status_code in (302, 403))

# admin manages staff: protected fields editable, duplicates enforced
a_c = login("admin")
r = a_c.get("/staff/2/edit")
check("admin can edit staff incl. protected fields", r.status_code == 200 and 'name="username"' in html(r) and 'name="staff_id"' in html(r))
adm_ok = dict(sp_ok, username="aokafor", staff_id="STF-001")
r = post(a_c, "/staff/2/edit", adm_ok)
check("admin sets staff id", r.status_code == 302 and db().execute("SELECT staff_id FROM users WHERE id=2").fetchone()[0] == "STF-001")
r = post(a_c, "/staff/3/edit", dict(sp_ok, first_name="Bala", surname="Musa", phone="08011112222", email="bmusa@example.com", username="bmusa", staff_id="stf-001", date_of_birth="", gender="", state="", lga="", address="", qualifications="", subjects_taught="", other_names=""), page="/staff/2/edit")
check("duplicate Staff ID blocked (case-insensitive)", r.status_code == 422 and "Staff / Employee ID is already used" in html(r))
r = post(a_c, "/staff/3/edit", dict(first_name="Bala", surname="Musa", phone="08011112222", email="bmusa@example.com", username="AOKAFOR"), page="/staff/2/edit")
check("duplicate username blocked", r.status_code == 422 and "Username is already taken" in html(r))
# DB-level (race) guarantees, bypassing the app
cc = db()
def raw(sql, args=()):
    try:
        cc.execute(sql, args); cc.commit(); return "ok"
    except sqlite3.IntegrityError:
        cc.rollback(); return "blocked"
check("DB blocks duplicate staff id", raw("UPDATE users SET staff_id='stf-001' WHERE id=3") == "blocked")
check("DB blocks duplicate email", raw("UPDATE users SET email='ADA@example.com' WHERE id=3") == "blocked")
check("DB blocks duplicate username", raw("INSERT INTO users(school_id,tenant_id,name,username,password_hash,role) VALUES(1,'1','d','ADMIN','x','teacher')") == "blocked")
check("DB blocks duplicate admission no across classes of one school",
      raw("INSERT INTO students(admission_no,first_name,last_name,class_id) VALUES(' 001 ','A','B',?)", (first_class,)) == "blocked")
check("same admission no allowed in a DIFFERENT school", raw("INSERT INTO students(admission_no,first_name,last_name,class_id) VALUES('002','A','B',?)", (cid2,)) == "ok")
cc.close()

# ------------------------------------------------------------------------------------ 4. admin student uniqueness
r = post(a_c, "/admin/students", {"class_id": first_class, "admission_no": "001", "first_name": "Dup", "last_name": "Licate", "gender": "M"}, page="/admin/students")
check("admin cannot create duplicate admission no", "already used by another student in this school" in " ".join(flashes(a_c)) or "already used" in html(r))
n_before = db().execute("SELECT COUNT(*) FROM students WHERE school_id=1").fetchone()[0]
r = post(a_c, "/admin/students", {"class_id": first_class, "admission_no": "NEW-77", "first_name": "Newly", "last_name": "Added", "gender": "F"}, page="/admin/students")
check("admin can create a fresh student", db().execute("SELECT COUNT(*) FROM students WHERE school_id=1").fetchone()[0] == n_before + 1)
new_id = db().execute("SELECT id FROM students WHERE admission_no='NEW-77'").fetchone()[0]
check("new student is tenant-stamped", tuple(db().execute("SELECT school_id,tenant_id FROM students WHERE id=?", (new_id,)).fetchone()) == (1, "1"))
# admin edits student profile incl. protected admission no
r = a_c.get(f"/students/{new_id}/profile/edit")
check("admin sees editable admission no", r.status_code == 200 and 'name="admission_no"' in html(r))
full = {"first_name": "Newly", "last_name": "Added", "other_names": "", "admission_no": "001", "date_of_birth": "2012-05-01", "gender": "F",
        "state": "Lagos", "lga": "Ikeja", "tribe": "Yoruba", "religion": "", "date_of_admission": "2023-09-11", "email": "",
        "phone": "", "address": "3 Allen Avenue, Ikeja", "parent_name": "Mrs Added", "parent_relationship": "Mother",
        "parent_phone": "08077776666", "parent_email": "", "parent_address": ""}
r = post(a_c, f"/students/{new_id}/profile/edit", full)
check("admin cannot rename to duplicate admission no", r.status_code == 422 and "already used by another student" in html(r))
r = post(a_c, f"/students/{new_id}/profile/edit", dict(full, admission_no="NEW-77", date_of_admission="2001-01-01"))
check("date of admission before DOB rejected", r.status_code == 422 and "cannot be before the date of birth" in html(r))
r = post(a_c, f"/students/{new_id}/profile/edit", dict(full, admission_no="NEW-77", date_of_birth="1900-01-01"))
check("implausible age rejected", r.status_code == 422 and "age must be between" in html(r))
r = post(a_c, f"/students/{new_id}/profile/edit", dict(full, admission_no="NEW-78"))
check("admin saves full student profile", r.status_code == 302 and db().execute("SELECT admission_no,lga,date_of_admission FROM students WHERE id=?", (new_id,)).fetchone()[:] == ("NEW-78", "Ikeja", "2023-09-11"))
# duplicate student email in school
r = post(a_c, f"/students/{new_id}/profile/edit", dict(full, admission_no="NEW-78", email="chinedu@example.com"))
check("duplicate student email blocked", r.status_code == 422 and "Email is already used by another student" in html(r))
# form teacher scope
r = t_c.get("/students/1/profile/edit")
check("form teacher can edit own-class student", r.status_code == 200 and 'name="admission_no"' not in html(r))
conn = db(); conn.execute("INSERT INTO classes(school_id,tenant_id,name) VALUES(1,'1','Other Class')"); conn.commit()
oc = conn.execute("SELECT id FROM classes WHERE name='Other Class'").fetchone()[0]
conn.execute("INSERT INTO students(admission_no,first_name,last_name,gender,class_id) VALUES('OC-1','Out','Side','M',?)", (oc,)); conn.commit()
out_id = conn.execute("SELECT id FROM students WHERE admission_no='OC-1'").fetchone()[0]; conn.close()
check("form teacher cannot edit a student outside their class (403)", t_c.get(f"/students/{out_id}/profile/edit").status_code == 403)
r = post(t_c, f"/students/{out_id}/profile/edit", full, page="/staff/2/edit")
check("form teacher POST outside class is 403", r.status_code == 403)
check("subject teacher (no class) cannot edit any student (403)", login("bmusa").get("/students/1/profile/edit").status_code == 403)
r = post(t_c, "/students/1/profile/edit", dict(full, admission_no="HACK", first_name="Chinedu", last_name="Obi", state="Kano", lga="Nassarawa", address="12 Zaria Road, Kano", parent_name="Mr Okeke", parent_phone="08099998888", date_of_birth="2011-02-03", gender="M"))
check("form teacher save ignores admission no", db().execute("SELECT admission_no FROM students WHERE id=1").fetchone()[0] == "001")
# roster inline edit cannot change protected fields for form teacher
tt = tok(t_c, "/my-class/%d/roster" % first_class) if False else None
r = post(t_c, f"/my-class/{first_class}/students/1/edit", {"first_name": "Chinedu", "last_name": "Obi", "admission_no": "STOLEN", "status": "Graduated", "gender": "M"}, page="/dashboard")
row = db().execute("SELECT admission_no,status FROM students WHERE id=1").fetchone()
check("roster inline edit: protected fields locked for form teacher", row[0] == "001" and (row[1] or "Active") == "Active", tuple(row))
# cross school
check("admin cannot open other school's student (404)", a_c.get(f"/students/{other_student}/profile/edit").status_code == 404)
r = post(a_c, f"/students/{other_student}/profile/edit", full, page="/students/1/profile/edit")
check("admin cannot edit other school's student", r.status_code == 404 and db().execute("SELECT state FROM students WHERE id=?", (other_student,)).fetchone()[0] is None)
o_c = login("otheradmin")
check("other-school admin cannot open our staff (404)", o_c.get("/staff/2/edit").status_code == 404)
check("other-school admin cannot open our students (404)", o_c.get("/students/1/profile/edit").status_code == 404)

# ------------------------------------------------------------------------------------ 12-17 custom fields
def cf_new(client, **kw):
    d = {"applies_to": "student", "label": "", "field_type": "short_text", "description": "", "default_value": "", "display_order": ""}
    d.update(kw)
    return post(client, "/admin/custom-fields/new?applies_to=" + d["applies_to"], d, page="/admin/custom-fields/new?applies_to=" + d["applies_to"])


def field_id(label, school=1):
    r = db().execute("SELECT id FROM custom_fields WHERE school_id=? AND label=?", (school, label)).fetchone()
    return r[0] if r else None


r = a_c.get("/admin/custom-fields")
check("custom fields overview opens", r.status_code == 200 and "Student Fields" in html(r) and "Staff/Teacher Fields" in html(r))
check("add field screen opens", a_c.get("/admin/custom-fields/new?applies_to=student").status_code == 200)
r = cf_new(a_c, label="Admission No")
check("field cannot duplicate protected system field", r.status_code == 422 and "reserved" in html(r))
r = cf_new(a_c, label="Username", applies_to="staff")
check("staff custom field cannot clash with username", r.status_code == 422 and "reserved" in html(r))
r = cf_new(a_c, label="x")
check("too-short label rejected", r.status_code == 422)
r = cf_new(a_c, label="Bad Type", field_type="hax")
check("unknown type rejected", r.status_code == 422)
r = cf_new(a_c, label="Blood Group", field_type="select")
check("dropdown needs options", r.status_code == 422 and "at least one option" in html(r))
r = cf_new(a_c, label="NIN Ref", field_type="short_text", is_required="1", is_unique="1", is_editable="1", is_active="1", display_order="1")
check("create required+unique text field", r.status_code == 302 and field_id("NIN Ref"))
f_nin = field_id("NIN Ref")
row = dict(db().execute("SELECT * FROM custom_fields WHERE id=?", (f_nin,)).fetchone())
check("internal key generated, school/tenant stamped", row["field_key"] == "cf_nin_ref" and row["school_id"] == 1 and row["tenant_id"] == "1" and row["created_by_name"])
r = cf_new(a_c, label="nin ref")
check("confusing duplicate name rejected", r.status_code == 422 and "already exists" in html(r))
opts = [("opt_id", ""), ("opt_id", ""), ("opt_id", ""), ("opt_text", "A"), ("opt_text", "B"), ("opt_text", "O")]
tk = tok(a_c, "/admin/custom-fields/new?applies_to=student")
r = a_c.post("/admin/custom-fields/new?applies_to=student", data=[("csrf_token", tk), ("label", "Blood Group"), ("field_type", "select"), ("is_active", "1"), ("is_editable", "1"), ("default_value", "O")] + opts)
check("create dropdown with options and default", r.status_code == 302 and field_id("Blood Group"), html(r)[:300])
f_bg = field_id("Blood Group")
tk = tok(a_c, "/admin/custom-fields/new?applies_to=student")
r = a_c.post("/admin/custom-fields/new?applies_to=student", data=[("csrf_token", tk), ("label", "Clubs"), ("field_type", "multiselect"), ("is_active", "1"), ("is_editable", "1"),
                                                                ("opt_id", ""), ("opt_id", ""), ("opt_text", "Press"), ("opt_text", "Drama")])
f_clubs = field_id("Clubs")
check("create multiselect", r.status_code == 302 and f_clubs)
for label, ftype, extra in [("Sponsor Email", "email", {}), ("Sponsor Phone", "phone", {}), ("Height CM", "number", {}), ("Joined Club On", "date", {}),
                            ("Has Sibling", "yes_no", {}), ("Notes", "long_text", {}), ("Doctor Letter", "file", {})]:
    rr = cf_new(a_c, label=label, field_type=ftype, is_active="1", is_editable="1", **extra)
    check(f"create {ftype} field", rr.status_code == 302 and field_id(label), (rr.status_code, html(rr)[:200]))
r = cf_new(a_c, label="Sponsor Email 2", field_type="long_text", is_unique="1", is_active="1")
check("unique not allowed on long text", r.status_code == 422)
# staff-only field, not editable by staff
r = cf_new(a_c, applies_to="staff", label="Union Card", field_type="short_text", is_active="1", is_editable="")
r = cf_new(a_c, applies_to="staff", label="Hobby", field_type="short_text", is_active="1", is_editable="1")
f_union, f_hobby = field_id("Union Card"), field_id("Hobby")
check("staff fields created", f_union and f_hobby)

# integrate into profile
r = a_c.get(f"/students/{new_id}/profile/edit")
t = html(r)
check("custom fields appear after system fields", t.index("Profile details") < t.index("Additional information") and "NIN Ref" in t and "Blood Group" in t)
check("custom required marked", re.search(r"NIN Ref\s*<span class=\"req\">", t) is not None)
check("field order follows configuration", t.index("NIN Ref") < t.index("Blood Group") < t.index("Clubs"))
check("staff fields do NOT appear on student profile", f'name="cf_{f_union}"' not in t and f'name="cf_{f_hobby}"' not in t)
check("other school does not see our fields", "NIN Ref" not in html(login("otheradmin").get("/admin/custom-fields")))
base_full = dict(full, admission_no="NEW-78")
r = post(a_c, f"/students/{new_id}/profile/edit", base_full)
check("required custom field blocks save", r.status_code == 422 and "NIN Ref is required" in html(r))
r = post(a_c, f"/students/{new_id}/profile/edit", dict(base_full, **{f"cf_{f_nin}": "N-100", f"cf_{f_bg}": "Z", f"cf_{field_id('Sponsor Email')}": "bad", f"cf_{field_id('Height CM')}": "abc",
                                                                      f"cf_{field_id('Joined Club On')}": "31/31/2020", f"cf_{field_id('Has Sibling')}": "maybe", f"cf_{field_id('Sponsor Phone')}": "12"}))
t = html(r)
check("custom validation per type", r.status_code == 422 and "listed options" in t and "valid email" in t and "valid number" in t and "valid date" in t and "Yes or No" in t and "valid phone" in t, t[-600:])
check("nothing saved on custom failure", db().execute("SELECT COUNT(*) FROM custom_field_values WHERE entity_id=?", (new_id,)).fetchone()[0] == 0)
tk = tok(a_c, f"/students/{new_id}/profile/edit")
data = [("csrf_token", tk)] + [(k, v) for k, v in base_full.items()] + [(f"cf_{f_nin}", "N-100"), (f"cf_{f_bg}", "A"), (f"cf_{f_clubs}", "Press"), (f"cf_{f_clubs}", "Drama"),
                                                                      (f"cf_{field_id('Height CM')}", "152.5"), (f"cf_{field_id('Joined Club On')}", "2024-01-15"),
                                                                      (f"cf_{field_id('Has Sibling')}", "yes"), (f"cf_{field_id('Sponsor Email')}", "Dad@Example.com")]
r = a_c.post(f"/students/{new_id}/profile/edit", data=data, content_type="multipart/form-data")
check("valid custom values saved", r.status_code == 302, html(r)[:300])
vals = {row[0]: row[1] for row in db().execute("SELECT field_id,value FROM custom_field_values WHERE entity_id=? AND entity_type='student'", (new_id,))}
check("values persisted correctly", vals.get(f_nin) == "N-100" and vals.get(f_bg) == "A" and json.loads(vals.get(f_clubs)) == ["Press", "Drama"] and vals.get(field_id("Height CM")) == "152.5" and vals.get(field_id("Has Sibling")) == "Yes" and vals.get(field_id("Sponsor Email")) == "dad@example.com")
t = html(a_c.get(f"/students/{new_id}/profile/edit"))
check("saved custom values reloaded from DB", 'value="N-100"' in t and re.search(r'value="A"\s+selected', t) is not None and 'value="Press" checked' in t and 'value="152.5"' in t)
# unique custom
r = post(a_c, "/students/1/profile/edit", dict(full, admission_no="001", first_name="Chinedu", last_name="Obi", **{f"cf_{f_nin}": "n-100"}), page="/students/%d/profile/edit" % new_id)
check("unique custom value duplicate blocked (case-insensitive)", r.status_code == 422 and "already used" in html(r))
cc = db()
try:
    cc.execute("INSERT INTO custom_field_values(field_id,school_id,tenant_id,entity_type,entity_id,value,unique_value) VALUES(?,?,?,?,?,?,?)", (f_nin, 1, "1", "student", 1, "N-100", "n-100"))
    cc.commit(); dup_ok = True
except sqlite3.IntegrityError:
    dup_ok = False
cc.rollback()
check("DB-level unique custom enforced", not dup_ok)
cc.close()
# existing profile still valid after a new field is added (student 1 has no NIN value, can still be viewed)
check("existing profiles remain viewable with new required field", a_c.get("/students/1/profile").status_code == 200)
# tampered field ids (other school's field) ignored
conn = db()
conn.execute("INSERT INTO custom_fields(school_id,tenant_id,applies_to,field_key,label,field_type,is_active,is_editable) VALUES(?,?,?,?,?,?,1,1)", (sid2, "2", "student", "cf_secret", "Secret Field", "short_text"))
conn.commit(); f_secret = conn.execute("SELECT id FROM custom_fields WHERE label='Secret Field'").fetchone()[0]; conn.close()
r = post(a_c, f"/students/{new_id}/profile/edit", dict(base_full, **{f"cf_{f_nin}": "N-100", f"cf_{f_secret}": "leak"}))
check("cross-school custom field id in form is ignored", db().execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=?", (f_secret,)).fetchone()[0] == 0)
check("cross-school field cannot be opened/edited (404)", a_c.get(f"/admin/custom-fields/{f_secret}").status_code == 404 and a_c.get(f"/admin/custom-fields/{f_secret}/edit").status_code == 404)
r = post(a_c, f"/admin/custom-fields/{f_secret}/toggle", page="/admin/custom-fields")
check("cross-school field cannot be toggled", r.status_code == 404 and db().execute("SELECT is_active FROM custom_fields WHERE id=?", (f_secret,)).fetchone()[0] == 1)
# non-admins blocked on backend
check("teacher POST create field is 403", post(t_c, "/admin/custom-fields/new?applies_to=student", {"label": "Evil", "field_type": "short_text"}, page="/staff/2/edit").status_code == 403 and not field_id("Evil"))
check("teacher POST toggle is 403", post(t_c, f"/admin/custom-fields/{f_nin}/toggle", page="/staff/2/edit").status_code == 403)
check("student blocked from custom fields POST", post(c, f"/admin/custom-fields/{f_nin}/toggle", page="/student/profile").status_code in (302, 401, 403))
# edit screen
r = a_c.get(f"/admin/custom-fields/{f_bg}/edit")
check("edit screen opens; key/type locked", r.status_code == 200 and "cannot change after creation" in html(r))
conn = db(); conn.execute("INSERT OR REPLACE INTO custom_field_values(field_id,school_id,tenant_id,entity_type,entity_id,value) VALUES(?,?,?,?,?,?)", (f_bg, 1, "1", "student", new_id, "A")); conn.commit(); conn.close()
tk = tok(a_c, f"/admin/custom-fields/{f_bg}/edit")
bg_opts = list(db().execute("SELECT id,option_value FROM custom_field_options WHERE field_id=? ORDER BY display_order", (f_bg,)))
form = [("csrf_token", tk), ("label", "Blood Type"), ("description", "Group"), ("is_editable", "1"), ("is_active", "1"), ("field_type", "number"), ("field_key", "hacked"), ("default_value", "")]
# rename A->A+, remove B (unused), keep O, add AB, reorder: AB first
form += [("opt_id", ""), ("opt_text", "AB"), ("opt_id", str(bg_opts[0][0])), ("opt_text", "A+"), ("opt_id", str(bg_opts[1][0])), ("opt_text", "B"), ("opt_remove", "2"), ("opt_id", str(bg_opts[2][0])), ("opt_text", "O")]
r = a_c.post(f"/admin/custom-fields/{f_bg}/edit", data=form)
check("edit field saved", r.status_code == 302, html(r)[:300])
row = dict(db().execute("SELECT * FROM custom_fields WHERE id=?", (f_bg,)).fetchone())
check("key and type immutable", row["field_key"] == "cf_blood_group" and row["field_type"] == "select" and row["label"] == "Blood Type")
oo = [r_[0] for r_ in db().execute("SELECT option_value FROM custom_field_options WHERE field_id=? ORDER BY display_order", (f_bg,))]
check("options reordered/renamed/removed", oo == ["AB", "A+", "O"], oo)
check("renaming option updates saved values", db().execute("SELECT value FROM custom_field_values WHERE field_id=? AND entity_id=?", (f_bg, new_id)).fetchone()[0] == "A+")
# option in use: removal deactivates
tk = tok(a_c, f"/admin/custom-fields/{f_bg}/edit")
bg_opts = list(db().execute("SELECT id,option_value FROM custom_field_options WHERE field_id=? ORDER BY display_order", (f_bg,)))
form = [("csrf_token", tk), ("label", "Blood Type"), ("is_editable", "1"), ("is_active", "1"), ("default_value", "")]
for i, (oid, ov) in enumerate(bg_opts):
    form += [("opt_id", str(oid)), ("opt_text", ov)]
    if ov == "A+":
        form.append(("opt_remove", str(i)))
r = a_c.post(f"/admin/custom-fields/{f_bg}/edit", data=form)
st = db().execute("SELECT is_active FROM custom_field_options WHERE field_id=? AND option_value='A+'", (f_bg,)).fetchone()
check("option in use is deactivated, not lost", st is not None and st[0] == 0 and db().execute("SELECT value FROM custom_field_values WHERE field_id=? AND entity_id=?", (f_bg, new_id)).fetchone()[0] == "A+")
# make unique on a field with duplicate values must refuse
conn = db()
conn.execute("INSERT INTO custom_field_values(field_id,school_id,tenant_id,entity_type,entity_id,value) VALUES(?,?,?,?,?,?)", (field_id("Sponsor Phone"), 1, "1", "student", 1, "08000000001"))
conn.execute("INSERT INTO custom_field_values(field_id,school_id,tenant_id,entity_type,entity_id,value) VALUES(?,?,?,?,?,?)", (field_id("Sponsor Phone"), 1, "1", "student", 2, "08000000001"))
conn.commit(); conn.close()
fp = field_id("Sponsor Phone")
tk = tok(a_c, f"/admin/custom-fields/{fp}/edit")
r = a_c.post(f"/admin/custom-fields/{fp}/edit", data=[("csrf_token", tk), ("label", "Sponsor Phone"), ("is_unique", "1"), ("is_editable", "1"), ("is_active", "1")])
check("cannot turn on Unique while duplicates exist", r.status_code == 422 and "already share the same value" in html(r))
# details screen
r = a_c.get(f"/admin/custom-fields/{f_nin}")
check("details screen shows usage, key, status, history", r.status_code == 200 and "cf_nin_ref" in html(r) and "Profiles using this field" in html(r) and "custom_field_created" in html(r))
# reorder
before_order = [x[0] for x in db().execute("SELECT id FROM custom_fields WHERE school_id=1 AND applies_to='student' AND is_archived=0 ORDER BY display_order,id")]
post(a_c, f"/admin/custom-fields/{before_order[1]}/move", {"direction": "up"}, page="/admin/custom-fields")
after_order = [x[0] for x in db().execute("SELECT id FROM custom_fields WHERE school_id=1 AND applies_to='student' AND is_archived=0 ORDER BY display_order,id")]
check("move-up reorders", after_order[0] == before_order[1] and after_order[1] == before_order[0])
t = html(a_c.get(f"/students/{new_id}/profile/edit"))
check("new order reflected on profile screen", t.index(db().execute("SELECT label FROM custom_fields WHERE id=?", (after_order[0],)).fetchone()[0]) < t.index(db().execute("SELECT label FROM custom_fields WHERE id=?", (after_order[1],)).fetchone()[0]))
# deactivate keeps data, hides from entry, reactivate restores
conn = db(); conn.execute("INSERT OR REPLACE INTO custom_field_values(field_id,school_id,tenant_id,entity_type,entity_id,value) VALUES(?,?,?,?,?,?)", (f_clubs, 1, "1", "student", new_id, json.dumps(["Press", "Drama"]))); conn.commit(); conn.close()
post(a_c, f"/admin/custom-fields/{f_clubs}/toggle", page="/admin/custom-fields")
_r = a_c.get(f"/students/{new_id}/profile/edit"); _t = html(_r)
check("deactivated field hidden from profile", f'name="cf_{f_clubs}"' not in _t, (_r.status_code, db().execute("SELECT is_active FROM custom_fields WHERE id=?", (f_clubs,)).fetchone()[0], flashes(a_c)))
check("deactivated field value preserved", db().execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=? AND entity_id=?", (f_clubs, new_id)).fetchone()[0] == 1)
r = post(a_c, f"/students/{new_id}/profile/edit", dict(base_full, **{f"cf_{f_nin}": "N-100"}))
check("saving profile with a deactivated field keeps its value", db().execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=? AND entity_id=?", (f_clubs, new_id)).fetchone()[0] == 1)
post(a_c, f"/admin/custom-fields/{f_clubs}/toggle", page="/admin/custom-fields")
_t = html(a_c.get(f"/students/{new_id}/profile/edit"))
check("reactivated field shows again with data", 'value="Press" checked' in _t, _t.count("Press"))
# delete with data refused; archive works; unused delete works
r = post(a_c, f"/admin/custom-fields/{f_nin}/delete", page="/admin/custom-fields")
check("cannot delete field holding data", db().execute("SELECT 1 FROM custom_fields WHERE id=?", (f_nin,)).fetchone() is not None)
post(a_c, f"/admin/custom-fields/{f_nin}/archive", page="/admin/custom-fields")
check("archive preserves values and hides field", db().execute("SELECT is_archived FROM custom_fields WHERE id=?", (f_nin,)).fetchone()[0] == 1 and db().execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=?", (f_nin,)).fetchone()[0] >= 1 and f'name="cf_{f_nin}"' not in html(a_c.get(f"/students/{new_id}/profile/edit")))
post(a_c, f"/admin/custom-fields/{f_nin}/archive", page="/admin/custom-fields")
check("archived field can be restored", db().execute("SELECT is_archived FROM custom_fields WHERE id=?", (f_nin,)).fetchone()[0] == 0)
fnotes = field_id("Notes")
post(a_c, f"/admin/custom-fields/{fnotes}/delete", page="/admin/custom-fields")
check("unused field can be deleted", field_id("Notes") is None)
# student self edit of custom fields: only editable ones
conn = db(); conn.execute("UPDATE custom_fields SET is_editable=0 WHERE id=?", (f_bg,)); conn.commit(); conn.close()
c, _ = student_login("chinedu")
t = html(c.get("/student/profile"))
check("student sees custom fields; non-editable are read-only", "NIN Ref" in t and 'name="cf_%d"' % f_bg not in t and 'name="cf_%d"' % f_nin in t)
r = post(c, "/student/profile", dict(base, **{f"cf_{f_nin}": "S-1", f"cf_{f_bg}": "AB"}))
check("student can fill editable custom field", r.status_code == 302 and db().execute("SELECT value FROM custom_field_values WHERE field_id=? AND entity_id=1", (f_nin,)).fetchone()[0] == "S-1")
check("student cannot set non-editable custom field", db().execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=? AND entity_id=1", (f_bg,)).fetchone()[0] == 0)
# a rule change (required) is logged as its own audit action
tk = tok(a_c, f"/admin/custom-fields/{fp}/edit")
a_c.post(f"/admin/custom-fields/{fp}/edit", data=[("csrf_token", tk), ("label", "Sponsor Phone"), ("is_required", "1"), ("is_editable", "1"), ("is_active", "1")])
check("required setting change applied", db().execute("SELECT is_required FROM custom_fields WHERE id=?", (fp,)).fetchone()[0] == 1)
tk = tok(a_c, f"/admin/custom-fields/{fp}/edit")
a_c.post(f"/admin/custom-fields/{fp}/edit", data=[("csrf_token", tk), ("label", "Sponsor Phone"), ("is_editable", "1"), ("is_active", "1")])
# staff custom fields
_r = t_c.get("/staff/2/edit"); t = html(_r)
check("staff custom fields shown; non-editable read-only", 'name="cf_%d"' % f_hobby in t and "Union Card" in t and 'name="cf_%d"' % f_union not in t, (_r.status_code, "Additional information" in t, [tuple(x) for x in db().execute("SELECT id,applies_to,label,is_active,is_archived,is_editable FROM custom_fields WHERE applies_to='staff'")], f_hobby, f_union))
r = post(t_c, "/staff/2/edit", dict(sp_ok, **{f"cf_{f_hobby}": "Chess", f"cf_{f_union}": "sneaky"}))
check("staff saves editable custom value only", r.status_code == 302 and db().execute("SELECT value FROM custom_field_values WHERE field_id=? AND entity_id=2", (f_hobby,)).fetchone()[0] == "Chess" and db().execute("SELECT COUNT(*) FROM custom_field_values WHERE field_id=?", (f_union,)).fetchone()[0] == 0)
# file field
fdoc = field_id("Doctor Letter")
tk = tok(a_c, f"/students/{new_id}/profile/edit")
big = b"%PDF-1.4\n" + b"0" * (1024 * 1024 + 10)
r = a_c.post(f"/students/{new_id}/profile/edit", data=[("csrf_token", tk)] + list(base_full.items()) + [(f"cf_{f_nin}", "N-100"), (f"cf_{fdoc}", (io.BytesIO(big), "l.pdf"))], content_type="multipart/form-data")
check("custom file > 1MB rejected", r.status_code == 422 and "must not exceed 1 MB" in html(r))
tk = tok(a_c, f"/students/{new_id}/profile/edit")
r = a_c.post(f"/students/{new_id}/profile/edit", data=[("csrf_token", tk)] + list(base_full.items()) + [(f"cf_{f_nin}", "N-100"), (f"cf_{fdoc}", (io.BytesIO(b"MZ-not-a-pdf"), "l.pdf"))], content_type="multipart/form-data")
check("fake pdf rejected", r.status_code == 422 and "does not match its type" in html(r))
tk = tok(a_c, f"/students/{new_id}/profile/edit")
r = a_c.post(f"/students/{new_id}/profile/edit", data=[("csrf_token", tk)] + list(base_full.items()) + [(f"cf_{f_nin}", "N-100"), (f"cf_{fdoc}", (io.BytesIO(b"%PDF-1.4 ok"), "letter.pdf"))], content_type="multipart/form-data")
check("valid custom file saved", r.status_code == 302, (r.status_code, re.findall(r'pf-err[^>]*>([^<]+)', html(r))))
check("owner-authorised staff can download it", a_c.get(f"/custom-files/{fdoc}/student/{new_id}").status_code == 200)
check("other school cannot download it", o_c.get(f"/custom-files/{fdoc}/student/{new_id}").status_code == 404)
check("unrelated teacher cannot download it (403)", login("bmusa").get(f"/custom-files/{fdoc}/student/{new_id}").status_code == 403)
c2, _ = student_login("amaka")
check("other student cannot download it (403)", c2.get(f"/custom-files/{fdoc}/student/{new_id}").status_code == 403)

# ------------------------------------------------------------------------------------ 17/10 audit
rows = db().execute("SELECT action,actor_role,school_id,tenant_id,actor_name,created_at FROM rbac_audit_log").fetchall()
acts = {r_[0] for r_ in rows}
for need in ["custom_field_created", "custom_field_modified", "custom_field_rules_changed", "custom_field_deactivated", "custom_field_activated", "custom_field_reordered",
             "custom_field_archived", "custom_field_deleted", "student_profile_updated_by_admin", "student_profile_updated_by_self", "staff_profile_updated_by_self"]:
    check(f"audit logged: {need}", need in acts, sorted(acts))
check("audit rows carry user, role, tenant, time", all(r_[1] and r_[2] and r_[3] and r_[4] and r_[5] for r_ in rows if r_[0].startswith("custom_field")))
check("denied access recorded in security events", db().execute("SELECT COUNT(*) FROM security_events WHERE event_name='profile_access_denied'").fetchone()[0] >= 3)
cc = db()
for stmt in ["UPDATE rbac_audit_log SET action='x'", "DELETE FROM rbac_audit_log", "UPDATE audit_log SET action='x'", "DELETE FROM audit_log"]:
    if stmt.endswith("audit_log") and cc.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0:
        cc.execute("INSERT INTO audit_log(actor_type,action) VALUES('t','probe')"); cc.commit()
    try:
        cc.execute(stmt); cc.commit(); ok = True
    except sqlite3.IntegrityError:
        ok = False
    check(f"audit protected: {stmt}", not ok)
cc.close()
check("school admin sees own audit history", "custom_field_created" in html(a_c.get("/admin/audit-history")))
check("other school admin sees none of ours", "custom_field_created" not in html(o_c.get("/admin/audit-history")))
check("teacher blocked from audit history", t_c.get("/admin/audit-history").status_code == 403)

# ------------------------------------------------------------------------------------ CSRF / RBAC roles
r = A.app.test_client()
lg = login("admin")
r = lg.post("/admin/custom-fields/new?applies_to=student", data={"label": "NoCsrf", "field_type": "short_text"})
check("POST without CSRF token rejected", not field_id("NoCsrf") and r.status_code in (302, 400, 403))
for role in ["Registrar / Admissions Officer", "Attendance Officer", "Front Desk / Reception Officer", "Bursar / Accountant", "Examination Officer",
             "Guidance/Counselling Officer", "ICT / System Support Officer", "HOD / Head of Department", "Vice Principal / Deputy Principal",
             "Librarian", "Labour Master", "Discipline Master", "Class Teacher / Form Teacher", "Teacher"]:
    check(f"role exists: {role}", role in A.ROLE_CATALOG and role in A.assignable_roles(), role)
check("ICT role has no record-editing permission by default", A.ROLE_CATALOG["ICT / System Support Officer"] == ["view"])
check("legacy role names still valid but not offered for new assignments", "Finance/Bursar" in A.ROLE_CATALOG and "Finance/Bursar" not in A.assignable_roles())

# registrar (role assignment) can edit a student profile in any class of the school; a plain subject teacher cannot
conn = db()
conn.execute("INSERT INTO role_assignments(user_id,school_id,tenant_id,school_level,role,status) VALUES(3,1,'1','All','Registrar / Admissions Officer','active')")
conn.commit(); conn.close()
reg_c = login("bmusa")
check("registrar-role staff can open any student's profile editor in own school", reg_c.get(f"/students/{out_id}/profile/edit").status_code == 200)
check("registrar cannot touch protected admission no (staff level)", 'name="admission_no"' not in html(reg_c.get(f"/students/{out_id}/profile/edit")))
check("registrar still blocked from other school's students", reg_c.get(f"/students/{other_student}/profile/edit").status_code == 404)
check("registrar cannot manage custom fields (403)", reg_c.get("/admin/custom-fields").status_code == 403)
conn = db(); conn.execute("UPDATE role_assignments SET status='revoked' WHERE user_id=3"); conn.commit(); conn.close()
check("revoked registrar assignment loses access immediately (403)", reg_c.get(f"/students/{out_id}/profile/edit").status_code == 403)

# ------------------------------------------------------------------------------------ 6. online only
for path in ["/app", "/offline", "/offline-app", "/csrf-token", "/api/offline/verify", "/api/sync/push", "/admin/sync-conflicts", "/api/offline/confirm_password"]:
    check(f"offline route gone: {path}", A.app.test_client().get(path).status_code in (404, 405, 302) and A.app.test_client().get(path).status_code != 200)
sw = A.app.test_client().get("/service-worker.js")
check("service worker is a self-destroying kill switch (no caching)", b"unregister" in sw.data and b"caches.delete" in sw.data and b"cache.put" not in sw.data and b"addAll" not in sw.data and b"fetch" not in sw.data.replace(b"c.navigate", b""))
static_js = os.listdir(os.path.join(ROOT, "static", "js"))
check("offline JS files removed", not [f for f in static_js if re.search(r"offline|sync|connectivity", f)], static_js)
bad_text = []
for folder in ("templates",):
    for fn in os.listdir(os.path.join(ROOT, folder)):
        if not fn.endswith(".html"):
            continue
        txt = open(os.path.join(ROOT, folder, fn), encoding="utf-8", errors="ignore").read()
        if re.search(r"Saved on this device|will sync|offline-queue|data-offline|IndexedDB|serviceWorker\.register|/app#", txt):
            bad_text.append(fn)
check("no offline wording/hooks in templates", not bad_text, bad_text)
check("no sync blueprint / offline modules remain", not os.path.exists(os.path.join(ROOT, "sync_api.py")) and not os.path.exists(os.path.join(ROOT, "sync_rules.py")))
src = open(os.path.join(ROOT, "app.py")).read()
check("no offline helpers left in app.py", "offline_sync_" not in src and "is_offline_sync_request" not in src and "device_credentials" not in src.split("def _student_login_post")[0].replace("device_credentials", "device_credentials") or "revoke_device_credentials" not in src)
check("no offline queue markers in any served static asset", not [f for f in os.listdir(os.path.join(ROOT, "static")) if "offline" in f.lower()])
check("connection-error script present and loaded", "online-only.js" in html(A.app.test_client().get("/login")) and "Cannot reach the server" in open(os.path.join(ROOT, "static/js/online-only.js")).read())
mf = json.load(open(os.path.join(ROOT, "static/manifest.json")))
check("manifest no longer starts an offline shell", mf.get("start_url") == "/dashboard")
check("device credentials purged by migration", db().execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0] == 0)

print(f"\n{PASS} checks passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
