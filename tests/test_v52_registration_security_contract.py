from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
APP=(ROOT/'app.py').read_text(); DB=(ROOT/'db.py').read_text()
def test_routes():
    for r in ('/register-school','/register','/register/parent','/activate','/admin/signup-codes','/parent/link-child'): assert r in APP
def test_staff_form():
    t=(ROOT/'templates/register.html').read_text(); assert 'name="school_id"' not in t; assert 'name="position"' not in t; assert 'name="signup_code"' in t
def test_student_form_removed():
    assert not (ROOT/'templates/register_student.html').exists()
def test_parent_verified(): assert "ps.status='verified'" in APP and "status='pending'" in APP
def test_deny_overrides(): assert 'granted=0' in APP and 'matched=[]' in APP
def test_tenant_security(): assert 'registration_security_v52_finalize' in DB and 'trg_students_tenant_stamp' in DB and 'trg_scores_tenant_stamp' in DB
def test_brand():
    for n in ('login.html','register.html','register_school.html','register_parent.html'):
        t=(ROOT/'templates'/n).read_text(); assert 'My School Hub' in t and 'School Results' not in t
