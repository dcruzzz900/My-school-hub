from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text()
DB = (ROOT / 'db.py').read_text()
ATT = (ROOT / 'templates/staff_attendance.html').read_text()
AN = (ROOT / 'templates/reports_analytics.html').read_text()


def test_student_online_save_is_tenant_stamped_and_safe():
    assert 'INSERT INTO students (school_id,tenant_id' in APP
    assert 'School tenant information is incomplete' in APP
    assert 'Student could not be saved because the submitted data could not be processed.' in APP


def test_staff_attendance_has_check_times_and_filters():
    assert 'check_in_at' in DB and 'check_out_at' in DB
    assert 'name="check_in_' not in ATT and 'name="check_out_' not in ATT   # V63: times are stamped by the server, never typed
    assert 'name="q"' in ATT and 'name="status"' in ATT


def test_assign_subjects_online_route_and_duplicate_protection():
    assert '/academics/assign-subjects' in APP
    assert 'UNIQUE(class_id, subject_id)' in (ROOT / 'schema.sql').read_text()
    assert 'already assigned to this class/arm' in APP


def test_class_form_teacher_is_single_canonical_role():
    assert '"Class Teacher / Form Teacher"' in APP
    assert 'Class Teacher / Form Teacher" in roles' in APP   # V63: checked against the whole role set
    assert 'UPDATE role_assignments SET role=\'Class Teacher / Form Teacher\'' in DB


def test_staff_self_profile_and_password_routes():
    assert '/staff/<int:user_id>/edit' in (ROOT / 'profile_routes.py').read_text()
    assert '/account/password' in APP
    assert 'school_id=? AND tenant_id=?' in APP


def test_reports_analytics_has_required_chart_types_and_filters():
    charts_src = (ROOT / 'charts.py').read_text()
    page = (ROOT / 'templates' / 'reports_analytics.html').read_text()
    assert 'def bar_chart' in charts_src and 'def line_chart' in charts_src and 'def donut_chart' in charts_src
    for needle in ('charts.gender', 'charts.enrol', 'charts.subject', 'charts.class', 'charts.grades', 'charts.passfail',
                   'charts.trend', 'charts.attendance', 'charts.staff_att', 'charts.completion', 'charts.published', 'name="term_id"', 'name="class_id"', 'name="subject_id"'):
        assert needle in page, needle
