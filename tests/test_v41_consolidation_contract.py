from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text()
DB = (ROOT / 'db.py').read_text()
BASE = (ROOT / 'templates' / 'base.html').read_text()


def test_parent_portal_contract_present():
    for marker in (
        'parent_login_required', 'parent_dashboard', 'parent_children_page',
        'parent_result', 'parent_attendance', 'parent_timetable',
        'parent_notifications', 'parent_message_thread',
        'teacher_parent_messages', 'teacher_parent_thread',
        'admin_parent_create', 'admin_parent_reset', 'admin_parent_toggle',
    ):
        assert marker in APP
    for table in ('parent_accounts', 'parent_students', 'parent_teacher_messages', 'parent_consent_events'):
        assert f'CREATE TABLE IF NOT EXISTS {table}' in DB


def test_parent_navigation_and_tenant_boundary():
    assert 'session.get(\'parent_id\')' in BASE
    assert 'parent_children(conn,session["parent_id"])' in APP
    assert 'ps.school_id=?' in APP
    assert 'school_id=current_school_id()' in APP


def test_parent_messages_are_role_scoped():
    assert 'target_role,title,message' in APP
    assert '"parent","Teacher replied"' in APP
    assert '"teacher","New parent message"' in APP


def test_core_files_compile():
    import py_compile
    for path in [ROOT / 'app.py', ROOT / 'db.py']:
        py_compile.compile(str(path), doraise=True)
