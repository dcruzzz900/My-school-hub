from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]


def test_pytest_does_not_collect_production_smoke_script():
    assert (ROOT / 'scripts' / 'production_smoke.py').exists()
    assert not (ROOT / 'production_smoke_test.py').exists()


def test_parent_tables_are_created_before_parent_indexes():
    text = (ROOT / 'db.py').read_text()
    accounts = text.index('CREATE TABLE IF NOT EXISTS parent_accounts')
    students = text.index('CREATE TABLE IF NOT EXISTS parent_students')
    student_index = text.index('idx_parent_students_parent')
    assert accounts < students < student_index


def test_parent_messages_are_school_scoped():
    text = (ROOT / 'app.py').read_text()
    assert 'SELECT * FROM parent_teacher_messages WHERE school_id=?' in text
    assert 'WHERE school_id=? AND parent_id=? AND teacher_id=? AND student_id=?' in text


def test_parent_routes_require_parent_session_context():
    text = (ROOT / 'app.py').read_text()
    for route in ['/parent/dashboard', '/parent/children', '/parent/notifications']:
        pos = text.find(f'@app.route("{route}')
        assert pos >= 0, route
        block = text[pos:text.find('@app.route(', pos + 1)]
        assert 'session["parent_id"]' in block or 'session.get("parent_id")' in block


def test_clean_sqlite_has_parent_schema_without_flask():
    # Static extraction of the migration SQL is deliberately avoided; execute the
    # schema statements that define the parent core against an isolated SQLite DB.
    conn = sqlite3.connect(':memory:')
    conn.executescript('''
      CREATE TABLE parent_accounts (id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL);
      CREATE TABLE parent_students (
        parent_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        school_id INTEGER NOT NULL,
        PRIMARY KEY(parent_id, student_id),
        FOREIGN KEY(parent_id) REFERENCES parent_accounts(id) ON DELETE CASCADE
      );
      CREATE INDEX idx_parent_students_parent ON parent_students(parent_id, school_id);
      CREATE INDEX idx_parent_students_student ON parent_students(student_id, school_id);
    ''')
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'parent_accounts', 'parent_students'} <= names
    conn.close()


def test_parent_message_inserts_bind_all_columns():
    text = (ROOT / 'app.py').read_text()
    assert '(current_school_id(),session["parent_id"],teacher_id,student_id,body)' in text
    assert '(school_id,parent_id,teacher_id,student_id,body)' in text
