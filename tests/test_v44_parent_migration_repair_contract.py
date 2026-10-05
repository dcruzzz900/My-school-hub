from pathlib import Path


def test_parent_migration_repairs_missing_tables_even_when_step_is_recorded():
    text = Path("db.py").read_text()
    assert 'name == "parent_portal"' in text
    assert 'not table_exists(conn, "parent_students")' in text
    assert 'INSERT OR IGNORE INTO schema_steps' in text


def test_parent_portal_migration_is_idempotent():
    text = Path("db.py").read_text()
    assert "CREATE TABLE IF NOT EXISTS parent_accounts" in text
    assert "CREATE TABLE IF NOT EXISTS parent_students" in text
    assert "CREATE TABLE IF NOT EXISTS parent_teacher_messages" in text
    assert "CREATE TABLE IF NOT EXISTS parent_consent_events" in text
