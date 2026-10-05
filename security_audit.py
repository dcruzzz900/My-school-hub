"""Read-only security and tenant-isolation audit for the school platform.

The audit deliberately reports metadata/counts only. It never returns student
names, scores, passwords, device secrets, SMTP credentials, or other school
content to the platform administrator.
"""
from collections import Counter


def _tables(conn):
    return [r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()]


def _cols(conn, table):
    return {r["name"] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()}


def run_security_audit(conn):
    findings = []

    def add(code, severity, message, count=0):
        findings.append({"code": code, "severity": severity, "message": message, "count": int(count or 0)})

    schools = conn.execute("SELECT id, tenant_id, school_code FROM schools").fetchall()
    tenant_counts = Counter((r["tenant_id"] or "").strip() for r in schools)
    missing = sum(1 for r in schools if not (r["tenant_id"] or "").strip())
    duplicate = sum(n - 1 for k, n in tenant_counts.items() if k and n > 1)
    add("TENANT_MISSING", "CRITICAL", "School records without a permanent Tenant ID.", missing)
    add("TENANT_DUPLICATE", "CRITICAL", "Duplicate Tenant IDs detected.", duplicate)

    # Any table with a school_id must point to an existing school.
    for table in _tables(conn):
        cols = _cols(conn, table)
        if "school_id" not in cols or table == "schools":
            continue
        try:
            n = conn.execute(
                f'SELECT COUNT(*) c FROM "{table}" t LEFT JOIN schools s ON s.id=t.school_id WHERE t.school_id IS NOT NULL AND s.id IS NULL'
            ).fetchone()["c"]
        except Exception:
            n = 0
        if n:
            add("ORPHAN_SCHOOL_REF", "HIGH", f"{table} contains records referencing a non-existent school.", n)

    # Tenant-bearing records must agree with their school.
    for table in _tables(conn):
        cols = _cols(conn, table)
        if "tenant_id" not in cols or table == "schools":
            continue
        try:
            n = conn.execute(
                f'''SELECT COUNT(*) c FROM "{table}" t JOIN schools s ON s.id=t.school_id
                    WHERE COALESCE(t.tenant_id,'') != COALESCE(s.tenant_id,'')'''
            ).fetchone()["c"] if "school_id" in cols else 0
        except Exception:
            n = 0
        if n:
            add("TENANT_MISMATCH", "CRITICAL", f"{table} contains Tenant IDs inconsistent with its school.", n)

    # Cross-school relationship checks. These are especially important because
    # a numeric foreign key alone must never be enough to cross a tenant.
    checks = [
        ("CLASS_SUBJECT_SCHOOL_MISMATCH", "class_subjects", """
            SELECT COUNT(*) c FROM class_subjects cs
            JOIN classes c ON c.id=cs.class_id
            JOIN subjects s ON s.id=cs.subject_id
            WHERE c.school_id != s.school_id""", "class-subject assignments link different schools."),
        ("CLASS_SUBJECT_TEACHER_MISMATCH", "class_subjects", """
            SELECT COUNT(*) c FROM class_subjects cs
            JOIN classes c ON c.id=cs.class_id
            JOIN users u ON u.id=cs.teacher_id
            WHERE cs.teacher_id IS NOT NULL AND c.school_id != u.school_id""", "class-subject assignments link a teacher from another school."),
        ("STUDENT_CLASS_MISMATCH", "students", """
            SELECT COUNT(*) c FROM students st JOIN classes c ON c.id=st.class_id
            WHERE 'school_id' IN (SELECT name FROM pragma_table_info('students'))
              AND st.school_id != c.school_id""", "student school and class school disagree."),
        ("SCORE_STUDENT_SUBJECT_MISMATCH", "scores", """
            SELECT COUNT(*) c FROM scores sc
            JOIN students st ON st.id=sc.student_id
            JOIN classes c ON c.id=st.class_id
            JOIN subjects sub ON sub.id=sc.subject_id
            WHERE c.school_id != sub.school_id""", "scores link a student/class to a subject from another school."),
        ("SCORE_TERM_MISMATCH", "scores", """
            SELECT COUNT(*) c FROM scores sc
            JOIN students st ON st.id=sc.student_id
            JOIN classes c ON c.id=st.class_id
            JOIN terms t ON t.id=sc.term_id
            JOIN sessions se ON se.id=t.session_id
            WHERE c.school_id != se.school_id""", "scores link a student/class to a term from another school."),
        ("ATTENDANCE_STUDENT_CLASS_MISMATCH", "attendance_records", """
            SELECT COUNT(*) c FROM attendance_records ar
            JOIN students st ON st.id=ar.student_id
            JOIN classes c ON c.id=ar.class_id
            WHERE st.class_id != ar.class_id OR c.school_id != (SELECT c2.school_id FROM classes c2 WHERE c2.id=st.class_id)""", "attendance links a student to a different class/school."),
        ("ROLE_ASSIGNMENT_TENANT_MISMATCH", "role_assignments", """
            SELECT COUNT(*) c FROM role_assignments ra JOIN schools s ON s.id=ra.school_id
            WHERE COALESCE(ra.tenant_id,'') != COALESCE(s.tenant_id,'')""", "role assignments have a Tenant ID inconsistent with their school."),
        ("DEVICE_TENANT_MISMATCH", "device_credentials", """
            SELECT COUNT(*) c FROM device_credentials d JOIN schools s ON s.id=d.school_id
            WHERE COALESCE(d.tenant_id,'') != COALESCE(s.tenant_id,'')""", "offline device credentials have a Tenant ID inconsistent with their school."),
    ]
    for code, table, sql, msg in checks:
        if table not in _tables(conn):
            continue
        try:
            n = conn.execute(sql).fetchone()["c"]
        except Exception:
            n = 0
        if n:
            add(code, "CRITICAL", msg, n)

    # Informational coverage metrics.
    add("SCHOOL_COUNT", "INFO", "Schools currently represented in the platform.", len(schools))
    for table in ("role_assignments", "device_credentials"):
        if table in _tables(conn):
            n = conn.execute(f'SELECT COUNT(*) c FROM "{table}"').fetchone()["c"]
            add(table.upper() + "_COUNT", "INFO", f"{table.replace('_',' ').title()} records.", n)

    critical = sum(f["count"] for f in findings if f["severity"] == "CRITICAL")
    high = sum(f["count"] for f in findings if f["severity"] == "HIGH")
    status = "PASS" if critical == 0 and high == 0 else "ATTENTION_REQUIRED"
    return {"status": status, "critical_count": critical, "high_count": high, "findings": findings}
