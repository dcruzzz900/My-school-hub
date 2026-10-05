"""Single source of truth for everything that controls what a result sheet shows.

School Setup -> Result Display Settings is the ONLY place these are edited, and the HTML sheet,
print page and PDF all read them through `display_settings()`. To add a future setting, add one
row to FIELDS (and, if it needs a column, it is created automatically by the migration)."""

# (group, key, label, schools-column, default, help text)
FIELDS = [
    ("Header & identity", "logo", "Show School Logo", "result_show_logo", 1, "The school's own uploaded logo. Blank area if none is uploaded."),
    ("Header & identity", "passport", "Show Student Passport", "result_show_passport", 1, "When on but a student has no passport, the area stays blank (no avatar)."),
    ("Header & identity", "admission_no", "Show Student Admission No. / Register No.", "result_show_admission_no", 1, ""),
    ("Header & identity", "class", "Show Class / Arm", "result_show_class", 1, ""),
    ("Header & identity", "session", "Show Academic Session", "result_show_session", 1, ""),
    ("Header & identity", "term", "Show Term", "result_show_term", 1, ""),
    ("Header & identity", "result_date", "Show Result Date", "show_result_date", 1, "The date saved on each student's result."),
    ("Header & identity", "contact", "Show School Contact Information", "result_show_contact", 1, ""),
    ("Scores", "score", "Show Score / Mark", "result_show_score", 1, "CA, exam and total columns."),
    ("Scores", "grade", "Show Grade", "result_show_grade", 1, ""),
    ("Scores", "remarks", "Show Remarks", "result_show_remarks", 1, ""),
    ("Scores", "grading_key", "Show Grading Key", "result_show_grading_key", 1, ""),
    ("Scores", "promotion", "Show Promotion / Status", "result_show_promotion", 1, ""),
    ("Positions", "overall_position", "Show Overall Position", "show_overall_position", 1, "e.g. 1st, 2nd, 3rd. Positions are always calculated, so you can switch this on later."),
    ("Positions", "subject_position", "Show Subject Position", "show_subject_position", 0, "A Position column beside each subject."),
    ("Attendance", "attendance", "Show Attendance", "result_show_attendance", 1, "Master switch for the attendance block."),
    ("Attendance", "days_opened", "Show Days School Opened", "result_show_days_opened", 1, ""),
    ("Attendance", "days_present", "Show Days Present", "result_show_days_present", 1, ""),
    ("Attendance", "days_absent", "Show Days Absent", "result_show_days_absent", 1, ""),
    ("Comments, signatures & dates", "teacher_comment", "Show Teacher / Class Teacher Comment", "result_show_teacher_comment", 1, ""),
    ("Comments, signatures & dates", "principal_comment", "Show Principal Comment", "result_show_principal_comment", 1, ""),
    ("Comments, signatures & dates", "teacher_name", "Show Teacher Name", "show_form_teacher_name", 1, ""),
    ("Comments, signatures & dates", "teacher_signature", "Show Teacher Signature", "show_form_teacher_signature", 1, ""),
    ("Comments, signatures & dates", "teacher_sign_date", "Show Teacher Sign Date", "result_show_teacher_sign_date", 1, ""),
    ("Comments, signatures & dates", "principal_name", "Show Principal Name", "show_principal_name", 1, ""),
    ("Comments, signatures & dates", "principal_signature", "Show Principal Signature", "show_principal_signature", 1, ""),
    ("Comments, signatures & dates", "principal_sign_date", "Show Principal Sign Date", "result_show_principal_sign_date", 1, ""),
    ("Layout", "watermark", "Show Watermark", "result_show_watermark", 0, ""),
]

TEMPLATES = [
    ("classic", "Professional Classic", "Traditional bordered table with every score column."),
    ("modern", "Modern Academic", "Coloured header band, rounded cards, passport beside the identity panel."),
    ("formal", "Formal School", "Double-ruled, serif, centred letterhead for a ceremonial look."),
    ("compact", "Compact Academic", "Tight rows so a long subject list fits one page."),
    ("detailed", "Detailed Report", "Adds remarks, class statistics and the grading key."),
]
TEMPLATE_KEYS = tuple(t[0] for t in TEMPLATES)

KEYS = [f[1] for f in FIELDS]
COLUMNS = {f[1]: f[3] for f in FIELDS}


def display_settings(school):
    """{key: bool} for one school row (or None). Missing/NULL columns fall back to the default."""
    out = {}
    names = set(school.keys()) if school is not None else set()
    for _g, key, _l, col, default, _h in FIELDS:
        v = school[col] if col in names and school[col] is not None else default
        out[key] = bool(int(v)) if str(v).lstrip("-").isdigit() else bool(v)
    return out


def groups():
    seen, out = [], {}
    for g, key, label, col, default, helptext in FIELDS:
        if g not in out:
            out[g] = []
            seen.append(g)
        out[g].append({"key": key, "label": label, "column": col, "help": helptext})
    return [(g, out[g]) for g in seen]


def form_values(form):
    """Column -> 0/1 from a submitted settings form (an unticked box is simply absent)."""
    return {col: (1 if form.get("d_" + key) else 0) for key, col in COLUMNS.items()}


def migrate(conn, ensure_column):
    for _g, _k, _l, col, default, _h in FIELDS:
        ensure_column(conn, "schools", col, f"INTEGER DEFAULT {int(default)}")
