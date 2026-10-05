import io
import os
from db import format_dmy
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# Reportlab only ships the base-14 fonts without embedding a font file, so
# "font customization" here means choosing among these three families —
# each has real regular/bold variants reportlab already knows about.
PDF_FONT_CHOICES = {
    "Helvetica": ("Helvetica", "Helvetica-Bold"),
    "Times-Roman": ("Times-Roman", "Times-Bold"),
    "Courier": ("Courier", "Courier-Bold"),
}


def _apply_pdf_font(styles, font_choice):
    """Mutates the base stylesheet in place so every ParagraphStyle built
    from it afterwards (via parent=styles[...]) picks up the school's
    chosen font automatically. Returns (regular, bold) font names, since
    Tables don't inherit from the paragraph stylesheet and need their
    FONTNAME set explicitly wherever one is used below."""
    regular, bold = PDF_FONT_CHOICES.get(font_choice, PDF_FONT_CHOICES["Helvetica"])
    for name in styles.byName:
        style = styles[name]
        is_heading = name.lower().startswith("heading") or name.lower() == "title"
        style.fontName = bold if is_heading else regular
    return regular, bold


def _header_elements(school_name, logo_path, document_title, subtitle_text, styles, accent_color="#1f3a5f", name_align=None, logo_align="center"):
    """Shared letterhead. The LOGO row and the TEXT block are aligned independently: the logo sits on its own row
    (left / center / right) and the school text below it keeps its own alignment, so changing one never moves the other."""
    t_align = {"left": TA_LEFT, "right": TA_RIGHT}.get(name_align, TA_CENTER)
    school_style = ParagraphStyle("school", parent=styles["Heading1"], alignment=t_align, fontSize=17, leading=21)
    title_style = ParagraphStyle("title", parent=styles["Heading2"], alignment=t_align, textColor=colors.HexColor(accent_color))
    sub_style = ParagraphStyle("sub", parent=styles["Normal"], alignment=t_align)

    elements = []

    if logo_path and os.path.exists(logo_path):
        try:
            from PIL import Image as PILImage
            with PILImage.open(logo_path) as im:
                w, h = im.size
            target_h = 2.3 * cm
            target_w = min(target_h * (w / h), 4.6 * cm)
            target_h = target_w * (h / w)            # keep the aspect ratio when the width was capped
            img = Image(logo_path, width=target_w, height=target_h)
            img.hAlign = {"left": "LEFT", "right": "RIGHT"}.get(logo_align, "CENTER")
            elements.append(img)
            elements.append(Spacer(1, 0.2 * cm))
        except Exception:
            pass

    if school_name:
        elements.append(Paragraph(school_name, school_style))

    elements.append(Paragraph(document_title, title_style))
    elements.append(Paragraph(subtitle_text, sub_style))
    elements.append(Spacer(1, 0.5 * cm))
    return elements


def build_broadsheet_pdf(class_row, term, subjects, rows, school_name=None, logo_path=None, student_full_name=None, font_choice="Helvetica", accent_color="#1f3a5f", logo_align="center", name_align=None):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), topMargin=1 * cm, bottomMargin=1 * cm)
    styles = getSampleStyleSheet()
    regular, bold = _apply_pdf_font(styles, font_choice)

    elements = _header_elements(
        school_name, logo_path, "BROADSHEET",
        f"{class_row['name']}" + (f" ({class_row['category']})" if class_row['category'] else "") +
        f" &mdash; {term['session_name']} &mdash; {term['name']}",
        styles, accent_color=accent_color, name_align=name_align, logo_align=logo_align,
    )

    header = ["S/N", "Student Name"] + [s["name"] for s in subjects] + ["Total", "Average", "Position"]
    data = [header]
    for i, r in enumerate(rows, start=1):
        name = student_full_name(r["student"]) if student_full_name else f"{r['student']['last_name']} {r['student']['first_name']}"
        row = [str(i), name]
        for subj in subjects:
            row.append(str(r["scores"][subj["id"]]["total"]))
        row.append(str(r["total"]))
        row.append(str(r["average"]))
        row.append(str(r["position"]))
        data.append(row)

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(accent_color)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), regular),
        ("FONTNAME", (0, 0), (-1, 0), bold),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    elements.append(table)
    doc.build(elements)
    buf.seek(0)
    return buf


def _default_display():
    import result_display as RD
    return {f[1]: bool(f[4]) for f in RD.FIELDS}


def _sig_image(sig, fallback_text, normal, cm_h=1.1 * cm):
    """Signature picture (aspect ratio kept) or a blank signing line."""
    if sig and sig.get("path") and os.path.exists(sig["path"]):
        try:
            from PIL import Image as PILImage
            with PILImage.open(sig["path"]) as im:
                im.load(); w, h = im.size
            return Image(sig["path"], width=cm_h * (w / h), height=cm_h)
        except Exception:
            pass
    return Paragraph(fallback_text, normal)


def _result_elements(data, term, school_name, logo_path, student_full_name, styles, accent_color="#1f3a5f",
                      name_align=None, teacher_signature=None, principal_signature=None):
    """Flowables for one student's terminal result (single-student PDF and whole-class PDF).

    Every on/off decision comes from data["rs"]["d"] -- the same School Setup -> Result Display Settings
    that drive the on-screen sheet and the print page -- so the three outputs always agree."""
    section_style = ParagraphStyle("section", parent=styles["Heading3"])
    regular = styles["Normal"].fontName
    bold = styles["Heading1"].fontName

    student = data["student"]
    class_row = data["class_row"]
    name = student_full_name(student) if student_full_name else f"{student['last_name']} {student['first_name']}"

    rs = data.get("rs") or {}
    d = {**_default_display(), **(rs.get("d") or {})}
    if "d" in rs:
        logo_path = rs.get("logo_path")          # None when "Show School Logo" is off or no logo was uploaded
    accent_color = rs.get("accent") or accent_color
    template = rs.get("template", "classic")
    compact = template == "compact"
    sub_bits = []
    if d["session"]:
        sub_bits.append(str(term["session_name"]))
    if d["term"]:
        sub_bits.append(str(term["name"]))
    elements = _header_elements(
        school_name, logo_path, (rs.get("title") or "Terminal Report Sheet").upper(),
        " &mdash; ".join(sub_bits), styles, accent_color=accent_color,
        name_align=rs.get("text_align") or name_align, logo_align=rs.get("logo_align", "center"),
    )
    _ta = {"left": TA_LEFT, "right": TA_RIGHT}.get(rs.get("text_align") or name_align, TA_CENTER)
    _esc_h = lambda v: str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    _small = ParagraphStyle("contactLine", parent=styles["Normal"], alignment=_ta, fontSize=9, leading=11.5, textColor=colors.HexColor("#444444"))
    if d["contact"] and rs.get("contact"):
        elements.append(Paragraph(_esc_h(rs["contact"]), _small))
    for f_ in rs.get("info_fields") or []:
        elements.append(Paragraph(f"<b>{_esc_h(f_['label'])}:</b> {_esc_h(f_['value'])}", _small))
    if data.get("result_date"):
        elements.append(Paragraph(f"Date: {data['result_date']}", _small))
    if (d["contact"] and rs.get("contact")) or rs.get("info_fields") or data.get("result_date"):
        elements.append(Spacer(1, 0.25 * cm))

    cells = [("Name:", name)]
    if d["admission_no"]:
        cells.append(("Adm./Reg. No.:", student["admission_no"]))
    if d["class"]:
        cells.append(("Class / Arm:", class_row["name"]))
    if d["session"] or d["term"]:
        cells.append(("Session / Term:" if d["session"] and d["term"] else ("Session:" if d["session"] else "Term:"),
                      " / ".join(sub_bits)))
    if d["score"]:
        cells += [("Total Score:", str(data["total"])), ("Average:", str(data["average"]))]
    cells.append(("No. of Subjects:", f"{data.get('subjects_written', '-')} of {len(data['subjects'])}"))
    if d["overall_position"]:
        cells.append(("Overall Position:", f"{data.get('position_text', data['position'])} of {data['class_size']}"))
    for cf in data.get("custom_fields") or []:
        cells.append((f"{cf['label']}:", cf["value"]))
    info_rows = []
    for k in range(0, len(cells), 2):
        pair = cells[k:k + 2]
        row = []
        for lab, val in pair:
            row += [lab, val]
        while len(row) < 4:
            row.append("")
        info_rows.append(row)
    info_table = Table(info_rows, colWidths=[3 * cm, 5 * cm, 3.5 * cm, 5.5 * cm])
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, -1), regular),
        ("FONTNAME", (0, 0), (0, -1), bold),
        ("FONTNAME", (2, 0), (2, -1), bold),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    passport_path = rs.get("passport_path") if d["passport"] else None
    if d["passport"]:
        # Passport area is reserved whenever the setting is ON. With a photo it is filled; with none it stays
        # blank -- never an avatar, initial, silhouette or placeholder.
        pp = ""
        if passport_path and os.path.exists(passport_path):
            try:
                from PIL import Image as PILImage
                with PILImage.open(passport_path) as im:
                    im.load(); w, h = im.size
                box_w, box_h = 2.4 * cm, 3 * cm
                r = min(box_w / w, box_h / h)
                pp = Image(passport_path, width=w * r, height=h * r)
            except Exception:
                pp = ""
        wrapper = Table([[info_table, pp]], colWidths=[17 * cm, 2.6 * cm])
        wrapper.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        elements.append(wrapper)
    else:
        elements.append(info_table)
    elements.append(Spacer(1, 0.4 * cm if compact else 0.5 * cm))

    elements.append(Paragraph("Academic Performance", section_style))
    show_ca3 = bool(data.get("show_ca3")) and d["score"]
    show_subj_pos = d["subject_position"]
    with_remark = d["remarks"] and not compact
    header = ["Subject"]
    if d["score"]:
        header += ["CA1", "CA2"] + (["CA3"] if show_ca3 else []) + ["Exam", "Total"]
    if d["grade"]:
        header.append("Grade")
    if show_subj_pos:
        header.append("Position")
    if with_remark:
        header.append("Remark")
    subj_data = [header]
    for s_ in data["subjects"]:
        row = [s_["name"]]
        if d["score"]:
            row += [str(s_["ca1"]), str(s_["ca2"])] + ([str(s_.get("ca3", "-"))] if show_ca3 else []) + [str(s_["exam"]), str(s_["total"])]
        if d["grade"]:
            row.append(str(s_["grade"]))
        if show_subj_pos:
            row.append(str(s_.get("position_text", "-")))
        if with_remark:
            row.append(str(s_["remark"]))
        subj_data.append(row)
    n_num = len(header) - 1 - (1 if with_remark else 0)
    name_w = 4.6 * cm
    rem_w = 2.8 * cm if with_remark else 0
    num_w = max(1.2 * cm, (18.4 * cm - name_w - rem_w) / max(1, n_num)) if n_num else 0
    subj_col_widths = [name_w] + [num_w] * n_num + ([rem_w] if with_remark else [])
    if not n_num and not with_remark:
        subj_col_widths = [name_w]
    subj_table = Table(subj_data, repeatRows=1, colWidths=subj_col_widths)
    subj_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(accent_color)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), regular),
        ("FONTNAME", (0, 0), (-1, 0), bold),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    elements.append(subj_table)
    elements.append(Spacer(1, 0.5 * cm))

    groups = data.get("domain_groups")
    if groups is None and data.get("ratings"):
        groups = [{"label": "Psychomotor / Affective Skills", "items": [(r["name"], r["rating"]) for r in data["ratings"]]}]
    if groups:
        elements.append(Paragraph("Educational Domains (rated 1-5)", section_style))
        for g in groups:
            skill_data = [[g["label"], "Rating"]] + [[n, str(v)] for n, v in g["items"]]
            skill_table = Table(skill_data, colWidths=[12 * cm, 3 * cm], repeatRows=1)
            skill_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(accent_color)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), regular),
                ("FONTNAME", (0, 0), (-1, 0), bold),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5 if compact else 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ]))
            elements.append(skill_table)
            elements.append(Spacer(1, 0.25 * cm))
        elements.append(Spacer(1, 0.25 * cm))

    info = data["info"]
    att = data.get("attendance") or {}
    promo = data.get("promotion_status")
    show_promo = bool(d["promotion"] and promo)
    att_cols = []
    if d["attendance"]:
        if d["days_opened"]:
            att_cols.append(("Days School Opened", att.get("opened")))
        if d["days_present"]:
            att_cols.append(("Days Present", att.get("present")))
        if d["days_absent"]:
            att_cols.append(("Days Absent", att.get("absent")))
    if show_promo:
        att_cols.append(("Promotion / Status", promo))
    if att_cols:
        if d["attendance"] and any(c[0].startswith("Days") for c in att_cols):
            elements.append(Paragraph("Attendance", section_style))
        att_table = Table([[c[0] for c in att_cols], [("-" if c[1] is None else str(c[1])) for c in att_cols]])
        att_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, -1), regular),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        elements.append(att_table)
        elements.append(Spacer(1, 0.5 * cm))

    normal = styles["Normal"]

    def _esc(t):
        return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    if d["teacher_comment"]:
        tc = _esc(info["teacher_comment"]) if info and info["teacher_comment"] else "_" * 70
        elements.append(Paragraph(f"<b>Class/Form Teacher's Comment:</b> {tc}", normal))
        elements.append(Spacer(1, 0.3 * cm))
    if d["teacher_name"] or d["teacher_signature"] or d["teacher_sign_date"]:
        teacher_date = format_dmy(info["teacher_signed_date"]) if info and info["teacher_signed_date"] else "________________"
        if data.get("teacher_name") and d["teacher_name"]:
            elements.append(Paragraph(f"<b>Class/Form Teacher:</b> {_esc(data['teacher_name'])}", normal))
        if d["teacher_signature"]:
            elements.append(_sig_image(teacher_signature, "Teacher's Signature: ________________________________", normal))
        if d["teacher_sign_date"]:
            elements.append(Paragraph(f"Date: {teacher_date}", normal))
        elements.append(Spacer(1, 0.5 * cm))

    if d["principal_comment"]:
        pc_ = _esc(info["principal_comment"]) if info and info["principal_comment"] else "_" * 70
        elements.append(Paragraph(f"<b>Principal's Comment:</b> {pc_}", normal))
        elements.append(Spacer(1, 0.3 * cm))
    if d["principal_name"] or d["principal_signature"] or d["principal_sign_date"]:
        principal_date = format_dmy(info["principal_signed_date"]) if info and info["principal_signed_date"] else "________________"
        if data.get("principal_name") and d["principal_name"]:
            elements.append(Paragraph(f"<b>Principal:</b> {_esc(data['principal_name'])}", normal))
        if d["principal_signature"]:
            elements.append(_sig_image(principal_signature, "Principal's Signature: ________________________________", normal))
        if d["principal_sign_date"]:
            elements.append(Paragraph(f"Date: {principal_date}", normal))

    small = ParagraphStyle("rsSmall", parent=normal, fontSize=7.5, textColor=colors.HexColor("#444444"))
    scale = rs.get("grading_scale") or []
    if scale and (d["grading_key"] or template == "detailed"):
        elements.append(Spacer(1, 0.3 * cm))
        key = "; ".join(f"{g['grade']} = {g['min_score']:g}-{g['max_score']:g} ({g['remark']})" for g in scale)
        elements.append(Paragraph(f"<b>Grading key:</b> {key}", small))
    if rs.get("footer"):      # the school's own footer text only -- no automatic "Issued <date>"
        elements.append(Spacer(1, 0.2 * cm))
        elements.append(Paragraph(rs["footer"].replace("&", "&amp;"), small))

    return elements


def _one_page(doc, elements):
    """Shrink a result's flowables so the whole sheet fits on a single A4 page."""
    from reportlab.platypus import KeepInFrame
    return [KeepInFrame(doc.width, doc.height, list(elements), mode="shrink")]


def build_result_pdf(data, term, school_name=None, logo_path=None, student_full_name=None, font_choice="Helvetica",
                      accent_color="#1f3a5f", name_align=None, teacher_signature=None, principal_signature=None):
    if teacher_signature is None and data.get("teacher_signature_path"):
        teacher_signature = {"path": data.get("teacher_signature_path"), "name": data.get("teacher_name")}
    if principal_signature is None and data.get("principal_signature_path"):
        principal_signature = {"path": data.get("principal_signature_path"), "name": data.get("principal_name")}
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.2 * cm, bottomMargin=1.2 * cm, leftMargin=1.2 * cm, rightMargin=1.2 * cm)
    styles = getSampleStyleSheet()
    _apply_pdf_font(styles, font_choice)
    elements = _result_elements(data, term, school_name, logo_path, student_full_name, styles,
                                 accent_color=accent_color, name_align=name_align,
                                 teacher_signature=teacher_signature, principal_signature=principal_signature)
    doc.build(_one_page(doc, elements))
    buf.seek(0)
    return buf


def build_class_results_pdf(data_list, term, school_name=None, logo_path=None, student_full_name=None, font_choice="Helvetica",
                             accent_color="#1f3a5f", name_align=None):
    """One combined, printable PDF containing every student's terminal
    result in a class, each starting on its own page."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.2 * cm, bottomMargin=1.2 * cm, leftMargin=1.2 * cm, rightMargin=1.2 * cm)
    styles = getSampleStyleSheet()
    _apply_pdf_font(styles, font_choice)
    elements = []
    for i, data in enumerate(data_list):
        if i > 0:
            elements.append(PageBreak())
        elements.extend(_one_page(doc, _result_elements(data, term, school_name, logo_path, student_full_name, styles,
                                                        accent_color=accent_color, name_align=name_align)))
    doc.build(elements)
    buf.seek(0)
    return buf


def build_cumulative_result_pdf(data, session, school_name=None, logo_path=None, student_full_name=None, font_choice="Helvetica",
                                 accent_color="#1f3a5f", name_align=None):
    """Annual/Cumulative Result: one column per term plus a cumulative
    average/grade per subject, for the whole session rather than one term."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.2 * cm, bottomMargin=1.2 * cm)
    styles = getSampleStyleSheet()
    regular, bold = _apply_pdf_font(styles, font_choice)
    section_style = ParagraphStyle("section", parent=styles["Heading3"], textColor=colors.HexColor(accent_color))

    elements = _header_elements(
        school_name, logo_path, "ANNUAL / CUMULATIVE RESULT", session["name"], styles,
        accent_color=accent_color, name_align=name_align,
    )

    student = data["student"]
    class_row = data["class_row"]
    name = student_full_name(student) if student_full_name else f"{student['last_name']} {student['first_name']}"

    info_table = Table([
        ["Name:", name, "Adm./Reg. No.:", student["admission_no"]],
        ["Class / Arm:", class_row["name"], "Category:" if class_row["category"] else "", class_row["category"] or ""],
        ["Cumulative Average:", str(data["average"]), "Grade:", str(data["grade"])],
        ["Position:", f"{data['position']} of {data['class_size']}", "", ""],
    ], colWidths=[3.5 * cm, 5 * cm, 3.5 * cm, 5 * cm])
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, -1), regular),
        ("FONTNAME", (0, 0), (0, -1), bold),
        ("FONTNAME", (2, 0), (2, -1), bold),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 0.5 * cm))

    elements.append(Paragraph("Academic Performance Across the Session", section_style))
    term_names = [t["name"] for t in data["terms"]]
    subj_header = ["Subject"] + term_names + ["Cumulative Avg", "Grade"]
    subj_data = [subj_header]
    for s in data["subjects"]:
        row = [s["name"]]
        for v in s["term_values"]:
            row.append(str(v) if v is not None else "-")
        row.append(str(s["average"]))
        row.append(str(s["grade"]))
        subj_data.append(row)
    col_widths = [5 * cm] + [2.2 * cm] * len(term_names) + [2.8 * cm, 2 * cm]
    subj_table = Table(subj_data, repeatRows=1, colWidths=col_widths)
    subj_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(accent_color)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), regular),
        ("FONTNAME", (0, 0), (-1, 0), bold),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    elements.append(subj_table)
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph(
        "Cumulative Average is the mean of the totals from every term above that has a score "
        "recorded for that subject.", styles["Normal"],
    ))

    doc.build(elements)
    buf.seek(0)
    return buf


def build_generic_table_pdf(title, subtitle, headers, rows, school_name=None, logo_path=None, font_choice="Helvetica",
                             accent_color="#1f3a5f"):
    """A plain landscape table report (headers + rows) with the school's
    letterhead — used for reports that aren't a results document, like the
    Staff Attendance export."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), topMargin=1 * cm, bottomMargin=1 * cm)
    styles = getSampleStyleSheet()
    regular, bold = _apply_pdf_font(styles, font_choice)
    elements = _header_elements(school_name, logo_path, title, subtitle, styles, accent_color=accent_color)

    data = [headers] + [[str(c) for c in row] for row in rows]
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(accent_color)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), regular),
        ("FONTNAME", (0, 0), (-1, 0), bold),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    elements.append(table)
    doc.build(elements)
    buf.seek(0)
    return buf
