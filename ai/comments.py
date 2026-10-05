"""Safe draft comments. They are always returned as drafts for human review."""
def teacher_comment(name, analysis, attendance=None):
    avg=analysis["average"]
    strength=", ".join(analysis["strengths"]) or "the assessed subjects"
    weak=", ".join(analysis["weaknesses"])
    if avg>=70: lead="has demonstrated excellent academic performance"
    elif avg>=60: lead="has demonstrated good and consistent academic performance"
    elif avg>=50: lead="has made satisfactory progress"
    elif avg>=40: lead="has shown some progress but needs greater consistency"
    else: lead="needs significant academic support and consistent study"
    text=f"{name} {lead}. Stronger performance is evident in {strength}."
    if weak: text += f" Further attention is recommended in {weak}."
    if attendance is not None: text += f" Attendance for the term is {attendance:.0f}%."
    return text

def principal_comment(name, analysis, attendance=None):
    avg=analysis["average"]
    trend=analysis.get("trend")
    if trend=="Improving": opening="has shown encouraging improvement this term"
    elif trend=="Declining": opening="has experienced a decline in performance this term and would benefit from targeted support"
    else: opening="has maintained a generally stable academic profile this term"
    text=f"{name} {opening}. The overall average is {avg:.1f}%"
    if attendance is not None: text += f", with attendance of {attendance:.0f}%"
    text += ". Continued effort, regular attendance and focused revision are encouraged."
    return text
