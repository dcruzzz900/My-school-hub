"""Deterministic, explainable result analysis used when no external model is configured."""

def analyze_student(rows):
    if not rows:
        return {"average":0,"strengths":[],"weaknesses":[],"trend":"No scores","subjects":[]}
    subjects=[]
    for r in rows:
        total=(r["ca1"] or 0)+(r["ca2"] or 0)+(r["exam"] or 0)
        subjects.append({"name":r["subject_name"],"score":round(total,1)})
    avg=round(sum(x["score"] for x in subjects)/len(subjects),1)
    strengths=[x["name"] for x in sorted(subjects,key=lambda x:x["score"],reverse=True)[:3] if x["score"]>=60]
    weaknesses=[x["name"] for x in sorted(subjects,key=lambda x:x["score"])[:3] if x["score"]<50]
    return {"average":avg,"strengths":strengths,"weaknesses":weaknesses,"trend":"Current term","subjects":subjects}


def compare(current, previous):
    c=analyze_student(current); p=analyze_student(previous)
    delta=round(c["average"]-p["average"],1) if previous else None
    trend="Improving" if delta is not None and delta>=5 else "Declining" if delta is not None and delta<=-5 else "Stable" if delta is not None else "No previous term"
    c["previous_average"]=p["average"] if previous else None; c["delta"]=delta; c["trend"]=trend
    return c
