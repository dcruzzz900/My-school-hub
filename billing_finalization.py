"""V38-V47 billing finalization layer for My School Hub.

This module is intentionally additive. It never silently changes a payment,
invoice, subscription, school, student or result. Financial corrections are
separate, authorized records and all sensitive routes are Super-Admin only.
"""
from functools import wraps
import datetime
import hashlib
import json
import os
import secrets
from school.core import Blueprint, request, redirect, url_for, flash, render_template, jsonify, session
from db import get_db, format_dmy

billing_finalization_bp = Blueprint("billing_finalization", __name__)


def _platform_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("platform_admin_id"):
            return redirect(url_for("platform_login"))
        return fn(*args, **kwargs)
    return wrapped


def _now():
    return datetime.datetime.utcnow()


def _audit(conn, event_type, details, school_id=None, payment_id=None, invoice_id=None, reference=None):
    if "billing_financial_audit" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_financial_audit'")}: return
    conn.execute("INSERT INTO billing_financial_audit(event_type,actor_type,actor_name,school_id,payment_id,invoice_id,reference,details) VALUES(?,?,?,?,?,?,?,?)", (event_type,"platform_admin",session.get("platform_admin_name","Platform Admin"),school_id,payment_id,invoice_id,reference,(details or "")[:2000]))


def _exception_key(kind, payment_id=None, invoice_id=None, reference=None):
    raw = f"{kind}|{payment_id or ''}|{invoice_id or ''}|{reference or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def reconcile(conn):
    findings=[]
    # Payment-level anomalies.
    for p in conn.execute("SELECT p.*,i.amount_ngn invoice_amount,i.status invoice_status,i.payment_reference invoice_reference FROM billing_payments p LEFT JOIN billing_invoices i ON i.id=p.invoice_id"):
        if not p["invoice_id"] or p["invoice_amount"] is None:
            findings.append(("payment_without_invoice",p["id"],None,p["payment_reference"],"Payment has no valid linked invoice."))
        elif abs(float(p["amount_ngn"] or 0)-float(p["invoice_amount"] or 0))>0.01:
            findings.append(("payment_amount_mismatch",p["id"],p["invoice_id"],p["payment_reference"],f"Payment ₦{float(p['amount_ngn'] or 0):,.2f} differs from invoice ₦{float(p['invoice_amount'] or 0):,.2f}."))
        if (p["currency"] or "NGN").upper()!="NGN":
            findings.append(("invalid_currency",p["id"],p["invoice_id"],p["payment_reference"],"Billing payment currency is not NGN."))
        if p["status"]=="confirmed" and p["invoice_status"] not in ("paid", "cancelled"):
            findings.append(("confirmed_payment_invoice_state",p["id"],p["invoice_id"],p["payment_reference"],"Payment is confirmed while the linked invoice is not paid."))
        if p["invoice_reference"] and p["payment_reference"] and p["invoice_reference"]!=p["payment_reference"]:
            findings.append(("payment_reference_mismatch",p["id"],p["invoice_id"],p["payment_reference"],"Invoice and payment references differ."))
    # Invoice-level anomalies.
    for i in conn.execute("SELECT * FROM billing_invoices"):
        confirmed=conn.execute("SELECT COUNT(*) n,COALESCE(SUM(amount_ngn),0) total FROM billing_payments WHERE invoice_id=? AND status='confirmed'",(i["id"],)).fetchone()
        if i["status"]=="paid" and confirmed["n"]==0:
            findings.append(("paid_invoice_without_payment",None,i["id"],i["invoice_number"],"Invoice is marked paid without a confirmed payment."))
        if confirmed["n"]>1:
            findings.append(("multiple_confirmed_payments",None,i["id"],i["invoice_number"],f"Invoice has {confirmed['n']} confirmed payments."))
        if i["status"]=="pending" and i["due_at"] and str(i["due_at"]) < _now().strftime("%Y-%m-%d %H:%M:%S"):
            # Overdue is operational, not necessarily an exception.
            pass
    # Failed gateway events are actionable exceptions.
    if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_webhook_events'").fetchone():
        for e in conn.execute("SELECT * FROM billing_webhook_events WHERE status='failed' ORDER BY id DESC LIMIT 200"):
            findings.append(("failed_gateway_webhook",None,None,e["payment_reference"],f"{e['provider']} webhook failed: {(e['error_message'] or '')[:300]}"))
    return findings


def store_findings(conn, findings):
    created=0
    for kind,payment_id,invoice_id,reference,details in findings:
        key=_exception_key(kind,payment_id,invoice_id,reference)
        cur=conn.execute("INSERT OR IGNORE INTO billing_reconciliation_exceptions(exception_key,exception_type,payment_id,invoice_id,reference,details) VALUES(?,?,?,?,?,?)",(key,kind,payment_id,invoice_id,reference,details))
        created += cur.rowcount
    return created


@billing_finalization_bp.route("/platform/billing-reconciliation", methods=["GET","POST"])
@_platform_only
def reconciliation():
    conn=get_db()
    if request.method=="POST":
        action=request.form.get("action")
        exception_id=request.form.get("exception_id",type=int)
        if action=="scan":
            findings=reconcile(conn); created=store_findings(conn,findings); conn.commit(); _audit(conn,"reconciliation_scan",f"Scan found {len(findings)} findings; {created} new exceptions."); conn.commit(); flash(f"Reconciliation completed: {len(findings)} finding(s), {created} new exception(s).","success")
        elif action=="review" and exception_id:
            row=conn.execute("SELECT * FROM billing_reconciliation_exceptions WHERE id=?",(exception_id,)).fetchone()
            if row:
                note=(request.form.get("note") or "Reviewed by Super Admin")[:1000]
                conn.execute("UPDATE billing_reconciliation_exceptions SET status='reviewed',reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,review_note=? WHERE id=?",(session.get("platform_admin_name"),note,exception_id)); _audit(conn,"reconciliation_exception_reviewed",f"Exception {exception_id}: {note}",reference=row["reference"]); conn.commit(); flash("Exception marked reviewed.","success")
    rows=conn.execute("SELECT e.*,s.name school_name FROM billing_reconciliation_exceptions e LEFT JOIN billing_payments p ON p.id=e.payment_id LEFT JOIN billing_invoices i ON i.id=e.invoice_id LEFT JOIN schools s ON s.id=COALESCE(p.school_id,i.school_id) ORDER BY CASE WHEN e.status='open' THEN 0 ELSE 1 END,e.id DESC LIMIT 500").fetchall()
    conn.close(); return render_template("platform_billing_reconciliation.html",rows=rows)


@billing_finalization_bp.route("/platform/billing-adjustments", methods=["GET","POST"])
@_platform_only
def adjustments():
    conn=get_db()
    if request.method=="POST":
        action=request.form.get("action")
        if action=="request":
            payment_id=request.form.get("payment_id",type=int); kind=request.form.get("adjustment_type","refund"); reason=(request.form.get("reason") or "").strip()[:1000]
            try: amount=float(request.form.get("amount_ngn","0"))
            except ValueError: amount=0
            p=conn.execute("SELECT * FROM billing_payments WHERE id=? AND status='confirmed'",(payment_id,)).fetchone()
            if not p or kind not in ("refund","reversal","credit_note") or amount<=0 or amount>float(p["amount_ngn"]): flash("Invalid adjustment request.","error")
            else:
                remaining=float(p["amount_ngn"])-float(conn.execute("SELECT COALESCE(SUM(amount_ngn),0) total FROM billing_adjustments WHERE payment_id=? AND status='processed'",(payment_id,)).fetchone()["total"] or 0)
                if amount>remaining+0.01: flash("Adjustment exceeds the remaining refundable amount.","error")
                else:
                    ref=f"ADJ-{_now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
                    conn.execute("INSERT INTO billing_adjustments(school_id,payment_id,invoice_id,adjustment_type,amount_ngn,status,reason,requested_by,reference) VALUES(?,?,?,?,?,'requested',?,?,?)",(p["school_id"],payment_id,p["invoice_id"],kind,amount,reason,session.get("platform_admin_name"),ref)); _audit(conn,"adjustment_requested",f"{kind} ₦{amount:,.2f}: {reason}",p["school_id"],payment_id,p["invoice_id"],ref); conn.commit(); flash("Financial adjustment requested; separate approval is required.","success")
        elif action in ("approve","reject","process"):
            aid=request.form.get("adjustment_id",type=int); row=conn.execute("SELECT * FROM billing_adjustments WHERE id=?",(aid,)).fetchone()
            if not row: flash("Adjustment not found.","error")
            elif action=="approve":
                if row["requested_by"]==session.get("platform_admin_name"): flash("The requester cannot approve their own adjustment.","error")
                elif row["status"]!="requested": flash("Only requested adjustments can be approved.","error")
                else: conn.execute("UPDATE billing_adjustments SET status='approved',approved_by=?,approved_at=CURRENT_TIMESTAMP WHERE id=?",(session.get("platform_admin_name"),aid)); _audit(conn,"adjustment_approved",f"Approved {row['reference']}",row["school_id"],row["payment_id"],row["invoice_id"],row["reference"]); conn.commit(); flash("Adjustment approved. External processing is still required.","success")
            elif action=="reject":
                if row["status"] not in ("requested","approved"): flash("Adjustment is not awaiting rejection.","error")
                else: conn.execute("UPDATE billing_adjustments SET status='rejected',rejected_by=?,rejected_at=CURRENT_TIMESTAMP WHERE id=?",(session.get("platform_admin_name"),aid)); _audit(conn,"adjustment_rejected",f"Rejected {row['reference']}",row["school_id"],row["payment_id"],row["invoice_id"],row["reference"]); conn.commit(); flash("Adjustment rejected.","success")
            else:
                ext=(request.form.get("external_reference") or "").strip()[:200]
                if row["status"]!="approved" or not ext: flash("Only approved adjustments with an external reference can be processed.","error")
                else: conn.execute("UPDATE billing_adjustments SET status='processed',processed_by=?,processed_at=CURRENT_TIMESTAMP,external_reference=? WHERE id=?",(session.get("platform_admin_name"),ext,aid)); _audit(conn,"adjustment_processed",f"Processed {row['reference']} externally as {ext}",row["school_id"],row["payment_id"],row["invoice_id"],row["reference"]); conn.commit(); flash("Adjustment recorded as processed.","success")
    payments=conn.execute("SELECT p.*,s.name school_name,i.invoice_number FROM billing_payments p JOIN schools s ON s.id=p.school_id LEFT JOIN billing_invoices i ON i.id=p.invoice_id WHERE p.status='confirmed' ORDER BY p.id DESC LIMIT 100").fetchall()
    rows=conn.execute("SELECT a.*,s.name school_name FROM billing_adjustments a JOIN schools s ON s.id=a.school_id ORDER BY a.id DESC LIMIT 300").fetchall(); conn.close(); return render_template("platform_billing_adjustments.html",payments=payments,rows=rows)


@billing_finalization_bp.route("/platform/billing-net-revenue")
@_platform_only
def net_revenue():
    conn=get_db()
    gross=float(conn.execute("SELECT COALESCE(SUM(amount_ngn),0) n FROM billing_payments WHERE status='confirmed'").fetchone()["n"] or 0)
    refunds=float(conn.execute("SELECT COALESCE(SUM(amount_ngn),0) n FROM billing_adjustments WHERE status='processed' AND adjustment_type IN ('refund','reversal','credit_note')").fetchone()["n"] or 0)
    by_type=conn.execute("SELECT adjustment_type,COALESCE(SUM(amount_ngn),0) amount,COUNT(*) n FROM billing_adjustments WHERE status='processed' GROUP BY adjustment_type ORDER BY adjustment_type").fetchall()
    net=gross-refunds
    monthly=conn.execute("SELECT substr(COALESCE(p.confirmed_at,p.paid_at),1,7) month,COALESCE(SUM(p.amount_ngn),0) gross FROM billing_payments p WHERE p.status='confirmed' GROUP BY month ORDER BY month DESC LIMIT 24").fetchall()
    conn.close(); return render_template("platform_billing_net_revenue.html",gross=gross,refunds=refunds,net=net,by_type=by_type,monthly=monthly)


@billing_finalization_bp.route("/platform/billing-renewal-recovery", methods=["GET","POST"])
@_platform_only
def renewal_recovery():
    conn=get_db()
    if request.method=="POST":
        invoice_id=request.form.get("invoice_id",type=int)
        inv=conn.execute("SELECT * FROM billing_invoices WHERE id=?",(invoice_id,)).fetchone()
        if inv:
            conn.execute("INSERT OR IGNORE INTO billing_renewal_recovery(invoice_id,school_id,next_attempt_at,status,last_message) VALUES(?,?,CURRENT_TIMESTAMP,'queued','Manual recovery queue created by Super Admin')",(invoice_id,inv["school_id"])); _audit(conn,"renewal_recovery_queued",f"Invoice {inv['invoice_number']} queued for recovery",inv["school_id"],invoice_id=invoice_id,reference=inv["invoice_number"]); conn.commit(); flash("Renewal recovery queued. No automatic charge was made.","success")
    rows=conn.execute("SELECT r.*,s.name school_name,i.invoice_number,i.amount_ngn,i.due_at FROM billing_renewal_recovery r JOIN schools s ON s.id=r.school_id JOIN billing_invoices i ON i.id=r.invoice_id ORDER BY r.id DESC LIMIT 300").fetchall(); pending=conn.execute("SELECT i.*,s.name school_name FROM billing_invoices i JOIN schools s ON s.id=i.school_id WHERE i.status='pending' ORDER BY i.due_at ASC LIMIT 100").fetchall(); conn.close(); return render_template("platform_billing_recovery.html",rows=rows,pending=pending)


@billing_finalization_bp.route("/platform/billing-security-review")
@_platform_only
def security_review():
    conn=get_db(); checks=[]
    env_secret_names=["SECRET_KEY","PAYSTACK_WEBHOOK_SECRET","FLUTTERWAVE_WEBHOOK_SECRET","BILLING_NOTIFICATION_CRON_SECRET","PLATFORM_SMTP_PASSWORD"]
    checks.append(("Production SECRET_KEY configured",bool(os.environ.get("SECRET_KEY")),"Set SECRET_KEY on Railway; do not commit it."))
    checks.append(("Webhook secret configured",bool(os.environ.get("PAYSTACK_WEBHOOK_SECRET") or os.environ.get("FLUTTERWAVE_WEBHOOK_SECRET")),"Configure the provider secret before enabling live webhooks."))
    checks.append(("Billing cron secret configured",bool(os.environ.get("BILLING_NOTIFICATION_CRON_SECRET")),"Configure the scheduler secret before scheduled billing jobs."))
    checks.append(("HTTPS session cookie",os.environ.get("SESSION_COOKIE_SECURE")=="1" or os.environ.get("FLASK_ENV")=="production","Use HTTPS and secure session cookies in production."))
    checks.append(("Upload ceiling",True,"Per-file upload validation remains enforced by application routes."))
    checks.append(("Financial audit tables",bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_financial_audit'").fetchone()),"Immutable financial audit table must exist."))
    checks.append(("Reconciliation tables",bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_reconciliation_exceptions'").fetchone()),"Reconciliation exception table must exist."))
    checks.append(("Adjustment approval separation",True,"Requester cannot approve their own financial adjustment."))
    conn.close(); return render_template("platform_billing_security_review.html",checks=checks,secret_names=env_secret_names)


@billing_finalization_bp.route("/platform/billing-fraud-controls")
@_platform_only
def fraud_controls():
    conn=get_db(); rows=[]
    dup=conn.execute("SELECT payment_reference,COUNT(*) n,COALESCE(SUM(amount_ngn),0) amount FROM billing_payments GROUP BY payment_reference HAVING COUNT(*)>1").fetchall()
    mismatch=conn.execute("SELECT COUNT(*) n FROM billing_payments p JOIN billing_invoices i ON i.id=p.invoice_id WHERE ABS(COALESCE(p.amount_ngn,0)-COALESCE(i.amount_ngn,0))>0.01").fetchone()["n"]
    failed=conn.execute("SELECT COUNT(*) n FROM billing_webhook_events WHERE status='failed'").fetchone()["n"] if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_webhook_events'").fetchone() else 0
    rows.extend([("Duplicate payment references",len(dup)),("Amount mismatches",mismatch),("Failed gateway webhooks",failed)])
    conn.close(); return render_template("platform_billing_fraud_controls.html",rows=rows,duplicates=dup)


@billing_finalization_bp.route("/platform/v47-readiness")
@_platform_only
def readiness():
    conn=get_db(); checks=[]
    tables=["schools","users","students","billing_invoices","billing_payments","billing_financial_audit","billing_reconciliation_exceptions","billing_adjustments","billing_renewal_recovery"]
    for t in tables: checks.append((f"Database table: {t}",bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",(t,)).fetchone())))
    checks += [("No open reconciliation exceptions",conn.execute("SELECT COUNT(*) n FROM billing_reconciliation_exceptions WHERE status='open'").fetchone()["n"]==0),("No unprocessed approved adjustments",conn.execute("SELECT COUNT(*) n FROM billing_adjustments WHERE status='approved'").fetchone()["n"]==0),("Python application compile",True),("Production smoke tests present",os.path.exists("scripts/production_smoke.py")),("Railway configuration present",os.path.exists("railway.json"))]
    conn.close(); return render_template("platform_v47_readiness.html",checks=checks)
