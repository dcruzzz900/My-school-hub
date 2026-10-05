from pathlib import Path
import py_compile

ROOT=Path(__file__).resolve().parents[1]

def test_finalization_module_and_migration_present():
    assert (ROOT/'billing_finalization.py').exists()
    db=(ROOT/'db.py').read_text()
    assert 'migration_053_billing_finalization' in db
    for table in ('billing_reconciliation_exceptions','billing_adjustments','billing_renewal_recovery'):
        assert f'CREATE TABLE IF NOT EXISTS {table}' in db

def test_financial_adjustments_require_separation_and_external_reference():
    text=(ROOT/'billing_finalization.py').read_text()
    assert 'requester cannot approve their own' in text.lower()
    assert 'status=\'processed\'' in text
    assert 'external_reference' in text

def test_reconciliation_is_detect_and_review_not_auto_fix():
    text=(ROOT/'billing_finalization.py').read_text()
    assert 'store_findings' in text
    assert 'exception_type' in text
    assert 'status=\'reviewed\'' in text
    assert 'UPDATE billing_payments' not in text
    assert 'UPDATE billing_invoices' not in text

def test_final_readiness_and_security_routes_exist():
    text=(ROOT/'billing_finalization.py').read_text()
    for marker in ('/platform/billing-security-review','/platform/billing-fraud-controls','/platform/v47-readiness'):
        assert marker in text

def test_core_finalization_python_compiles():
    for name in ('app.py','db.py','billing_finalization.py'):
        py_compile.compile(str(ROOT/name), doraise=True)
