from pathlib import Path
import ast, re, zipfile

ROOT = Path(__file__).resolve().parents[1]

def test_railway_checklist_and_config_docs_exist():
    assert (ROOT / 'RAILWAY_PRODUCTION_CHECKLIST.md').exists()
    assert (ROOT / 'railway.json').exists()
    assert 'healthcheckPath' in (ROOT / 'railway.json').read_text()

def test_uiux_static_audit_passes():
    tree = ast.parse((ROOT / 'app.py').read_text())
    endpoints = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for _extra in ('profile_routes.py', 'v61_routes.py', 'registrar.py'):
        endpoints |= {n.name for n in ast.walk(ast.parse((ROOT / _extra).read_text())) if isinstance(n, ast.FunctionDef)}
    refs = set()
    for p in (ROOT / 'templates').rglob('*.html'):
        refs.update(re.findall(r"url_for\(\s*['\"]([^'\"]+)", p.read_text(encoding='utf-8')))
    # V38–V47 billing finalization routes live in a registered Flask blueprint.
    blueprint = (ROOT / 'billing_finalization.py').read_text(encoding='utf-8')
    blueprint_endpoints = set(re.findall(r'def ([A-Za-z_][A-Za-z0-9_]*)\(', blueprint))
    refs = {r for r in refs if r not in endpoints and r != 'static' and not (r.startswith('billing_finalization.') and r.split('.',1)[1] in blueprint_endpoints)}
    assert sorted(refs) == []

def test_railway_start_command_is_gunicorn():
    text=(ROOT/'railway.json').read_text()
    assert 'gunicorn app:app' in text

