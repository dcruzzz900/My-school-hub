#!/usr/bin/env python3
"""Static UI/UX integration audit; does not import Flask or mutate the DB."""
import ast, glob, re, sys

app_path='app.py'
tree=ast.parse(open(app_path,encoding='utf-8').read())
endpoints={n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
for extra in ('profile_routes.py','v61_routes.py','billing_finalization.py'):
    endpoints |= {n.name for n in ast.walk(ast.parse(open(extra,encoding='utf-8').read())) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
refs=set()
for path in glob.glob('templates/**/*.html',recursive=True):
    text=open(path,encoding='utf-8').read()
    refs.update(re.findall(r"url_for\(\s*['\"]([^'\"]+)",text))
missing=sorted(r for r in refs if r.split('.',1)[-1] not in endpoints and r!='static')
required_templates={
 'login.html','register.html','admin_dashboard.html','teacher_dashboard.html',
 'student_dashboard.html','parent_dashboard.html','parent_children.html',
 'ai_command_center.html','ai_privacy.html','ai_tutor.html','ai_learning_materials.html',
 'ai_result_assistant.html','result_preview.html','theme_branding.html'
}
files={p.rsplit('/',1)[-1] for p in glob.glob('templates/**/*.html',recursive=True)}
missing_templates=sorted(required_templates-files)
print(f'endpoint functions: {len(endpoints)}')
print(f'template url_for references: {len(refs)}')
print('missing endpoints:', missing or 'none')
print('missing core UI templates:', missing_templates or 'none')
if missing or missing_templates:
    sys.exit(1)
