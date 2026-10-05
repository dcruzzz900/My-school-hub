#!/usr/bin/env python3
"""Minimal post-deployment smoke test using only Python's standard library."""
import json, os, sys, urllib.request

base = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get('APP_URL','')).rstrip('/')
if not base:
    print('Usage: python production_smoke_test.py https://your-app.example.com')
    raise SystemExit(2)

checks = ['/healthz', '/readyz']
failed = False
for path in checks:
    try:
        with urllib.request.urlopen(base + path, timeout=20) as r:
            body = r.read().decode('utf-8', 'replace')
            print(f'{path}: HTTP {r.status} {body[:300]}')
            if r.status != 200:
                failed = True
            if path == '/readyz':
                try:
                    data = json.loads(body)
                    if data.get('status') != 'ready': failed = True
                except Exception:
                    failed = True
    except Exception as exc:
        print(f'{path}: FAILED - {exc}')
        failed = True
raise SystemExit(1 if failed else 0)
