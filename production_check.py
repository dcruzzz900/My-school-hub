#!/usr/bin/env python3
"""Read-only production configuration checks. Does not modify the database."""
import os, sys

errors=[]; warnings=[]
if not os.environ.get('SECRET_KEY'):
    warnings.append('SECRET_KEY is not explicitly set; configure a stable Railway SECRET_KEY before production.')
if os.environ.get('SKIP_DEMO_SEED','0') != '1':
    warnings.append('SKIP_DEMO_SEED is not 1; verify that demo seeding is intentionally disabled in production.')
if os.environ.get('DATA_DIR') and not os.path.isdir(os.environ['DATA_DIR']):
    warnings.append(f"DATA_DIR does not currently exist: {os.environ['DATA_DIR']}")
if os.environ.get('FLASK_ENV') == 'development':
    warnings.append('FLASK_ENV=development; do not use development settings in production.')
print('PRODUCTION CONFIG CHECK')
for x in errors: print('ERROR:', x)
for x in warnings: print('WARNING:', x)
print('Status:', 'FAIL' if errors else ('WARNING' if warnings else 'PASS'))
raise SystemExit(1 if errors else 0)
