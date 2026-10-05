# V47 Production Readiness

Before live release:
1. Run `pytest -q`.
2. Run `python -m py_compile app.py db.py billing_finalization.py`.
3. Verify `railway.json` starts with `gunicorn app:app`.
4. Configure persistent `DATA_DIR=/data` on Railway.
5. Set production `SECRET_KEY` and secure session cookies.
6. Configure and test Paystack/Flutterwave webhook secrets before enabling live gateways.
7. Configure `BILLING_NOTIFICATION_CRON_SECRET` and scheduled billing job.
8. Run the Super Admin V47 Readiness page and resolve ATTENTION items.
9. Run a fresh database backup and verify `PRAGMA integrity_check`.
10. Perform browser QA on login, tenant isolation, offline sync, results, parent portal, AI consent and billing.
11. Verify no production database reset/reseed occurs during deployment.
