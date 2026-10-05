#!/usr/bin/env python3
"""One-shot scheduled runner for the School Result System billing reminders.

Run this from a separate Railway cron service (or another scheduler). It makes
one authenticated HTTP request to the live application and then exits.
No database is opened directly by the scheduler process.
"""
import os
import sys
import urllib.error
import urllib.request


def main():
    base = os.environ.get("BILLING_APP_URL", "").strip().rstrip("/")
    secret = os.environ.get("BILLING_NOTIFICATION_CRON_SECRET", "").strip()
    if not base or not secret:
        print("BILLING_APP_URL and BILLING_NOTIFICATION_CRON_SECRET are required", file=sys.stderr)
        return 2
    url = base + "/internal/billing-notifications"
    request = urllib.request.Request(
        url,
        method="POST",
        headers={
            "X-Billing-Cron-Secret": secret,
            "User-Agent": "SchoolResultSystem-BillingScheduler/1.0",
            "Content-Length": "0",
        },
        data=b"",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8", errors="replace")
            print(body)
            return 0 if 200 <= response.status < 300 else 1
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code}: {body}", file=sys.stderr)
        return 0 if exc.code == 202 else 1
    except Exception as exc:
        print(f"Billing scheduler failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
