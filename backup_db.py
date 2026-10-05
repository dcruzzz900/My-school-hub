#!/usr/bin/env python3
"""Make a safe, verified copy of the school database.

    python backup_db.py                 # copy to <data folder>/backups/, keep the newest 14
    python backup_db.py --keep 30 --dest /some/other/folder

Uses SQLite's own online-backup call, so it is safe to run while the site is serving people
(a plain file copy of a busy database can be corrupt), then checks the copy with an integrity
check before keeping it. Schedule it daily: PythonAnywhere -> Tasks, Railway -> a cron service,
or your own server's crontab. Also copy the `materials/` folder and the logo files that live
beside the database if you want a complete backup.
"""
import argparse
import datetime
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402


def make_backup(dest_dir=None, keep=14):
    dest_dir = dest_dir or os.path.join(db.INSTANCE_DIR, "backups")
    os.makedirs(dest_dir, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    target = os.path.join(dest_dir, f"school-{stamp}.db")
    src = sqlite3.connect(db.DB_PATH, timeout=60)
    try:
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)                  # consistent snapshot, even while the site is busy
        finally:
            dst.close()
    finally:
        src.close()
    check = sqlite3.connect(target)
    try:
        verdict = check.execute("PRAGMA integrity_check").fetchone()[0]
        schools = check.execute("SELECT COUNT(*) FROM schools").fetchone()[0]
    finally:
        check.close()
    if verdict != "ok":
        os.remove(target)
        raise SystemExit(f"Backup FAILED its integrity check ({verdict}); it was discarded.")
    old = sorted(f for f in os.listdir(dest_dir) if f.startswith("school-") and f.endswith(".db"))
    for name in old[:-keep] if keep > 0 else []:
        os.remove(os.path.join(dest_dir, name))
    return target, schools


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", help="folder for the backups (default: <data folder>/backups)")
    ap.add_argument("--keep", type=int, default=14, help="how many recent backups to keep (default 14)")
    args = ap.parse_args()
    path, schools = make_backup(args.dest, args.keep)
    print(f"Backup OK: {path} ({os.path.getsize(path) / 1024:.0f} KB, {schools} school(s))")
