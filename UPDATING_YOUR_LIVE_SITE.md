# Update: Login by Email/Phone, Staff Contact Fields, Passport Photo & Parent Relationship

## What's new in this update

- **Login by username, email, or phone.** The login box now accepts any of
  the three. Existing usernames keep working exactly as before — this is
  additive, nobody's login changes unless they choose to add an email/phone.
- **Staff can have an email and phone number on file**, settable three ways:
  optionally at self-registration, by an admin from **Teachers** (inline
  Save next to each row), or by the staff member themselves from
  **Settings → Your Account**. Each is optional and must be unique
  platform-wide (same rule as usernames) — you'll get a clear error if one
  is already in use.
- **Students can have an optional passport photo**, uploaded from the
  student's profile page. Like the school logo, this requires an internet
  connection to upload (photos are not bulk-synced to offline devices — the
  rest of the student's record still is).
- **A "Relationship to Student" field** (e.g. Mother, Father, Uncle)
  alongside the existing parent/guardian contact fields — available
  everywhere those fields already are: Admin → Students, a form teacher's
  Class Register (add + inline edit), and both CSV import/export paths.

## Database changes

Two new migration steps (`user_contact_identifiers`,
`student_photo_and_relationship`) run automatically the first time the
updated app starts — no manual SQL needed, and no data is touched beyond
adding the new (empty) columns. As always, back up first.

## Steps

1. Log in to **pythonanywhere.com** and go to the **Files** tab.
2. Upload this new `school-result-system.zip` to your home directory.
3. Go to the **Consoles** tab, open a **Bash** console.
4. Back up your database first:
   ```
   cd school-results
   python backup_db.py
   ```
5. Unzip the new version to a temporary folder:
   ```
   cd ~
   unzip -o school-result-system.zip -d new_version
   ```
6. Copy over the changed files (skips `instance/`, so your database is untouched):
   ```
   cp new_version/school-results/app.py school-results/app.py
   cp new_version/school-results/db.py school-results/db.py
   cp new_version/school-results/sync_api.py school-results/sync_api.py
   cp new_version/school-results/schema.sql school-results/schema.sql
   cp -r new_version/school-results/templates/. school-results/templates/
   ```
7. Reload dependencies aren't needed this time (no new packages), but it's
   safe to run:
   ```
   workon schoolenv
   cd school-results
   pip install -r requirements.txt
   ```
8. Go to the **Web** tab and click the big green **Reload** button. The
   database upgrades itself on this first request.
9. Test it:
   - Log in with your usual username — should work unchanged.
   - As an admin, go to **Teachers**, add an email/phone to a teacher's row
     and hit **Save**, then log out and log back in using that email —
     should work.
   - Open a student's profile, upload a passport photo, confirm it shows.
   - Add a "Relationship to Student" on a student and confirm it saves.

If anything looks off after reloading, check the **Error log** link on the
Web tab and paste me what it says.

---



Staff now land in **the app** after logging in (`/app`) instead of the old server-rendered
dashboard. It looks and navigates like the old one (same colours, top bar and menu) but
works with or without internet, saves to the device first and syncs automatically, and shows
a small 🟢 / 🟠 / 🔄 indicator. The old dashboard is still available at `/dashboard?classic=1`.
Pages that only make sense online (Terms, Promote Students, Notifications, school profile,
etc.) are still the same server pages, reachable from the same menu.

---

# Upgrading from the earlier "queue-based" build (the one with the lock-screen overlay)

If your live site is the build whose offline mode shows "You're offline. Confirm your password…" over
a cached dashboard, this is the path for you. (It is also tested to upgrade a database from the other
earlier build; both used the same database version numbers 24–25 for different changes, so this release
works out what a database really contains instead of trusting the number.)

**1. Before you upgrade the server**
- Run `python backup_db.py`, then try the upgrade on a **copy** of `instance/school.db` first. It is tested against a real
  database made by that build's own code (pupils, scores, a deactivated teacher) and the app runs on it afterwards.
- Ask staff to open **Offline Queue** on their phones and press **Sync Now** while online. This is a courtesy, not a
  requirement: anything still queued is kept and sent after the upgrade (see below).

**2. What happens to the phones**
- The app updates itself the next time it is opened with internet. Opening it offline before that keeps the old version.
- **Items still queued by the old version are not lost.** They are kept in the phone's storage under the same per-school key,
  the new app shows "n items saved by the previous version are still waiting to be sent — Send them now", and the Offline Queue
  page sends them (dependencies resolved, retried safely: the server understands the old build's replay tokens, so a resend
  never creates a duplicate).
- The old saved offline login (the lock-screen overlay) does not carry over. **Each person logs in online once** with their
  normal username and password; the phone then sets itself up automatically, and from then on opening the app with no
  connection goes to the app's password box (the same password), not a cached page.
- Staff you had deactivated stay deactivated; the Deactivate/Reactivate button is still there (and now also cuts off that
  person's phones).
- Staff now land in **the app** (`/app`), the same look but working offline. The old dashboard is `/dashboard?classic=1`.

**3. New setting:** `OFFLINE_CREDENTIAL_DAYS` (default 30) — how long a phone may stay completely offline before one online
login is needed to renew it (its saved work is never deleted).

---


# Update: multi-school / multi-device release (read this first)

**What changed**
- Optional CA3, offline results/broadsheets/printing, offline CSV + Excel import/export,
  saved learning materials, field-level merging of two devices' edits, an audit trail,
  deletions that reach every device, and Railway support (`DEPLOY_RAILWAY.md`).
- Security fixes: devices no longer receive password hashes; a device's access follows the
  user's *current* role; a sub-admin can't overwrite the main admin account through sync;
  every pushed record is checked to belong to the caller's school; the offline screens escape
  staff/student text; cached pages are cleared when the user/school changes.

**How to update (PythonAnywhere)**
1. Back up `instance/school.db` (copy it somewhere safe).
2. Upload the new files over the old ones (keep your `instance/` folder).
3. `pip install --user -r requirements.txt`, then reload the web app. The database upgrades itself
   (migrations 27–29) the first time it starts. Nothing changes for a school until an admin turns CA3 on.
4. Devices update themselves the next time they are online: they download the new scripts, add
   the new local tables and pull the grading settings. A device with unsynced changes keeps them.
5. Optional: `python tests/run.py` runs the full test suite (needs `node`).

**Behaviour changes to know about**
- Deleting records through the sync API is refused (no screen used it). Deleting online still works
  and now propagates to devices.
- The Grading Setup screen (online and offline) now refuses maximums that add up to more than 100,
  or that are lower than a mark already saved in the school.
- New offline enrolments need a PIN of at least 6 characters. Devices enrolled earlier keep working.
- Score entry screens refuse marks above the school's maximums (before, only CSV import did).
- Edits made on an *older* app version that are still queued on a device will be treated as
  conflicts if someone else changed the same record meanwhile (older versions didn't send the
  information needed to merge them).

---

# Updating Your Live Site With This New Version

You already have this app deployed and working on PythonAnywhere. This is a
small update — no schema changes, no new files. It upgrades your live
database in place with **zero data loss**.

## What's new in this update

Fully wires up offline data entry so staff can keep working with no
connection and have it sync automatically once they're back online.

- **Pages now open while fully offline.** Previously, only form
  *submissions* were queued while offline — but if you opened Score Entry,
  Roll Call, or any admin form fresh with zero connectivity, you'd just see
  a "please reconnect" message instead of the form. Now, any page that's
  been opened once while online is cached and can be reopened offline after
  that, with the data as it was at last load.
- **Logins now last 30 days** instead of ending whenever the browser or
  app is closed. This matters for offline use — without it, a teacher who's
  offline for a stretch (weekend, poor signal for a few days) could get
  logged out, and their queued offline entries would fail to sync silently
  once back online, with no login screen to tell them why.
- No changes to the offline queue itself (Score Entry, Roll Call, Update
  Comments/Attendance, and the admin add/edit forms) — that queuing and
  auto-sync was already working; this update makes sure the pages behind it
  are actually reachable offline too.

**One inherent limit worth knowing:** a page has to be opened at least once
while online before it can be opened offline. There's no way around this —
the device has to receive the page from the server before it can show it
without one. So the recommended habit for staff: open your Score Entry and
Roll Call pages for your usual classes once while you still have signal
(e.g. at the start of the term), and they'll stay available offline from
then on.

## Steps

1. Log in to **pythonanywhere.com** and go to the **Files** tab.
2. Upload this new `school-result-system.zip` to your home directory.
3. Go to the **Consoles** tab, open a **Bash** console.
4. Unzip it to a temporary folder:
   ```
   unzip -o school-result-system.zip -d new_version
   ```
5. Copy over the code files (skips `instance/`, so your database is untouched):
   ```
   cp new_version/school-results/app.py school-results/app.py
   cp new_version/school-results/db.py school-results/db.py
   cp new_version/school-results/pdf_utils.py school-results/pdf_utils.py
   cp new_version/school-results/email_utils.py school-results/email_utils.py
   cp new_version/school-results/create_super_admin.py school-results/create_super_admin.py
   cp new_version/school-results/reports.py school-results/reports.py
   cp new_version/school-results/schema.sql school-results/schema.sql
   cp new_version/school-results/requirements.txt school-results/requirements.txt
   cp -r new_version/school-results/templates/. school-results/templates/
   cp -r new_version/school-results/static/. school-results/static/
   ```
6. Reinstall dependencies (safe either way, no new packages this time):
   ```
   workon schoolenv
   cd school-results
   pip install -r requirements.txt
   ```
7. Go to the **Web** tab and click the big green **Reload** button.
8. On a phone that already has this app installed/bookmarked, do a full
   refresh once (pull-to-refresh or close and reopen the tab/app) so it
   picks up the new service worker — it auto-updates in the background
   otherwise, just not instantly.
9. While still online, open Score Entry and Roll Call for each class staff
   will need, so those pages get cached for offline use.
10. Test it: turn on Airplane Mode, open a previously-visited Score Entry
    or Roll Call page, make an entry, and save. You should see a "Saved
    offline" toast. Turn Airplane Mode back off and either wait a moment or
    visit **Offline Queue** (in Settings) and tap **Sync Now** — the entry
    should disappear from the queue once it's synced.

If anything looks off after reloading, check the **Error log** link on the
Web tab and paste me what it says.
