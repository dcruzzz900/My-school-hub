# Pilot checklist — running this at one school first

Everything below has been tested in a desktop browser against test data. **It has not been run
on real phones or tablets** — that is what the pilot is for. Pick one school and a small group
(admin + 2–3 teachers) for one full term-week before rolling out.

## Before the pilot (admin, 1 hour)

1. **Back up, then upgrade a COPY first.** Run `python backup_db.py`, then try the new version on a
   copy of `school.db` (see `UPDATING_YOUR_LIVE_SITE.md`) and check your existing schools' results
   look right. Only then upgrade the live site.
2. **Set the environment** (`DEPLOY_RAILWAY.md` / PythonAnywhere): `SECRET_KEY`, `SKIP_DEMO_SEED=1`,
   `SESSION_COOKIE_SECURE=1`. On a host with a normal local disk, set `DATA_DIR` (turns on the
   faster WAL database mode); on PythonAnywhere leave it off.
3. **Schedule the daily backup** (`backup_db.py`).
4. Make sure each pilot user has a **strong password** — it is also their offline unlock password.
5. Check the school has an **active session and term**, its **class subjects assigned**, and the
   **grading maximums/bands** set. Devices download exactly that.

## Setting up each device (2 minutes, needs internet once)

1. Open the site in **Chrome (Android) or Safari (iPhone)**, log in normally with username + password.
   The device sets itself up and downloads the school's data ("Setting up this device…").
2. **Add it to the home screen** ("Install app" / "Add to Home Screen"). On iPhone this matters:
   Safari can clear a site's stored data after a week of not using it unless it's on the home screen.
3. Check the small pill at the top says **🟢 Online — Synced**.
4. Turn on the phone's **screen lock** — the school data on the device is protected by it.

## Things to try on real devices (please write down what happens)

| Try | Expect |
|---|---|
| Put the phone in airplane mode, open the app | Password box, then the same dashboard; pill 🟠 Offline — Saved Locally |
| Enter scores / take attendance offline | Saves instantly; pill stays 🟠 |
| Turn airplane mode off | Within ~30 s pill goes 🔄 then 🟢, entries appear in the admin's view online |
| Connected to wifi that has **no internet** (or a login page) | Treated as offline; work continues |
| Two teachers edit the same score row at once | Different fields merge; same field → "to review" |
| Leave a phone offline for several days, then reconnect | Everything syncs; after 30 days offline it asks for one online login |
| Log in on a new phone | First-time download; note how long it takes over mobile data |
| Print a result sheet to PDF from the phone | Looks right; note the paper size |
| Change the active term online | Devices pick it up on their next sync |

**Record:** phone model, browser, how long the first download took, anything that looked different
from a computer, anything that failed.

## During the pilot

- Sync Status (tap the pill) shows unsynced changes, conflicts, and a **Download backup** button.
  If someone reports "my scores vanished", have them do that first.
- **Conflicts** ("🟠 n to review") are resolved from Sync Status: keep mine / keep the server's.
- A teacher **offline over 30 days** must log in online once (their work is kept).
- Deactivating a staff member (Setup → Teachers) or resetting their password cuts off their
  devices immediately; they log in online again to set the device up.
- If the site itself has a problem, `/healthz` should answer `{"status":"ok"}`.

## What is not in the app yet (same menu, needs internet)

Terms/sessions, Promote Students, sending notifications, change password, school profile/logo,
email settings, removing a grade band, uploading materials, per-student score history, the
server's own PDFs, the Super Admin pages, the student portal. (See `OFFLINE_ARCHITECTURE.md`.)

## Known limits to keep in mind

- Cached school data is on the device in the browser's storage; protect it with the phone's lock.
- Only the **current session's** scores and the **current term's** attendance are on a phone.
- One SQLite database: fine for many schools' worth of devices syncing at once (tested with 100+
  simultaneous devices), but plan a move to PostgreSQL if you grow to hundreds of schools.
