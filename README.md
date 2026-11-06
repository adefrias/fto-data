# Coastal Medical Transportation Systems — Company Onboard Tracking (Vercel + Neon)

```
public/index.html   the app
public/shim.js      connects the app to /api/db
api/db.js           Vercel serverless function (Neon Postgres)
lib/handler.js      sign-in, sessions, role permissions and database logic (tables are created automatically)
vercel.json         output folder, security headers, daily reminder cron
```

## Deploy
1. **Vercel dashboard → Add New → Project →** import this GitHub repository (branch `main`). Framework preset: **Other**. Leave build settings as they are. Deploy once.
2. In the project open **Storage → Create Database → Neon (Postgres)**, create it, and **Connect** it to the project for all environments. Vercel adds `DATABASE_URL` automatically.
3. **Deployments → Redeploy** so the function picks up `DATABASE_URL`.
4. Open the site. The first visit shows **Create the administrator account**. Do this right away: whoever opens a brand-new site first can create the administrator.

## Sign-in and security (server-side)
- Sign-in happens on the server. The browser gets a session cookie (HttpOnly, SameSite=Strict, Secure); sessions end after 30 minutes without activity, and the app signs out after 15 minutes of inactivity.
- The server enforces who can read and write each record type: candidates only see their own records, FTO reviews are visible to administrators only, FTOs can only create their own ride-time entries and evaluations, submitted evaluations can never be changed or removed, and so on. Role and active-status changes apply immediately. Password hashes are never sent to browsers.
- Repeated failed sign-ins lock the email address for 5 minutes (and an IP address after 30 failures).
- **Upgrading from the earlier version:** push the new files. Existing accounts keep their passwords (same hash format). No database migration is needed; new tables are created automatically.
- Limits worth knowing: a user's name/role list is visible to other signed-in users (needed for the app to work); the lock-out counters work per email and per IP behind Vercel's proxy.

## Email reminders (optional)
Set these in **Project → Settings → Environment Variables**, then redeploy:

| Variable | Purpose |
|---|---|
| `RESEND_API_KEY` | API key from [resend.com](https://resend.com) (sends the email) |
| `MAIL_FROM` | e.g. `Coastal Onboarding <onboarding@yourdomain.com>` (a domain verified in Resend) |
| `SITE_URL` | the site address, added to the end of each email |
| `CRON_SECRET` | any long random string; Vercel sends it automatically with the daily cron |
| `APP_TZ` | time zone for "tomorrow" (default `America/New_York`) |
| `MAIL_DRY_RUN` | set to `1` to log emails instead of sending them |

- Every in-app notification is also emailed to that user.
- `vercel.json` runs `/api/db?a=remind` daily at 13:00 UTC: ride time tomorrow, FTO evaluations waiting, FTO reviews waiting. Each reminder is sent once per day per person. (Vercel's free Hobby plan allows one cron run per day.)
- Text messages (SMS) are not included. They need a paid provider such as Twilio.

## Notes
- **Plan:** Vercel's free Hobby plan is for non-commercial use. A company tool belongs on Pro.
- **Traffic:** each open browser asks the server for changes every 8 seconds (30 seconds in a background tab).
- **Backups:** in the app, **Users → Backup & restore** downloads all records as JSON (administrators only; passwords are not included) and restores them (submitted evaluations and FTO reviews are never changed). Also use Neon's branching / point-in-time restore.
- **Local development:** `npm i -g vercel`, `npm install`, `vercel link`, `vercel env pull`, then `vercel dev`.
- Updating the app: replace `public/index.html` (keep the `<script src="shim.js"></script>` line above the main script) and push.
