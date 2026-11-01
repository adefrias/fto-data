# Coastal Medical Transportation Systems — Company Onboard Tracking (Vercel + Neon)

```
public/index.html   the app
public/shim.js      connects the app to /api/db
api/db.js           Vercel serverless function (Neon Postgres)
lib/handler.js      database logic (tables are created automatically on first use)
vercel.json         output folder + security headers
```

## Deploy
1. **Vercel dashboard → Add New → Project →** import this GitHub repository (choose the branch that holds these files). Framework preset: **Other**. Leave build settings as they are (`vercel.json` sets the output folder). Deploy once.
2. In the project open **Storage → Create Database → Neon (Postgres)**, create it, and **Connect** it to the project for all environments. Vercel adds `DATABASE_URL` automatically.
3. **Deployments → Redeploy** so the function picks up `DATABASE_URL`.
4. Open the site. The first visit shows **Create the administrator account**. Do this right away: whoever opens the site first can create the administrator.

## Notes
- **Plan:** Vercel's free Hobby plan is for non-commercial use. A company tool belongs on Pro.
- **Traffic:** each open browser asks the server for changes every 8 seconds (30 seconds in a background tab).
- **Security:** sign-in and role rules are still enforced in the browser. `/api/db` accepts requests from anyone who can load the site, so a technical person could read or edit records directly, including password hashes. Submitted evaluations are protected server-side (they cannot be changed or deleted). To limit who can reach the site at all, turn on Vercel's Deployment/Password Protection (paid plans). Server-side login with sessions is the proper fix.
- **Backups:** use Neon's branching / point-in-time restore (window depends on your Neon plan), and export the database periodically.
- **Local development:** `npm i -g vercel`, `npm install`, `vercel link`, `vercel env pull`, then `vercel dev`.
- Updating the app: replace `public/index.html` (keep the `<script src="shim.js"></script>` line above the main script) and push.
