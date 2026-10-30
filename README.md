# Coastal Medical Transportation Systems — Company Onboard Tracking

Single-file web app (`index.html`) for EMS new-hire ride time, FTO evaluations, competencies and candidate shift evaluations.

## Important
- The app stores data through the Claude artifact shared database (`window.claude` `db` capability). Outside a published Claude artifact it has no database, so it will not save data when hosted elsewhere (GitHub Pages, Cloudflare Pages).
- Sign-in and role checks run in the browser only. Moving to a standalone host needs a real backend (e.g. Cloudflare Workers + D1) for storage and server-side authorization.
