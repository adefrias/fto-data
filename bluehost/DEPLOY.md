# Deploying to Bluehost (cPanel shared hosting)

## What's in the package
- `index.html` – the app
- `shim.js` – connects the app to the server database
- `api.php` – the shared database (stores data in a SQLite file; PHP 7.4+ with `pdo_sqlite`, standard on Bluehost)
- `.htaccess` – forces HTTPS, hides folder listings, blocks search-engine indexing
- `data/` – holds the database; its `.htaccess` blocks direct web access

## Steps
1. In cPanel open **File Manager** and go to `public_html` (or the folder of the domain/subdomain you want, e.g. `public_html/onboard`).
2. **Upload** `coastal-onboard.zip` there and **Extract** it. Move the contents of the `coastal-onboard` folder up if you want the app at the domain root.
3. Make sure `data/` is writable (permissions 755 or 750). The app creates `data/app.sqlite` on first load.
4. Turn on a free SSL certificate in cPanel (**SSL/TLS Status > Run AutoSSL**) if the domain does not have one.
5. Open the site. The first visit shows **Create the administrator account**. Create it right away, then add staff and candidates.

## Before you rely on it
- **Do the first-run setup yourself, immediately.** Whoever opens the site first can create the administrator.
- **Back up `data/app.sqlite`** (download it from File Manager, or enable Bluehost backups). That one file is all of your data.
- **Sign-in is enforced in the browser, not on the server.** `api.php` is open to anyone who can reach the site, so a technical person could read or edit records directly, including password hashes. For stronger protection, add a server-level gate in cPanel: **Directory Privacy** (password-protect the folder). Staff then enter that shared password before the app loads. Only submitted evaluations are protected server-side (they cannot be changed or deleted).
- Updating the app: replace `index.html` only. Do not touch `data/`.
- Moving hosts later: copy `data/app.sqlite` to the new server.
