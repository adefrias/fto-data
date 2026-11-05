# Deploying to Bluehost (cPanel shared hosting)

## What's in the package
- `index.html`: the app
- `shim.js`: connects the app to the server
- `api.php`: sign-in, sessions, role permissions and the shared database (a SQLite file; PHP 7.4+ with `pdo_sqlite`, standard on Bluehost)
- `config.sample.php`: optional settings for email and reminders (copy to `config.php`)
- `.htaccess`: forces HTTPS, hides folder listings, blocks search-engine indexing and direct access to `config.php`
- `data/`: holds the database; its `.htaccess` blocks direct web access

## Steps
1. In cPanel open **File Manager** and go to `public_html` (or the folder of the domain/subdomain you want, e.g. `public_html/onboard`).
2. **Upload** `coastal-onboard.zip` there and **Extract** it. Move the contents of the `coastal-onboard` folder up if you want the app at the domain root.
3. Make sure `data/` is writable (permissions 755 or 750). The app creates `data/app.sqlite` on first load.
4. Turn on a free SSL certificate in cPanel (**SSL/TLS Status > Run AutoSSL**). Sign-in cookies are only marked Secure on HTTPS.
5. Open the site. The first visit shows **Create the administrator account**. Do this right away, then add staff and candidates.

## Sign-in and security (server-side)
- Sign-in happens on the server. The browser gets a session cookie (HttpOnly, SameSite=Strict, Secure on HTTPS); sessions end after 30 minutes without activity, and the app also signs out after 15 minutes of inactivity.
- The server enforces who can read and write each kind of record (candidates only see their own records, FTO reviews are visible to administrators only, submitted evaluations can never be changed, and so on). Password hashes are never sent to browsers.
- Repeated failed sign-ins lock the email address for 5 minutes (and an IP address after 30 failures).
- **Upgrading from an earlier package:** keep your `data/` folder and replace the other files. Existing accounts keep their passwords.
- Do the first-run setup yourself immediately: whoever opens a brand-new site first can create the administrator.

## Email reminders (optional)
1. Copy `config.sample.php` to `config.php` and set `MAIL_FROM` (an address on your domain), `SITE_URL` and `CRON_SECRET`.
2. Every in-app notification is then also emailed to that user (users need an email address on their account, which they have).
3. Daily reminders (ride time tomorrow, FTO evaluations and FTO reviews waiting) come from a cron job. In cPanel open **Cron Jobs** and add a daily command such as
   `/usr/local/bin/php /home/YOURUSER/public_html/onboard/api.php remind`
   Each reminder is sent once per day per person.
4. To test without sending real mail, set `'MAIL_DRY_RUN' => '1'` in `config.php`; messages are written to `data/mail.log` instead.
5. Text messages (SMS) are not included. They need a paid provider such as Twilio.

## Backups
- In the app, **Users → Backup & restore** downloads all records as a JSON file (administrators only). Restoring replaces templates, users, candidates, rides and assignments with the file's contents; submitted evaluations and FTO reviews are never changed or removed. Password hashes are never included in backups made from this server version, so people restored into an empty site need a password reset.
- Also back up `data/app.sqlite` (download it from File Manager, or enable Bluehost backups). That one file is all of your data.

## Other notes
- Updating the app: replace `index.html` (keep the `<script src="shim.js"></script>` line above the main script). Do not touch `data/`.
- Moving hosts later: copy `data/app.sqlite` to the new server.
