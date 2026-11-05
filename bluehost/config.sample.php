<?php
// Copy this file to config.php and fill in what you need. config.php is blocked from web access by .htaccess.
return [
  // Email (optional). Without MAIL_FROM no emails are sent. Use an address on your own domain so mail is not marked as spam.
  'MAIL_FROM'   => 'Coastal Onboarding <onboarding@yourdomain.com>',
  'SITE_URL'    => 'https://yourdomain.com/onboard/',   // added to the end of each email
  // Reminders (optional): secret for the web cron URL, and the time zone used for "tomorrow".
  'CRON_SECRET' => '',                                  // e.g. a long random string
  'APP_TZ'      => 'America/New_York',
];
