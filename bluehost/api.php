<?php
// Shared-database API with server-side sign-in, sessions and role permissions.
// Requires PHP 7.4+ with pdo_sqlite. Optional settings go in config.php (see config.sample.php).
declare(strict_types=1);

const COLS = ['users','cands','rides','evals','notifs','audit','templates','rtTpls','evTpls','levels','comps','messages','ceTpls','cevals','assigns','reqTpls','settings'];
const IMMUTABLE = ['evals','cevals'];
const ROLES = ['admin','instructor','fto','candidate'];
const MAX_DOC = 524288;
const IDLE = 1800;
const COOKIE = 'cmts_s';

$CFG = is_file(__DIR__ . '/config.php') ? (array)(include __DIR__ . '/config.php') : [];
function cfgv(string $k, string $d = ''): string { global $CFG; $v = $CFG[$k] ?? getenv($k); return ($v === false || $v === null || $v === '') ? $d : (string)$v; }

$CLI = PHP_SAPI === 'cli';
if (!$CLI) {
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store');
  header('X-Content-Type-Options: nosniff');
}
function out($obj, int $code = 200): void { http_response_code($code); echo json_encode($obj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION); exit; }
function fail(int $code, string $msg): void { out(['error' => $msg], $code); }

if (!$CLI) {
  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
  if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== explode(':', $_SERVER['HTTP_HOST'] ?? '')[0]) fail(403, 'Forbidden');
}

$dir = __DIR__ . '/data';
if (!is_dir($dir)) {
  @mkdir($dir, 0750, true);
  @file_put_contents($dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
  @file_put_contents($dir . '/index.html', '');
}
try {
  $pdo = new PDO('sqlite:' . $dir . '/app.sqlite');
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $pdo->exec('PRAGMA busy_timeout=8000');
  $pdo->exec('CREATE TABLE IF NOT EXISTS docs(c TEXT NOT NULL, id TEXT NOT NULL, j TEXT NOT NULL, PRIMARY KEY(c,id))');
  $pdo->exec('CREATE TABLE IF NOT EXISTS rev(c TEXT PRIMARY KEY, n INTEGER NOT NULL)');
  $pdo->exec('CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, uid TEXT NOT NULL, last INTEGER NOT NULL)');
  $pdo->exec('CREATE TABLE IF NOT EXISTS attempts(k TEXT PRIMARY KEY, n INTEGER NOT NULL, until_ts INTEGER NOT NULL, first_ts INTEGER NOT NULL)');
  $pdo->exec('CREATE TABLE IF NOT EXISTS sent(k TEXT PRIMARY KEY, ts INTEGER NOT NULL)');
} catch (Throwable $e) { fail(500, 'Database unavailable. Check that pdo_sqlite is enabled and the data folder is writable.'); }

function jenc($v): string { return (string)json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION); }
function bump(PDO $pdo, string $c): void { $pdo->prepare('INSERT INTO rev(c,n) VALUES(?,1) ON CONFLICT(c) DO UPDATE SET n=n+1')->execute([$c]); }
function getDoc(PDO $pdo, string $c, string $id): ?array { $st = $pdo->prepare('SELECT j FROM docs WHERE c=? AND id=?'); $st->execute([$c, $id]); $j = $st->fetchColumn(); return $j === false ? null : json_decode((string)$j, true); }
function putDoc(PDO $pdo, string $c, string $id, string $j): void {
  $st = $pdo->prepare('SELECT j FROM docs WHERE c=? AND id=?'); $st->execute([$c, $id]); $old = $st->fetchColumn();
  if ($old !== false && json_encode(json_decode((string)$old)) === json_encode(json_decode($j))) return;
  $pdo->prepare('REPLACE INTO docs(c,id,j) VALUES(?,?,?)')->execute([$c, $id, $j]); bump($pdo, $c);
}
function delDoc(PDO $pdo, string $c, string $id): void { $st = $pdo->prepare('DELETE FROM docs WHERE c=? AND id=?'); $st->execute([$c, $id]); if ($st->rowCount()) bump($pdo, $c); }

function hashPw(string $pw): string { $salt = bin2hex(random_bytes(16)); return $salt . ':' . hash_pbkdf2('sha256', $pw, $salt, 150000, 64, false); }
function checkPw(string $pw, $stored): bool {
  if (!is_string($stored) || strpos($stored, ':') === false) { hash_pbkdf2('sha256', $pw, str_repeat('x', 32), 150000, 64, false); return false; }
  [$salt, $h] = explode(':', $stored, 2);
  return hash_equals($h, hash_pbkdf2('sha256', $pw, $salt, 150000, 64, false));
}

// ---------- mail + reminders ----------
function mailTo(PDO $pdo, string $uid, string $subject, string $text): bool {
  $from = cfgv('MAIL_FROM'); $dry = cfgv('MAIL_DRY_RUN');
  if ($from === '' && $dry === '') return false;
  $u = getDoc($pdo, 'users', $uid);
  if (!$u || empty($u['active']) || empty($u['email']) || !filter_var($u['email'], FILTER_VALIDATE_EMAIL)) return false;
  $body = $text . "\n\n" . cfgv('SITE_URL');
  if ($dry !== '') { @file_put_contents(__DIR__ . '/data/mail.log', jenc(['to' => $u['email'], 'subject' => $subject, 'text' => $body]) . "\n", FILE_APPEND); return true; }
  $subject = preg_replace('~[\r\n]+~', ' ', $subject);
  return @mail($u['email'], $subject, $body, 'From: ' . preg_replace('~[\r\n]+~', '', $from) . "\r\nContent-Type: text/plain; charset=UTF-8");
}
function loadAll(PDO $pdo, string $c): array { $o = []; foreach ($pdo->query("SELECT id,j FROM docs WHERE c=" . $pdo->quote($c)) as $r) { $d = json_decode($r['j'], true); $d['id'] = $r['id']; $o[] = $d; } return $o; }
function dayStr(int $off): string { $d = new DateTime('now', new DateTimeZone(cfgv('APP_TZ', 'America/New_York'))); if ($off) $d->modify(($off > 0 ? '+' : '') . $off . ' day'); return $d->format('Y-m-d'); }
function once(PDO $pdo, string $k): bool { $st = $pdo->prepare('INSERT OR IGNORE INTO sent(k,ts) VALUES(?,?)'); $st->execute([$k, time()]); return $st->rowCount() > 0; }
function remind(PDO $pdo): int {
  $assigns = loadAll($pdo, 'assigns'); $rides = loadAll($pdo, 'rides'); $evals = loadAll($pdo, 'evals'); $cevals = loadAll($pdo, 'cevals'); $users = loadAll($pdo, 'users'); $cands = loadAll($pdo, 'cands'); $sett = loadAll($pdo, 'settings');
  $today = dayStr(0); $tomorrow = dayStr(1); $days = 3; foreach ($sett as $s) if ($s['id'] === 'main' && !empty($s['reviewDays'])) $days = max(1, (int)$s['reviewDays']);
  $uname = function ($id) use ($users) { foreach ($users as $u) if ($u['id'] === $id) return $u['name'] ?? ''; return ''; };
  $cand = function ($id) use ($cands) { foreach ($cands as $c) if ($c['id'] === $id) return $c; return null; };
  $n = 0;
  foreach ($assigns as $a) {
    if (($a['status'] ?? '') !== 'Scheduled' || ($a['date'] ?? '') !== $tomorrow) continue;
    $c = $cand($a['cid'] ?? ''); $when = $a['date'] . ' ' . ($a['start'] ?? '') . '-' . ($a['end'] ?? '');
    foreach ([[$a['fto'] ?? '', 'with ' . $uname($c['uid'] ?? '')], [$c['uid'] ?? '', 'with FTO ' . $uname($a['fto'] ?? '')]] as [$uid, $who])
      if ($uid && once($pdo, "a:{$a['id']}:{$a['date']}:$uid") && mailTo($pdo, $uid, 'Ride time tomorrow', "Reminder: ride time tomorrow, $when $who" . (!empty($a['unit']) ? " ({$a['unit']})" : '') . '.')) $n++;
  }
  $evDone = []; foreach ($evals as $e) if (!empty($e['rid'])) $evDone[$e['rid']] = 1;
  $cvDone = []; foreach ($cevals as $e) if (!empty($e['rid'])) $cvDone[$e['rid']] = 1;
  $pe = []; $pr = []; $cutoff = (new DateTime($today))->modify("-$days day")->format('Y-m-d');
  foreach ($rides as $r) {
    if (!empty($r['void'])) continue;
    if (!empty($r['evreq']) && ($r['date'] ?? '9') < $today && empty($evDone[$r['id']])) $pe[$r['fto']] = ($pe[$r['fto']] ?? 0) + 1;
    if (($r['date'] ?? '9') < $cutoff && empty($cvDone[$r['id']])) { $c = $cand($r['cid'] ?? ''); if ($c) $pr[$c['uid']] = ($pr[$c['uid']] ?? 0) + 1; }
  }
  foreach ($pe as $uid => $k) if (once($pdo, "e:$uid:$today") && mailTo($pdo, (string)$uid, 'Evaluations waiting', "You have $k ride-time shift" . ($k > 1 ? 's' : '') . ' waiting for your FTO evaluation.')) $n++;
  foreach ($pr as $uid => $k) if (once($pdo, "r:$uid:$today") && mailTo($pdo, (string)$uid, 'FTO review waiting', "You have $k ride-time shift" . ($k > 1 ? 's' : '') . ' waiting for your FTO review.')) $n++;
  return $n;
}
if ($CLI) { if (($argv[1] ?? '') === 'remind') { echo 'sent ' . remind($pdo) . "\n"; } else echo "usage: php api.php remind\n"; exit; }

// ---------- sessions ----------
function cookieTok(): string { $t = $_COOKIE[COOKIE] ?? ''; return is_string($t) && preg_match('~^[0-9a-f]{64}$~', $t) ? $t : ''; }
function isHttps(): bool { return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'); }
function setCookieTok(string $v, int $max): void { setcookie(COOKIE, $v, ['expires' => $max ? time() + $max : 1, 'path' => '/', 'secure' => isHttps(), 'httponly' => true, 'samesite' => 'Strict']); }
function currentSession(PDO $pdo): ?array {
  $tok = cookieTok(); if ($tok === '') return null; $h = hash('sha256', $tok);
  $st = $pdo->prepare('SELECT uid,last FROM sessions WHERE h=?'); $st->execute([$h]); $r = $st->fetch(PDO::FETCH_ASSOC); if (!$r) return null;
  $t = time();
  if ((int)$r['last'] < $t - IDLE) { $pdo->prepare('DELETE FROM sessions WHERE h=?')->execute([$h]); return null; }
  $u = getDoc($pdo, 'users', $r['uid']); if (!$u || empty($u['active']) || !in_array($u['role'] ?? '', ROLES, true)) return null;
  if ((int)$r['last'] < $t - 60) $pdo->prepare('UPDATE sessions SET last=? WHERE h=?')->execute([$t, $h]);
  $u['id'] = $r['uid']; return ['user' => $u, 'h' => $h];
}
function newSession(PDO $pdo, string $uid): void {
  $tok = bin2hex(random_bytes(32)); $t = time();
  $pdo->prepare('INSERT INTO sessions(h,uid,last) VALUES(?,?,?)')->execute([hash('sha256', $tok), $uid, $t]);
  $pdo->prepare('DELETE FROM sessions WHERE last<?')->execute([$t - 86400]);
  setCookieTok($tok, 86400);
}
function lockedFor(PDO $pdo, array $keys): int {
  $t = time(); foreach ($keys as [$k]) { $st = $pdo->prepare('SELECT until_ts FROM attempts WHERE k=?'); $st->execute([$k]); $u = $st->fetchColumn(); if ($u !== false && (int)$u > $t) return (int)$u - $t; } return 0;
}
function noteFail(PDO $pdo, array $keys): void {
  $t = time();
  foreach ($keys as [$k, $max]) {
    $st = $pdo->prepare('SELECT n,first_ts FROM attempts WHERE k=?'); $st->execute([$k]); $r = $st->fetch(PDO::FETCH_ASSOC);
    $n = 1; $first = $t; if ($r && $t - (int)$r['first_ts'] < 900) { $n = (int)$r['n'] + 1; $first = (int)$r['first_ts']; }
    $pdo->prepare('REPLACE INTO attempts(k,n,until_ts,first_ts) VALUES(?,?,?,?)')->execute([$k, $n, $n >= $max ? $t + 300 : 0, $first]);
  }
}
function ownCand(PDO $pdo, string $uid): ?string { foreach ($pdo->query("SELECT id,j FROM docs WHERE c='cands'") as $r) { $d = json_decode($r['j'], true); if (($d['uid'] ?? null) === $uid) return $r['id']; } return null; }

// ---------- permissions ----------
function keysChanged($o, $n): array {
  $o = (array)$o; $n = (array)$n; $out = [];
  foreach (array_unique(array_merge(array_keys($o), array_keys($n))) as $k) if (jenc($o[$k] ?? null) !== jenc($n[$k] ?? null)) $out[] = $k;
  return $out;
}
function within($o, $n, array $allowed): bool { foreach (keysChanged($o, $n) as $k) if (!in_array($k, $allowed, true)) return false; return true; }
function authorize(array $user, ?string $ownCid, string $c, string $op, ?array $old, ?array $nu): string {
  $role = $user['role']; $me = $user['id']; $isNew = $old === null;
  if (in_array($c, IMMUTABLE, true)) {
    if ($op === 'delete') return 'ignore';
    if ($old !== null) return 'ignore';
    if ($c === 'evals') return $role === 'fto' && ($nu['fto'] ?? null) === $me ? 'ok' : 'deny';
    return $role === 'candidate' && $ownCid !== null && ($nu['cid'] ?? null) === $ownCid && ($nu['by'] ?? null) === $me ? 'ok' : 'deny';
  }
  if ($c === 'audit') { if ($op === 'delete') return 'ignore'; if ($old !== null) return 'ignore'; return (($nu['u'] ?? null) === $me || ($nu['u'] ?? null) === 'system') ? 'ok' : 'deny'; }
  if ($c === 'notifs') { if ($isNew) return $op === 'set' ? 'ok' : 'deny'; return (($old['u'] ?? null) === $me || $role === 'admin') ? 'ok' : 'deny'; }
  if ($role === 'admin') return 'ok';
  switch ($c) {
    case 'cands': if ($op === 'delete' || $isNew) return 'deny'; return $role === 'instructor' ? 'ok' : ($role === 'fto' && within($old, $nu, ['remed']) ? 'ok' : 'deny');
    case 'comps': return $op === 'set' && ($role === 'instructor' || $role === 'fto') ? 'ok' : 'deny';
    case 'assigns': if ($op === 'delete') return 'deny'; if ($role === 'instructor') return 'ok';
      return $role === 'fto' && $old !== null && ($old['fto'] ?? null) === $me && within($old, $nu, ['status', 'rid', 'done']) ? 'ok' : 'deny';
    case 'rides': if ($op === 'delete') return 'deny';
      if ($role === 'fto') return $isNew && ($nu['fto'] ?? null) === $me ? 'ok' : 'deny';
      return $role === 'candidate' && $old !== null && $ownCid !== null && ($old['cid'] ?? null) === $ownCid && within($old, $nu, ['ack', 'ackt']) ? 'ok' : 'deny';
    case 'messages': if ($role !== 'candidate' || $op === 'delete') return 'deny';
      return $isNew ? (($nu['from'] ?? null) === $me ? 'ok' : 'deny') : (($old['from'] ?? null) === $me && within($old, $nu, ['rseen']) ? 'ok' : 'deny');
    case 'templates': case 'rtTpls': case 'evTpls': case 'levels': return $role === 'instructor' ? 'ok' : 'deny';
    default: return 'deny';
  }
}
function readCol(PDO $pdo, string $c, array $user, ?string $own): array {
  $role = $user['role']; $me = $user['id'];
  $st = $pdo->prepare('SELECT id,j FROM docs WHERE c=? ORDER BY id'); $st->execute([$c]); $out = [];
  foreach ($st as $r) {
    $d = json_decode($r['j'], true); $id = $r['id'];
    if ($c === 'notifs' && ($d['u'] ?? null) !== $me) continue;
    if ($c === 'audit' && $role !== 'admin') continue;
    if ($c === 'messages') { if ($role === 'admin') {} elseif ($role === 'candidate') { if (($d['from'] ?? null) !== $me) continue; } else continue; }
    if ($c === 'cevals') {
      if ($role === 'admin') {} elseif ($role === 'candidate' && $own !== null && ($d['cid'] ?? null) === $own) {
        $d = array_intersect_key($d, array_flip(['id', 'cid', 'rid', 'date', 'unit', 'sub', 'by', '_t']));
      } else continue;
    }
    if ($role === 'candidate') {
      if ($c === 'cands' && ($d['uid'] ?? null) !== $me) continue;
      if (in_array($c, ['rides', 'evals', 'assigns'], true) && ($own === null || ($d['cid'] ?? null) !== $own)) continue;
      if ($c === 'comps' && $id !== $own) continue;
      if ($c === 'users' && ($d['role'] ?? '') === 'candidate' && $id !== $me) continue;
    }
    if ($c === 'users') unset($d['pw']);
    $out[] = ['id' => $id, 'data' => $d];
  }
  return $out;
}

// ---------- routing ----------
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$a = (string)($_GET['a'] ?? '');

if ($method === 'GET' && $a === 'remind') {
  $key = (string)($_GET['key'] ?? ''); $sec = cfgv('CRON_SECRET');
  if ($sec === '' || !hash_equals($sec, $key)) fail(403, 'Forbidden');
  out(['sent' => remind($pdo)]);
}
$sess = currentSession($pdo);
if ($method === 'GET' && $a === 'me') {
  if ($sess) out(['user' => ['id' => $sess['user']['id'], 'name' => $sess['user']['name'] ?? '', 'role' => $sess['user']['role']], 'setup' => false]);
  $has = (bool)$pdo->query("SELECT 1 FROM docs WHERE c='users' LIMIT 1")->fetchColumn();
  out(['user' => null, 'setup' => !$has]);
}
if ($method === 'GET') {
  if (!$sess) fail(401, 'auth');
  $want = [];
  foreach (explode(',', (string)($_GET['v'] ?? '')) as $p) { $kv = explode(':', $p); if (count($kv) === 2 && in_array($kv[0], COLS, true) && preg_match('~^-?\d+$~', $kv[1])) $want[$kv[0]] = (int)$kv[1]; }
  $cur = []; foreach ($pdo->query('SELECT c,n FROM rev') as $r) $cur[$r['c']] = (int)$r['n'];
  $own = $sess['user']['role'] === 'candidate' ? ownCand($pdo, $sess['user']['id']) : null; $cols = [];
  foreach ($want as $c => $v) { $n = $cur[$c] ?? 0; if ($n === $v) continue; $cols[$c] = ['v' => $n, 'docs' => readCol($pdo, $c, $sess['user'], $own)]; }
  echo json_encode(['cols' => (object)$cols], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION); exit;
}
if ($method !== 'POST') fail(405, 'Method not allowed');
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0 || ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'onboard') fail(400, 'Bad request');
$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > MAX_DOC * 4) fail(413, 'Request too large');
$b = json_decode($raw);
if (!is_object($b) || !isset($b->op) || !is_string($b->op)) fail(400, 'Bad request');
$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');

if ($b->op === 'login') {
  $email = strtolower(substr(trim((string)($b->email ?? '')), 0, 200)); $pw = substr((string)($b->pw ?? ''), 0, 200);
  $keys = [['e:' . $email, 5], ['i:' . $ip, 30]]; $wait = lockedFor($pdo, $keys);
  if ($wait) fail(429, 'Too many attempts. Try again in ' . (int)ceil($wait / 60) . ' minute(s).');
  $found = null; foreach ($pdo->query("SELECT id,j FROM docs WHERE c='users'") as $r) { $d = json_decode($r['j'], true); if (strtolower((string)($d['email'] ?? '')) === $email) { $found = [$r['id'], $d]; break; } }
  $good = checkPw($pw, $found ? ($found[1]['pw'] ?? null) : null);
  if (!$found || !$good) { noteFail($pdo, $keys); fail(401, 'Email or password is incorrect.'); }
  if (empty($found[1]['active'])) fail(403, 'This account is deactivated. Contact an administrator.');
  $pdo->prepare('DELETE FROM attempts WHERE k=?')->execute(['e:' . $email]);
  newSession($pdo, $found[0]); out(['user' => ['id' => $found[0], 'mustChange' => !empty($found[1]['mustChange'])]]);
}
if ($b->op === 'setup') {
  $name = substr(trim((string)($b->name ?? '')), 0, 120); $email = strtolower(substr(trim((string)($b->email ?? '')), 0, 200)); $pw = (string)($b->pw ?? '');
  if ($name === '' || !preg_match('~^[^@\s]+@[^@\s]+$~', $email) || strlen($pw) < 8) fail(400, 'Enter a name, a valid email and a password of 8+ characters.');
  $id = 'u' . bin2hex(random_bytes(5));
  $doc = ['id' => $id, 'name' => $name, 'email' => $email, 'role' => 'admin', 'active' => true, 'pw' => hashPw($pw), 'created' => date('Y-m-d'), '_t' => (int)(microtime(true) * 1000000)];
  $pdo->exec('BEGIN IMMEDIATE');
  if ($pdo->query("SELECT 1 FROM docs WHERE c='users' LIMIT 1")->fetchColumn()) { $pdo->exec('ROLLBACK'); fail(409, 'An administrator already exists. Reload and sign in.'); }
  putDoc($pdo, 'users', $id, jenc($doc));
  $st = isset($b->starter) && is_object($b->starter) ? (array)$b->starter : [];
  foreach ($st as $c => $arr) {
    if (!in_array($c, COLS, true) || $c === 'users' || !is_array($arr)) continue; $t = (int)(microtime(true) * 1000000);
    foreach ($arr as $o) { if (!is_object($o) || !isset($o->id) || !preg_match('~^[A-Za-z0-9_.-]{1,64}$~', (string)$o->id)) continue; if (!isset($o->_t)) $o->_t = $t++; $j = jenc($o); if (strlen($j) < MAX_DOC) putDoc($pdo, $c, (string)$o->id, $j); }
  }
  $pdo->exec('COMMIT'); newSession($pdo, $id); out(['user' => ['id' => $id]]);
}
if (!$sess) fail(401, 'auth');
$me = $sess['user'];
if ($b->op === 'logout') { $pdo->prepare('DELETE FROM sessions WHERE h=?')->execute([$sess['h']]); setCookieTok('', 0); out(['ok' => true]); }
if ($b->op === 'password') {
  $old = (string)($b->old ?? ''); $nw = (string)($b->new ?? '');
  if (strlen($nw) < 8 || strlen($nw) > 200) fail(400, 'Use at least 8 characters.');
  if (!checkPw($old, $me['pw'] ?? null)) fail(403, 'Your current password is incorrect.');
  $u = $me; $u['pw'] = hashPw($nw); unset($u['mustChange']);
  putDoc($pdo, 'users', $me['id'], jenc($u));
  $pdo->prepare('DELETE FROM sessions WHERE uid=? AND h<>?')->execute([$me['id'], $sess['h']]); out(['ok' => true]);
}

$c = (string)($b->c ?? ''); $id = (string)($b->id ?? '');
if (!in_array($c, COLS, true) || !preg_match('~^[A-Za-z0-9_.-]{1,64}$~', $id) || !in_array($b->op, ['set', 'delete'], true)) fail(400, 'Bad request');
$nuObj = null; $nu = null;
if ($b->op === 'set') {
  if (!isset($b->data) || !is_object($b->data)) fail(400, 'Bad request');
  $nuObj = $b->data; $nuObj->id = $id; $j = jenc($nuObj); if ($j === '' || strlen($j) > MAX_DOC) fail(413, 'Document too large'); $nu = json_decode($j, true);
}
$pdo->exec('BEGIN IMMEDIATE');
try {
  $old = getDoc($pdo, $c, $id); $own = $me['role'] === 'candidate' ? ownCand($pdo, $me['id']) : null;
  if ($b->op === 'set' && $old !== null && count(keysChanged($old, $nu)) === 0) { $pdo->exec('COMMIT'); out(['ok' => true, 'ignored' => true]); }
  $d = authorize($me, $own, $c, (string)$b->op, $old, $nu);
  if ($d === 'deny') { $pdo->exec('ROLLBACK'); fail(403, 'You do not have permission to make that change.'); }
  if ($d === 'ignore') { $pdo->exec('COMMIT'); out(['ok' => true, 'ignored' => true]); }
  if ($b->op === 'delete') {
    if ($c === 'users' && $id === $me['id']) { $pdo->exec('ROLLBACK'); fail(403, 'You cannot delete your own account.'); }
    delDoc($pdo, $c, $id); $pdo->exec('COMMIT'); out(['ok' => true]);
  }
  if ($c === 'users') {
    if (array_key_exists('pw', $nu) && !(is_string($nu['pw']) && preg_match('~^[0-9a-f]{32}:[0-9a-f]{64}$~', $nu['pw']))) { $pdo->exec('ROLLBACK'); fail(400, 'Bad request'); }
    if (!in_array($nu['role'] ?? '', ROLES, true)) { $pdo->exec('ROLLBACK'); fail(400, 'Bad request'); }
    if (!array_key_exists('pw', $nu) && $old && isset($old['pw'])) { $nuObj->pw = $old['pw']; }
    if ($id === $me['id'] && (($nu['role'] ?? '') !== $me['role'] || ($nu['active'] ?? true) === false)) { $pdo->exec('ROLLBACK'); fail(403, 'You cannot change your own role or deactivate yourself.'); }
  }
  putDoc($pdo, $c, $id, jenc($nuObj));
  $pdo->exec('COMMIT');
} catch (Throwable $e) { try { $pdo->exec('ROLLBACK'); } catch (Throwable $e2) {} fail(500, 'Server error.'); }
if ($c === 'notifs' && $old === null && !empty($nu['u']) && !empty($nu['m'])) mailTo($pdo, (string)$nu['u'], 'Coastal Onboard Tracking', substr((string)$nu['m'], 0, 500));
out(['ok' => true]);
