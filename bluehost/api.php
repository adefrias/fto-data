<?php
// Shared-database API for Company Onboard Tracking (PHP 7.4+ with pdo_sqlite).
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const COLS = ['users','cands','rides','evals','notifs','audit','templates','rtTpls','evTpls','levels','comps','messages','ceTpls','cevals','assigns'];
const IMMUTABLE = ['evals','cevals'];          // submitted evaluations can never be changed or removed
const MAX_DOC = 524288;                         // 512 KB per document

function fail(int $code, string $msg): void { http_response_code($code); echo json_encode(['error'=>$msg]); exit; }

// Same-origin only.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== ($_SERVER['SERVER_NAME'] ?? '') && parse_url($origin, PHP_URL_HOST) !== explode(':', $_SERVER['HTTP_HOST'] ?? '')[0]) fail(403, 'Forbidden');

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
  $pdo->exec('CREATE TABLE IF NOT EXISTS leases(k TEXT PRIMARY KEY, holder TEXT NOT NULL, until_ts INTEGER NOT NULL)');
} catch (Throwable $e) { fail(500, 'Database unavailable. Check that pdo_sqlite is enabled and the data folder is writable.'); }

function revs(PDO $pdo): array { $o=[]; foreach ($pdo->query('SELECT c,n FROM rev') as $r) $o[$r['c']]=(int)$r['n']; return $o; }
function bump(PDO $pdo, string $c): void { $pdo->prepare('INSERT INTO rev(c,n) VALUES(?,1) ON CONFLICT(c) DO UPDATE SET n=n+1')->execute([$c]); }

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
  // ?v=users:5,cands:-1  -> returns collections whose version differs from the client's
  $want = [];
  foreach (explode(',', (string)($_GET['v'] ?? '')) as $p) {
    $kv = explode(':', $p); if (count($kv) === 2 && in_array($kv[0], COLS, true)) $want[$kv[0]] = (int)$kv[1];
  }
  $cur = revs($pdo); $parts = [];
  foreach ($want as $c => $v) {
    $n = $cur[$c] ?? 0; if ($n === $v) continue;
    $st = $pdo->prepare('SELECT id,j FROM docs WHERE c=? ORDER BY id'); $st->execute([$c]); $ds = [];
    foreach ($st as $r) $ds[] = '{"id":' . json_encode($r['id']) . ',"data":' . $r['j'] . '}';
    $parts[] = json_encode($c) . ':{"v":' . $n . ',"docs":[' . implode(',', $ds) . ']}';
  }
  echo '{"cols":{' . implode(',', $parts) . '}}'; exit;
}

if ($method !== 'POST') fail(405, 'Method not allowed');
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0 || ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'onboard') fail(400, 'Bad request');
$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > MAX_DOC + 2048) fail(413, 'Request too large');
$b = json_decode($raw);
if (!is_object($b) || !isset($b->op)) fail(400, 'Bad request');

if ($b->op === 'acquire') {
  $k = (string)($b->k ?? ''); $holder = (string)($b->holder ?? ''); $ttl = max(1000, min(120000, (int)($b->ttlMs ?? 30000)));
  if (!preg_match('~^[A-Za-z0-9_/.-]{1,64}$~', $k) || $holder === '' || strlen($holder) > 64) fail(400, 'Bad request');
  $pdo->exec('BEGIN IMMEDIATE');
  $st = $pdo->prepare('SELECT holder,until_ts FROM leases WHERE k=?'); $st->execute([$k]); $r = $st->fetch(PDO::FETCH_ASSOC);
  $now = (int)(microtime(true) * 1000); $ok = !$r || (int)$r['until_ts'] < $now || $r['holder'] === $holder;
  if ($ok) $pdo->prepare('REPLACE INTO leases(k,holder,until_ts) VALUES(?,?,?)')->execute([$k, $holder, $now + $ttl]);
  $pdo->exec('COMMIT'); echo json_encode(['acquired'=>$ok]); exit;
}

$c = (string)($b->c ?? ''); $id = (string)($b->id ?? '');
if (!in_array($c, COLS, true) || !preg_match('~^[A-Za-z0-9_.-]{1,64}$~', $id)) fail(400, 'Bad request');

$pdo->exec('BEGIN IMMEDIATE');
$st = $pdo->prepare('SELECT 1 FROM docs WHERE c=? AND id=?'); $st->execute([$c, $id]); $exists = (bool)$st->fetchColumn();
if (in_array($c, IMMUTABLE, true) && $exists) { $pdo->exec('COMMIT'); echo json_encode(['ok'=>true,'ignored'=>true]); exit; }
if ($b->op === 'set') {
  if (!isset($b->data) || !is_object($b->data)) { $pdo->exec('ROLLBACK'); fail(400, 'Bad request'); }
  $j = json_encode($b->data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
  if ($j === false || strlen($j) > MAX_DOC) { $pdo->exec('ROLLBACK'); fail(413, 'Document too large'); }
  $pdo->prepare('REPLACE INTO docs(c,id,j) VALUES(?,?,?)')->execute([$c, $id, $j]); bump($pdo, $c);
} elseif ($b->op === 'delete') {
  if ($exists) { $pdo->prepare('DELETE FROM docs WHERE c=? AND id=?')->execute([$c, $id]); bump($pdo, $c); }
} else { $pdo->exec('ROLLBACK'); fail(400, 'Bad request'); }
$pdo->exec('COMMIT'); echo json_encode(['ok'=>true]);
