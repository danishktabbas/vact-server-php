<?php
// Plain-PHP test runner — no PHPUnit dependency, matching the package's
// no-dependency promise. Run: php tests/run.php
declare(strict_types=1);
require __DIR__ . '/../src/VactServer.php';

use Vact\VactServer;
use Vact\VactServerError;
use function Vact\verifyVactWebhook;

$pass = 0; $fail = 0;
function check(string $name, callable $fn): void {
    global $pass, $fail;
    try { $fn(); $pass++; echo "  ok   $name\n"; }
    catch (\Throwable $e) { $fail++; echo "  FAIL $name — {$e->getMessage()}\n"; }
}
function assertTrue(bool $c, string $m = 'assertion failed'): void {
    if (!$c) throw new \RuntimeException($m);
}
function assertThrows(callable $fn, string $m): void {
    try { $fn(); } catch (\Throwable) { return; }
    throw new \RuntimeException("expected a throw: $m");
}

$APP_ID = 'vact_app_' . str_repeat('a', 24);
$APP_SECRET = 'vact_live_' . str_repeat('b', 16) . '_' . str_repeat('C', 43);
$SIGNING = 'vact_whsec_' . str_repeat('d', 43);

function sign(string $body, string $secret, ?int $ts = null): array {
    $ts = (string) ($ts ?? time());
    return [
        'Vact-Timestamp' => $ts,
        'Vact-Signature' => 'v1=' . hash_hmac('sha256', $ts . '.' . $body, $secret),
    ];
}

echo "credentials\n";
check('rejects a malformed appId', fn() => assertThrows(
    fn() => new VactServer('nope', $GLOBALS['APP_SECRET']), 'bad appId'));
check('rejects a malformed appSecret', fn() => assertThrows(
    fn() => new VactServer($GLOBALS['APP_ID'], 'nope'), 'bad secret'));
check('requires https', fn() => assertThrows(
    fn() => new VactServer($GLOBALS['APP_ID'], $GLOBALS['APP_SECRET'], 'http://vact.online'), 'http'));
check('never exposes the secret in debug output', function () {
    $v = new VactServer($GLOBALS['APP_ID'], $GLOBALS['APP_SECRET']);
    assertTrue(!str_contains(print_r($v, true), $GLOBALS['APP_SECRET']), 'secret leaked');
});
check('rejects an invalid userId before any request', function () {
    $v = new VactServer($GLOBALS['APP_ID'], $GLOBALS['APP_SECRET']);
    foreach (['', str_repeat('a', 65), 'has space'] as $bad) {
        assertThrows(fn() => $v->createAccessToken($bad), "userId '$bad'");
    }
});

echo "webhook signature\n";
check('accepts a genuine delivery', function () {
    $b = '{"eventId":"call_1"}';
    $e = verifyVactWebhook($b, sign($b, $GLOBALS['SIGNING']), $GLOBALS['SIGNING']);
    assertTrue($e['eventId'] === 'call_1', 'wrong payload');
});
check('rejects a tampered body', function () {
    $b = '{"amount":1}';
    $h = sign($b, $GLOBALS['SIGNING']);
    assertThrows(fn() => verifyVactWebhook('{"amount":9999}', $h, $GLOBALS['SIGNING']), 'tampered');
});
check('rejects the wrong secret', function () {
    $b = '{}';
    assertThrows(fn() => verifyVactWebhook($b, sign($b, $GLOBALS['SIGNING']),
        'vact_whsec_' . str_repeat('e', 43)), 'wrong secret');
});
check('rejects a replayed delivery', function () {
    $b = '{}';
    $old = time() - 3600;
    assertThrows(fn() => verifyVactWebhook($b, sign($b, $GLOBALS['SIGNING'], $old),
        $GLOBALS['SIGNING']), 'replay');
});
check('rejects missing or malformed headers', function () {
    $b = '{}';
    foreach ([[], ['Vact-Timestamp' => '123'], ['Vact-Signature' => 'v1=a'],
              ['Vact-Timestamp' => 'nan', 'Vact-Signature' => 'v1=a']] as $h) {
        assertThrows(fn() => verifyVactWebhook($b, $h, $GLOBALS['SIGNING']), 'bad headers');
    }
});
check('matches headers case-insensitively', function () {
    $b = '{}';
    $h = [];
    foreach (sign($b, $GLOBALS['SIGNING']) as $k => $v) $h[strtolower($k)] = $v;
    verifyVactWebhook($b, $h, $GLOBALS['SIGNING']);
});
check('accepts the pre-rename headers', function () {
    $b = '{}';
    $s = sign($b, $GLOBALS['SIGNING']);
    verifyVactWebhook($b, [
        'CallerPro-Timestamp' => $s['Vact-Timestamp'],
        'CallerPro-Signature' => $s['Vact-Signature'],
    ], $GLOBALS['SIGNING']);
});
check('surfaces a stable error code', function () {
    try { verifyVactWebhook('{}', [], $GLOBALS['SIGNING']); }
    catch (VactServerError $e) { assertTrue($e->errorCode === 'invalid_signature', $e->errorCode); return; }
    throw new \RuntimeException('no error raised');
});

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
