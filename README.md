# `firstlogicmetalab/vact-server`

Server-only VACT client for PHP. **No Composer dependencies** — just
`ext-curl` and `ext-json`.

```bash
composer require firstlogicmetalab/vact-server
```

Your backend is the only place the App Secret ever lives. It authenticates
your own user, then asks VACT for a short-lived token scoped to them.

```php
use Vact\VactServer;

$vact = new VactServer(
    getenv('VACT_APP_ID'),
    getenv('VACT_APP_SECRET'),
);

// After YOUR login has decided who this is:
$token = $vact->createAccessToken(
    userId: $currentUser->id,
    allowedCalleeIds: ['user_42'],   // optional: restrict who they may call
);

header('Content-Type: application/json');
echo json_encode(['accessToken' => $token['accessToken']]);
```

## Verifying webhooks

Read the **raw body**. Using `$_POST` or a re-encoded array changes the bytes
and the signature will not match.

```php
use function Vact\verifyVactWebhook;
use Vact\VactServerError;

$raw = file_get_contents('php://input');
try {
    $event = verifyVactWebhook($raw, getallheaders(), getenv('VACT_WEBHOOK_SECRET'));
} catch (VactServerError $e) {
    http_response_code(400);   // never process an unverified body
    exit;
}

// Deduplicate on $event['eventId'] — delivery is retried.
if ($event['type'] === 'incoming_call') {
    sendPush($event['data']['toUserId'], $event['data']);
}
http_response_code(200);
```

Verification is timing-safe (`hash_equals`) and rejects deliveries whose
timestamp is more than five minutes old, which stops replay.

## Deleting a user's data

```php
$result = $vact->deleteUserData($userId);   // pages internally until complete
```

Full documentation: <https://vact.online/docs.html>
