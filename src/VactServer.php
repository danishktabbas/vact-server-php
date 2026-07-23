<?php

declare(strict_types=1);

namespace Vact;

/**
 * A VACT API error. The code is stable; the message is human-readable.
 */
class VactServerError extends \RuntimeException
{
    public function __construct(
        public readonly string $code,
        string $message,
        public readonly ?int $status = null
    ) {
        parent::__construct($message);
    }
}

/**
 * Server-only VACT client.
 *
 * Mints one-time access tokens, configures webhooks and deletes user data.
 * Uses only ext-curl and ext-json, so it adds no Composer dependencies.
 *
 * The App Secret belongs on your server and nowhere else. There is
 * deliberately no method here that hands it to a client.
 */
final class VactServer
{
    private const APP_ID_RE = '/^(?:vact_app_[a-f0-9]{24}|cp_app_[a-f0-9]{24}|app_[a-f0-9]{8})$/';
    private const APP_SECRET_RE = '/^(?:vact|cp)_(?:test|live)_[a-f0-9]{16}_[A-Za-z0-9_-]{32,128}$/';
    private const USER_ID_RE = '/^[A-Za-z0-9_.-]{1,64}$/';

    private string $apiBase;

    public function __construct(
        private readonly string $appId,
        private readonly string $appSecret,
        string $apiBase = 'https://vact.online',
        private readonly int $timeoutSeconds = 10
    ) {
        if (!preg_match(self::APP_ID_RE, $appId)) {
            throw new \InvalidArgumentException('invalid appId');
        }
        if (!preg_match(self::APP_SECRET_RE, $appSecret)) {
            throw new \InvalidArgumentException('invalid appSecret');
        }
        if (!str_starts_with($apiBase, 'https://')) {
            throw new \InvalidArgumentException('apiBase must use https');
        }
        $this->apiBase = rtrim($apiBase, '/');
    }

    /** Keeps the App Secret out of var_dump() and stack traces. */
    public function __debugInfo(): array
    {
        return ['appId' => $this->appId, 'appSecret' => '[redacted]'];
    }

    /**
     * Mints a one-time access token for one of *your* users.
     *
     * Call this only after your own authentication has decided who the user
     * is — the token is scoped to whatever $userId you pass.
     *
     * @param list<string>|null $permissions
     * @param list<string>|null $allowedCalleeIds
     */
    public function createAccessToken(
        string $userId,
        ?array $permissions = null,
        ?array $allowedCalleeIds = null,
        ?int $sessionTtlSeconds = null
    ): array {
        if (!preg_match(self::USER_ID_RE, $userId)) {
            throw new \InvalidArgumentException('invalid userId');
        }
        $body = ['userId' => $userId];
        if ($permissions !== null) {
            $body['permissions'] = array_values($permissions);
        }
        if ($allowedCalleeIds !== null) {
            $body['allowedCalleeIds'] = array_values($allowedCalleeIds);
        }
        if ($sessionTtlSeconds !== null) {
            $body['sessionTtlSeconds'] = $sessionTtlSeconds;
        }
        return $this->request('POST', "/v1/apps/{$this->appId}/tokens", $body);
    }

    /**
     * Registers your webhook endpoint and returns its signing secret.
     *
     * Store the returned signingSecret beside your App Secret — it is shown
     * once and is what proves a delivery really came from VACT.
     */
    public function configureWebhook(string $url): array
    {
        if (!str_starts_with($url, 'https://')) {
            throw new \InvalidArgumentException('webhook URL must use https');
        }
        return $this->request('PUT', "/v1/apps/{$this->appId}/webhook", ['url' => $url]);
    }

    public function disableWebhook(): array
    {
        return $this->request('DELETE', "/v1/apps/{$this->appId}/webhook", null);
    }

    /** Recent delivery attempts, so you can see what your endpoint missed. */
    public function listWebhookDeliveries(int $limit = 50, bool $failedOnly = false): array
    {
        $query = '?limit=' . $limit . ($failedOnly ? '&failed=true' : '');
        return $this->request('GET', "/v1/apps/{$this->appId}/webhook-deliveries{$query}", null);
    }

    /**
     * Erases and anonymizes everything VACT holds for one of your users.
     *
     * The server clears as much as it can per request; this keeps calling
     * until the deletion is complete, because a partially erased user is not
     * a satisfied deletion request.
     */
    public function deleteUserData(string $userId, int $maxRequests = 20): array
    {
        if (!preg_match(self::USER_ID_RE, $userId)) {
            throw new \InvalidArgumentException('invalid userId');
        }
        $totals = [
            'sessionsDeleted' => 0,
            'callsDeleted' => 0,
            'logsAnonymized' => 0,
            'billingEventsAnonymized' => 0,
            'requests' => 0,
            'truncated' => true,
        ];
        $path = "/v1/apps/{$this->appId}/users/{$userId}";
        for ($i = 0; $i < $maxRequests; $i++) {
            $result = $this->request('DELETE', $path, ['confirm' => true], 120);
            foreach (['sessionsDeleted', 'callsDeleted', 'logsAnonymized', 'billingEventsAnonymized'] as $key) {
                $totals[$key] += (int) ($result[$key] ?? 0);
            }
            $totals['requests']++;
            if (($result['truncated'] ?? false) !== true) {
                $totals['truncated'] = false;
                break;
            }
        }
        return $totals;
    }

    private function request(string $method, string $path, ?array $body, ?int $timeout = null): array
    {
        $headers = [
            // The secret travels only here, on your server's outbound call.
            'Authorization: Bearer ' . $this->appSecret,
            'Accept: application/json',
        ];
        $payload = null;
        if ($body !== null) {
            $payload = json_encode($body, JSON_THROW_ON_ERROR);
            $headers[] = 'Content-Type: application/json';
        }

        $curl = curl_init($this->apiBase . $path);
        $options = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $timeout ?? $this->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        // Assigned rather than spread: CURLOPT_* are integer constants, and
        // the spread operator renumbers integer keys, which would silently
        // drop the request body.
        if ($payload !== null) {
            $options[CURLOPT_POSTFIELDS] = $payload;
        }
        curl_setopt_array($curl, $options);
        $raw = curl_exec($curl);
        if ($raw === false) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new VactServerError('network_error', 'Could not reach VACT: ' . $error);
        }
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);

        $decoded = json_decode((string) $raw, true) ?: [];
        if ($status < 200 || $status >= 300) {
            $detail = $decoded['error'] ?? $decoded;
            throw new VactServerError(
                (string) ($detail['code'] ?? 'request_failed'),
                (string) ($detail['message'] ?? 'VACT request failed'),
                $status
            );
        }
        return $decoded;
    }
}

/**
 * Verifies a webhook signature and returns the decoded event.
 *
 * Pass the **exact raw request body** (file_get_contents('php://input')).
 * Re-encoding a parsed array changes the bytes and the signature will not
 * match.
 *
 * @param array<string,string> $headers
 * @throws VactServerError if the signature is missing, stale or wrong.
 */
function verifyVactWebhook(
    string $rawBody,
    array $headers,
    string $signingSecret,
    int $toleranceSeconds = 300,
    ?int $now = null
): array {
    $lookup = [];
    foreach ($headers as $key => $value) {
        // Header case varies by SAPI; normalise before looking anything up.
        $lookup[strtolower((string) $key)] = (string) $value;
    }
    // CallerPro-* are the pre-rename header names, still accepted.
    $timestamp = $lookup['vact-timestamp'] ?? $lookup['callerpro-timestamp'] ?? null;
    $signature = $lookup['vact-signature'] ?? $lookup['callerpro-signature'] ?? null;

    if ($timestamp === null || $signature === null) {
        throw new VactServerError('invalid_signature', 'signature headers are missing');
    }
    if (!str_starts_with($signature, 'v1=')) {
        throw new VactServerError('invalid_signature', 'unsupported signature version');
    }
    if (!preg_match('/^\d+$/', $timestamp)) {
        throw new VactServerError('invalid_signature', 'timestamp is not a number');
    }

    $current = $now ?? time();
    if (abs($current - (int) $timestamp) > $toleranceSeconds) {
        // An old delivery replayed by an attacker looks otherwise valid.
        throw new VactServerError('invalid_signature', 'timestamp is outside the tolerance window');
    }

    $expected = hash_hmac('sha256', $timestamp . '.' . $rawBody, $signingSecret);
    if (!hash_equals($expected, substr($signature, 3))) {
        throw new VactServerError('invalid_signature', 'signature is invalid');
    }

    return json_decode($rawBody ?: '{}', true, 512, JSON_THROW_ON_ERROR);
}
