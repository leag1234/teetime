<?php

declare(strict_types=1);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'status' => 'error',
        'error' => 'Only POST is supported',
    ]);
    exit;
}

$rawBody = file_get_contents('php://input');
if ($rawBody === false) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Unable to read request body']);
    exit;
}

$body = json_decode($rawBody, true);
if (!is_array($body)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Request body must be valid JSON']);
    exit;
}

$token = $body['token'] ?? null;
$expectedNonceBase64 = $body['expectedNonce'] ?? null;
$includePayload = (bool)($body['includePayload'] ?? false);

if (!is_string($token) || $token === '') {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Missing token']);
    exit;
}

if (!is_string($expectedNonceBase64) || $expectedNonceBase64 === '') {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'error' => 'Missing expectedNonce']);
    exit;
}

try {
    $result = verifyPlayIntegrityToken($token, $expectedNonceBase64, $includePayload);
    echo json_encode(['status' => 'ok'] + $result, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
} catch (RuntimeException $exception) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'error' => $exception->getMessage(),
    ]);
}

/**
 * @param string $token Integrity token (JWS)
 * @param string $expectedNonceBase64 Base64 (URL-safe) encoded nonce expected by the server
 * @param bool $includePayload Whether to include the decoded payload in the response
 * @return array<string, mixed>
 */
function verifyPlayIntegrityToken(string $token, string $expectedNonceBase64, bool $includePayload = false): array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        throw new RuntimeException('Malformed integrity token');
    }

    [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

    $headerJson = base64UrlDecode($encodedHeader);
    $payloadJson = base64UrlDecode($encodedPayload);
    $signature = base64UrlDecode($encodedSignature);

    $header = json_decode($headerJson, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($header) || empty($header['x5c'][0])) {
        throw new RuntimeException('Integrity token missing signing certificate');
    }

    $leafCertificate = formatCertificate($header['x5c'][0]);
    $publicKey = openssl_pkey_get_public($leafCertificate);
    if ($publicKey === false) {
        throw new RuntimeException('Unable to parse signing certificate');
    }

    $verified = openssl_verify($encodedHeader . '.' . $encodedPayload, $signature, $publicKey, OPENSSL_ALGO_SHA256);
    if ($verified !== 1) {
        throw new RuntimeException('Signature verification failed');
    }

    $payload = json_decode($payloadJson, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($payload)) {
        throw new RuntimeException('Integrity payload is not valid JSON');
    }

    $external = $payload['tokenPayloadExternal'] ?? $payload;
    if (!is_array($external)) {
        throw new RuntimeException('tokenPayloadExternal is not present');
    }

    validateNonce($external, $expectedNonceBase64);

    $summary = extractSummary($external);
    if ($includePayload) {
        $summary['payload'] = $external;
    }

    return $summary;
}

function base64UrlDecode(string $value): string
{
    $remainder = strlen($value) % 4;
    if ($remainder) {
        $value .= str_repeat('=', 4 - $remainder);
    }
    $decoded = base64_decode(strtr($value, '-_', '+/'), true);
    if ($decoded === false) {
        throw new RuntimeException('Base64 decode failed');
    }
    return $decoded;
}

function formatCertificate(string $base64Cert): string
{
    $clean = preg_replace('/\s+/', '', $base64Cert);
    if ($clean === null) {
        throw new RuntimeException('Invalid certificate encoding');
    }
    return "-----BEGIN CERTIFICATE-----\n" . chunk_split($clean, 64, "\n") . "-----END CERTIFICATE-----\n";
}

/**
 * @param array<string, mixed> $payload
 */
function validateNonce(array $payload, string $expectedNonceBase64): void
{
    if (empty($payload['requestDetails']['nonce'])) {
        throw new RuntimeException('Payload missing request nonce');
    }

    $nonceFromPayload = $payload['requestDetails']['nonce'];
    $expectedNonce = base64UrlDecode($expectedNonceBase64);

    $expectedHash = hash('sha256', $expectedNonce, true);
    $payloadHash = null;

    if (isset($payload['requestDetails']['requestHash'])) {
        $payloadHash = base64UrlDecode($payload['requestDetails']['requestHash']);
    }

    if ($expectedNonceBase64 === $nonceFromPayload) {
        return; // Nonce matches exactly – ok
    }

    if ($payloadHash !== null && hash_equals($expectedHash, $payloadHash)) {
        return; // Matches SHA-256 digest in payload
    }

    throw new RuntimeException('Nonce mismatch');
}

/**
 * @param array<string, mixed> $payload
 * @return array<string, mixed>
 */
function extractSummary(array $payload): array
{
    $device = $payload['deviceIntegrity']['deviceRecognitionVerdict'] ?? [];
    $app = $payload['appIntegrity']['appRecognitionVerdict'] ?? null;
    $account = $payload['accountDetails']['appLicensingVerdict'] ?? null;
    $timestamp = $payload['requestDetails']['timestampMillis'] ?? null;
    $package = $payload['requestDetails']['requestPackageName'] ?? null;

    return [
        'deviceVerdicts' => $device,
        'appRecognitionVerdict' => $app,
        'accountLicensingVerdict' => $account,
        'requestPackageName' => $package,
        'requestTimestampMillis' => $timestamp,
    ];
}
