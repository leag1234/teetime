# Play Integrity verification backend (PHP)

This is a tiny PHP application that verifies Play Integrity tokens returned by the Android client.

## How it works

`public/index.php` exposes a single endpoint that accepts a JSON payload:

```json
{
  "token": "<integrity_token>",
  "expectedNonce": "<base64 raw nonce>",
  "includePayload": true
}
```

- `token` is the JWS returned by the Play Integrity API.
- `expectedNonce` is the original nonce (Base64 URL-safe encoded) that the server expects. The server recomputes `SHA-256` and compares it against the value embedded in the token payload.
- `includePayload` is optional; when `true` the endpoint echoes the decoded payload body for inspection.

The script performs the following steps:

1. Decode the token header/payload and extract the leaf certificate from the `x5c` chain.
2. Verify the JWS signature using `openssl_verify` (RS256).
3. Decode the payload, pull out the external token payload, and validate the nonce.
4. Return a summary of the server-trustworthy verdicts (`device`, `app`, `account`) in JSON.

## Running locally

These snippets assume PHP 8.1+, but the code only uses core functions (`json_decode`, `openssl_verify`).

```bash
php -S 127.0.0.1:8080 -t public
```

Then POST a token for verification:

```bash
curl -X POST http://127.0.0.1:8080/ \
  -H 'Content-Type: application/json' \
  -d '{"token":"<TOKEN>","expectedNonce":"<NONCE>","includePayload":true}'
```

## Production notes

- Harden TLS and authentication (e.g. require an API key) before accepting tokens from devices.
- Cache the Google signing certificate chain if you call the endpoint frequently; this sample trusts the certificate embedded in the JWS.
- Log only anonymised data — Integrity payloads may qualify as personal data.
