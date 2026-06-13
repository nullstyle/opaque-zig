# Full-stack OPAQUE interop — HTTP contract

This contract is implemented by **all three** components and must match byte-for-byte:

- `server-go/` — HTTP server using [`github.com/bytemare/opaque`](https://github.com/bytemare/opaque) v0.18.0 (RFC 9807).
- `cli-zig/` — native Zig CLI using `nullstyle/opaque-zig` (the native Zig API).
- `cli-deno/` — Deno CLI using `nullstyle/opaque-zig` via the WASM module + `web/` wrappers.

## Cryptographic configuration (identical on every side)

| Parameter | Value |
|---|---|
| OPRF | ristretto255-SHA512 |
| AKE group | ristretto255 |
| KDF / MAC / Hash | HKDF-SHA512 / HMAC-SHA512 / SHA-512 |
| `context` | ASCII `opaque-zig-fullstack-v1` (hashed into the AKE transcript — a mismatch silently breaks KE2/KE3 MACs) |
| `credential_identifier` | the UTF-8 bytes of `username` |
| client / server identity | omitted → default to the respective public keys |
| KSF (client only) | Argon2id, OWASP params (t=2, m=19456 KiB, p=1). The server never runs the KSF. |

Message sizes (bytes, for sanity checks): registration_request 32, registration_response 64, registration_record 192, KE1 96, KE2 320, KE3 64, session_key 64.

## Transport

HTTP/1.1, `Content-Type: application/json`. Every OPAQUE message is a **standard base64 (padded)** string. Errors use a non-2xx status with `{ "error": "..." }`.

## Endpoints

### `POST /register/start`
```
req: { "username": string, "registration_request": b64(32) }
res: { "registration_response": b64(64) }
```
Server: `credential_identifier = []byte(username)`; derives the per-credential OPRF key from its global `oprf_seed`.

### `POST /register/finish`
```
req: { "username": string, "registration_record": b64(192) }
res: { "ok": true }
```
Server: stores `ClientRecord{ CredentialIdentifier: []byte(username), ClientIdentity: nil, RegistrationRecord }`. Re-registration overwrites (demo convenience).

### `POST /login/start`
```
req: { "username": string, "ke1": b64(96) }
res: { "login_id": string, "ke2": b64(320) }
```
Server: `GenerateKE2(ke1, record)`; stash `{ login_id -> (ClientMAC, SessionSecret, username) }`. For an **unknown** username, respond with a fake record (`GetFakeRecord`) and a real `login_id` so the response is indistinguishable (anti-enumeration); `/login/finish` then fails at the MAC.

### `POST /login/finish`
```
req: { "login_id": string, "ke3": b64(64) }
res (200): { "authenticated": true }
res (401): { "authenticated": false }
```
Server: `LoginFinish(ke3, ClientMAC)`. On success the login session is authenticated and `SessionSecret` is the shared key. Consumes the `login_id`.

### `GET /health`
```
res: { "ok": true, "context": "opaque-zig-fullstack-v1", "suite": "ristretto255-SHA512" }
```

## Proving mutual authentication (demo)

The session key is **never sent over the wire**. Instead, on a successful login both sides print one line to their own stdout/stderr:

```
SESSION_KEY <username> <hex of the 64-byte session key>
```

- The **server** prints it (stderr) in `/login/finish` when `LoginFinish` succeeds, looking up the username via `login_id`.
- The **client** prints it (stdout) after computing its session key from KE3.

The runner (`run.sh`) extracts both lines for a username and asserts the hex is identical — that equality is the OPAQUE mutual-authentication guarantee, demonstrated across two independent implementations.

## Client flow (both CLIs)

Register: `register <username> <password>`
1. `RegistrationRequest` ← start(password)  → `POST /register/start`
2. `RegistrationRecord`, `export_key` ← finish(start-state, registration_response, password) → `POST /register/finish`

Login: `login <username> <password>`
1. `KE1` ← loginStart(password) → `POST /login/start`
2. `KE3`, `session_key` ← loginFinish(login-state, KE2, password) → `POST /login/finish`
3. print `SESSION_KEY <username> <hex(session_key)>`

The CLI is a single process per command, so the start-state is held in memory until finish. Randomness (blinds/nonces/seeds) is generated from a CSPRNG: `std.crypto.random` (native) / `crypto.getRandomValues` (Deno).
