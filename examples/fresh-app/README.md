# OPAQUE on Fresh (client **and** server in WebAssembly)

A [Deno Fresh](https://fresh.deno.dev/) (2.x) website that does end-to-end
[OPAQUE](https://www.rfc-editor.org/rfc/rfc9807) (RFC 9807) password
authentication using the [`nullstyle/opaque-zig`](../../README.md) library —
compiled to WebAssembly — on **both** ends:

- the **OPAQUE client runs in a browser island** (`islands/AuthForm.tsx`), so
  the password is hashed locally and **never leaves the browser**; only OPAQUE
  protocol messages (base64) are sent;
- the **OPAQUE server runs in Fresh server routes** (`routes/api/**`), verifies
  the login proof, and issues an HttpOnly **session cookie**.

Both ends load the **same** prebuilt `opaque.wasm` (ABI v4, production Argon2id
KSF, ristretto255). The server never sees the password and only stores an OPAQUE
registration record, from which a password cannot be recovered.

## What it demonstrates

- The OPAQUE **client** in a browser island and the OPAQUE **server** in Fresh
  routes, both via the repository's dependency-free TS wrappers in `web/`.
- A real password-authenticated login: register → login → an HttpOnly session
  cookie → a server-protected `/dashboard`.
- **Anti-enumeration**: an unknown username gets an indistinguishable,
  well-formed 320-byte KE2 (the server synthesizes a fake record); login then
  fails exactly like a wrong password does, with no way to tell the two apart.
- The client `export_key` (a key only the user can derive from their password):
  after login the island shows its first bytes as a "could encrypt local data"
  teaser. It is never sent to the server.

## Run it

Requires Deno 2.8.x. The production wasm must already be built at the repo root
(`../../zig-out/wasm/opaque.wasm`); this example does **not** run `zig build`.

```sh
deno task setup     # copies ../../zig-out/wasm/opaque.wasm -> static/opaque.wasm
deno task dev       # Vite dev server (hot reload) — open the printed URL (http://localhost:5173/)
```

Or run the production build:

```sh
deno task setup
deno task build     # vite build -> _fresh/
deno task start     # deno serve -A _fresh/server.js
```

Then open the URL, enter a username + password, click **Register**, then **Log
in**. On success you are redirected to `/dashboard`, which greets you by name.
Click **Log out** to clear the session.

## The flow

```
Browser island (OPAQUE client, WASM)            Fresh routes (OPAQUE server, WASM)
------------------------------------            ---------------------------------
registrationStart(password) ───────────────────►
                                                serverRegistrationResponse()
                            ◄─────────────────── RegistrationResponse
registrationFinish(password) → RegistrationRecord
                            ───────────────────► store record under username

loginStart(password) → KE1  ───────────────────►
                                                serverLoginStart() (or fake record
                                                for unknown user → anti-enumeration)
                            ◄─────────────────── { loginId, KE2 }
loginFinish(password) → KE3 ───────────────────►
                                                serverLoginFinish() verifies KE3 MAC
                            ◄─────────────────── 200 + Set-Cookie (HttpOnly session)
                                                 or 401 on failure
```

The password is used **only** for local WASM calls in the island and is never
placed in any request body. The 64-byte session key derived on each side is the
OPAQUE mutual-authentication proof; the server uses success/failure of the KE3
MAC check to decide whether to mint a session cookie.

## How the WASM is wired

- **Served to the browser**: `deno task setup` copies the prebuilt
  `../../zig-out/wasm/opaque.wasm` to `static/opaque.wasm`. Fresh's
  `staticFiles()` middleware serves it at `/opaque.wasm` with
  `Content-Type: application/wasm`, and the island fetches it lazily on first
  use (`instantiateOpaqueWasm("/opaque.wasm")`, ABI asserted to v4).
- **Read by the server**: `server/opaque_server.ts` reads the same
  `static/opaque.wasm` from disk (`instantiateOpaqueWasmFromBytes`) and keeps a
  process-global OPAQUE server (wasm instance + long-term keypair + oprf seed)
  plus in-memory `users` / `pending` / `sessions` maps.

## Structure

```
deno.json                 tasks (setup, dev, build, start, test, check) + imports
vite.config.ts            Fresh Vite plugin
main.ts                   App: staticFiles() + fsRoutes()
scripts/setup.ts          copies the prebuilt wasm into static/
shared/opaque.ts          shared context constant + ABI sizes (client + server)
server/opaque_server.ts   OPAQUE server singletons + user/pending/session maps
server/session.ts         session-cookie parse/build helpers
islands/AuthForm.tsx      OPAQUE CLIENT (browser): register + login
islands/LogoutButton.tsx  POST /api/logout, then back to /
routes/index.tsx          auth page (redirects to /dashboard if logged in)
routes/dashboard.tsx      PROTECTED page (redirects to / if not logged in)
routes/api/register/start.ts , finish.ts
routes/api/login/start.ts    , finish.ts
routes/api/logout.ts
tests/integration_test.ts boots the built app + drives a full flow over HTTP
```

## API routes (JSON; OPAQUE fields are base64)

- `POST /api/register/start` `{username, registrationRequest}` →
  `{registrationResponse}`. `credential_identifier = utf8(username)`.
  Re-registering a username is **allowed** (overwrite) to keep the demo
  re-runnable.
- `POST /api/register/finish` `{username, registrationRecord}` → `{ok:true}`.
- `POST /api/login/start` `{username, ke1}` → `{loginId, ke2}`. For an unknown
  username a fake 192-byte record (valid random client public key, 64 random
  masking-key bytes, 96-byte zero envelope) is synthesized so the KE2 is
  indistinguishable; a real `loginId` is still issued.
- `POST /api/login/finish` `{loginId, ke3}` → on success `{ok:true}` +
  `Set-Cookie: opaque_session=…; HttpOnly; SameSite=Lax; Path=/`; on failure
  `401 {ok:false}`. The `loginId` is single-use.
- `POST /api/logout` → clears the cookie + server-side session entry.

## Tests / checks

```sh
deno task check     # deno fmt --check + deno lint + deno check (whole app)
deno task test      # deno test -A tests/integration_test.ts
```

`tests/integration_test.ts` builds the app (if needed), boots `_fresh/server.js`
as a subprocess, then drives a full flow as a simulated browser: it runs the
**client** OPAQUE ops in a second wasm instance against the running server's
`/api` routes. It asserts: register → login → capture `Set-Cookie`, then
`GET /dashboard` with the cookie shows the username (200, not a redirect); wrong
password → `/api/login/finish` 401; unknown user → `/api/login/start` returns a
well-formed 320-byte KE2 (200) but `/api/login/finish` 401; and logout
re-protects `/dashboard`.

## Demo, not production

This is a demonstration. Before anything real:

- **All state is in-memory** (`users` / `pending` / `sessions` Maps) and lost on
  restart — use a database.
- **The server keypair and oprf seed are regenerated on every restart**, which
  invalidates every previously stored registration record. Persist them (and
  treat them as long-term secrets).
- **Serve over TLS and add `Secure`** to the session cookie (the cookie is
  HttpOnly + SameSite=Lax here but intentionally not `Secure` so the demo works
  over plain `http://localhost`). Consider a `__Host-` prefix and a short
  `Max-Age` / server-side expiry.
- Add rate limiting, `pending`/`sessions` expiry/eviction, and CSRF defenses as
  appropriate. Passwords and session keys are never logged here — keep it that
  way.
