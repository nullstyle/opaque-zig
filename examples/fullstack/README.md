# Full-stack OPAQUE interoperability example

A working, cross-implementation demonstration of OPAQUE (RFC 9807): a **Go
server** built on [`github.com/bytemare/opaque`](https://github.com/bytemare/opaque)
authenticates two independent clients — a **native Zig CLI** and a
**Deno/WASM CLI** — both built on [`nullstyle/opaque-zig`](../..).

Two independent implementations, written in three languages, complete OPAQUE
registration and login and **agree on the session key** every time. That
agreement is the whole point of OPAQUE: a password-authenticated key exchange
where the server never sees the password and both parties derive the same secret
only on success.

```
                          HTTP + JSON (base64 RFC 9807 messages)
   ┌─────────────────┐                                   ┌──────────────────────────┐
   │ cli-zig (native)│ ──register / login──────────────▶ │  server-go               │
   │  opaque-zig     │                                   │  bytemare/opaque v0.18.0 │
   └─────────────────┘                                   │  (RFC 9807, ristretto255)│
   ┌─────────────────┐                                   │  in-memory record store  │
   │ cli-deno (WASM) │ ──register / login──────────────▶ │                          │
   │  opaque-zig.wasm│                                   └──────────────────────────┘
   └─────────────────┘
```

## Run it

Prerequisites (all already pinned via `mise` in this repo): **Go**, **Deno**, **Zig**.

```sh
./run.sh
```

`run.sh` builds all three components, starts the server, and runs six scenarios,
asserting the client's and server's session keys match for each login:

1. **Zig native ↔ Go** — register + login (`alice`)
2. **Deno/WASM ↔ Go** — register + login (`bob`)
3. **Cross-client** — Zig registers `carol`, **Deno logs her in**
4. **Cross-client (reverse)** — Deno registers `dave`, **Zig logs him in**
5. **Wrong password** is rejected by both clients
6. **Unknown user** is rejected (the server still returns a well-formed `KE2`, so it does not leak which usernames exist)

Expected tail:

```
  7 passed, 0 failed
  ALL GREEN — opaque-zig (Zig + Deno/WASM) interops with bytemare/opaque (Go)
```

## Why it interoperates

Both libraries implement **final RFC 9807** with the `ristretto255-SHA512`
suite, and both are verified byte-exact against the RFC's Appendix C.1.1 test
vector — so they emit identical bytes from identical inputs. Every wire message
is the same size on both sides (registration_request 32, registration_response
64, registration_record 192, KE1 96, KE2 320, KE3 64).

Two facts make the design simple:

- **The KSF (Argon2id) runs only client-side.** The server stores the envelope
  and masking key opaquely and never stretches a password, so the server is
  completely KSF-agnostic. A client can use any KSF and still interoperate.
- **Cross-client works because both opaque-zig clients use identical Argon2id
  parameters** (`argon2id_owasp`: t=2, m=19 MiB, p=1). The native and WASM
  builds derive the same `randomized_password`, so a record created by one is
  usable by the other — verified by scenarios 3 and 4.

The one value that *must* match on every side is the AKE `context`
(`opaque-zig-fullstack-v1`); it is hashed into the transcript and a mismatch
silently breaks the KE2/KE3 MACs.

See [`protocol.md`](protocol.md) for the exact HTTP contract and crypto config.

## Components

| Dir | Stack | OPAQUE role | Notes |
|---|---|---|---|
| [`server-go/`](server-go/) | Go + bytemare/opaque | server | stdlib `net/http`; in-memory record + pending-login store; `GetFakeRecord` for unknown users; `go test ./...` drives a bytemare *client* through the handlers as an isolation check |
| [`cli-zig/`](cli-zig/) | native Zig + opaque-zig | client | path-depends on the repo's `opaque` module; `std.http.Client`; `zig build test` runs an in-process opaque-zig client↔server round trip |
| [`cli-deno/`](cli-deno/) | Deno + opaque-zig WASM | client | uses the production `zig-out/wasm/opaque.wasm` (ABI v3, Argon2id) via `web/` wrappers; `deno test self_test.ts` runs a full in-wasm round trip |

CLI usage (after `run.sh` has built them, or build per-component):

```sh
# native Zig
OPAQUE_SERVER=http://127.0.0.1:8799 cli-zig/zig-out/bin/opaque-cli register alice hunter2
OPAQUE_SERVER=http://127.0.0.1:8799 cli-zig/zig-out/bin/opaque-cli login    alice hunter2

# Deno / WASM
OPAQUE_SERVER=http://127.0.0.1:8799 OPAQUE_WASM_PATH=../../zig-out/wasm/opaque.wasm \
  deno run --allow-read --allow-net --allow-env cli-deno/opaque_cli.ts register bob s3cret
```

## This is a demo, not production

- **No TLS.** OPAQUE protects the password even over plaintext, but a real
  deployment still needs TLS for transport integrity and to bind the channel.
- **The session key is printed locally** by each side only so `run.sh` can prove
  they match; it is never transmitted. Never log or expose session keys for real.
- **Storage is in-memory** and lost on restart; the server keypair and OPRF seed
  are generated fresh each launch (so records do not survive a restart).
- opaque-zig itself is **pre-1.0 and unaudited** — see the repository's
  `SECURITY.md` and `PRODUCTION_REVIEW.md`.
