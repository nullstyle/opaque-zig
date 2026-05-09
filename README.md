# opaque-zig

`opaque-zig` is an early Zig implementation of OPAQUE, the asymmetric password-authenticated key exchange specified by RFC 9807. OPAQUE lets a client authenticate with a password without revealing the password to the server and produces a shared session key after a successful login.

## Status

This package is early-stage cryptographic software. It has not been audited, hardened, or reviewed for production use. Treat it as experimental until the implementation, API, test coverage, and release process mature.

## What is included

- Core OPAQUE registration and login flows: registration request/response/finalize, KE1/KE2/KE3, and server finish.
- RFC-vector-oriented suite components built around Ristretto255-SHA512 OPRF, X25519 key agreement, HKDF-SHA512, HMAC-SHA512, and SHA-512.
- Fixed-size protocol message structs with parse and serialize helpers for registration records, credential messages, and KE messages.
- A WASM export layer for browser and Deno callers.
- Small dependency-free TypeScript wrappers in `web/` for loading the WASM module and calling byte-oriented operations.

## Randomness

Callers must supply all protocol randomness. The Zig API accepts blinds, nonces, envelope nonces, keyshare seeds, server keys, and OPRF seed material as explicit byte arrays. Browser and Deno callers should generate these bytes with a cryptographically secure source such as `crypto.getRandomValues()`. The WASM ABI v2 registration and login-start blind inputs are 64-byte uniform random values.

Never reuse values that are required to be fresh, including OPRF blinds, nonces, envelope nonces, or keyshare seeds.

## WASM, Browser, and Deno

The WASM interface is intentionally byte-oriented. JavaScript callers pass `Uint8Array` inputs to exported operations and receive `Uint8Array` outputs; wrapper helpers build binary operation inputs, and callers should render outputs as encodings such as hex or base64 when displaying them.

Supported WASM operations are:

- `registrationStart`
- `registrationFinish`
- `loginStart`
- `loginFinish`
- `serverLoginStart`
- `serverLoginFinish`

See `docs/wasm.md` for the exact ABI, byte layouts, and browser/Deno loader examples.

The browser/Deno artifact is built at `zig-out/wasm/opaque.wasm`.

## Local Development

This repository uses `mise` to pin and run local tools.

```sh
mise run test
mise run wasm
mise run deno-check
mise run ci
mise run ci-local
```

`mise run test` runs the Zig test suite. `mise run wasm` builds the browser/Deno WASM module. `mise run deno-check` type-checks the TypeScript wrappers. `mise run ci` runs the same checks as GitHub Actions, including tool version visibility. `mise run ci-local` runs the GitHub Actions workflow locally with `act`.
`mise run deno-smoke` loads the built WASM module from Deno and completes an identity-suite registration/login smoke test through the wrapper.
