# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, minor version bumps may include breaking changes.

## [Unreleased]

Work toward the `0.2.0` release. This is a large hardening pass with breaking
changes to the protocol suite, the public API, and the WASM ABI; the API is
still pre-1.0 and not yet frozen. The library remains unaudited.

### Added

- **ristretto255 AKE group**, now the default suite (`Suite.group`), matching the
  RFC 9807 RECOMMENDED configuration. curve25519 remains selectable.
- **Safe-by-default randomness API**: `createRegistrationRequestRandom`,
  `generateKE1Random`, `generateKE2Random`, `finalizeRegistrationRequestRandom`
  (take a `std.Random` and generate all blinds/nonces/seeds internally), plus
  public `*FromUniform` variants that reduce a 64-byte uniform blind.
- **Client-enumeration resistance**: `createFakeRecord` builds an RFC 9807
  §6.3.2.2 fake credential record so servers can answer unknown-user logins
  indistinguishably.
- **Server-side registration over WASM**: new `serverRegistrationResponse`
  export, completing the Deno/browser server enrollment flow.
- **Server key generation over WASM**: new `serverKeyPair` export (with a
  `serverKeyPairLen` helper) derives the server's long-term ristretto255 DH
  keypair from a 32-byte seed, so a WASM/Deno-hosted server can mint its own
  `server_private_key`/`server_public_key` (previously the server protocol
  exports took the keypair as input but nothing could generate one). Production
  export: no KSF, no caller secrets beyond the seed. The TypeScript wrapper gains
  a matching `serverKeyPair(seed): { sk, pk }` method.
- **Parameterized key stretching**: `Ksf = union(enum){ identity_test_only,
  argon2id: Params }` with named `argon2id_owasp` (t=2, m=19 MiB, p=1) and
  `argon2id_rfc9807` presets.
- Byte-exact RFC 9807 test vectors **C.1.1–C.1.4** (both groups, with and without
  identities), RFC 9497 OPRF vector 2, a hand-rolled-map equivalence test against
  `std`, low-order/invalid-point rejection tests, an Argon2id KSF test, a
  fake-record test, and a runtime canary that fails (rather than silently skips)
  if the OPRF runtime breaks.
- Packaging: `build.zig.zon` + a consumable `opaque` module (`b.addModule`).
- Dual `MIT OR Apache-2.0` license, `SECURITY.md`, this changelog, and an OPAQUE
  threat model (`docs/threat-model.md`).

### Changed

- **WASM ABI v2 → v3** (`version()` returns 3): ristretto255-only; production
  finish paths use Argon2id (OWASP parameters); the unstretched
  `*IdentityTestVector` exports are gated behind `-Dtest-exports` and excluded
  from the production artifact; the linear-memory arena is 32 MiB; out-of-memory
  is reported distinctly. The TypeScript wrapper poisons the instance on a wasm
  trap and requires re-instantiation.
- **WASM ABI v3 → v4** (`version()` returns 4): additive only — adds the
  `serverKeyPair`/`serverKeyPairLen` exports (see Added). Every message byte size
  and every existing export is unchanged from v3. The TypeScript wrapper bumps
  `OPAQUE_WASM_ABI_VERSION` to 4 and adds `OPAQUE_WASM_V4` (an alias of the
  unchanged `OPAQUE_WASM_V3` size table).
- **`Suite.default` now stretches passwords** (Argon2id `argon2id_owasp`); the
  previous identity (no-stretching) default is renamed `identity_test_only`.
- The login/registration password is supplied again at finish and is no longer
  retained in client state (kills a borrowed-slice lifetime footgun).
- `ServerLoginState.session_key` → `unconfirmed_session_key` (only
  `serverFinish`'s return value is a confirmed key).
- The WASM module builds as `ReleaseSafe` by default (was `ReleaseSmall`).
- CI hardening: SHA-pinned actions, an OS matrix, `zig fmt --check`, the fuzz
  battery wired into the gate, and a checksummed WASM artifact upload.

### Security

- **Pervasive secret zeroization** with `std.crypto.secureZero`, including the
  RFC 9807 §4.1.3 wipe of derived intermediates on envelope-recovery and
  server-MAC failure, plus `wipe()` helpers on state structs.
- Constant-time wide scalar reduction (`reduce64`) replacing a variable-time
  big-integer modulo on secret material.
- Bounds-checked WASM input parsing, closing an out-of-bounds read / trap-based
  denial-of-service in `serverRegistrationResponse`.
- Removed dead/footgun code: the dangling-pointer `CleartextCredentials.init`
  and duplicate PascalCase OPRF aliases.
