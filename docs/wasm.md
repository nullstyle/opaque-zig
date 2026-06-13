# WASM packaging

This package exposes a small dependency-free TypeScript wrapper for browser and
Deno callers. The wrapper is intentionally byte-oriented: protocol helpers build
binary inputs and return binary outputs, leaving display choices such as hex or
base64 to JavaScript callers.

## Files

- `web/opaque_wasm.ts` contains the shared ABI adapter.
- `web/browser.ts` loads a WASM module from a URL, `Response`, or byte buffer.
- `web/deno.ts` loads a WASM module from a file, URL, or byte buffer.
- `examples/browser/index.html` shows browser usage.

Build output is installed at `zig-out/wasm/opaque.wasm`.

## ABI version and group

`version()` returns the WASM ABI version. The current version is **4**.

Version 4 is an **additive** bump over 3: it adds the `serverKeyPair` export (and
its `serverKeyPairLen` helper) for server long-term key generation. Every message
byte size and existing export is unchanged from version 3.

The ABI is **ristretto255-only**. Both the OPRF (always ristretto255-SHA512)
and the 3DH AKE run on ristretto255 across every export, so the WASM flows are
group-consistent end to end. All message byte sizes are unchanged from v2
(ristretto255 and curve25519 both use 32-byte group elements/keys), so the
framing constants below are identical to the previous version.

## Expected Zig export ABI

### Production exports (always present)

These are the exports of the shipped artifact (`zig build wasm`), and the only
ones the TypeScript wrapper requires when an instance loads:

```zig
memory
allocate(byte_len: u32) u32
free(ptr: u32, byte_len: u32) void
resetAllocator() void
version() u32
registrationRequestLen() u32
registrationResponseLen() u32
registrationRecordLen() u32
ke1Len() u32
ke2Len() u32
ke3Len() u32
serverKeyPairLen() u32
registrationStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32
registrationFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32
serverRegistrationResponse(input_ptr: u32, input_len: u32, out_ptr: u32) i32
serverKeyPair(input_ptr: u32, input_len: u32, out_ptr: u32) i32
loginStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32
loginFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32
serverLoginStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32
serverLoginFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32
```

### Gated test-vector exports (only with `-Dtest-exports=true`)

The following exports run the protocol with the **identity** KSF (no password
stretching) to reproduce the RFC 9807 Appendix **C.1.1** vectors (ristretto255 +
Identity KSF). They are **absent from the production artifact** and are emitted
only when the module is built with `zig build wasm -Dtest-exports=true`:

```zig
registrationFinishIdentityTestVector(input_ptr: u32, input_len: u32, out_ptr: u32) i32
loginFinishIdentityTestVector(input_ptr: u32, input_len: u32, out_ptr: u32) i32
serverLoginStartIdentityTestVector(input_ptr: u32, input_len: u32, out_ptr: u32) i32
```

There is intentionally **no** `loginStartIdentityTestVector`: the identity login
path reuses the production `loginStart` (its ristretto255 keyshare is
group-agnostic) and feeds the identity finishes above. The TypeScript wrapper
treats these three as optional; calling one against a production build throws a
clear error telling you to rebuild with `-Dtest-exports=true`. Do not ship a
wasm built with this flag.

Each protocol function receives an input byte slice and an `out_ptr`. The wrapper
allocates 8 bytes for `out_ptr`. On success, Zig writes:

```text
out_ptr + 0: result_ptr as little-endian u32
out_ptr + 4: result_len as little-endian u32
```

Return `0` for success. Return a non-zero status code for failure; the wrapper
throws `OpaqueWasmError` with the operation name and status code. Status codes
are currently:

```text
0: ok
1: protocol_error
2: invalid_input
3: out_of_memory
```

The wrapper copies the result bytes into JavaScript memory, calls
`free(result_ptr, result_len)`, frees its temporary input and output descriptor
allocations, and resets the arena for the next operation. `free` wipes validated
heap ranges; `resetAllocator` wipes the full heap before rewinding it.

`allocate(0)` may return `0`. Non-empty allocations and non-empty operation
results must return a non-zero pointer.

## Linear memory

The module uses a single fixed 32 MiB linear-memory arena (a
`FixedBufferAllocator`; the module never calls `memory.grow`). The size is driven
by the production KSF: Argon2id with a 19 MiB working set needs an arena large
enough to hold one fill plus the protocol scratch. Because the arena is fixed and
wiped on `resetAllocator`, the wrapper can rely on a stable buffer base and a
clean slate between calls. Several concurrent finishes before a `resetAllocator`
can exhaust the arena; the ABI reports that distinctly as `out_of_memory` (status
`3`) so callers can tell a resource limit apart from a protocol failure.

## Password stretching (KSF)

The production finish/start paths (`registrationFinish`, `loginFinish`,
`serverLoginStart`) use **Argon2id** with the OWASP-recommended parameters:

```text
t (iterations / time cost) = 2
m (memory)                 = 19 MiB
p (parallelism)            = 1
```

This is deliberately CPU- and memory-expensive: each such call performs a full
19 MiB Argon2id fill (hundreds of milliseconds and ~19 MiB of working set on
typical hardware), which is the point — it hardens the password against offline
guessing. Budget for it on the main thread (prefer a worker) and do not call
these in a tight loop. The gated `*IdentityTestVector` exports skip stretching
entirely (identity KSF) and exist only to reproduce RFC vectors.

## Trap poisoning

A wasm trap surfaces in JavaScript as a `WebAssembly.RuntimeError` and leaves the
module's internal `__stack_pointer` corrupt, so the instance is no longer safe to
reuse. When an underlying export call throws a `RuntimeError` (as opposed to a
normal non-zero status, which becomes an `OpaqueWasmError`), the wrapper marks the
instance **poisoned**: it skips the post-call cleanup (to avoid a second trap
masking the first) and rethrows an error explaining that the instance was poisoned
and must be re-instantiated. Every subsequent method on a poisoned instance throws
immediately. Check `opaque.poisoned` if you need to detect this; recover by
discarding the object and instantiating a fresh module. A normal status-code
failure does **not** poison the instance — it stays usable.

## Secret lifetime in JavaScript

Bytes the wrapper returns (export keys, session keys, registration records, KE3
MACs, client/server login state) are copied out of the wasm arena into ordinary
JavaScript `Uint8Array`s. The wasm-side arena is wiped after every call, so no
secret persists in linear memory between calls — but the returned buffers live in
JS garbage-collected memory, which the wrapper cannot wipe and the runtime may
copy while compacting the heap. Treat these buffers as sensitive: zero them
(`buf.fill(0)`) as soon as you are done and do not retain them longer than
necessary. Their lifetime is the caller's responsibility.

## Protocol byte layouts

All integers are big-endian unless the export descriptor above says otherwise.
All random-looking fields must be generated by the caller, typically with
`crypto.getRandomValues()` in browsers or Deno.

`registrationStart` input:

```text
blind_uniform[64] || password
```

Output:

```text
client_registration_state[32] || RegistrationRequest[32]
```

`registrationFinish` input:

```text
client_registration_state[32] ||
envelope_nonce[32] ||
RegistrationResponse[64] ||
opaque16(password) ||
opaque16(context) ||
opaque16(server_identity_or_empty) ||
opaque16(client_identity_or_empty)
```

Output:

```text
RegistrationRecord[192] || export_key[64]
```

`serverRegistrationResponse` input (server-side enrollment; evaluates the OPRF
over the client's blinded message and returns the `RegistrationResponse`):

```text
RegistrationRequest[32] ||
server_public_key[32] ||
opaque16(credential_identifier) ||
oprf_seed[64]
```

The whole input must be consumed exactly (no trailing bytes). The OPRF is always
ristretto255-SHA512, so this export is group-agnostic.

Output:

```text
RegistrationResponse[64]
```

where `RegistrationResponse` is `evaluated_message[32] || server_public_key[32]`.

`serverKeyPair` input (server long-term key generation; derives the ristretto255
DH keypair from a seed, RFC 9807 Section 6.4.1.1):

```text
seed[32]
```

The input must be exactly 32 bytes (any other length returns `invalid_input`).
The seed must be fresh entropy (`crypto.getRandomValues(new Uint8Array(32))`).
Derivation is deterministic and group-fixed (ristretto255). This is a
**production** export: it runs no KSF and handles no caller secrets beyond the
seed, so it ships in the default artifact.

Output:

```text
server_private_key[32] || server_public_key[32]
```

where `server_public_key = basepoint * server_private_key`. Feed `sk` to
`server_private_key` and `pk` to `server_public_key` in `serverLoginStart` /
`serverRegistrationResponse`. Persist the seed (or `sk`) — both are long-term
server secrets; treat them with the same care as any other returned secret.

`loginStart` input:

```text
blind_uniform[64] || client_nonce[32] || client_keyshare_seed[32] || password
```

Output:

```text
ClientLoginState[160] || KE1[96]
```

`ClientLoginState` is:

```text
blind[32] || client_secret[32] || KE1[96]
```

`loginFinish` input:

```text
ClientLoginState[160] ||
KE2[320] ||
opaque16(password) ||
opaque16(context) ||
opaque16(server_identity_or_empty) ||
opaque16(client_identity_or_empty)
```

Output:

```text
KE3[64] || session_key[64] || export_key[64]
```

`serverLoginStart` input:

```text
server_private_key[32] ||
server_public_key[32] ||
RegistrationRecord[192] ||
oprf_seed[64] ||
KE1[96] ||
masking_nonce[32] ||
server_nonce[32] ||
server_keyshare_seed[32] ||
opaque16(credential_identifier) ||
opaque16(context) ||
opaque16(server_identity_or_empty) ||
opaque16(client_identity_or_empty)
```

Output:

```text
ServerLoginState[128] || KE2[320]
```

`ServerLoginState` is:

```text
expected_client_mac[64] || session_key[64]
```

`serverLoginFinish` input:

```text
ServerLoginState[128] || KE3[64]
```

Output:

```text
session_key[64]
```

The production WASM finish paths use Argon2id (see "Password stretching (KSF)"
above) and require callers to pass the same non-empty application `context` on
both client and server operations. Empty identity fields mean "use the protocol
default public key identity"; non-empty fields are explicit identities. The
gated `*IdentityTestVector` exports use the identity KSF (no stretching) for RFC
9807 C.1.1 vectors and compatibility tests only, and are absent from the
production artifact.

## Browser usage

```ts
import {
  bytesToBase64,
  bytesToHex,
  encodeRegistrationStartInput,
  instantiateOpaqueWasm,
  utf8Encode,
} from "./web/browser.ts";

const opaque = await instantiateOpaqueWasm("/zig-out/wasm/opaque.wasm");
opaque.assertVersion(4);

const blind = crypto.getRandomValues(new Uint8Array(64));
const response = opaque.registrationStart(encodeRegistrationStartInput({
  blindUniform: blind,
  password: utf8Encode("correct horse battery staple"),
}));

console.log(bytesToHex(response));
console.log(bytesToBase64(response));
```

The included example imports the wrapper source directly and expects the wrapper
to export binary builders and display helpers such as
`encodeRegistrationStartInput`, `bytesToHex`, and `bytesToBase64`. Use a
TS-aware dev server, or transpile/copy the `web/*.ts` modules to `.js` files and
update the example imports for a plain static server.

If the repository adds a Deno serve task, run it through `mise`:

```sh
mise x -- deno task serve
```

Then open the served `/examples/browser/` path.

## Deno usage

```ts
import {
  buildLoginStartInput,
  instantiateOpaqueWasmFromFile,
  utf8Encode,
} from "./web/deno.ts";

const opaque = await instantiateOpaqueWasmFromFile("./zig-out/wasm/opaque.wasm");
const response = opaque.loginStart(buildLoginStartInput({
  blindUniform: crypto.getRandomValues(new Uint8Array(64)),
  clientNonce: crypto.getRandomValues(new Uint8Array(32)),
  clientKeyshareSeed: crypto.getRandomValues(new Uint8Array(32)),
  password: utf8Encode("correct horse battery staple"),
}));
```

## Local packaging checks

Use `mise` as the command runner when local tools are pinned by the repository:

```sh
mise run wasm
mise run deno-check
mise run deno-smoke
mise run ci
```

Use `act` for GitHub Actions dry-runs when workflows are added:

```sh
mise x -- act
```

These wrappers do not depend on generated bindings, npm packages, or Deno
standard-library imports.
