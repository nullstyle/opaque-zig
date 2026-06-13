/**
 * Acceptance test for the OPAQUE Deno CLI — no HTTP server required.
 *
 * Runs a FULL in-wasm OPAQUE round trip with the PRODUCTION Argon2id exports
 * (registrationFinish / loginFinish / serverLoginStart — the exact ones the CLI
 * uses), driving both the client and the server side inside the same wasm
 * instance, and asserts the client and server session keys match byte-for-byte.
 *
 * This deliberately mirrors opaque_cli.ts: identical wrapper builders, identical
 * `context`, randomness from crypto.getRandomValues with the same field sizes.
 * It validates the real CLI crypto path end to end (the only difference vs. the
 * CLI is that the messages travel in-process instead of over fetch()).
 *
 * Run:  deno test --allow-read --allow-env self_test.ts
 *
 * Server-side OPRF-key derivation needs a credential_identifier (the username
 * bytes) + a global oprf_seed[64]; the long-term server keypair is a valid
 * ristretto255 (sk, pk) pair. We reuse the RFC 9807 Appendix C.1.1 server
 * keypair + oprf_seed constants — their validity is independent of the KSF, so
 * they work unchanged on the production Argon2id path (the smoke test in
 * tests/deno/wasm_smoke_test.ts uses the same constants).
 */

import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  buildServerRegistrationResponseInput,
  hexToBytes,
  OPAQUE_WASM_V3,
  utf8Encode,
} from "../../../web/opaque_wasm.ts";
import { instantiateOpaqueWasmFromFile } from "../../../web/deno.ts";

// Dependency-free assert (matches the repo convention of no Deno std imports),
// so the self-test runs with just `deno test --allow-read --allow-env`.
function assertEquals(actual: unknown, expected: unknown, message?: string): void {
  if (actual !== expected) {
    throw new Error(
      `assertEquals failed${message ? ` (${message})` : ""}: expected ${expected}, got ${actual}`,
    );
  }
}

const CONTEXT = utf8Encode("opaque-zig-fullstack-v1");

// RFC 9807 C.1.1 long-term server material (valid ristretto255 keypair; the
// oprf_seed is global, used to derive each per-credential OPRF key).
const SERVER_PRIVATE_KEY = hexToBytes(
  "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d",
);
const SERVER_PUBLIC_KEY = hexToBytes(
  "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
);
const OPRF_SEED = hexToBytes(
  "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc6" +
    "5347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef",
);

function resolveWasmPath(): URL {
  const envPerm = Deno.permissions.querySync({ name: "env", variable: "OPAQUE_WASM_PATH" });
  if (envPerm.state === "granted") {
    const override = Deno.env.get("OPAQUE_WASM_PATH");
    if (override !== undefined && override !== "") {
      return new URL(override, `file://${Deno.cwd()}/`);
    }
  }
  return new URL("../../../zig-out/wasm/opaque.wasm", import.meta.url);
}

function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

Deno.test("CLI wrapper path: production Argon2id round trip, client and server session keys match", async () => {
  const opaque = await instantiateOpaqueWasmFromFile(resolveWasmPath());
  opaque.assertVersion(4);

  const username = "alice@example.com";
  const credentialIdentifier = utf8Encode(username); // server: credential_identifier = username bytes
  const password = utf8Encode("correct horse battery staple");

  // ---- REGISTRATION (mirrors CLI register) -------------------------------

  // Client: registrationStart(blindUniform[64] + password)
  const regStartOut = opaque.registrationStart(
    buildRegistrationStartInput({
      blindUniform: random(OPAQUE_WASM_V3.blindUniform),
      password,
    }),
  );
  assertEquals(regStartOut.byteLength, OPAQUE_WASM_V3.blind + OPAQUE_WASM_V3.registrationRequest);
  const clientRegistrationState = regStartOut.slice(0, OPAQUE_WASM_V3.blind);
  const registrationRequest = regStartOut.slice(OPAQUE_WASM_V3.blind);

  // Exercise the base64 hop the CLI does over the wire (client -> server).
  const registrationRequestWire = base64ToBytes(bytesToBase64(registrationRequest));

  // Server: serverRegistrationResponse(registration_request + server_pk + cred_id + oprf_seed)
  const registrationResponse = opaque.serverRegistrationResponse(
    buildServerRegistrationResponseInput({
      registrationRequest: registrationRequestWire,
      serverPublicKey: SERVER_PUBLIC_KEY,
      credentialIdentifier,
      oprfSeed: OPRF_SEED,
    }),
  );
  assertEquals(registrationResponse.byteLength, OPAQUE_WASM_V3.registrationResponse);

  // Client: registrationFinish(state + envelope_nonce + response + password + CONTEXT)
  const regFinishOut = opaque.registrationFinish(
    buildRegistrationFinishInput({
      blind: clientRegistrationState,
      envelopeNonce: random(OPAQUE_WASM_V3.nonce),
      registrationResponse: base64ToBytes(bytesToBase64(registrationResponse)),
      password,
      context: CONTEXT,
    }),
  );
  assertEquals(regFinishOut.byteLength, OPAQUE_WASM_V3.registrationRecord + OPAQUE_WASM_V3.hash);
  const registrationRecord = regFinishOut.slice(0, OPAQUE_WASM_V3.registrationRecord);
  const registrationExportKey = regFinishOut.slice(OPAQUE_WASM_V3.registrationRecord);

  // ---- LOGIN (mirrors CLI login) -----------------------------------------

  // Client: loginStart(blindUniform[64] + client_nonce[32] + client_keyshare_seed[32] + password)
  const loginStartOut = opaque.loginStart(
    buildLoginStartInput({
      blindUniform: random(OPAQUE_WASM_V3.blindUniform),
      clientNonce: random(OPAQUE_WASM_V3.nonce),
      clientKeyshareSeed: random(OPAQUE_WASM_V3.seed),
      password,
    }),
  );
  assertEquals(loginStartOut.byteLength, OPAQUE_WASM_V3.clientLoginState + OPAQUE_WASM_V3.ke1);
  const clientLoginState = loginStartOut.slice(0, OPAQUE_WASM_V3.clientLoginState);
  const ke1 = loginStartOut.slice(OPAQUE_WASM_V3.clientLoginState);

  // Server: serverLoginStart(server_sk + server_pk + record + oprf_seed + KE1 + nonces + cred_id + CONTEXT)
  const serverLoginStartOut = opaque.serverLoginStart(
    buildServerLoginStartInput({
      serverPrivateKey: SERVER_PRIVATE_KEY,
      serverPublicKey: SERVER_PUBLIC_KEY,
      registrationRecord,
      oprfSeed: OPRF_SEED,
      ke1: base64ToBytes(bytesToBase64(ke1)),
      maskingNonce: random(OPAQUE_WASM_V3.nonce),
      serverNonce: random(OPAQUE_WASM_V3.nonce),
      serverKeyshareSeed: random(OPAQUE_WASM_V3.seed),
      credentialIdentifier,
      context: CONTEXT,
    }),
  );
  assertEquals(serverLoginStartOut.byteLength, OPAQUE_WASM_V3.serverLoginState + OPAQUE_WASM_V3.ke2);
  const serverLoginState = serverLoginStartOut.slice(0, OPAQUE_WASM_V3.serverLoginState);
  const ke2 = serverLoginStartOut.slice(OPAQUE_WASM_V3.serverLoginState);

  // Client: loginFinish(client_login_state + KE2 + password + CONTEXT)
  const loginFinishOut = opaque.loginFinish(
    buildLoginFinishInput({
      clientLoginState,
      ke2: base64ToBytes(bytesToBase64(ke2)),
      password,
      context: CONTEXT,
    }),
  );
  assertEquals(
    loginFinishOut.byteLength,
    OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey + OPAQUE_WASM_V3.hash,
  );
  const ke3 = loginFinishOut.slice(0, OPAQUE_WASM_V3.ke3);
  const clientSessionKey = loginFinishOut.slice(
    OPAQUE_WASM_V3.ke3,
    OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey,
  );
  const loginExportKey = loginFinishOut.slice(OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey);

  // Server: serverLoginFinish(server_login_state + KE3) -> session_key
  const serverSessionKey = opaque.serverLoginFinish(
    buildServerLoginFinishInput({
      serverLoginState,
      ke3: base64ToBytes(bytesToBase64(ke3)),
    }),
  );
  assertEquals(serverSessionKey.byteLength, OPAQUE_WASM_V3.sessionKey);

  // ---- Assertions: mutual authentication ---------------------------------
  assertEquals(
    bytesToHex(clientSessionKey),
    bytesToHex(serverSessionKey),
    "client and server session keys must match byte-for-byte",
  );
  // The export_key derived at login must equal the one from registration.
  assertEquals(
    bytesToHex(loginExportKey),
    bytesToHex(registrationExportKey),
    "login export_key must match registration export_key",
  );

  console.log(`session_key (client == server) = ${bytesToHex(clientSessionKey)}`);
});

Deno.test("wrong password fails the KE2 MAC at loginFinish (no session key)", async () => {
  const opaque = await instantiateOpaqueWasmFromFile(resolveWasmPath());
  opaque.assertVersion(4);

  const credentialIdentifier = utf8Encode("bob");
  const password = utf8Encode("right password");
  const wrongPassword = utf8Encode("WRONG password");

  // Enroll with the correct password.
  const regStartOut = opaque.registrationStart(
    buildRegistrationStartInput({ blindUniform: random(64), password }),
  );
  const clientRegistrationState = regStartOut.slice(0, OPAQUE_WASM_V3.blind);
  const registrationRequest = regStartOut.slice(OPAQUE_WASM_V3.blind);
  const registrationResponse = opaque.serverRegistrationResponse(
    buildServerRegistrationResponseInput({
      registrationRequest,
      serverPublicKey: SERVER_PUBLIC_KEY,
      credentialIdentifier,
      oprfSeed: OPRF_SEED,
    }),
  );
  const registrationRecord = opaque
    .registrationFinish(
      buildRegistrationFinishInput({
        blind: clientRegistrationState,
        envelopeNonce: random(32),
        registrationResponse,
        password,
        context: CONTEXT,
      }),
    )
    .slice(0, OPAQUE_WASM_V3.registrationRecord);

  // Log in with the WRONG password.
  const loginStartOut = opaque.loginStart(
    buildLoginStartInput({
      blindUniform: random(64),
      clientNonce: random(32),
      clientKeyshareSeed: random(32),
      password: wrongPassword,
    }),
  );
  const clientLoginState = loginStartOut.slice(0, OPAQUE_WASM_V3.clientLoginState);
  const ke1 = loginStartOut.slice(OPAQUE_WASM_V3.clientLoginState);
  const ke2 = opaque
    .serverLoginStart(
      buildServerLoginStartInput({
        serverPrivateKey: SERVER_PRIVATE_KEY,
        serverPublicKey: SERVER_PUBLIC_KEY,
        registrationRecord,
        oprfSeed: OPRF_SEED,
        ke1,
        maskingNonce: random(32),
        serverNonce: random(32),
        serverKeyshareSeed: random(32),
        credentialIdentifier,
        context: CONTEXT,
      }),
    )
    .slice(OPAQUE_WASM_V3.serverLoginState);

  let threw = false;
  try {
    opaque.loginFinish(
      buildLoginFinishInput({ clientLoginState, ke2, password: wrongPassword, context: CONTEXT }),
    );
  } catch {
    threw = true; // expected: protocol/MAC failure
  }
  assertEquals(threw, true, "loginFinish must reject a wrong password");
});
