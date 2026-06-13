import {
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  buildServerRegistrationResponseInput,
  hexToBytes,
  instantiateOpaqueWasmFromFile,
  OPAQUE_WASM_V3,
} from "../../web/deno.ts";

// RFC 9807 Appendix C.1.1 ("OPAQUE-3DH Real Test Vector 1"): ristretto255-SHA512
// OPRF + ristretto255 AKE + Identity KSF, with NO client/server identity. The
// gated *IdentityTestVector wasm exports (built with `-Dtest-exports=true`)
// reproduce this exact vector; the production loginStart/serverRegistrationResponse
// are group-agnostic / ristretto255 and feed it. We assert every published
// output byte-for-byte, not just lengths.
Deno.test("WASM wrapper reproduces RFC 9807 C.1.1 byte-exact (ristretto255 + Identity KSF)", async () => {
  const opaque = await instantiateOpaqueWasmFromFile(resolveWasmUrl());
  opaque.assertVersion(4);

  // --- C.1.1.2 Input Values ---
  const oprfSeed = hex(
    "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b0" +
      "54a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989e" +
      "f",
  );
  const credentialIdentifier = hex("31323334");
  const password = hex("436f7272656374486f72736542617474657279537461706c65");
  const envelopeNonce = hex(
    "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d2" +
      "3ba7a38dfec",
  );
  const maskingNonce = hex(
    "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80" +
      "f612fdfc6d",
  );
  const serverPrivateKey = hex(
    "47451a85372f8b3537e249d7b54188091fb18edde78094b43" +
      "e2ba42b5eb89f0d",
  );
  const serverPublicKey = hex(
    "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a" +
      "382c9b79df1a78",
  );
  const serverNonce = hex(
    "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e" +
      "138e3d4a1",
  );
  const clientNonce = hex(
    "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb38" +
      "0cae6a6cc",
  );
  const clientKeyshareSeed = hex(
    "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf" +
      "1091933541936304b",
  );
  const serverKeyshareSeed = hex(
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a" +
      "1e85ff80da12f982f",
  );
  const blindRegistration = hex(
    "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070" +
      "a265d9c2d6abe01",
  );
  const blindLogin = hex(
    "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4" +
      "b0790308",
  );

  // --- C.1.1.1 Configuration: Context ---
  const context = hex("4f50415155452d504f43");

  // --- C.1.1.4 Output Values (expected, asserted byte-exact below) ---
  const expectedRegistrationRequest = hex(
    "5059ff249eb1551b7ce4991f3336205bde44a105a032e74" +
      "7d21bf382e75f7a71",
  );
  const expectedRegistrationResponse = hex(
    "7408a268083e03abc7097fc05b587834539065e86fb0c7" +
      "b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a3" +
      "82c9b79df1a78",
  );
  const expectedRegistrationUpload = hex(
    "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccb" +
      "accafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e" +
      "66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa8" +
      "2785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfe" +
      "c634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e" +
      "9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5",
  );
  const expectedKe1 = hex(
    "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d" +
      "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29b" +
      "ee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326",
  );
  const expectedKe2 = hex(
    "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb471" +
      "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec6" +
      "0bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced" +
      "4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c" +
      "52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0" +
      "b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f749498" +
      "6fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f197" +
      "1b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852e" +
      "bc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23d" +
      "a246e7bd73b47369169c5c90",
  );
  const expectedKe3 = hex(
    "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2" +
      "661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442",
  );
  const expectedExportKey = hex(
    "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a" +
      "970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f" +
      "16",
  );
  const expectedSessionKey = hex(
    "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214" +
      "a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b" +
      "96f",
  );

  // --- Client: registrationStart (production, ristretto255). The 64-byte
  // uniform blind is the C.1.1 32-byte scalar left-padded into a 64-byte LE
  // buffer; reduced mod L it is identity (the scalar is canonical), so the
  // emitted registration_request matches the vector exactly. ---
  const registrationStart = opaque.registrationStart(buildRegistrationStartInput({
    blindUniform: scalarAsUniform(blindRegistration),
    password,
  }));
  assertLength(
    registrationStart,
    OPAQUE_WASM_V3.blind + OPAQUE_WASM_V3.registrationRequest,
  );
  const registrationState = registrationStart.slice(0, OPAQUE_WASM_V3.blind);
  const registrationRequest = registrationStart.slice(OPAQUE_WASM_V3.blind);
  assertEqualBytes(registrationRequest, expectedRegistrationRequest, "registration_request");

  // --- Server: serverRegistrationResponse (NEW export). Drives enrollment and
  // also strengthens coverage by asserting the response byte-exact. ---
  const registrationResponse = opaque.serverRegistrationResponse(
    buildServerRegistrationResponseInput({
      registrationRequest,
      serverPublicKey,
      credentialIdentifier,
      oprfSeed,
    }),
  );
  assertEqualBytes(registrationResponse, expectedRegistrationResponse, "registration_response");

  // --- Client: registrationFinishIdentityTestVector (Identity KSF). ---
  const registrationFinish = opaque.registrationFinishIdentityTestVector(
    buildRegistrationFinishInput({
      blind: registrationState,
      envelopeNonce,
      registrationResponse,
      password,
      context,
    }),
  );
  assertLength(
    registrationFinish,
    OPAQUE_WASM_V3.registrationRecord + OPAQUE_WASM_V3.hash,
  );
  const registrationRecord = registrationFinish.slice(0, OPAQUE_WASM_V3.registrationRecord);
  const registrationExportKey = registrationFinish.slice(OPAQUE_WASM_V3.registrationRecord);
  // registration_upload in the RFC is the RegistrationRecord.
  assertEqualBytes(registrationRecord, expectedRegistrationUpload, "registration_upload");
  assertEqualBytes(registrationExportKey, expectedExportKey, "export_key (registration)");

  // --- Client: loginStart (production, ristretto255 keyshare). ---
  const loginStart = opaque.loginStart(buildLoginStartInput({
    blindUniform: scalarAsUniform(blindLogin),
    clientNonce,
    clientKeyshareSeed,
    password,
  }));
  assertLength(loginStart, OPAQUE_WASM_V3.clientLoginState + OPAQUE_WASM_V3.ke1);
  const clientLoginState = loginStart.slice(0, OPAQUE_WASM_V3.clientLoginState);
  const ke1 = loginStart.slice(OPAQUE_WASM_V3.clientLoginState);
  assertEqualBytes(ke1, expectedKe1, "KE1");

  // --- Server: serverLoginStartIdentityTestVector (Identity KSF). ---
  const serverLoginStart = opaque.serverLoginStartIdentityTestVector(
    buildServerLoginStartInput({
      serverPrivateKey,
      serverPublicKey,
      registrationRecord,
      oprfSeed,
      ke1,
      maskingNonce,
      serverNonce,
      serverKeyshareSeed,
      credentialIdentifier,
      context,
    }),
  );
  assertLength(serverLoginStart, OPAQUE_WASM_V3.serverLoginState + OPAQUE_WASM_V3.ke2);
  const serverLoginState = serverLoginStart.slice(0, OPAQUE_WASM_V3.serverLoginState);
  const ke2 = serverLoginStart.slice(OPAQUE_WASM_V3.serverLoginState);
  assertEqualBytes(ke2, expectedKe2, "KE2");

  // --- Client: loginFinishIdentityTestVector (Identity KSF). ---
  const loginFinish = opaque.loginFinishIdentityTestVector(buildLoginFinishInput({
    clientLoginState,
    ke2,
    password,
    context,
  }));
  assertLength(
    loginFinish,
    OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey + OPAQUE_WASM_V3.hash,
  );
  const ke3 = loginFinish.slice(0, OPAQUE_WASM_V3.ke3);
  const clientSessionKey = loginFinish.slice(
    OPAQUE_WASM_V3.ke3,
    OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey,
  );
  const loginExportKey = loginFinish.slice(OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey);
  assertEqualBytes(ke3, expectedKe3, "KE3");
  assertEqualBytes(clientSessionKey, expectedSessionKey, "session_key (client)");
  // The login-derived export_key must equal the registration-derived one.
  assertEqualBytes(loginExportKey, expectedExportKey, "export_key (login)");

  // --- Server: serverLoginFinish (production, group-agnostic). ---
  const serverSessionKey = opaque.serverLoginFinish(buildServerLoginFinishInput({
    serverLoginState,
    ke3,
  }));
  assertEqualBytes(serverSessionKey, expectedSessionKey, "session_key (server)");
  // Client and server agree on the session key.
  assertEqualBytes(serverSessionKey, clientSessionKey, "session_key (client == server)");
});

// The smoke test needs a wasm built with `-Dtest-exports=true` (the gated
// *IdentityTestVector exports). The default points at the conventional
// `zig-out/wasm/opaque.wasm`, which the deliverable command populates with the
// test-exports build. The `mise deno-smoke` task instead builds the test-exports
// artifact to a SEPARATE prefix (so it never clobbers / races the production
// `wasm` task in `ci`) and points here via OPAQUE_WASM_PATH. Reading that env var
// is optional: `Deno.permissions.querySync` needs no `--allow-env`, so the
// standalone `deno test --allow-read=.` invocation simply falls back to the
// default path.
function resolveWasmUrl(): URL {
  const fallback = new URL("../../zig-out/wasm/opaque.wasm", import.meta.url);
  const envPerm = Deno.permissions.querySync({ name: "env", variable: "OPAQUE_WASM_PATH" });
  if (envPerm.state !== "granted") {
    return fallback;
  }
  const override = Deno.env.get("OPAQUE_WASM_PATH");
  if (override === undefined || override === "") {
    return fallback;
  }
  return new URL(override, `file://${Deno.cwd()}/`);
}

function hex(value: string): Uint8Array {
  return hexToBytes(value);
}

function scalarAsUniform(scalar: Uint8Array): Uint8Array {
  assertLength(scalar, OPAQUE_WASM_V3.blind);
  // registrationStart/loginStart take a 64-byte uniform blind that is reduced
  // mod L. C.1.1's blind_{registration,login} are 32-byte canonical scalars;
  // placed little-endian in the low 32 bytes (high 32 = 0) they reduce to
  // themselves, so the gated test-vector path reproduces the RFC scalar exactly.
  const uniform = new Uint8Array(OPAQUE_WASM_V3.blindUniform);
  uniform.set(scalar);
  return uniform;
}

function assertLength(value: Uint8Array, expected: number): void {
  if (value.byteLength !== expected) {
    throw new Error(`expected ${expected} bytes, got ${value.byteLength}`);
  }
}

function assertEqualBytes(actual: Uint8Array, expected: Uint8Array, label: string): void {
  if (actual.byteLength !== expected.byteLength) {
    throw new Error(
      `${label}: expected ${expected.byteLength} bytes, got ${actual.byteLength}`,
    );
  }
  for (let i = 0; i < actual.byteLength; i += 1) {
    if (actual[i] !== expected[i]) {
      throw new Error(`${label}: byte ${i} differed: expected ${expected[i]}, got ${actual[i]}`);
    }
  }
}
