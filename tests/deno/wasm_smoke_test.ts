import {
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  hexToBytes,
  instantiateOpaqueWasmFromFile,
  OPAQUE_WASM_V2,
} from "../../web/deno.ts";

Deno.test("WASM wrapper completes registration and login with identity test-vector suite", async () => {
  const opaque = await instantiateOpaqueWasmFromFile(
    new URL("../../zig-out/wasm/opaque.wasm", import.meta.url),
  );

  const password = hex("436f7272656374486f72736542617474657279537461706c65");
  const context = hex("4f50415155452d504f43");
  const credentialIdentifier = hex("31323334");
  const oprfSeed = hex(
    "a78342ab84d3d30f08d5a9630c79bf311c31ed7f85d9d4959bf492ec67" +
      "a0eec8a67dfbf4497248eebd49e878aab173e5e4ff76354288fdd53e949a5f7c9f7f1b",
  );
  const serverPrivateKey = hex(
    "c06139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d564",
  );
  const serverPublicKey = hex(
    "a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031",
  );
  const envelopeNonce = hex(
    "40d6b67fdd7da7c49894750754514dbd2070a407166bd2a5237cca9bf44d6e0b",
  );
  const maskingNonce = hex(
    "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
  );
  const serverNonce = hex(
    "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
  );
  const clientNonce = hex(
    "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc",
  );
  const clientKeyshareSeed = hex(
    "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b",
  );
  const serverKeyshareSeed = hex(
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
  );
  const blindRegistration = hex(
    "c575731ffe1cb0ca5ba63b42c4699767b8b9ab78ba39316ee04baddb2034a70a",
  );
  const blindLogin = hex(
    "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308",
  );
  const registrationResponse = hex(
    "506e8f1b89c098fb89b5b6210a05f7898cafdaea221761e8d5272fc39e0f9f08" +
      "a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031",
  );

  const registrationStart = opaque.registrationStart(buildRegistrationStartInput({
    blindUniform: scalarAsUniform(blindRegistration),
    password,
  }));
  assertLength(registrationStart, OPAQUE_WASM_V2.blind + OPAQUE_WASM_V2.registrationRequest);
  const registrationState = registrationStart.slice(0, OPAQUE_WASM_V2.blind);
  const registrationRequest = registrationStart.slice(OPAQUE_WASM_V2.blind);
  assertEqualBytes(
    registrationRequest,
    hex("26f3dbfd76b8e5f85b4da604f42889a7d4b1bc919f655381a67de02c59fd5436"),
  );

  const registrationFinish = opaque.registrationFinishIdentityTestVector(
    buildRegistrationFinishInput({
      blind: registrationState,
      envelopeNonce,
      registrationResponse,
      password,
      context,
    }),
  );
  assertLength(registrationFinish, OPAQUE_WASM_V2.registrationRecord + OPAQUE_WASM_V2.hash);
  const registrationRecord = registrationFinish.slice(0, OPAQUE_WASM_V2.registrationRecord);

  const loginStart = opaque.loginStart(buildLoginStartInput({
    blindUniform: scalarAsUniform(blindLogin),
    clientNonce,
    clientKeyshareSeed,
    password,
  }));
  assertLength(loginStart, OPAQUE_WASM_V2.clientLoginState + OPAQUE_WASM_V2.ke1);
  const clientLoginState = loginStart.slice(0, OPAQUE_WASM_V2.clientLoginState);
  const ke1 = loginStart.slice(OPAQUE_WASM_V2.clientLoginState);

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
  assertLength(serverLoginStart, OPAQUE_WASM_V2.serverLoginState + OPAQUE_WASM_V2.ke2);
  const serverLoginState = serverLoginStart.slice(0, OPAQUE_WASM_V2.serverLoginState);
  const ke2 = serverLoginStart.slice(OPAQUE_WASM_V2.serverLoginState);

  const loginFinish = opaque.loginFinishIdentityTestVector(buildLoginFinishInput({
    clientLoginState,
    ke2,
    password,
    context,
  }));
  assertLength(loginFinish, OPAQUE_WASM_V2.ke3 + OPAQUE_WASM_V2.sessionKey + OPAQUE_WASM_V2.hash);
  const ke3 = loginFinish.slice(0, OPAQUE_WASM_V2.ke3);
  const clientSessionKey = loginFinish.slice(
    OPAQUE_WASM_V2.ke3,
    OPAQUE_WASM_V2.ke3 + OPAQUE_WASM_V2.sessionKey,
  );

  const serverSessionKey = opaque.serverLoginFinish(buildServerLoginFinishInput({
    serverLoginState,
    ke3,
  }));
  assertEqualBytes(serverSessionKey, clientSessionKey);
});

function hex(value: string): Uint8Array {
  return hexToBytes(value);
}

function scalarAsUniform(scalar: Uint8Array): Uint8Array {
  assertLength(scalar, OPAQUE_WASM_V2.blind);
  const uniform = new Uint8Array(OPAQUE_WASM_V2.blindUniform);
  uniform.set(scalar);
  return uniform;
}

function assertLength(value: Uint8Array, expected: number): void {
  if (value.byteLength !== expected) {
    throw new Error(`expected ${expected} bytes, got ${value.byteLength}`);
  }
}

function assertEqualBytes(actual: Uint8Array, expected: Uint8Array): void {
  assertLength(actual, expected.byteLength);
  for (let i = 0; i < actual.byteLength; i += 1) {
    if (actual[i] !== expected[i]) {
      throw new Error(`byte ${i} differed: expected ${expected[i]}, got ${actual[i]}`);
    }
  }
}
