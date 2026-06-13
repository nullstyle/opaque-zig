#!/usr/bin/env -S deno run --allow-read --allow-net --allow-env
/**
 * OPAQUE full-stack Deno CLI.
 *
 * Registers and authenticates against the OPAQUE HTTP server described in
 * ../protocol.md, using the `nullstyle/opaque-zig` WASM module (ABI v3,
 * production Argon2id KSF) via the repository's TypeScript wrappers in web/.
 *
 *   deno run --allow-read --allow-net --allow-env opaque_cli.ts register <username> <password>
 *   deno run --allow-read --allow-net --allow-env opaque_cli.ts login    <username> <password>
 *
 * Environment:
 *   OPAQUE_SERVER     server base URL          (default http://127.0.0.1:8787)
 *   OPAQUE_WASM_PATH  path to opaque.wasm      (default ../../../zig-out/wasm/opaque.wasm,
 *                                               resolved relative to this script)
 *
 * On a successful login it prints, to STDOUT, exactly:
 *
 *   SESSION_KEY <username> <hex(session_key)>
 *
 * and exits 0. A failed login exits non-zero. The 64-byte session key is never
 * sent over the wire; equality of the client and server SESSION_KEY lines is the
 * OPAQUE mutual-authentication proof (see ../protocol.md).
 */

import {
  type OpaqueWasm,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  utf8Encode,
  OPAQUE_WASM_V3,
} from "../../../web/opaque_wasm.ts";
import { instantiateOpaqueWasmFromFile } from "../../../web/deno.ts";

/** Application context, hashed into the AKE transcript. MUST match the server. */
const CONTEXT = utf8Encode("opaque-zig-fullstack-v1");

const DEFAULT_SERVER = "http://127.0.0.1:8787";
const DEFAULT_WASM_PATH = "../../../zig-out/wasm/opaque.wasm";

/** Generate `n` cryptographically-random bytes via the platform CSPRNG. */
function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Resolve the wasm path: OPAQUE_WASM_PATH, else default relative to this file. */
function resolveWasmPath(): URL {
  const override = Deno.env.get("OPAQUE_WASM_PATH");
  if (override !== undefined && override !== "") {
    // Resolve relative to the current working directory (absolute paths pass through).
    return new URL(override, `file://${Deno.cwd()}/`);
  }
  return new URL(DEFAULT_WASM_PATH, import.meta.url);
}

function serverBase(): string {
  return (Deno.env.get("OPAQUE_SERVER") ?? DEFAULT_SERVER).replace(/\/+$/, "");
}

/** POST JSON to `<base><path>` and return the parsed JSON body. */
async function postJson(
  path: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const url = `${serverBase()}${path}`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (cause) {
    throw new Error(`request to ${url} failed: ${(cause as Error).message}`, { cause });
  }

  const text = await response.text();
  let parsed: Record<string, unknown> = {};
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error(`${url} returned non-JSON (HTTP ${response.status}): ${text.slice(0, 200)}`);
    }
  }

  if (!response.ok) {
    const detail = typeof parsed.error === "string" ? parsed.error : text || response.statusText;
    throw new Error(`${url} -> HTTP ${response.status}: ${detail}`);
  }
  return parsed;
}

/** Read a required string field from a JSON object, or throw a clear error. */
function requireString(obj: Record<string, unknown>, key: string, where: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${where} response is missing string field "${key}"`);
  }
  return value;
}

async function register(opaque: OpaqueWasm, username: string, password: Uint8Array): Promise<void> {
  // 1. registrationStart(blindUniform[64] + password) -> state[32] || registration_request[32]
  const startOut = opaque.registrationStart(
    buildRegistrationStartInput({
      blindUniform: random(OPAQUE_WASM_V3.blindUniform),
      password,
    }),
  );
  const clientRegistrationState = startOut.slice(0, OPAQUE_WASM_V3.blind);
  const registrationRequest = startOut.slice(OPAQUE_WASM_V3.blind);

  // POST /register/start { username, registration_request:b64 } -> { registration_response }
  const startResp = await postJson("/register/start", {
    username,
    registration_request: bytesToBase64(registrationRequest),
  });
  const registrationResponse = base64ToBytes(
    requireString(startResp, "registration_response", "/register/start"),
  );

  // 2. registrationFinish(state + envelope_nonce + registration_response + password + context)
  //    -> registration_record[192] || export_key[64].  context is REQUIRED here.
  let finishOut: Uint8Array | undefined;
  try {
    finishOut = opaque.registrationFinish(
      buildRegistrationFinishInput({
        blind: clientRegistrationState,
        envelopeNonce: random(OPAQUE_WASM_V3.nonce),
        registrationResponse,
        password,
        context: CONTEXT,
      }),
    );
    const registrationRecord = finishOut.slice(0, OPAQUE_WASM_V3.registrationRecord);
    // export_key (finishOut[192..256]) is the client's derived app key; not sent.

    // POST /register/finish { username, registration_record:b64 } -> { ok: true }
    await postJson("/register/finish", {
      username,
      registration_record: bytesToBase64(registrationRecord),
    });
  } finally {
    // Wipe secret-bearing buffers (export_key, record, client state) from the JS heap.
    finishOut?.fill(0);
    clientRegistrationState.fill(0);
  }

  console.log(`registered ${username}`);
}

async function login(opaque: OpaqueWasm, username: string, password: Uint8Array): Promise<void> {
  // 1. loginStart(blindUniform[64] + client_nonce[32] + client_keyshare_seed[32] + password)
  //    -> client_login_state[160] || KE1[96]
  const startOut = opaque.loginStart(
    buildLoginStartInput({
      blindUniform: random(OPAQUE_WASM_V3.blindUniform),
      clientNonce: random(OPAQUE_WASM_V3.nonce),
      clientKeyshareSeed: random(OPAQUE_WASM_V3.seed),
      password,
    }),
  );
  const clientLoginState = startOut.slice(0, OPAQUE_WASM_V3.clientLoginState);
  const ke1 = startOut.slice(OPAQUE_WASM_V3.clientLoginState);

  // POST /login/start { username, ke1:b64 } -> { login_id, ke2 }
  const startResp = await postJson("/login/start", {
    username,
    ke1: bytesToBase64(ke1),
  });
  const loginId = requireString(startResp, "login_id", "/login/start");
  const ke2 = base64ToBytes(requireString(startResp, "ke2", "/login/start"));

  // 2. loginFinish(client_login_state + KE2 + password + context)
  //    -> KE3[64] || session_key[64] || export_key[64].  context is REQUIRED here.
  //    A wrong password / fake (unknown-user) record fails the KE2 MAC here.
  let finishOut: Uint8Array | undefined;
  let sessionKeyHex: string | undefined;
  try {
    try {
      finishOut = opaque.loginFinish(
        buildLoginFinishInput({
          clientLoginState,
          ke2,
          password,
          context: CONTEXT,
        }),
      );
    } catch (cause) {
      // A protocol/MAC failure means authentication failed (bad password or
      // anti-enumeration fake record). Report and exit non-zero.
      throw new AuthenticationError((cause as Error).message);
    }

    const ke3 = finishOut.slice(0, OPAQUE_WASM_V3.ke3);
    const sessionKey = finishOut.slice(
      OPAQUE_WASM_V3.ke3,
      OPAQUE_WASM_V3.ke3 + OPAQUE_WASM_V3.sessionKey,
    );
    sessionKeyHex = bytesToHex(sessionKey);

    // POST /login/finish { login_id, ke3:b64 } -> { authenticated: bool }
    const finishResp = await postJson("/login/finish", {
      login_id: loginId,
      ke3: bytesToBase64(ke3),
    });
    if (finishResp.authenticated !== true) {
      throw new AuthenticationError("server reported authenticated=false");
    }
  } finally {
    finishOut?.fill(0);
    clientLoginState.fill(0);
  }

  // Authenticated: prove mutual auth by printing the shared session key (hex).
  console.log(`SESSION_KEY ${username} ${sessionKeyHex}`);
}

/** Distinguishes an authentication failure (non-zero exit) from other errors. */
class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

function usage(): never {
  console.error(
    "usage: opaque_cli.ts <register|login> <username> <password>\n" +
      "  env OPAQUE_SERVER (default http://127.0.0.1:8787), OPAQUE_WASM_PATH",
  );
  Deno.exit(2);
}

async function main(): Promise<void> {
  const [command, username, passwordArg] = Deno.args;
  if (
    (command !== "register" && command !== "login") ||
    typeof username !== "string" ||
    username.length === 0 ||
    typeof passwordArg !== "string"
  ) {
    usage();
  }

  const opaque = await instantiateOpaqueWasmFromFile(resolveWasmPath());
  opaque.assertVersion(3); // require ABI v3 (production Argon2id exports)

  const password = utf8Encode(passwordArg);
  try {
    if (command === "register") {
      await register(opaque, username, password);
    } else {
      await login(opaque, username, password);
    }
  } finally {
    password.fill(0);
  }
}

if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.error(`login failed: ${error.message}`);
      Deno.exit(1);
    }
    console.error(error instanceof Error ? error.message : String(error));
    Deno.exit(1);
  }
}
