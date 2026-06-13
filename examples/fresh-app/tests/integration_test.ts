/**
 * End-to-end integration test for the OPAQUE Fresh demo.
 *
 * This boots the BUILT Fresh app (`_fresh/server.js`) as a subprocess on a
 * fixed port, then drives a FULL OPAQUE flow as a simulated browser: it runs
 * the CLIENT operations in a SECOND wasm instance (loaded via the same
 * `../../web/deno.ts` server wrapper) and talks to the running server's /api
 * routes over real HTTP — exactly what the browser island does, minus the DOM.
 *
 * Assertions:
 *   1. register -> login -> capture Set-Cookie -> GET /dashboard with the cookie
 *      shows the username (200, not a redirect).
 *   2. wrong password -> /api/login/finish returns 401.
 *   3. unknown user -> /api/login/start returns a well-formed 320-byte KE2 (200),
 *      but /api/login/finish returns 401 (anti-enumeration).
 *
 * Prereqs (the test verifies/produces them): `deno task setup` (copies the wasm)
 * and `deno task build` (produces _fresh/server.js). The test runs the build
 * itself if _fresh/server.js is missing, and copies the wasm if static/ lacks it.
 *
 * Run:  deno test -A tests/integration_test.ts
 */

import {
  base64ToBytes,
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  bytesToBase64,
  OPAQUE_WASM_V4,
  type OpaqueWasm,
} from "../../../web/opaque_wasm.ts";
import { instantiateOpaqueWasmFromFile } from "../../../web/deno.ts";
import { OPAQUE_CONTEXT } from "../shared/opaque.ts";
import { SESSION_COOKIE } from "../server/session.ts";

const SIZES = OPAQUE_WASM_V4;
const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;

// Dependency-free assertions (matches the repo convention of no std imports).
function assert(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(`assertion failed: ${message}`);
}
function assertEquals(
  actual: unknown,
  expected: unknown,
  message?: string,
): void {
  if (actual !== expected) {
    throw new Error(
      `assertEquals failed${
        message ? ` (${message})` : ""
      }: expected ${expected}, got ${actual}`,
    );
  }
}

function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

const appDir = new URL("..", import.meta.url);
const wasmPath = new URL("../static/opaque.wasm", import.meta.url);

async function exists(url: URL): Promise<boolean> {
  try {
    await Deno.stat(url);
    return true;
  } catch {
    return false;
  }
}

/** Ensure static/opaque.wasm and _fresh/server.js exist (run setup/build if not). */
async function ensureBuilt(): Promise<void> {
  if (!(await exists(wasmPath))) {
    const setup = new Deno.Command(Deno.execPath(), {
      args: ["task", "setup"],
      cwd: appDir,
      stdout: "inherit",
      stderr: "inherit",
    });
    const { code } = await setup.output();
    assertEquals(code, 0, "deno task setup");
  }
  if (!(await exists(new URL("../_fresh/server.js", import.meta.url)))) {
    const build = new Deno.Command(Deno.execPath(), {
      args: ["task", "build"],
      cwd: appDir,
      stdout: "inherit",
      stderr: "inherit",
    });
    const { code } = await build.output();
    assertEquals(code, 0, "deno task build");
  }
}

/** Start `deno serve` on PORT, wait until `/` answers, return a stop fn. */
async function startServer(): Promise<() => Promise<void>> {
  const child = new Deno.Command(Deno.execPath(), {
    args: ["serve", "-A", "--port", String(PORT), "_fresh/server.js"],
    cwd: appDir,
    stdout: "piped",
    stderr: "piped",
  }).spawn();

  // Drain stdout/stderr so the pipes never fill (and surface boot errors).
  const decoder = new TextDecoder();
  let serverLog = "";
  const drain = async (stream: ReadableStream<Uint8Array>) => {
    for await (const chunk of stream) serverLog += decoder.decode(chunk);
  };
  drain(child.stdout);
  drain(child.stderr);

  const stop = async () => {
    try {
      child.kill("SIGTERM");
    } catch { /* already gone */ }
    await child.status;
  };

  // Poll "/" until it responds (server up) or we give up.
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/`, { redirect: "manual" });
      await res.body?.cancel();
      if (res.status > 0) return stop;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  await stop();
  throw new Error(
    `server did not start on ${BASE}\n--- server log ---\n${serverLog}`,
  );
}

async function postJson(
  path: string,
  body: Record<string, unknown>,
  cookie?: string,
): Promise<
  { status: number; data: Record<string, unknown>; setCookie: string | null }
> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (cookie) headers["cookie"] = cookie;
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  if (text.length > 0) {
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      data = { _raw: text };
    }
  }
  return { status: res.status, data, setCookie: res.headers.get("set-cookie") };
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`response missing "${key}": ${JSON.stringify(obj)}`);
  }
  return value;
}

/** Extract `opaque_session=<id>` from a Set-Cookie header for use as a Cookie. */
function sessionCookieFrom(setCookie: string | null): string {
  assert(setCookie !== null, "expected a Set-Cookie header");
  const first = setCookie.split(";")[0];
  assert(
    first.startsWith(`${SESSION_COOKIE}=`),
    `Set-Cookie should set ${SESSION_COOKIE}`,
  );
  return first;
}

// ---- Client OPAQUE ops (mirror islands/AuthForm.tsx) ---------------------

async function clientRegister(
  opaque: OpaqueWasm,
  username: string,
  password: Uint8Array,
): Promise<void> {
  const startOut = opaque.registrationStart(
    buildRegistrationStartInput({
      blindUniform: random(SIZES.blindUniform),
      password,
    }),
  );
  const clientRegistrationState = startOut.slice(0, SIZES.blind);
  const registrationRequest = startOut.slice(SIZES.blind);

  const startResp = await postJson("/api/register/start", {
    username,
    registrationRequest: bytesToBase64(registrationRequest),
  });
  assertEquals(startResp.status, 200, "register/start status");
  const registrationResponse = base64ToBytes(
    requireString(startResp.data, "registrationResponse"),
  );

  const finishOut = opaque.registrationFinish(
    buildRegistrationFinishInput({
      blind: clientRegistrationState,
      envelopeNonce: random(SIZES.nonce),
      registrationResponse,
      password,
      context: OPAQUE_CONTEXT,
    }),
  );
  const registrationRecord = finishOut.slice(0, SIZES.registrationRecord);

  const finishResp = await postJson("/api/register/finish", {
    username,
    registrationRecord: bytesToBase64(registrationRecord),
  });
  assertEquals(finishResp.status, 200, "register/finish status");
  assertEquals(finishResp.data.ok, true, "register/finish ok");
}

/**
 * Drive a login. Returns { finishStatus, setCookie }. `finishOk` controls
 * whether we assert the client loginFinish succeeded (it won't for a wrong
 * password / unknown user — the MAC fails locally before we even POST).
 */
async function clientLogin(
  opaque: OpaqueWasm,
  username: string,
  password: Uint8Array,
): Promise<
  { clientFinishThrew: boolean; finishStatus: number; setCookie: string | null }
> {
  const startOut = opaque.loginStart(
    buildLoginStartInput({
      blindUniform: random(SIZES.blindUniform),
      clientNonce: random(SIZES.nonce),
      clientKeyshareSeed: random(SIZES.seed),
      password,
    }),
  );
  const clientLoginState = startOut.slice(0, SIZES.clientLoginState);
  const ke1 = startOut.slice(SIZES.clientLoginState);

  const startResp = await postJson("/api/login/start", {
    username,
    ke1: bytesToBase64(ke1),
  });
  assertEquals(startResp.status, 200, "login/start status");
  // KE2 must always be a well-formed 320-byte message (even for unknown users).
  const ke2 = base64ToBytes(requireString(startResp.data, "ke2"));
  assertEquals(ke2.byteLength, SIZES.ke2, "KE2 must be 320 bytes");
  const loginId = requireString(startResp.data, "loginId");

  // loginFinish fails the KE2 MAC locally for a wrong password or fake record.
  let ke3: Uint8Array;
  try {
    const finishOut = opaque.loginFinish(
      buildLoginFinishInput({
        clientLoginState,
        ke2,
        password,
        context: OPAQUE_CONTEXT,
      }),
    );
    ke3 = finishOut.slice(0, SIZES.ke3);
  } catch {
    // Client could not produce a valid KE3. Send a bogus KE3 so we still
    // exercise the server's /api/login/finish 401 path (consumes the loginId).
    const bogus = await postJson("/api/login/finish", {
      loginId,
      ke3: bytesToBase64(random(SIZES.ke3)),
    });
    return {
      clientFinishThrew: true,
      finishStatus: bogus.status,
      setCookie: bogus.setCookie,
    };
  }

  const finishResp = await postJson("/api/login/finish", {
    loginId,
    ke3: bytesToBase64(ke3),
  });
  return {
    clientFinishThrew: false,
    finishStatus: finishResp.status,
    setCookie: finishResp.setCookie,
  };
}

// ---- The test ------------------------------------------------------------

Deno.test("OPAQUE Fresh app: full register -> login -> session -> /dashboard, plus failure paths", async () => {
  await ensureBuilt();
  const stop = await startServer();

  // The "browser": a second wasm instance running the CLIENT ops.
  const opaque = await instantiateOpaqueWasmFromFile(wasmPath);
  opaque.assertVersion(4);

  try {
    const username = `alice-${crypto.randomUUID().slice(0, 8)}`;
    const password = new TextEncoder().encode("correct horse battery staple");
    const wrongPassword = new TextEncoder().encode("WRONG password");

    // 1a. Register.
    await clientRegister(opaque, username, password);

    // 1b. Before login, /dashboard with no cookie must redirect to "/".
    const noCookie = await fetch(`${BASE}/dashboard`, { redirect: "manual" });
    await noCookie.body?.cancel();
    assert(
      noCookie.status === 302 || noCookie.status === 307,
      `/dashboard without a session should redirect, got ${noCookie.status}`,
    );
    assertEquals(
      noCookie.headers.get("location"),
      "/",
      "redirect target should be /",
    );

    // 1c. Login with the correct password -> 200 + Set-Cookie.
    const ok = await clientLogin(opaque, username, password);
    assertEquals(
      ok.clientFinishThrew,
      false,
      "client loginFinish should succeed for right password",
    );
    assertEquals(
      ok.finishStatus,
      200,
      "login/finish should be 200 for right password",
    );
    const cookie = sessionCookieFrom(ok.setCookie);

    // 1d. GET /dashboard WITH the cookie -> 200 and shows the username (no redirect).
    const dash = await fetch(`${BASE}/dashboard`, {
      headers: { cookie },
      redirect: "manual",
    });
    const dashHtml = await dash.text();
    assertEquals(
      dash.status,
      200,
      "/dashboard with a valid session should be 200",
    );
    assert(
      dashHtml.includes(username),
      "/dashboard should greet the authenticated username",
    );
    assert(dashHtml.includes("OPAQUE"), "/dashboard should mention OPAQUE");

    // 2. Wrong password -> /api/login/finish 401.
    const bad = await clientLogin(opaque, username, wrongPassword);
    assertEquals(
      bad.finishStatus,
      401,
      "wrong password should yield 401 at login/finish",
    );
    assertEquals(
      bad.setCookie,
      null,
      "no session cookie should be set on a failed login",
    );

    // 3. Unknown user -> well-formed 320-byte KE2 (asserted inside clientLogin), then 401.
    const unknown = await clientLogin(
      opaque,
      `nobody-${crypto.randomUUID().slice(0, 8)}`,
      password,
    );
    assertEquals(
      unknown.finishStatus,
      401,
      "unknown user should yield 401 at login/finish",
    );
    assertEquals(
      unknown.setCookie,
      null,
      "no session cookie for an unknown user",
    );

    // 4. Logout clears the session; /dashboard redirects again.
    const loggedOut = await postJson("/api/logout", {}, cookie);
    assertEquals(loggedOut.status, 200, "logout status");
    const afterLogout = await fetch(`${BASE}/dashboard`, {
      headers: { cookie },
      redirect: "manual",
    });
    await afterLogout.body?.cancel();
    assert(
      afterLogout.status === 302 || afterLogout.status === 307,
      `/dashboard after logout should redirect, got ${afterLogout.status}`,
    );

    // deno-lint-ignore no-console
    console.log(
      `OK: register -> login -> /dashboard (200, greets "${username}"); ` +
        `wrong-password 401; unknown-user well-formed-KE2 then 401; logout redirects.`,
    );
  } finally {
    await stop();
  }
});
