/**
 * Browser island: the OPAQUE CLIENT.
 *
 * Runs entirely in the browser. The password is used ONLY for local WASM calls
 * and is never placed in any request body — only OPAQUE protocol messages
 * (base64) leave the browser. This is the whole point of OPAQUE: the server
 * never sees the password.
 *
 * Flow (RFC 9807, ABI v4):
 *   Register: registrationStart -> POST /api/register/start -> registrationFinish
 *             -> POST /api/register/finish
 *   Login:    loginStart        -> POST /api/login/start    -> loginFinish
 *             -> POST /api/login/finish (server sets the session cookie)
 * On login success the server's Set-Cookie establishes the session, so we just
 * navigate to /dashboard.
 *
 * The wasm is fetched once (lazily) from /opaque.wasm (copied into static/ by
 * `deno task setup`). The browser wrapper lives in the repository's web/ dir;
 * Vite bundles this island and follows that relative import into the client
 * bundle (it is dependency-free TS, so it bundles cleanly).
 */
import { useSignal } from "@preact/signals";
import {
  base64ToBytes,
  buildLoginFinishInput,
  buildLoginStartInput,
  buildRegistrationFinishInput,
  buildRegistrationStartInput,
  bytesToBase64,
  bytesToHex,
  instantiateOpaqueWasm,
  type OpaqueWasm,
  utf8Encode,
} from "../../../web/browser.ts";
import { OPAQUE_ABI_VERSION, OPAQUE_CONTEXT, SIZES } from "../shared/opaque.ts";

/** Generate `n` cryptographically-random bytes via the browser CSPRNG. */
function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Lazily instantiate the browser wasm once and reuse it. */
let opaquePromise: Promise<OpaqueWasm> | null = null;
function getOpaque(): Promise<OpaqueWasm> {
  if (opaquePromise === null) {
    opaquePromise = (async () => {
      const opaque = await instantiateOpaqueWasm("/opaque.wasm");
      opaque.assertVersion(OPAQUE_ABI_VERSION);
      return opaque;
    })();
  }
  return opaquePromise;
}

async function postJson(
  path: string,
  body: Record<string, unknown>,
): Promise<{ status: number; data: Record<string, unknown> }> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let data: Record<string, unknown> = {};
  const text = await res.text();
  if (text.length > 0) {
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      data = {};
    }
  }
  return { status: res.status, data };
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`server response missing "${key}"`);
  }
  return value;
}

export default function AuthForm() {
  const username = useSignal("");
  const password = useSignal("");
  const status = useSignal("");
  const busy = useSignal(false);
  // First bytes of the login export_key, shown as a "key only you can derive".
  const exportKeyPreview = useSignal("");

  function setStatus(message: string): void {
    status.value = message;
  }

  // ---- Register ----------------------------------------------------------
  async function register(): Promise<void> {
    const user = username.value.trim();
    if (user.length === 0 || password.value.length === 0) {
      setStatus("Enter a username and password.");
      return;
    }
    busy.value = true;
    exportKeyPreview.value = "";
    setStatus("Registering (OPAQUE, hashing password locally)…");

    // password bytes live only in the browser; never sent over the wire.
    const pw = utf8Encode(password.value);
    let startOut: Uint8Array | undefined;
    let finishOut: Uint8Array | undefined;
    try {
      const opaque = await getOpaque();

      // 1. registrationStart -> client_registration_state[32] || RegistrationRequest[32]
      startOut = opaque.registrationStart(
        buildRegistrationStartInput({
          blindUniform: random(SIZES.blindUniform),
          password: pw,
        }),
      );
      const clientRegistrationState = startOut.slice(0, SIZES.blind);
      const registrationRequest = startOut.slice(SIZES.blind);

      // POST /api/register/start -> { registrationResponse }
      const startResp = await postJson("/api/register/start", {
        username: user,
        registrationRequest: bytesToBase64(registrationRequest),
      });
      if (startResp.status !== 200) {
        throw new Error(stringError(startResp.data, "register start failed"));
      }
      const registrationResponse = base64ToBytes(
        requireString(startResp.data, "registrationResponse"),
      );

      // 2. registrationFinish -> RegistrationRecord[192] || export_key[64] (Argon2id; tens of ms)
      finishOut = opaque.registrationFinish(
        buildRegistrationFinishInput({
          blind: clientRegistrationState,
          envelopeNonce: random(SIZES.nonce),
          registrationResponse,
          password: pw,
          context: OPAQUE_CONTEXT,
        }),
      );
      const registrationRecord = finishOut.slice(0, SIZES.registrationRecord);
      // export_key (finishOut[192..256]) is the client's derived app key; never sent.

      const finishResp = await postJson("/api/register/finish", {
        username: user,
        registrationRecord: bytesToBase64(registrationRecord),
      });
      if (finishResp.status !== 200 || finishResp.data.ok !== true) {
        throw new Error(stringError(finishResp.data, "register finish failed"));
      }

      setStatus(`Registered "${user}". Now log in.`);
    } catch (error) {
      setStatus(`Registration failed: ${(error as Error).message}`);
    } finally {
      pw.fill(0);
      startOut?.fill(0);
      finishOut?.fill(0);
      busy.value = false;
    }
  }

  // ---- Login -------------------------------------------------------------
  async function login(): Promise<void> {
    const user = username.value.trim();
    if (user.length === 0 || password.value.length === 0) {
      setStatus("Enter a username and password.");
      return;
    }
    busy.value = true;
    exportKeyPreview.value = "";
    setStatus("Logging in (OPAQUE, hashing password locally)…");

    const pw = utf8Encode(password.value);
    let startOut: Uint8Array | undefined;
    let finishOut: Uint8Array | undefined;
    try {
      const opaque = await getOpaque();

      // 1. loginStart -> ClientLoginState[160] || KE1[96]
      startOut = opaque.loginStart(
        buildLoginStartInput({
          blindUniform: random(SIZES.blindUniform),
          clientNonce: random(SIZES.nonce),
          clientKeyshareSeed: random(SIZES.seed),
          password: pw,
        }),
      );
      const clientLoginState = startOut.slice(0, SIZES.clientLoginState);
      const ke1 = startOut.slice(SIZES.clientLoginState);

      // POST /api/login/start -> { loginId, ke2 }
      const startResp = await postJson("/api/login/start", {
        username: user,
        ke1: bytesToBase64(ke1),
      });
      if (startResp.status !== 200) {
        throw new Error(stringError(startResp.data, "login start failed"));
      }
      const loginId = requireString(startResp.data, "loginId");
      const ke2 = base64ToBytes(requireString(startResp.data, "ke2"));

      // 2. loginFinish -> KE3[64] || session_key[64] || export_key[64].
      //    A wrong password or anti-enumeration fake record fails the KE2 MAC here.
      try {
        finishOut = opaque.loginFinish(
          buildLoginFinishInput({
            clientLoginState,
            ke2,
            password: pw,
            context: OPAQUE_CONTEXT,
          }),
        );
      } catch {
        throw new Error("wrong username or password");
      }
      const ke3 = finishOut.slice(0, SIZES.ke3);
      // session_key = finishOut[64..128] (not needed client-side for the cookie session).
      const exportKey = finishOut.slice(SIZES.ke3 + SIZES.sessionKey);
      const exportKeyHexPrefix = bytesToHex(exportKey.slice(0, 8));

      // POST /api/login/finish -> server verifies KE3 MAC and sets the session cookie.
      const finishResp = await postJson("/api/login/finish", {
        loginId,
        ke3: bytesToBase64(ke3),
      });
      if (finishResp.status !== 200 || finishResp.data.ok !== true) {
        throw new Error("wrong username or password");
      }

      // Show the export key prefix as "a key only you can derive".
      exportKeyPreview.value = exportKeyHexPrefix;
      setStatus("Authenticated. Redirecting to your dashboard…");
      globalThis.location.href = "/dashboard";
    } catch (error) {
      setStatus(`Login failed: ${(error as Error).message}`);
    } finally {
      pw.fill(0);
      startOut?.fill(0);
      finishOut?.fill(0);
      busy.value = false;
    }
  }

  return (
    <div class="card">
      <label class="field">
        <span>Username</span>
        <input
          type="text"
          autocomplete="username"
          value={username.value}
          disabled={busy.value}
          onInput={(
            e,
          ) => (username.value = (e.target as HTMLInputElement).value)}
        />
      </label>
      <label class="field">
        <span>Password</span>
        <input
          type="password"
          autocomplete="current-password"
          value={password.value}
          disabled={busy.value}
          onInput={(
            e,
          ) => (password.value = (e.target as HTMLInputElement).value)}
        />
      </label>
      <div class="actions">
        <button
          type="button"
          class="btn"
          disabled={busy.value}
          onClick={register}
        >
          Register
        </button>
        <button
          type="button"
          class="btn btn-primary"
          disabled={busy.value}
          onClick={login}
        >
          Log in
        </button>
      </div>
      {status.value && <p class="status">{status.value}</p>}
      {exportKeyPreview.value && (
        <p class="note">
          export_key (first 8 bytes): <code>{exportKeyPreview.value}</code>{" "}
          — a key only you can derive from your password; it could encrypt local
          data.
        </p>
      )}
    </div>
  );
}

function stringError(data: Record<string, unknown>, fallback: string): string {
  return typeof data.error === "string" ? data.error : fallback;
}
