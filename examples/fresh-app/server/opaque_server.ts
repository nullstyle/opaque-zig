/**
 * Server-side OPAQUE state for the Fresh demo.
 *
 * Everything here is process-global, in-memory, and regenerated on every
 * restart — fine for a single-process demo, NOT for production (see README).
 * The OPAQUE *server* runs entirely in WASM (ABI v4) via the repository's
 * `web/deno.ts` wrapper; the server never sees the user's password.
 *
 * Singletons created once at module load:
 *   - the OPAQUE wasm instance (read from static/opaque.wasm)
 *   - the long-term server keypair {sk, pk}  (derived from a fresh 32-byte seed)
 *   - the global oprf_seed[64]                (derives each per-credential OPRF key)
 *
 * Maps:
 *   - users:    username -> { credentialIdentifier, registrationRecord[192] }
 *   - pending:  loginId  -> { serverLoginState[128], username }
 *   - sessions: sessionId -> { username, created }
 */
import {
  base64ToBytes,
  buildServerLoginFinishInput,
  buildServerLoginStartInput,
  buildServerRegistrationResponseInput,
  bytesToBase64,
  type OpaqueWasm,
  utf8Encode,
} from "../../../web/opaque_wasm.ts";
import { instantiateOpaqueWasmFromBytes } from "../../../web/deno.ts";
import { OPAQUE_ABI_VERSION, OPAQUE_CONTEXT, SIZES } from "../shared/opaque.ts";

export interface StoredUser {
  credentialIdentifier: Uint8Array;
  registrationRecord: Uint8Array; // 192 bytes
}

interface PendingLogin {
  serverLoginState: Uint8Array; // 128 bytes (expected_client_mac[64] || session_key[64])
  username: string;
  created: number;
}

export interface Session {
  username: string;
  created: number;
}

/** Generate `n` cryptographically-random bytes via the platform CSPRNG. */
function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Resolve the wasm artifact. We read the SAME file the browser fetches
 * (static/opaque.wasm, populated by `deno task setup`).
 *
 * Path resolution has to survive two different runtimes:
 *   - `deno task dev` (Vite): this module loads from its real on-disk path.
 *   - `deno task start` (`deno serve _fresh/server.js`): the build RELOCATES
 *     this module into `_fresh/server/assets/`, so an `import.meta.url`-relative
 *     `../static/opaque.wasm` would point at the wrong place.
 * Both runtimes run with the app root as the CWD, so we anchor on `Deno.cwd()`
 * first and fall back to module-relative + the repo's prebuilt artifact.
 */
async function resolveWasm(): Promise<Uint8Array> {
  const candidates: URL[] = [
    new URL("static/opaque.wasm", `file://${Deno.cwd()}/`),
    new URL("../static/opaque.wasm", import.meta.url),
    // Last resort: the prebuilt artifact at the repository root.
    new URL("../../../zig-out/wasm/opaque.wasm", import.meta.url),
  ];
  let lastErr: unknown;
  for (const url of candidates) {
    try {
      return await Deno.readFile(url);
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(
    `Could not read opaque.wasm. Run \`deno task setup\` to copy it into static/. ` +
      `(last error: ${(lastErr as Error).message})`,
    { cause: lastErr },
  );
}

/**
 * Process-global OPAQUE server: the wasm instance, the long-term keypair, the
 * oprf seed, and the in-memory user/pending/session maps. Instantiated lazily
 * on first use and cached for the lifetime of the process.
 */
export class OpaqueServer {
  readonly opaque: OpaqueWasm;
  readonly sk: Uint8Array; // server private key [32]
  readonly pk: Uint8Array; // server public key  [32]
  readonly oprfSeed: Uint8Array; // [64]

  readonly users = new Map<string, StoredUser>();
  readonly pending = new Map<string, PendingLogin>();
  readonly sessions = new Map<string, Session>();

  private constructor(
    opaque: OpaqueWasm,
    keys: { sk: Uint8Array; pk: Uint8Array },
    oprfSeed: Uint8Array,
  ) {
    this.opaque = opaque;
    this.sk = keys.sk;
    this.pk = keys.pk;
    this.oprfSeed = oprfSeed;
  }

  static async create(): Promise<OpaqueServer> {
    const opaque = await instantiateOpaqueWasmFromBytes(await resolveWasm());
    opaque.assertVersion(OPAQUE_ABI_VERSION);

    // Long-term server keypair from a fresh 32-byte seed (ABI v4 export).
    const keys = opaque.serverKeyPair(random(SIZES.seed));
    // Global OPRF seed (64 bytes); per-credential OPRF keys are derived from it.
    const oprfSeed = random(SIZES.hash);

    return new OpaqueServer(opaque, keys, oprfSeed);
  }

  /** credential_identifier = the UTF-8 bytes of the username (per the spec wiring). */
  private credentialIdentifier(username: string): Uint8Array {
    return utf8Encode(username);
  }

  // ---- Registration ------------------------------------------------------

  /**
   * Server side of registration start (RFC 9807 6.3.1.2): evaluate the OPRF over
   * the client's blinded RegistrationRequest and return the RegistrationResponse
   * (`evaluated_message[32] || server_public_key[32]`, 64 bytes), base64-encoded.
   */
  registrationResponse(
    username: string,
    registrationRequestB64: string,
  ): string {
    const registrationRequest = base64ToBytes(registrationRequestB64);
    const response = this.opaque.serverRegistrationResponse(
      buildServerRegistrationResponseInput({
        registrationRequest,
        serverPublicKey: this.pk,
        credentialIdentifier: this.credentialIdentifier(username),
        oprfSeed: this.oprfSeed,
      }),
    );
    return bytesToBase64(response);
  }

  /**
   * Store a finished RegistrationRecord under `username`. This demo ALLOWS
   * overwrite (re-registering the same username replaces the record); that keeps
   * the demo easy to re-run. A real system would reject duplicate usernames.
   */
  finishRegistration(username: string, registrationRecordB64: string): void {
    const registrationRecord = base64ToBytes(registrationRecordB64);
    if (registrationRecord.byteLength !== SIZES.registrationRecord) {
      throw new Error(
        `registrationRecord must be ${SIZES.registrationRecord} bytes, got ${registrationRecord.byteLength}`,
      );
    }
    this.users.set(username, {
      credentialIdentifier: this.credentialIdentifier(username),
      registrationRecord,
    });
  }

  // ---- Login -------------------------------------------------------------

  /**
   * Server side of login start (RFC 9807 6.4.2.1). Returns `{ loginId, ke2B64 }`.
   *
   * Anti-enumeration: for an UNKNOWN username we synthesize a FAKE record so the
   * KE2 is well-formed and indistinguishable from a real one. The record layout
   * is `client_public_key[32] || masking_key[64] || envelope[96]` (= 192 bytes).
   * We use a valid random ristretto255 point for client_public_key (via
   * serverKeyPair on fresh entropy — its pk is a valid point), 64 random bytes
   * for masking_key, and a 96-byte zero envelope. serverLoginStart still
   * produces a 320-byte KE2 and a real loginId; login then fails at the client
   * loginFinish MAC and again at serverLoginFinish.
   */
  loginStart(
    username: string,
    ke1B64: string,
  ): { loginId: string; ke2B64: string } {
    const ke1 = base64ToBytes(ke1B64);

    const known = this.users.get(username);
    const record = known?.registrationRecord ?? this.fakeRecord();
    const credentialIdentifier = known?.credentialIdentifier ??
      this.credentialIdentifier(username);

    const out = this.opaque.serverLoginStart(
      buildServerLoginStartInput({
        serverPrivateKey: this.sk,
        serverPublicKey: this.pk,
        registrationRecord: record,
        oprfSeed: this.oprfSeed,
        ke1,
        maskingNonce: random(SIZES.nonce),
        serverNonce: random(SIZES.nonce),
        serverKeyshareSeed: random(SIZES.seed),
        credentialIdentifier,
        context: OPAQUE_CONTEXT,
      }),
    );

    const serverLoginState = out.slice(0, SIZES.serverLoginState);
    const ke2 = out.slice(SIZES.serverLoginState);

    const loginId = crypto.randomUUID();
    this.pending.set(loginId, {
      serverLoginState,
      username,
      created: Date.now(),
    });

    return { loginId, ke2B64: bytesToBase64(ke2) };
  }

  /**
   * Server side of login finish (RFC 9807 6.4.3). Verifies the client's KE3 MAC
   * against the pending serverLoginState. Returns the authenticated username on
   * success or `null` on failure (wrong password / fake record / unknown
   * loginId). The loginId is ALWAYS consumed (single-use), success or not.
   */
  finishLogin(loginId: string, ke3B64: string): string | null {
    const pending = this.pending.get(loginId);
    // Single-use: consume the loginId regardless of the outcome.
    this.pending.delete(loginId);
    if (pending === undefined) return null;

    const ke3 = base64ToBytes(ke3B64);
    try {
      // Throws OpaqueWasmError on a MAC mismatch (bad password / fake record).
      const sessionKey = this.opaque.serverLoginFinish(
        buildServerLoginFinishInput({
          serverLoginState: pending.serverLoginState,
          ke3,
        }),
      );
      // We don't need to keep the session key around for the cookie session;
      // wipe it from the JS heap immediately (it's a 64-byte secret).
      sessionKey.fill(0);
    } catch {
      return null;
    } finally {
      // The pending serverLoginState holds the expected client MAC + session
      // key; wipe it now that this login attempt is resolved.
      pending.serverLoginState.fill(0);
    }

    return pending.username;
  }

  /**
   * Build a fake 192-byte RegistrationRecord for anti-enumeration (see
   * loginStart). client_public_key is a valid random ristretto255 point;
   * masking_key is 64 random bytes; envelope is 96 zero bytes.
   */
  private fakeRecord(): Uint8Array {
    const clientPublicKey = this.opaque.serverKeyPair(random(SIZES.seed)).pk; // [32], valid point
    const maskingKey = random(SIZES.mac); // [64]
    const envelope = new Uint8Array(96); // envelope_nonce[32] || auth_tag[64], zeroed

    const record = new Uint8Array(SIZES.registrationRecord); // 192
    record.set(clientPublicKey, 0);
    record.set(maskingKey, SIZES.publicKey); // offset 32
    record.set(envelope, SIZES.publicKey + SIZES.mac); // offset 96
    return record;
  }

  // ---- Sessions ----------------------------------------------------------

  createSession(username: string): string {
    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, { username, created: Date.now() });
    return sessionId;
  }

  getSession(sessionId: string | null | undefined): Session | undefined {
    if (!sessionId) return undefined;
    return this.sessions.get(sessionId);
  }

  destroySession(sessionId: string | null | undefined): void {
    if (!sessionId) return;
    this.sessions.delete(sessionId);
  }
}

/**
 * Module-level singleton promise. The first caller triggers wasm instantiation
 * + key generation; everyone else awaits the same instance.
 */
let serverPromise: Promise<OpaqueServer> | null = null;

export function getOpaqueServer(): Promise<OpaqueServer> {
  if (serverPromise === null) {
    serverPromise = OpaqueServer.create();
  }
  return serverPromise;
}
