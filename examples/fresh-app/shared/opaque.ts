/**
 * Shared OPAQUE constants used on BOTH the browser-island client and the
 * Fresh server routes.
 *
 * The wrapper itself lives in the repository's `web/` directory:
 *   - server routes import the loader from `../../web/deno.ts`
 *   - the browser island imports the loader from `../../web/browser.ts`
 * Both re-export `../../web/opaque_wasm.ts` (the dependency-free ABI adapter),
 * so the protocol builders / sizes / base64 helpers are identical on each side.
 *
 * This file only re-exports the constants we want both sides to agree on. Keep
 * it free of any `Deno.*` or browser-only API so it can be imported from a
 * server route AND from a client island.
 */
import { OPAQUE_WASM_V4, utf8Encode } from "../../../web/opaque_wasm.ts";

/**
 * Application `context`, mixed into the OPAQUE AKE transcript. RFC 9807 requires
 * the SAME non-empty context on the client `loginFinish`/`registrationFinish`
 * and the server `serverLoginStart`. Bump the version suffix if the protocol
 * wiring changes.
 */
export const OPAQUE_CONTEXT = utf8Encode("opaque-zig-fresh-v1");

/** ABI v4 byte sizes (ristretto255). Re-exported so both sides use one table. */
export const SIZES = OPAQUE_WASM_V4;

/** The OPAQUE ABI version this app is built against (production + serverKeyPair). */
export const OPAQUE_ABI_VERSION = 4;
