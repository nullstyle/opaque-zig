/**
 * Session cookie helpers for the OPAQUE Fresh demo.
 *
 * The session cookie is HttpOnly + SameSite=Lax + Path=/. It is intentionally
 * NOT marked `Secure` here so the demo works over plain http://localhost.
 * PRODUCTION NOTE: serve over TLS and add `Secure` (and consider `__Host-`
 * prefix + a short Max-Age) before deploying anything real.
 */

export const SESSION_COOKIE = "opaque_session";

/** Parse a `Cookie:` header into a name->value map. */
export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name.length > 0) out[name] = decodeURIComponent(value);
  }
  return out;
}

/** Read the session id from a request's Cookie header (or null). */
export function readSessionId(req: Request): string | null {
  return parseCookies(req.headers.get("cookie"))[SESSION_COOKIE] ?? null;
}

/** Build a `Set-Cookie` value that establishes the session cookie. */
export function buildSessionCookie(sessionId: string): string {
  // HttpOnly: not readable from JS. SameSite=Lax: sent on top-level nav.
  // Add `; Secure` here when serving over HTTPS in production.
  return `${SESSION_COOKIE}=${
    encodeURIComponent(sessionId)
  }; HttpOnly; SameSite=Lax; Path=/`;
}

/** Build a `Set-Cookie` value that clears the session cookie. */
export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}
