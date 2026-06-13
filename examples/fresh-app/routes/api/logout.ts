import { define } from "../../utils.ts";
import { getOpaqueServer } from "../../server/opaque_server.ts";
import { clearSessionCookie, readSessionId } from "../../server/session.ts";

/**
 * POST /api/logout
 * Clears the session cookie and removes the server-side session entry.
 * Response: { ok: true } + Set-Cookie that expires the cookie.
 */
export const handler = define.handlers({
  async POST(ctx) {
    const server = await getOpaqueServer();
    const sessionId = readSessionId(ctx.req);
    server.destroySession(sessionId);
    return Response.json(
      { ok: true },
      { headers: { "Set-Cookie": clearSessionCookie() } },
    );
  },
});
