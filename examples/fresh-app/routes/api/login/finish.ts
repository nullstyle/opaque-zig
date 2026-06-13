import { define } from "../../../utils.ts";
import { getOpaqueServer } from "../../../server/opaque_server.ts";
import { buildSessionCookie } from "../../../server/session.ts";

/**
 * POST /api/login/finish
 * Body:     { loginId, ke3 }   (ke3 is base64, 64 bytes)
 * Response: on success -> { ok: true } + Set-Cookie session cookie
 *           on failure -> 401 { ok: false }
 *
 * The loginId is single-use (consumed here regardless of outcome).
 */
export const handler = define.handlers({
  async POST(ctx) {
    const server = await getOpaqueServer();

    let body: { loginId?: unknown; ke3?: unknown };
    try {
      body = await ctx.req.json();
    } catch {
      return Response.json({ error: "invalid JSON" }, { status: 400 });
    }

    const { loginId, ke3 } = body;
    if (typeof loginId !== "string" || loginId.length === 0) {
      return Response.json({ error: "missing loginId" }, { status: 400 });
    }
    if (typeof ke3 !== "string" || ke3.length === 0) {
      return Response.json({ error: "missing ke3" }, { status: 400 });
    }

    let username: string | null;
    try {
      username = server.finishLogin(loginId, ke3);
    } catch {
      // A malformed KE3 (wrong length, bad base64) — treat as auth failure.
      username = null;
    }

    if (username === null) {
      // Wrong password, anti-enumeration fake record, or unknown/expired loginId.
      return Response.json({ ok: false }, { status: 401 });
    }

    const sessionId = server.createSession(username);
    return Response.json(
      { ok: true },
      { headers: { "Set-Cookie": buildSessionCookie(sessionId) } },
    );
  },
});
