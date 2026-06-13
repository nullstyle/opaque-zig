import { define } from "../../../utils.ts";
import { getOpaqueServer } from "../../../server/opaque_server.ts";

/**
 * POST /api/login/start
 * Body:     { username, ke1 }       (ke1 is base64, 96 bytes)
 * Response: { loginId, ke2 }        (ke2 is base64, 320 bytes)
 *
 * For an UNKNOWN username the server synthesizes a fake record so the KE2 is
 * well-formed and indistinguishable (anti-enumeration); a real loginId is still
 * issued and login then fails at finish. See server/opaque_server.ts.
 */
export const handler = define.handlers({
  async POST(ctx) {
    const server = await getOpaqueServer();

    let body: { username?: unknown; ke1?: unknown };
    try {
      body = await ctx.req.json();
    } catch {
      return Response.json({ error: "invalid JSON" }, { status: 400 });
    }

    const { username, ke1 } = body;
    if (typeof username !== "string" || username.length === 0) {
      return Response.json({ error: "missing username" }, { status: 400 });
    }
    if (typeof ke1 !== "string" || ke1.length === 0) {
      return Response.json({ error: "missing ke1" }, { status: 400 });
    }

    try {
      const { loginId, ke2B64 } = server.loginStart(username, ke1);
      return Response.json({ loginId, ke2: ke2B64 });
    } catch {
      // A malformed KE1 surfaces here as a wasm protocol error.
      return Response.json({ error: "login start failed" }, { status: 400 });
    }
  },
});
