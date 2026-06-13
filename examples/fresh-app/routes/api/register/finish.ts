import { define } from "../../../utils.ts";
import { getOpaqueServer } from "../../../server/opaque_server.ts";

/**
 * POST /api/register/finish
 * Body:     { username, registrationRecord }   (registrationRecord is base64, 192 bytes)
 * Response: { ok: true }
 */
export const handler = define.handlers({
  async POST(ctx) {
    const server = await getOpaqueServer();

    let body: { username?: unknown; registrationRecord?: unknown };
    try {
      body = await ctx.req.json();
    } catch {
      return Response.json({ error: "invalid JSON" }, { status: 400 });
    }

    const { username, registrationRecord } = body;
    if (typeof username !== "string" || username.length === 0) {
      return Response.json({ error: "missing username" }, { status: 400 });
    }
    if (
      typeof registrationRecord !== "string" || registrationRecord.length === 0
    ) {
      return Response.json({ error: "missing registrationRecord" }, {
        status: 400,
      });
    }

    try {
      server.finishRegistration(username, registrationRecord);
      return Response.json({ ok: true });
    } catch {
      return Response.json({ error: "registration finish failed" }, {
        status: 400,
      });
    }
  },
});
