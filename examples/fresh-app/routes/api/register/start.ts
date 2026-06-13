import { define } from "../../../utils.ts";
import { getOpaqueServer } from "../../../server/opaque_server.ts";

/**
 * POST /api/register/start
 * Body:     { username, registrationRequest }   (registrationRequest is base64)
 * Response: { registrationResponse }            (base64)
 *
 * credential_identifier = utf8(username). This demo allows re-registering an
 * existing username (overwrite); see server/opaque_server.ts.
 */
export const handler = define.handlers({
  async POST(ctx) {
    const server = await getOpaqueServer();

    let body: { username?: unknown; registrationRequest?: unknown };
    try {
      body = await ctx.req.json();
    } catch {
      return Response.json({ error: "invalid JSON" }, { status: 400 });
    }

    const { username, registrationRequest } = body;
    if (typeof username !== "string" || username.length === 0) {
      return Response.json({ error: "missing username" }, { status: 400 });
    }
    if (
      typeof registrationRequest !== "string" ||
      registrationRequest.length === 0
    ) {
      return Response.json({ error: "missing registrationRequest" }, {
        status: 400,
      });
    }

    try {
      const registrationResponse = server.registrationResponse(
        username,
        registrationRequest,
      );
      return Response.json({ registrationResponse });
    } catch {
      // A malformed registrationRequest surfaces as a wasm protocol/invalid-input
      // error; report it as a bad request without leaking internals.
      return Response.json({ error: "registration start failed" }, {
        status: 400,
      });
    }
  },
});
