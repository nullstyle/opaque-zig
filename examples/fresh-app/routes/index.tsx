import { define } from "../utils.ts";
import { getOpaqueServer } from "../server/opaque_server.ts";
import { readSessionId } from "../server/session.ts";
import AuthForm from "../islands/AuthForm.tsx";

/**
 * Auth page. If a valid session cookie is present, redirect to /dashboard.
 * Otherwise render the OPAQUE auth form (a browser island).
 */
export const handler = define.handlers({
  async GET(ctx) {
    const server = await getOpaqueServer();
    const session = server.getSession(readSessionId(ctx.req));
    if (session !== undefined) {
      return ctx.redirect("/dashboard");
    }
    return ctx.render(<Home />);
  },
});

function Home() {
  return (
    <main class="page">
      <section class="hero">
        <h1>OPAQUE on Fresh</h1>
        <p class="lede">
          A password-authenticated key exchange (RFC 9807) where{" "}
          <strong>both ends run the same opaque-zig WebAssembly</strong>: the
          client in this browser island, the server in Fresh routes. Your
          password is hashed locally and{" "}
          <strong>never leaves the browser</strong>.
        </p>
      </section>
      <AuthForm />
      <section class="explain">
        <h2>How it works</h2>
        <ol>
          <li>
            The browser blinds your password and runs the OPAQUE client (WASM).
          </li>
          <li>
            Only OPAQUE protocol messages (base64) are POSTed to the Fresh API.
          </li>
          <li>
            The Fresh server runs the OPAQUE server (WASM) and verifies the
            proof.
          </li>
          <li>
            On success the server sets an HttpOnly session cookie and you reach
            the dashboard.
          </li>
        </ol>
        <p class="muted">
          Unknown usernames get an indistinguishable response
          (anti-enumeration); login fails the same way a wrong password does.
        </p>
      </section>
    </main>
  );
}
