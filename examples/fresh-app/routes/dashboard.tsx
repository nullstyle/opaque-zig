import { define } from "../utils.ts";
import { getOpaqueServer } from "../server/opaque_server.ts";
import { readSessionId } from "../server/session.ts";
import LogoutButton from "../islands/LogoutButton.tsx";

/**
 * Protected dashboard. Server-side checks the session cookie; if it's absent or
 * invalid, redirect to "/". Otherwise greet the authenticated user.
 */
export const handler = define.handlers({
  async GET(ctx) {
    const server = await getOpaqueServer();
    const session = server.getSession(readSessionId(ctx.req));
    if (session === undefined) {
      return ctx.redirect("/");
    }
    return ctx.render(<Dashboard username={session.username} />);
  },
});

function Dashboard({ username }: { username: string }) {
  return (
    <main class="page">
      <section class="hero">
        <h1>Welcome, {username}</h1>
        <p class="lede">
          You authenticated with <strong>OPAQUE</strong>{" "}
          — the server never saw your password. The only thing the server holds
          for you is an OPAQUE registration record, from which a password cannot
          be recovered.
        </p>
      </section>
      <div class="card">
        <p>
          You are signed in. This page is protected by a server-side session
          check.
        </p>
        <LogoutButton />
      </div>
    </main>
  );
}
