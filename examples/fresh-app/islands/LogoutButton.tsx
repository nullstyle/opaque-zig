/**
 * Browser island: logout button. POSTs to /api/logout (which clears the session
 * cookie + server entry), then navigates back to the auth page.
 */
import { useSignal } from "@preact/signals";

export default function LogoutButton() {
  const busy = useSignal(false);

  async function logout(): Promise<void> {
    busy.value = true;
    try {
      await fetch("/api/logout", { method: "POST" });
    } finally {
      globalThis.location.href = "/";
    }
  }

  return (
    <button type="button" class="btn" disabled={busy.value} onClick={logout}>
      Log out
    </button>
  );
}
