#!/usr/bin/env bash
# Full-stack OPAQUE interop demo + check.
#
# Builds the Go server (bytemare/opaque), the native Zig CLI and the Deno/WASM
# CLI (both nullstyle/opaque-zig), starts the server, and drives every client
# through register + login against it. Mutual authentication is proven by
# asserting the client's session key equals the server's for each login -- the
# session key is never sent over the wire; both sides print it locally and this
# script compares the two.
#
# Usage:  ./run.sh          (exit 0 iff every scenario passes)
set -uo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
ROOT="$(cd ../.. && pwd)"
PORT="${PORT:-8799}"
export OPAQUE_SERVER="http://127.0.0.1:${PORT}"
export OPAQUE_WASM_PATH="${ROOT}/zig-out/wasm/opaque.wasm"

SRVLOG="$(mktemp)"
TMP="$(mktemp -d)"
PASS=0; FAIL=0
say()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

zig_cli()  { cli-zig/zig-out/bin/opaque-cli "$@"; }
deno_cli() { deno run --allow-read --allow-net --allow-env cli-deno/opaque_cli.ts "$@"; }

# --- build -------------------------------------------------------------------
say "build (wasm, go server, zig cli)"
( cd "$ROOT" && zig build --cache-dir .zig-cache --global-cache-dir .zig-global-cache wasm ) || { echo "wasm build failed"; exit 1; }
( cd server-go && go build -o opaque-fullstack-server . ) || { echo "go build failed"; exit 1; }
( cd cli-zig && zig build --cache-dir .zig-cache --global-cache-dir .zig-global-cache ) || { echo "zig cli build failed"; exit 1; }
echo "  built: server-go/opaque-fullstack-server, cli-zig/zig-out/bin/opaque-cli, zig-out/wasm/opaque.wasm"

# --- start server ------------------------------------------------------------
say "start go server (bytemare/opaque) on :$PORT"
PORT="$PORT" server-go/opaque-fullstack-server >/dev/null 2>"$SRVLOG" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; rm -rf "$TMP" "$SRVLOG"' EXIT
ready=""
for _ in $(seq 1 60); do
  if curl -fsS "$OPAQUE_SERVER/health" >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.25
done
[ -n "$ready" ] || { echo "server did not become healthy"; cat "$SRVLOG"; exit 1; }
curl -fsS "$OPAQUE_SERVER/health"; echo

# assert client (stdout file) and server (stderr log) agree on a user's key
assert_session() { # <label> <user> <client_stdout_file>
  local label="$1" user="$2" out="$3" ck sk
  ck="$(grep "^SESSION_KEY $user " "$out" 2>/dev/null | tail -1 | awk '{print $3}')"
  sk="$(grep "SESSION_KEY $user " "$SRVLOG" 2>/dev/null | tail -1 | awk '{print $3}')"
  if [ -n "$ck" ] && [ "$ck" = "$sk" ]; then pass "$label: $user client==server session key  ${ck:0:24}…"
  else fail "$label: $user client='${ck:-<none>}' server='${sk:-<none>}'"; fi
}

# --- scenario 1: native Zig client, full register + login --------------------
say "scenario 1 — Zig native client  (alice)"
zig_cli register alice hunter2 && \
  zig_cli login alice hunter2 >"$TMP/alice.out" && cat "$TMP/alice.out"
assert_session "zig↔go" alice "$TMP/alice.out"

# --- scenario 2: Deno/WASM client, full register + login ---------------------
say "scenario 2 — Deno/WASM client  (bob)"
deno_cli register bob s3cret && \
  deno_cli login bob s3cret >"$TMP/bob.out" && cat "$TMP/bob.out"
assert_session "deno↔go" bob "$TMP/bob.out"

# --- scenario 3: cross-client — register on Zig, log in on Deno --------------
say "scenario 3 — cross-client: Zig registers carol, Deno logs her in"
zig_cli register carol p@ssw0rd && \
  deno_cli login carol p@ssw0rd >"$TMP/carol.out" && cat "$TMP/carol.out"
assert_session "zig-reg/deno-login" carol "$TMP/carol.out"

# --- scenario 4: cross-client the other way ----------------------------------
say "scenario 4 — cross-client: Deno registers dave, Zig logs him in"
deno_cli register dave letmein && \
  zig_cli login dave letmein >"$TMP/dave.out" && cat "$TMP/dave.out"
assert_session "deno-reg/zig-login" dave "$TMP/dave.out"

# --- scenario 5: wrong password must fail ------------------------------------
say "scenario 5 — wrong password is rejected (both clients)"
if zig_cli login alice WRONG >/dev/null 2>&1; then fail "zig: wrong password was accepted"; else pass "zig: wrong password rejected"; fi
if deno_cli login bob WRONG >/dev/null 2>&1; then fail "deno: wrong password was accepted"; else pass "deno: wrong password rejected"; fi

# --- scenario 6: unknown user is rejected (anti-enumeration) -----------------
say "scenario 6 — unknown user rejected (server still answers /login/start)"
if zig_cli login ghost whatever >/dev/null 2>&1; then fail "zig: unknown user authenticated"; else pass "zig: unknown user rejected"; fi

# --- summary -----------------------------------------------------------------
say "summary"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "  ALL GREEN — opaque-zig (Zig + Deno/WASM) interops with bytemare/opaque (Go)"; exit 0; } || exit 1
