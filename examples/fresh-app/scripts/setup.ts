#!/usr/bin/env -S deno run --allow-read --allow-write
/**
 * Copy the prebuilt OPAQUE WASM artifact into this app's static/ directory so
 * the browser island can fetch it from `/opaque.wasm`.
 *
 * The production wasm (ABI v4, with the serverKeyPair export) is built at the
 * repository root with `zig build wasm`; this example does NOT rebuild it. We
 * just copy the existing `zig-out/wasm/opaque.wasm` (resolved relative to this
 * script) to `static/opaque.wasm`.
 *
 *   deno task setup
 *
 * Both the browser island (via fetch("/opaque.wasm")) and the Fresh server
 * routes (via Deno.readFile("static/opaque.wasm")) read this same copied file,
 * so a single `deno task setup` makes the wasm available to both ends.
 */

// zig-out is four levels up: scripts/ -> fresh-app/ -> examples/ -> repo root.
const SOURCE = new URL("../../../zig-out/wasm/opaque.wasm", import.meta.url);
const DEST = new URL("../static/opaque.wasm", import.meta.url);

async function main(): Promise<void> {
  let bytes: Uint8Array;
  try {
    bytes = await Deno.readFile(SOURCE);
  } catch (cause) {
    const path = SOURCE.pathname;
    throw new Error(
      `Could not read the prebuilt OPAQUE wasm at ${path}. ` +
        `Build it at the repository root first (\`zig build wasm\`), ` +
        `then re-run \`deno task setup\`. (cause: ${(cause as Error).message})`,
      { cause },
    );
  }

  await Deno.mkdir(new URL("../static/", import.meta.url), { recursive: true });
  await Deno.writeFile(DEST, bytes);

  const kib = (bytes.byteLength / 1024).toFixed(0);
  // deno-lint-ignore no-console
  console.log(`copied opaque.wasm -> static/opaque.wasm (${kib} KiB)`);
}

if (import.meta.main) {
  await main();
}
