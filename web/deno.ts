import { OpaqueWasm } from "./opaque_wasm.ts";

export async function instantiateOpaqueWasmFromFile(
  path: string | URL,
  imports: WebAssembly.Imports = {},
): Promise<OpaqueWasm> {
  return instantiateOpaqueWasmFromBytes(await Deno.readFile(path), imports);
}

export async function instantiateOpaqueWasmFromUrl(
  url: URL | string,
  imports: WebAssembly.Imports = {},
): Promise<OpaqueWasm> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch OPAQUE WASM: HTTP ${response.status}`);
  }
  return instantiateOpaqueWasmFromBytes(await response.arrayBuffer(), imports);
}

export async function instantiateOpaqueWasmFromBytes(
  bytes: ArrayBuffer | Uint8Array,
  imports: WebAssembly.Imports = {},
): Promise<OpaqueWasm> {
  const result = await WebAssembly.instantiate(bytes, imports);
  const wasm = new OpaqueWasm(result);
  wasm.assertVersion();
  return wasm;
}

export * from "./opaque_wasm.ts";
