// @ts-nocheck

import { OpaqueWasm } from "./opaque_wasm.ts";

/**
 * @param {string | URL} path
 * @param {WebAssembly.Imports} [imports]
 */
export async function instantiateOpaqueWasmFromFile(path, imports = {}) {
  return instantiateOpaqueWasmFromBytes(await Deno.readFile(path), imports);
}

/**
 * @param {URL | string} url
 * @param {WebAssembly.Imports} [imports]
 */
export async function instantiateOpaqueWasmFromUrl(url, imports = {}) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch OPAQUE WASM: HTTP ${response.status}`);
  }
  return instantiateOpaqueWasmFromBytes(await response.arrayBuffer(), imports);
}

/**
 * @param {ArrayBuffer | Uint8Array} bytes
 * @param {WebAssembly.Imports} [imports]
 */
export async function instantiateOpaqueWasmFromBytes(bytes, imports = {}) {
  const result = await WebAssembly.instantiate(bytes, imports);
  return new OpaqueWasm(result);
}

export { OpaqueWasm, OpaqueWasmError, utf8Decode, utf8Encode } from "./opaque_wasm.ts";
