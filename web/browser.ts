// @ts-nocheck

import { OpaqueWasm } from "./opaque_wasm.ts";

/**
 * @param {Response | URL | string | ArrayBuffer | Uint8Array} source
 * @param {WebAssembly.Imports} [imports]
 */
export async function instantiateOpaqueWasm(source, imports = {}) {
  if (source instanceof Response) {
    return instantiateFromResponse(source, imports);
  }

  if (source instanceof URL || typeof source === "string") {
    return instantiateFromResponse(fetch(source), imports);
  }

  return instantiateFromBytes(source, imports);
}

/**
 * @param {URL | string} url
 * @param {WebAssembly.Imports} [imports]
 */
export async function instantiateOpaqueWasmFromUrl(url, imports = {}) {
  return instantiateFromResponse(fetch(url), imports);
}

/**
 * @param {ArrayBuffer | Uint8Array} bytes
 * @param {WebAssembly.Imports} [imports]
 */
export async function instantiateOpaqueWasmFromBytes(bytes, imports = {}) {
  return instantiateFromBytes(bytes, imports);
}

/**
 * @param {Response | Promise<Response>} responseOrPromise
 * @param {WebAssembly.Imports} imports
 */
async function instantiateFromResponse(responseOrPromise, imports) {
  const response = await responseOrPromise;

  if (!response.ok) {
    throw new Error(`Failed to fetch OPAQUE WASM: HTTP ${response.status}`);
  }

  if ("instantiateStreaming" in WebAssembly) {
    try {
      const result = await WebAssembly.instantiateStreaming(response.clone(), imports);
      return new OpaqueWasm(result);
    } catch (error) {
      if (!(error instanceof TypeError)) {
        throw error;
      }
    }
  }

  return instantiateFromBytes(await response.arrayBuffer(), imports);
}

/**
 * @param {ArrayBuffer | Uint8Array} bytes
 * @param {WebAssembly.Imports} imports
 */
async function instantiateFromBytes(bytes, imports) {
  const result = await WebAssembly.instantiate(bytes, imports);
  return new OpaqueWasm(result);
}

export { OpaqueWasm, OpaqueWasmError, utf8Decode, utf8Encode } from "./opaque_wasm.ts";
