import { OpaqueWasm } from "./opaque_wasm.ts";

export async function instantiateOpaqueWasm(
  source: Response | URL | string | ArrayBuffer | Uint8Array,
  imports: WebAssembly.Imports = {},
): Promise<OpaqueWasm> {
  if (source instanceof Response) {
    return instantiateFromResponse(source, imports);
  }

  if (source instanceof URL || typeof source === "string") {
    return instantiateFromResponse(fetch(source), imports);
  }

  return instantiateFromBytes(source, imports);
}

export async function instantiateOpaqueWasmFromUrl(
  url: URL | string,
  imports: WebAssembly.Imports = {},
): Promise<OpaqueWasm> {
  return instantiateFromResponse(fetch(url), imports);
}

export async function instantiateOpaqueWasmFromBytes(
  bytes: ArrayBuffer | Uint8Array,
  imports: WebAssembly.Imports = {},
): Promise<OpaqueWasm> {
  return instantiateFromBytes(bytes, imports);
}

async function instantiateFromResponse(
  responseOrPromise: Response | Promise<Response>,
  imports: WebAssembly.Imports,
): Promise<OpaqueWasm> {
  const response = await responseOrPromise;

  if (!response.ok) {
    throw new Error(`Failed to fetch OPAQUE WASM: HTTP ${response.status}`);
  }

  if ("instantiateStreaming" in WebAssembly) {
    try {
      const result = await WebAssembly.instantiateStreaming(response.clone(), imports);
      return assertLoaded(new OpaqueWasm(result));
    } catch (error) {
      if (!(error instanceof TypeError)) {
        throw error;
      }
    }
  }

  return instantiateFromBytes(await response.arrayBuffer(), imports);
}

async function instantiateFromBytes(
  bytes: ArrayBuffer | Uint8Array,
  imports: WebAssembly.Imports,
): Promise<OpaqueWasm> {
  const result = await WebAssembly.instantiate(bytes, imports);
  return assertLoaded(new OpaqueWasm(result));
}

function assertLoaded(wasm: OpaqueWasm): OpaqueWasm {
  wasm.assertVersion();
  return wasm;
}

export * from "./opaque_wasm.ts";
