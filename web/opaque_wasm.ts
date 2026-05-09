// @ts-nocheck

const OUTPUT_DESCRIPTOR_BYTES = 8;
export const OPAQUE_WASM_ABI_VERSION = 1;
export const OPAQUE_WASM_STATUS = Object.freeze({
  ok: 0,
  protocolError: 1,
  invalidInput: 2,
  outOfMemory: 3,
});

const OPERATIONS = [
  "registrationStart",
  "registrationFinish",
  "loginStart",
  "loginFinish",
  "serverLoginStart",
  "serverLoginFinish",
];

export class OpaqueWasmError extends Error {
  /**
   * @param {string} operation
   * @param {number} status
   */
  constructor(operation, status) {
    super(`OPAQUE WASM ${operation} failed with status ${statusName(status)} (${status})`);
    this.name = "OpaqueWasmError";
    this.operation = operation;
    this.status = status;
  }
}

export class OpaqueWasm {
  /**
   * @param {WebAssembly.Instance | { instance: WebAssembly.Instance }} instanceOrResult
   */
  constructor(instanceOrResult) {
    const instance =
      "instance" in instanceOrResult ? instanceOrResult.instance : instanceOrResult;
    this.exports = assertOpaqueExports(instance.exports);
  }

  version() {
    return this.exports.version();
  }

  assertVersion(expected = OPAQUE_WASM_ABI_VERSION) {
    const actual = this.version();
    if (actual !== expected) {
      throw new TypeError(`Unsupported OPAQUE WASM ABI version ${actual}; expected ${expected}`);
    }
  }

  lengths() {
    return {
      registrationRequest: this.exports.registrationRequestLen(),
      registrationResponse: this.exports.registrationResponseLen(),
      registrationRecord: this.exports.registrationRecordLen(),
      ke1: this.exports.ke1Len(),
      ke2: this.exports.ke2Len(),
      ke3: this.exports.ke3Len(),
    };
  }

  resetAllocator() {
    this.exports.resetAllocator();
  }

  /** @param {Uint8Array} input */
  registrationStart(input) {
    return this.callBytes("registrationStart", input);
  }

  /** @param {Uint8Array} input */
  registrationFinish(input) {
    return this.callBytes("registrationFinish", input);
  }

  /** @param {Uint8Array} input */
  loginStart(input) {
    return this.callBytes("loginStart", input);
  }

  /** @param {Uint8Array} input */
  loginFinish(input) {
    return this.callBytes("loginFinish", input);
  }

  /** @param {Uint8Array} input */
  serverLoginStart(input) {
    return this.callBytes("serverLoginStart", input);
  }

  /** @param {Uint8Array} input */
  serverLoginFinish(input) {
    return this.callBytes("serverLoginFinish", input);
  }

  /**
   * @param {string} operation
   * @param {Uint8Array} input
   * @returns {Uint8Array}
   */
  callBytes(operation, input) {
    if (!OPERATIONS.includes(operation)) {
      throw new TypeError(`Unknown OPAQUE operation: ${operation}`);
    }

    if (!(input instanceof Uint8Array)) {
      throw new TypeError("OPAQUE operation input must be a Uint8Array");
    }

    const inputPointer = this.allocate(input.byteLength);
    const outputPointer = this.allocate(OUTPUT_DESCRIPTOR_BYTES);

    try {
      this.bytes().set(input, inputPointer);
      this.view().setUint32(outputPointer, 0, true);
      this.view().setUint32(outputPointer + 4, 0, true);

      const status = this.exports[operation](
        inputPointer,
        input.byteLength,
        outputPointer,
      );

      if (status !== 0) {
        throw new OpaqueWasmError(operation, status);
      }

      const resultPointer = this.view().getUint32(outputPointer, true);
      const resultLength = this.view().getUint32(outputPointer + 4, true);
      return this.copyAndFree(resultPointer, resultLength);
    } finally {
      this.free(inputPointer, input.byteLength);
      this.free(outputPointer, OUTPUT_DESCRIPTOR_BYTES);
    }
  }

  /** @param {number} byteLength */
  allocate(byteLength) {
    if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
      throw new RangeError(`Invalid byte length: ${byteLength}`);
    }

    const pointer = this.exports.allocate(byteLength);
    if (!Number.isSafeInteger(pointer) || pointer < 0) {
      throw new RangeError(`WASM allocator returned invalid pointer: ${pointer}`);
    }

    if (byteLength > 0 && pointer === 0) {
      throw new RangeError("WASM allocator returned null for a non-empty allocation");
    }

    return pointer;
  }

  /**
   * @param {number} pointer
   * @param {number} byteLength
   */
  free(pointer, byteLength) {
    if (pointer !== 0 || byteLength !== 0) {
      this.exports.free(pointer, byteLength);
    }
  }

  bytes() {
    return new Uint8Array(this.exports.memory.buffer);
  }

  view() {
    return new DataView(this.exports.memory.buffer);
  }

  /**
   * @param {number} pointer
   * @param {number} byteLength
   */
  copyAndFree(pointer, byteLength) {
    if (!Number.isSafeInteger(pointer) || pointer < 0) {
      throw new RangeError(`WASM function returned invalid pointer: ${pointer}`);
    }

    if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
      throw new RangeError(`WASM function returned invalid byte length: ${byteLength}`);
    }

    if (byteLength === 0) {
      return new Uint8Array();
    }

    if (pointer === 0) {
      throw new RangeError("WASM function returned null for a non-empty result");
    }

    try {
      const result = this.bytes().slice(pointer, pointer + byteLength);
      if (result.byteLength !== byteLength) {
        throw new RangeError("WASM function returned a result outside memory bounds");
      }
      return result;
    } finally {
      this.free(pointer, byteLength);
    }
  }
}

/** @param {WebAssembly.Exports} exports */
export function assertOpaqueExports(exports) {
  if (!(exports.memory instanceof WebAssembly.Memory)) {
    throw new TypeError("OPAQUE WASM module must export memory");
  }

  for (const name of [
    "allocate",
    "free",
    "resetAllocator",
    "version",
    "registrationRequestLen",
    "registrationResponseLen",
    "registrationRecordLen",
    "ke1Len",
    "ke2Len",
    "ke3Len",
    ...OPERATIONS,
  ]) {
    if (typeof exports[name] !== "function") {
      throw new TypeError(`OPAQUE WASM module must export function ${name}`);
    }
  }

  return exports;
}

/** @param {string} value */
export function utf8Encode(value) {
  return new TextEncoder().encode(value);
}

/** @param {Uint8Array} value */
export function utf8Decode(value) {
  return new TextDecoder().decode(value);
}

function statusName(status) {
  for (const [name, value] of Object.entries(OPAQUE_WASM_STATUS)) {
    if (value === status) return name;
  }
  return "unknown";
}
