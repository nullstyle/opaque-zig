const OUTPUT_DESCRIPTOR_BYTES = 8;

export const OPAQUE_WASM_ABI_VERSION = 2;
export const OPAQUE_WASM_STATUS = Object.freeze({
  ok: 0,
  protocolError: 1,
  invalidInput: 2,
  outOfMemory: 3,
});

export const OPAQUE_WASM_V2 = Object.freeze({
  blindUniform: 64,
  blind: 32,
  nonce: 32,
  seed: 32,
  hash: 64,
  publicKey: 32,
  mac: 64,
  sessionKey: 64,
  registrationRequest: 32,
  registrationResponse: 64,
  registrationRecord: 192,
  ke1: 96,
  ke2: 320,
  ke3: 64,
  clientLoginState: 160,
  serverLoginState: 128,
});

const OPERATIONS = [
  "registrationStart",
  "registrationFinish",
  "registrationFinishIdentityTestVector",
  "loginStart",
  "loginFinish",
  "loginFinishIdentityTestVector",
  "serverLoginStart",
  "serverLoginStartIdentityTestVector",
  "serverLoginFinish",
] as const;

type Operation = (typeof OPERATIONS)[number];
type WasmOperation = (inputPointer: number, inputLength: number, outputPointer: number) => number;

export type OpaqueExports = WebAssembly.Exports & {
  memory: WebAssembly.Memory;
  allocate(byteLength: number): number;
  free(pointer: number, byteLength: number): void;
  resetAllocator(): void;
  version(): number;
  registrationRequestLen(): number;
  registrationResponseLen(): number;
  registrationRecordLen(): number;
  ke1Len(): number;
  ke2Len(): number;
  ke3Len(): number;
} & { [K in Operation]: WasmOperation };

export type OpaqueLengths = {
  registrationRequest: number;
  registrationResponse: number;
  registrationRecord: number;
  ke1: number;
  ke2: number;
  ke3: number;
};

export type IdentityOptions = {
  context?: Uint8Array;
  serverIdentity?: Uint8Array | null;
  clientIdentity?: Uint8Array | null;
};

export type RegistrationStartInput = {
  blindUniform: Uint8Array;
  password: Uint8Array;
};

export type RegistrationFinishInput = IdentityOptions & {
  blind: Uint8Array;
  envelopeNonce: Uint8Array;
  registrationResponse: Uint8Array;
  password: Uint8Array;
};

export type LoginStartInput = {
  blindUniform: Uint8Array;
  clientNonce: Uint8Array;
  clientKeyshareSeed: Uint8Array;
  password: Uint8Array;
};

export type LoginFinishInput = IdentityOptions & {
  clientLoginState: Uint8Array;
  ke2: Uint8Array;
  password: Uint8Array;
};

export type ServerLoginStartInput = IdentityOptions & {
  serverPrivateKey: Uint8Array;
  serverPublicKey: Uint8Array;
  registrationRecord: Uint8Array;
  oprfSeed: Uint8Array;
  ke1: Uint8Array;
  maskingNonce: Uint8Array;
  serverNonce: Uint8Array;
  serverKeyshareSeed: Uint8Array;
  credentialIdentifier: Uint8Array;
};

export type ServerLoginFinishInput = {
  serverLoginState: Uint8Array;
  ke3: Uint8Array;
};

export class OpaqueWasmError extends Error {
  readonly operation: string;
  readonly status: number;

  constructor(operation: string, status: number) {
    super(`OPAQUE WASM ${operation} failed with status ${statusName(status)} (${status})`);
    this.name = "OpaqueWasmError";
    this.operation = operation;
    this.status = status;
  }
}

export class OpaqueWasm {
  #exports: OpaqueExports;

  constructor(instanceOrResult: WebAssembly.Instance | WebAssembly.WebAssemblyInstantiatedSource) {
    const instance =
      "instance" in instanceOrResult ? instanceOrResult.instance : instanceOrResult;
    this.#exports = assertOpaqueExports(instance.exports);
  }

  version(): number {
    return this.#exports.version();
  }

  assertVersion(expected = OPAQUE_WASM_ABI_VERSION): void {
    const actual = this.version();
    if (actual !== expected) {
      throw new TypeError(`Unsupported OPAQUE WASM ABI version ${actual}; expected ${expected}`);
    }
  }

  lengths(): OpaqueLengths {
    return {
      registrationRequest: this.#exports.registrationRequestLen(),
      registrationResponse: this.#exports.registrationResponseLen(),
      registrationRecord: this.#exports.registrationRecordLen(),
      ke1: this.#exports.ke1Len(),
      ke2: this.#exports.ke2Len(),
      ke3: this.#exports.ke3Len(),
    };
  }

  resetAllocator(): void {
    this.#exports.resetAllocator();
  }

  registrationStart(input: Uint8Array): Uint8Array {
    return this.callBytes("registrationStart", input);
  }

  registrationFinish(input: Uint8Array): Uint8Array {
    return this.callBytes("registrationFinish", input);
  }

  registrationFinishIdentityTestVector(input: Uint8Array): Uint8Array {
    return this.callBytes("registrationFinishIdentityTestVector", input);
  }

  loginStart(input: Uint8Array): Uint8Array {
    return this.callBytes("loginStart", input);
  }

  loginFinish(input: Uint8Array): Uint8Array {
    return this.callBytes("loginFinish", input);
  }

  loginFinishIdentityTestVector(input: Uint8Array): Uint8Array {
    return this.callBytes("loginFinishIdentityTestVector", input);
  }

  serverLoginStart(input: Uint8Array): Uint8Array {
    return this.callBytes("serverLoginStart", input);
  }

  serverLoginStartIdentityTestVector(input: Uint8Array): Uint8Array {
    return this.callBytes("serverLoginStartIdentityTestVector", input);
  }

  serverLoginFinish(input: Uint8Array): Uint8Array {
    return this.callBytes("serverLoginFinish", input);
  }

  callBytes(operation: Operation, input: Uint8Array): Uint8Array {
    if (!OPERATIONS.includes(operation)) {
      throw new TypeError(`Unknown OPAQUE operation: ${operation}`);
    }

    assertBytes(input, "OPAQUE operation input");

    let inputPointer = 0;
    let outputPointer = 0;

    try {
      inputPointer = this.allocate(input.byteLength);
      outputPointer = this.allocate(OUTPUT_DESCRIPTOR_BYTES);

      this.#memoryBytes().set(input, inputPointer);
      this.#memoryView().setUint32(outputPointer, 0, true);
      this.#memoryView().setUint32(outputPointer + 4, 0, true);

      const status = this.#exports[operation](
        inputPointer,
        input.byteLength,
        outputPointer,
      );

      if (status !== OPAQUE_WASM_STATUS.ok) {
        throw new OpaqueWasmError(operation, status);
      }

      const resultPointer = this.#memoryView().getUint32(outputPointer, true);
      const resultLength = this.#memoryView().getUint32(outputPointer + 4, true);
      return this.#copyAndFree(resultPointer, resultLength);
    } finally {
      this.free(inputPointer, input.byteLength);
      this.free(outputPointer, OUTPUT_DESCRIPTOR_BYTES);
      this.resetAllocator();
    }
  }

  allocate(byteLength: number): number {
    assertByteLength(byteLength, "byte length");

    if (byteLength === 0) {
      return 0;
    }

    const pointer = this.#exports.allocate(byteLength);
    assertPointer(pointer, "WASM allocator returned invalid pointer");

    if (pointer === 0) {
      throw new RangeError("WASM allocator returned null for a non-empty allocation");
    }

    this.#assertMemoryRange(pointer, byteLength, "WASM allocator returned a range outside memory");
    return pointer;
  }

  free(pointer: number, byteLength: number): void {
    assertByteLength(byteLength, "byte length");
    assertPointer(pointer, "pointer");
    if (pointer === 0 && byteLength === 0) {
      return;
    }

    this.#assertMemoryRange(pointer, byteLength, "free range is outside memory");
    this.#exports.free(pointer, byteLength);
  }

  #copyAndFree(pointer: number, byteLength: number): Uint8Array {
    assertPointer(pointer, "WASM function returned invalid pointer");
    assertByteLength(byteLength, "WASM function returned invalid byte length");

    if (byteLength === 0) {
      return new Uint8Array();
    }

    if (pointer === 0) {
      throw new RangeError("WASM function returned null for a non-empty result");
    }

    this.#assertMemoryRange(pointer, byteLength, "WASM function returned a result outside memory");

    try {
      return this.#memoryBytes().slice(pointer, pointer + byteLength);
    } finally {
      this.free(pointer, byteLength);
    }
  }

  #memoryBytes(): Uint8Array {
    return new Uint8Array(this.#exports.memory.buffer);
  }

  #memoryView(): DataView {
    return new DataView(this.#exports.memory.buffer);
  }

  #assertMemoryRange(pointer: number, byteLength: number, message: string): void {
    const end = pointer + byteLength;
    if (!Number.isSafeInteger(end) || pointer < 0 || byteLength < 0 || end > this.#exports.memory.buffer.byteLength) {
      throw new RangeError(message);
    }
  }
}

export function buildRegistrationStartInput(input: RegistrationStartInput): Uint8Array {
  return concatBytes(
    fixed(input.blindUniform, "blindUniform", OPAQUE_WASM_V2.blindUniform),
    bytes(input.password, "password"),
  );
}

export const encodeRegistrationStartInput = buildRegistrationStartInput;

export function buildRegistrationFinishInput(input: RegistrationFinishInput): Uint8Array {
  return concatBytes(
    fixed(input.blind, "blind", OPAQUE_WASM_V2.blind),
    fixed(input.envelopeNonce, "envelopeNonce", OPAQUE_WASM_V2.nonce),
    fixed(input.registrationResponse, "registrationResponse", OPAQUE_WASM_V2.registrationResponse),
    opaque16(input.password, "password"),
    opaque16(input.context ?? new Uint8Array(), "context"),
    opaque16(input.serverIdentity ?? new Uint8Array(), "serverIdentity"),
    opaque16(input.clientIdentity ?? new Uint8Array(), "clientIdentity"),
  );
}

export const encodeRegistrationFinishInput = buildRegistrationFinishInput;

export function buildLoginStartInput(input: LoginStartInput): Uint8Array {
  return concatBytes(
    fixed(input.blindUniform, "blindUniform", OPAQUE_WASM_V2.blindUniform),
    fixed(input.clientNonce, "clientNonce", OPAQUE_WASM_V2.nonce),
    fixed(input.clientKeyshareSeed, "clientKeyshareSeed", OPAQUE_WASM_V2.seed),
    bytes(input.password, "password"),
  );
}

export const encodeLoginStartInput = buildLoginStartInput;

export function buildLoginFinishInput(input: LoginFinishInput): Uint8Array {
  return concatBytes(
    fixed(input.clientLoginState, "clientLoginState", OPAQUE_WASM_V2.clientLoginState),
    fixed(input.ke2, "ke2", OPAQUE_WASM_V2.ke2),
    opaque16(input.password, "password"),
    opaque16(input.context ?? new Uint8Array(), "context"),
    opaque16(input.serverIdentity ?? new Uint8Array(), "serverIdentity"),
    opaque16(input.clientIdentity ?? new Uint8Array(), "clientIdentity"),
  );
}

export const encodeLoginFinishInput = buildLoginFinishInput;

export function buildServerLoginStartInput(input: ServerLoginStartInput): Uint8Array {
  return concatBytes(
    fixed(input.serverPrivateKey, "serverPrivateKey", OPAQUE_WASM_V2.blind),
    fixed(input.serverPublicKey, "serverPublicKey", OPAQUE_WASM_V2.publicKey),
    fixed(input.registrationRecord, "registrationRecord", OPAQUE_WASM_V2.registrationRecord),
    fixed(input.oprfSeed, "oprfSeed", OPAQUE_WASM_V2.hash),
    fixed(input.ke1, "ke1", OPAQUE_WASM_V2.ke1),
    fixed(input.maskingNonce, "maskingNonce", OPAQUE_WASM_V2.nonce),
    fixed(input.serverNonce, "serverNonce", OPAQUE_WASM_V2.nonce),
    fixed(input.serverKeyshareSeed, "serverKeyshareSeed", OPAQUE_WASM_V2.seed),
    opaque16(input.credentialIdentifier, "credentialIdentifier"),
    opaque16(input.context ?? new Uint8Array(), "context"),
    opaque16(input.serverIdentity ?? new Uint8Array(), "serverIdentity"),
    opaque16(input.clientIdentity ?? new Uint8Array(), "clientIdentity"),
  );
}

export const encodeServerLoginStartInput = buildServerLoginStartInput;

export function buildServerLoginFinishInput(input: ServerLoginFinishInput): Uint8Array {
  return concatBytes(
    fixed(input.serverLoginState, "serverLoginState", OPAQUE_WASM_V2.serverLoginState),
    fixed(input.ke3, "ke3", OPAQUE_WASM_V2.ke3),
  );
}

export const encodeServerLoginFinishInput = buildServerLoginFinishInput;

export function assertOpaqueExports(exports: WebAssembly.Exports): OpaqueExports {
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
  ] as const) {
    if (typeof exports[name] !== "function") {
      throw new TypeError(`OPAQUE WASM module must export function ${name}`);
    }
  }

  return exports as OpaqueExports;
}

export function utf8Encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function utf8Decode(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

export function bytesToHex(value: Uint8Array): string {
  assertBytes(value, "value");
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesToBase64(value: Uint8Array): string {
  assertBytes(value, "value");
  if (typeof btoa === "function") {
    let binary = "";
    for (const byte of value) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  let i = 0;
  while (i < value.byteLength) {
    const a = value[i++];
    const b = i < value.byteLength ? value[i++] : undefined;
    const c = i < value.byteLength ? value[i++] : undefined;
    const triple = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += chars[(triple >> 18) & 0x3f];
    out += chars[(triple >> 12) & 0x3f];
    out += b === undefined ? "=" : chars[(triple >> 6) & 0x3f];
    out += c === undefined ? "=" : chars[triple & 0x3f];
  }
  return out;
}

export function base64ToBytes(value: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  const clean = value.replace(/\s+/g, "");
  if (clean.length % 4 !== 0) {
    throw new RangeError("base64 input length must be a multiple of 4");
  }

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytesOut: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = decodeBase64Char(clean[i]);
    const c1 = decodeBase64Char(clean[i + 1]);
    const c2 = clean[i + 2] === "=" ? 0 : decodeBase64Char(clean[i + 2]);
    const c3 = clean[i + 3] === "=" ? 0 : decodeBase64Char(clean[i + 3]);
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    bytesOut.push((triple >> 16) & 0xff);
    if (clean[i + 2] !== "=") bytesOut.push((triple >> 8) & 0xff);
    if (clean[i + 3] !== "=") bytesOut.push(triple & 0xff);
  }
  return new Uint8Array(bytesOut);

  function decodeBase64Char(char: string): number {
    const index = chars.indexOf(char);
    if (index < 0) throw new RangeError(`invalid base64 character: ${char}`);
    return index;
  }
}

export function hexToBytes(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) {
    throw new RangeError("hex input must contain an even number of digits");
  }

  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.byteLength; i += 1) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) {
      throw new RangeError("hex input contains invalid digits");
    }
    out[i] = byte;
  }
  return out;
}

function statusName(status: number): string {
  for (const [name, value] of Object.entries(OPAQUE_WASM_STATUS)) {
    if (value === status) return name;
  }
  return "unknown";
}

function fixed(value: Uint8Array, name: string, byteLength: number): Uint8Array {
  const out = bytes(value, name);
  if (out.byteLength !== byteLength) {
    throw new RangeError(`${name} must be ${byteLength} bytes, got ${out.byteLength}`);
  }
  return out;
}

function bytes(value: Uint8Array, name: string): Uint8Array {
  assertBytes(value, name);
  return value;
}

function opaque16(value: Uint8Array, name: string): Uint8Array {
  const body = bytes(value, name);
  if (body.byteLength > 0xffff) {
    throw new RangeError(`${name} must fit in a uint16 length prefix`);
  }

  const out = new Uint8Array(2 + body.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint16(0, body.byteLength, false);
  out.set(body, 2);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function assertBytes(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function assertByteLength(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`Invalid ${name}: ${value}`);
  }
}

function assertPointer(value: number, message: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${message}: ${value}`);
  }
}
