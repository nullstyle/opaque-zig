const std = @import("std");
const builtin = @import("builtin");

// build.zig attaches the "build_options" module (with `test_exports: bool`) ONLY
// to the wasm32 artifact. In native/test builds that module does not exist, so
// we import it solely on the wasm32 target and fall back to a default otherwise.
// The `if` condition is comptime-known, so on non-wasm targets Zig never analyzes
// the `@import("build_options")` branch and the absent module is not an error.
// The gating below only governs what the wasm artifact exports, which is exactly
// where the real module is present.
const build_options = if (builtin.target.cpu.arch == .wasm32)
    @import("build_options")
else
    struct {
        pub const test_exports: bool = false;
    };

const constants = @import("constants.zig");
const messages = @import("messages.zig");
const protocol = @import("opaque.zig");

// Static arena for the wasm ABI. Sized at 32 MiB because the production KSF is
// argon2id_owasp (m = 19 MiB working set, see wasm_production_ksf below); the
// old 8 MiB buffer could not hold a single argon2 fill. We keep the
// FixedBufferAllocator + resetAllocator-wipes-everything model on purpose: the
// TS wrapper relies on a stable, fixed buffer base (we never call memory.grow),
// so the size is a compile-time constant driven by the Argon2id memory param.
var heap_buffer: [32 * 1024 * 1024]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&heap_buffer);

pub const Status = enum(i32) {
    ok = 0,
    protocol_error = 1,
    invalid_input = 2,
    out_of_memory = 3,
};

const login_state_len = constants.client_login_state_len;
const server_state_len = constants.server_login_state_len;

// Production KSF for the WASM ABI: OWASP-recommended Argon2id (t=2, m=19 MiB,
// p=1). The 32 MiB arena (heap_buffer above) is sized to hold this fill.
// Because p=1, argon2 stays on its synchronous path and never dereferences
// std.Io, so the production exports pass `null` for io (Ksf.stretch substitutes
// a valid freestanding-safe Io internally; no UB). This matches the native
// Suite default and is the real password-hardening configuration.
const wasm_production_ksf = protocol.Ksf{ .argon2id = protocol.argon2id_owasp };

// Slice-level entry points for native tests. Each function drives the EXACT same
// parsing + protocol code path as the corresponding production/gated wasm export
// (the only difference is the ResultSink): the bare-name variants are
// validate-only (`.none`, return ok/error without emitting bytes); the `*ToSlice`
// variants write the result into a caller-owned buffer (`.slice`) so a full round
// trip can read every message even on a native target whose static arena lives
// above 2^32 (where the u32-pointer descriptor ABI SKIPs). KSF scratch always
// comes from the same wasm `fba` arena the production exports use; tests call
// `resetAllocator` between steps exactly as the JS wrapper does.
//
// The `*ToSlice` finish/start variants come in two KSF flavors: the bare name
// (argon2id_owasp -- the PRODUCTION path) and the `Identity` suffix (identity KSF
// -- the gated RFC 9807 C.1.1 test-vector path). Both are ristretto255.
pub const test_api = if (builtin.is_test) struct {
    pub fn registrationStart(input: []const u8) i32 {
        return registrationStartInput(input, .none);
    }

    pub fn registrationStartToSlice(input: []const u8, out: []u8) i32 {
        return registrationStartInput(input, .{ .slice = out });
    }

    pub fn serverRegistrationResponse(input: []const u8) i32 {
        return serverRegistrationResponseInput(input, .none);
    }

    pub fn serverRegistrationResponseToSlice(input: []const u8, out: []u8) i32 {
        return serverRegistrationResponseInput(input, .{ .slice = out });
    }

    pub fn serverKeyPair(input: []const u8) i32 {
        return serverKeyPairInput(input, .none);
    }

    pub fn serverKeyPairToSlice(input: []const u8, out: []u8) i32 {
        return serverKeyPairInput(input, .{ .slice = out });
    }

    // --- Production-KSF (argon2id_owasp) finish/start, writing to a slice. ---
    pub fn registrationFinishToSlice(input: []const u8, out: []u8) i32 {
        return registrationFinishWithSuiteInput(input, .{ .slice = out }, wasm_production_ksf);
    }

    pub fn loginStartToSlice(input: []const u8, out: []u8) i32 {
        return loginStartInput(input, .{ .slice = out });
    }

    pub fn serverLoginStartToSlice(input: []const u8, out: []u8) i32 {
        return serverLoginStartWithSuiteInput(input, .{ .slice = out }, wasm_production_ksf);
    }

    pub fn loginFinishToSlice(input: []const u8, out: []u8) i32 {
        return loginFinishWithSuiteInput(input, .{ .slice = out }, wasm_production_ksf);
    }

    pub fn serverLoginFinishToSlice(input: []const u8, out: []u8) i32 {
        return serverLoginFinishInput(input, .{ .slice = out });
    }

    // --- Identity-KSF (RFC 9807 C.1.1, ristretto255) finish/start. ---
    pub fn registrationFinishIdentity(input: []const u8) i32 {
        return registrationFinishWithSuiteInput(input, .none, .identity_test_only);
    }

    pub fn registrationFinishIdentityToSlice(input: []const u8, out: []u8) i32 {
        return registrationFinishWithSuiteInput(input, .{ .slice = out }, .identity_test_only);
    }

    pub fn loginFinishIdentity(input: []const u8) i32 {
        return loginFinishWithSuiteInput(input, .none, .identity_test_only);
    }

    pub fn loginFinishIdentityToSlice(input: []const u8, out: []u8) i32 {
        return loginFinishWithSuiteInput(input, .{ .slice = out }, .identity_test_only);
    }

    pub fn serverLoginStartIdentity(input: []const u8) i32 {
        return serverLoginStartWithSuiteInput(input, .none, .identity_test_only);
    }

    pub fn serverLoginStartIdentityToSlice(input: []const u8, out: []u8) i32 {
        return serverLoginStartWithSuiteInput(input, .{ .slice = out }, .identity_test_only);
    }

    // loginStart and serverLoginFinish are KSF-agnostic (single shared path).
    pub fn loginStart(input: []const u8) i32 {
        return loginStartInput(input, .none);
    }

    pub fn serverLoginFinish(input: []const u8) i32 {
        return serverLoginFinishInput(input, .none);
    }
} else struct {};

pub export fn allocate(len: u32) u32 {
    if (len == 0) return 0;
    if (!heapFitsU32Pointers()) return 0;
    const bytes = fba.allocator().alloc(u8, len) catch return 0;
    @memset(bytes, 0);
    return @intCast(@intFromPtr(bytes.ptr));
}

pub export fn free(ptr: u32, len: u32) void {
    const bytes = heapSlice(ptr, len) catch return;
    @memset(bytes, 0);
    // FixedBufferAllocator cannot reclaim individual allocations. The JS
    // wrapper still calls this so sensitive ranges are wiped promptly and the
    // ABI can switch to a real allocator later without changing callers.
}

pub export fn resetAllocator() void {
    @memset(&heap_buffer, 0);
    fba.reset();
}

pub export fn version() u32 {
    return constants.wasm_abi_version;
}

// The *IdentityTestVector exports run the protocol with NO password stretching
// (KSF = identity). They exist solely to reproduce the ristretto255 RFC 9807
// (C.1.1) test vectors and MUST NOT ship in the production wasm artifact. They
// are gated behind the `build_options.test_exports` flag (build.zig attaches the
// "build_options" module with `test_exports: bool`, default false). Build with
// `zig build wasm -Dtest-exports=true` to include them.
//
// Mechanism: the three are defined as `pub fn ... callconv(.c)` (not `export`)
// further down; we `@export` them only inside this comptime block when the flag
// is set. Because the condition is comptime-known, when the flag is false this
// block emits nothing and the symbols are absent from the artifact (verified via
// the wasm export table: production exports only by default vs +3 with the flag).
// `@export` is the comptime form that lets us gate the export itself, which a
// bare `pub export fn` cannot.
comptime {
    if (build_options.test_exports) {
        @export(&registrationFinishIdentityTestVector, .{ .name = "registrationFinishIdentityTestVector" });
        @export(&loginFinishIdentityTestVector, .{ .name = "loginFinishIdentityTestVector" });
        @export(&serverLoginStartIdentityTestVector, .{ .name = "serverLoginStartIdentityTestVector" });
    }
}

pub export fn registrationRequestLen() u32 {
    return @import("constants.zig").registration_request_len;
}

pub export fn registrationResponseLen() u32 {
    return @import("constants.zig").registration_response_len;
}

pub export fn registrationRecordLen() u32 {
    return @import("constants.zig").registration_record_len;
}

pub export fn ke1Len() u32 {
    return @import("constants.zig").ke1_len;
}

pub export fn ke2Len() u32 {
    return @import("constants.zig").ke2_len;
}

pub export fn ke3Len() u32 {
    return @import("constants.zig").ke3_len;
}

pub export fn serverKeyPairLen() u32 {
    return constants.Nsk + constants.Npk;
}

pub export fn registrationStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return registrationStartInput(input, .{ .descriptor = out_ptr });
}

fn registrationStartInput(input: []const u8, sink: ResultSink) i32 {
    if (input.len < constants.blind_uniform_len) return @intFromEnum(Status.invalid_input);

    const blind_uniform = input[0..constants.blind_uniform_len].*;
    const password = input[constants.blind_uniform_len..];
    const result = createRegistrationRequestFromUniform(password, blind_uniform) catch |err| return mapProtocolError(err);

    var out = (sink.begin(constants.Nsk + constants.registration_request_len) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    @memcpy(out[0..constants.Nsk], &result.state.blind);
    const request_bytes = result.request.toBytes();
    @memcpy(out[constants.Nsk..][0..constants.registration_request_len], &request_bytes);
    return sink.finish(out);
}

pub export fn registrationFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    return registrationFinishWithSuite(input_ptr, input_len, out_ptr, wasm_production_ksf);
}

// The three *IdentityTestVector functions are `pub` (so native test code and the
// fuzz harness can call them directly) but are NOT `export`ed here -- they are
// conditionally `@export`ed in the comptime block above. callconv(.c) is required
// because @export rejects a bare Zig-convention fn on wasm32; a `pub export fn`
// would imply both the convention and an unconditional export, but we need the
// export itself gated, so we split it.
pub fn registrationFinishIdentityTestVector(input_ptr: u32, input_len: u32, out_ptr: u32) callconv(.c) i32 {
    return registrationFinishWithSuite(input_ptr, input_len, out_ptr, .identity_test_only);
}

fn registrationFinishWithSuite(input_ptr: u32, input_len: u32, out_ptr: u32, ksf: protocol.Ksf) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return registrationFinishWithSuiteInput(input, .{ .descriptor = out_ptr }, ksf);
}

fn registrationFinishWithSuiteInput(input: []const u8, sink: ResultSink, ksf: protocol.Ksf) i32 {
    const fixed_len = constants.Nsk + constants.Nn + constants.registration_response_len;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    var offset: usize = 0;
    const blind = readArray(input, &offset, constants.Nsk) catch return @intFromEnum(Status.invalid_input);
    const envelope_nonce = readArray(input, &offset, constants.Nn) catch return @intFromEnum(Status.invalid_input);
    const response = messages.RegistrationResponse.parse(readSlice(input, &offset, constants.registration_response_len) catch return @intFromEnum(Status.invalid_input)) catch return @intFromEnum(Status.invalid_input);
    const password = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const context = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const server_identity = optionalIdentity(readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input));
    const client_identity = optionalIdentity(readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input));
    if (offset != input.len) return @intFromEnum(Status.invalid_input);

    const state = protocol.RegistrationClientState{ .blind = blind };
    const suite = wasmSuite(ksf, context) catch return @intFromEnum(Status.invalid_input);
    // io = null is safe: identity_test_only ignores it, and the production KSF
    // (wasm_production_ksf) is p=1 so argon2 never dereferences it.
    // password is re-supplied here (the ABI carries it in the finish input); it
    // is no longer borrowed via the state.
    const result = protocol.finalizeRegistrationRequest(suite, fba.allocator(), state, response, envelope_nonce, password, server_identity, client_identity, null) catch |err| return mapProtocolError(err);

    var out = (sink.begin(constants.registration_record_len + constants.Nh) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    const record_bytes = result.record.toBytes();
    @memcpy(out[0..constants.registration_record_len], &record_bytes);
    @memcpy(out[constants.registration_record_len..][0..constants.Nh], &result.export_key);
    return sink.finish(out);
}

pub export fn loginStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return loginStartInput(input, .{ .descriptor = out_ptr });
}

fn loginStartInput(input: []const u8, sink: ResultSink) i32 {
    const fixed_len = constants.blind_uniform_len + constants.Nn + constants.Nseed;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    const blind_uniform = input[0..constants.blind_uniform_len].*;
    const client_nonce = input[constants.blind_uniform_len..][0..constants.Nn].*;
    const keyshare_seed = input[constants.blind_uniform_len + constants.Nn ..][0..constants.Nseed].*;
    const password = input[fixed_len..];
    const result = generateKE1FromUniform(password, blind_uniform, client_nonce, keyshare_seed) catch |err| return mapProtocolError(err);

    var out = (sink.begin(login_state_len + constants.ke1_len) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    @memcpy(out[0..constants.Nsk], &result.state.blind);
    @memcpy(out[constants.Nsk..][0..constants.Nsk], &result.state.client_secret);
    const ke1_bytes = result.ke1.toBytes();
    @memcpy(out[constants.Nsk * 2 ..][0..constants.ke1_len], &ke1_bytes);
    @memcpy(out[login_state_len..][0..constants.ke1_len], &ke1_bytes);
    return sink.finish(out);
}

pub export fn loginFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    return loginFinishWithSuite(input_ptr, input_len, out_ptr, wasm_production_ksf);
}

pub fn loginFinishIdentityTestVector(input_ptr: u32, input_len: u32, out_ptr: u32) callconv(.c) i32 {
    return loginFinishWithSuite(input_ptr, input_len, out_ptr, .identity_test_only);
}

fn loginFinishWithSuite(input_ptr: u32, input_len: u32, out_ptr: u32, ksf: protocol.Ksf) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return loginFinishWithSuiteInput(input, .{ .descriptor = out_ptr }, ksf);
}

fn loginFinishWithSuiteInput(input: []const u8, sink: ResultSink, ksf: protocol.Ksf) i32 {
    const fixed_len = login_state_len + constants.ke2_len;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    var offset: usize = 0;
    const blind = readArray(input, &offset, constants.Nsk) catch return @intFromEnum(Status.invalid_input);
    const client_secret = readArray(input, &offset, constants.Nsk) catch return @intFromEnum(Status.invalid_input);
    const ke1 = messages.KE1.parse(readSlice(input, &offset, constants.ke1_len) catch return @intFromEnum(Status.invalid_input)) catch return @intFromEnum(Status.invalid_input);
    const ke2 = messages.KE2.parse(readSlice(input, &offset, constants.ke2_len) catch return @intFromEnum(Status.invalid_input)) catch return @intFromEnum(Status.invalid_input);
    const password = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const context = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const server_identity = optionalIdentity(readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input));
    const client_identity = optionalIdentity(readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input));
    if (offset != input.len) return @intFromEnum(Status.invalid_input);

    const state = protocol.ClientLoginState{
        .blind = blind,
        .client_secret = client_secret,
        .ke1 = ke1,
    };
    const suite = wasmSuite(ksf, context) catch return @intFromEnum(Status.invalid_input);
    // io = null is safe (see registrationFinishWithSuiteInput).
    // password is re-supplied here (the ABI carries it in the finish input); it
    // is no longer borrowed via the state.
    const result = protocol.generateKE3(suite, fba.allocator(), state, ke2, password, server_identity, client_identity, null) catch |err| return mapProtocolError(err);

    var out = (sink.begin(constants.ke3_len + constants.Nx + constants.Nh) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    const ke3_bytes = result.ke3.toBytes();
    @memcpy(out[0..constants.ke3_len], &ke3_bytes);
    @memcpy(out[constants.ke3_len..][0..constants.Nx], &result.session_key);
    @memcpy(out[constants.ke3_len + constants.Nx ..][0..constants.Nh], &result.export_key);
    return sink.finish(out);
}

pub export fn serverLoginStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    return serverLoginStartWithSuite(input_ptr, input_len, out_ptr, wasm_production_ksf);
}

pub fn serverLoginStartIdentityTestVector(input_ptr: u32, input_len: u32, out_ptr: u32) callconv(.c) i32 {
    return serverLoginStartWithSuite(input_ptr, input_len, out_ptr, .identity_test_only);
}

fn serverLoginStartWithSuite(input_ptr: u32, input_len: u32, out_ptr: u32, ksf: protocol.Ksf) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return serverLoginStartWithSuiteInput(input, .{ .descriptor = out_ptr }, ksf);
}

fn serverLoginStartWithSuiteInput(input: []const u8, sink: ResultSink, ksf: protocol.Ksf) i32 {
    const fixed_len = constants.Nsk + constants.Npk + constants.registration_record_len + constants.Nh + constants.ke1_len + constants.Nn + constants.Nn + constants.Nseed;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    var offset: usize = 0;
    const server_private_key = readArray(input, &offset, constants.Nsk) catch return @intFromEnum(Status.invalid_input);
    const server_public_key = readArray(input, &offset, constants.Npk) catch return @intFromEnum(Status.invalid_input);
    const record = messages.RegistrationRecord.parse(readSlice(input, &offset, constants.registration_record_len) catch return @intFromEnum(Status.invalid_input)) catch return @intFromEnum(Status.invalid_input);
    const oprf_seed = readArray(input, &offset, constants.Nh) catch return @intFromEnum(Status.invalid_input);
    const ke1 = messages.KE1.parse(readSlice(input, &offset, constants.ke1_len) catch return @intFromEnum(Status.invalid_input)) catch return @intFromEnum(Status.invalid_input);
    const masking_nonce = readArray(input, &offset, constants.Nn) catch return @intFromEnum(Status.invalid_input);
    const server_nonce = readArray(input, &offset, constants.Nn) catch return @intFromEnum(Status.invalid_input);
    const server_keyshare_seed = readArray(input, &offset, constants.Nseed) catch return @intFromEnum(Status.invalid_input);
    const credential_identifier = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const context = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const server_identity = optionalIdentity(readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input));
    const client_identity = optionalIdentity(readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input));
    if (offset != input.len) return @intFromEnum(Status.invalid_input);

    const suite = wasmSuite(ksf, context) catch return @intFromEnum(Status.invalid_input);
    const result = protocol.generateKE2(
        suite,
        server_private_key,
        server_public_key,
        record,
        credential_identifier,
        oprf_seed,
        ke1,
        masking_nonce,
        server_nonce,
        server_keyshare_seed,
        server_identity,
        client_identity,
    ) catch |err| return mapProtocolError(err);

    var out = (sink.begin(server_state_len + constants.ke2_len) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    @memcpy(out[0..constants.Nm], &result.state.expected_client_mac);
    @memcpy(out[constants.Nm..][0..constants.Nx], &result.state.unconfirmed_session_key);
    const ke2_bytes = result.ke2.toBytes();
    @memcpy(out[server_state_len..][0..constants.ke2_len], &ke2_bytes);
    return sink.finish(out);
}

pub export fn serverLoginFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return serverLoginFinishInput(input, .{ .descriptor = out_ptr });
}

fn serverLoginFinishInput(input: []const u8, sink: ResultSink) i32 {
    if (input.len != server_state_len + constants.ke3_len) return @intFromEnum(Status.invalid_input);

    const state = protocol.ServerLoginState{
        .expected_client_mac = input[0..constants.Nm].*,
        .unconfirmed_session_key = input[constants.Nm..][0..constants.Nx].*,
    };
    const ke3 = messages.KE3.parse(input[server_state_len..][0..constants.ke3_len]) catch return @intFromEnum(Status.invalid_input);
    const session_key = protocol.serverFinish(state, ke3) catch |err| return mapProtocolError(err);

    var out = (sink.begin(constants.Nx) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    @memcpy(out[0..constants.Nx], &session_key);
    return sink.finish(out);
}

/// Server step of registration (RFC 9807 Section 6.3.1.2): evaluate the OPRF
/// over the client's blinded message and return the RegistrationResponse. This
/// is the server-side enrollment primitive; without it a Deno/browser-hosted
/// server could answer logins (serverLoginStart) but never enroll a new user.
///
/// Input layout (exact-length; offsets in bytes):
///   [0          .. Noe)            registration_request  (Noe = 32, blinded msg)
///   [Noe        .. Noe+Npk)        server_public_key      (Npk = 32)
///   [Noe+Npk    .. ...)            credential_identifier  (opaque16: u16-BE len
///                                                          prefix + that many bytes)
///   [...        .. ...+Nh)         oprf_seed              (Nh = 64)
/// The whole input must be consumed exactly (no trailing bytes).
///
/// Output (written to the allocated result buffer, descriptor at out_ptr):
///   registration_response_len (= Noe + Npk = 64) bytes: the RegistrationResponse
///   (evaluated_message || server_public_key).
///
/// Note: the OPRF is always ristretto255-SHA512 regardless of the AKE group, and
/// createRegistrationResponse takes no Suite, so this export is group-agnostic --
/// the same call serves the ristretto255 production client and the ristretto255
/// identity-vector client (both AKE flows are ristretto255 in the WASM ABI).
pub export fn serverRegistrationResponse(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return serverRegistrationResponseInput(input, .{ .descriptor = out_ptr });
}

fn serverRegistrationResponseInput(input: []const u8, sink: ResultSink) i32 {
    const fixed_len = constants.registration_request_len + constants.Npk + constants.Nh;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    var offset: usize = 0;
    const request = messages.RegistrationRequest.parse(readSlice(input, &offset, constants.registration_request_len) catch return @intFromEnum(Status.invalid_input)) catch return @intFromEnum(Status.invalid_input);
    const server_public_key = readArray(input, &offset, constants.Npk) catch return @intFromEnum(Status.invalid_input);
    const credential_identifier = readOpaque16(input, &offset) catch return @intFromEnum(Status.invalid_input);
    const oprf_seed = readArray(input, &offset, constants.Nh) catch return @intFromEnum(Status.invalid_input);
    if (offset != input.len) return @intFromEnum(Status.invalid_input);

    const response = protocol.createRegistrationResponse(request, server_public_key, credential_identifier, oprf_seed) catch |err| return mapProtocolError(err);

    var out = (sink.begin(constants.registration_response_len) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    const response_bytes = response.toBytes();
    @memcpy(out[0..constants.registration_response_len], &response_bytes);
    return sink.finish(out);
}

/// Derive the server's long-term ristretto255 DH keypair (RFC 9807 Section
/// 6.4.1.1) from a 32-byte seed. Without this a Deno/browser-hosted server could
/// answer the protocol exports (which take the keypair as INPUT) but had no way
/// to MINT one; this is the missing server key-generation primitive.
///
/// This is a PRODUCTION export (not gated behind -Dtest-exports): it runs no KSF
/// and handles no caller secrets beyond the seed, so it is safe to ship.
///
/// Input layout (exact-length):
///   [0 .. Nseed)   seed   (Nseed = 32)
/// The whole input must be exactly Nseed bytes (no trailing bytes).
///
/// Output (written to the allocated result buffer, descriptor at out_ptr):
///   Nsk + Npk (= 64) bytes: server_private_key[32] || server_public_key[32],
///   where pk = basepoint * sk on ristretto255.
pub export fn serverKeyPair(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    validateOutputDescriptor(out_ptr) catch return @intFromEnum(Status.invalid_input);
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    return serverKeyPairInput(input, .{ .descriptor = out_ptr });
}

fn serverKeyPairInput(input: []const u8, sink: ResultSink) i32 {
    // Exact-length: a server seed is always Nseed bytes; anything else is a
    // caller error, not a short read.
    if (input.len != constants.Nseed) return @intFromEnum(Status.invalid_input);

    const seed = input[0..constants.Nseed].*;
    const kp = protocol.Group.ristretto255.deriveDhKeyPair(seed) catch |err| return mapProtocolError(err);

    var out = (sink.begin(constants.Nsk + constants.Npk) catch |err| return mapSinkError(err)) orelse return @intFromEnum(Status.ok);
    @memcpy(out[0..constants.Nsk], &kp.sk);
    @memcpy(out[constants.Nsk..][0..constants.Npk], &kp.pk);
    return sink.finish(out);
}

fn writeResultDescriptor(out_ptr: u32, result_ptr: u32, result_len: u32) !void {
    const out = try heapSlice(out_ptr, 8);
    std.mem.writeInt(u32, out[0..4], result_ptr, .little);
    std.mem.writeInt(u32, out[4..8], result_len, .little);
}

fn inputSlice(ptr: u32, len: u32) ![]const u8 {
    return try heapSlice(ptr, len);
}

// Where a protocol export writes its result bytes. The production pointer ABI
// uses `.descriptor` (allocate in the wasm arena, then write a {ptr,len}
// descriptor at out_ptr). `.none` discards the result (validate-only). `.slice`
// writes the result bytes into a caller-owned buffer -- used ONLY by the native
// slice-level test_api so a full round trip can read every message even on a
// target whose static arena sits above 2^32 (where the u32-pointer descriptor
// path SKIPs). KSF scratch still comes from `fba.allocator()` in all cases.
const ResultSink = union(enum) {
    none,
    descriptor: u32,
    slice: []u8,

    // Acquire a `len`-byte buffer to fill with the result, or `null` if the
    // result should be discarded (validate-only). The caller serializes into the
    // returned buffer and then calls `finish`.
    fn begin(self: ResultSink, len: usize) !?[]u8 {
        return switch (self) {
            .none => null,
            .descriptor => try allocResult(len),
            .slice => |buf| if (buf.len == len) buf else error.InvalidInput,
        };
    }

    // Publish the filled buffer. For `.descriptor` this writes the {ptr,len}
    // descriptor; for `.slice` the bytes are already in the caller's buffer.
    fn finish(self: ResultSink, out: []u8) i32 {
        switch (self) {
            .none => {},
            .descriptor => |out_ptr| writeResultDescriptor(out_ptr, @intCast(@intFromPtr(out.ptr)), @intCast(out.len)) catch return @intFromEnum(Status.invalid_input),
            .slice => {},
        }
        return @intFromEnum(Status.ok);
    }
};

fn allocResult(len: usize) ![]u8 {
    if (len > std.math.maxInt(u32)) return error.OutOfMemory;
    if (!heapFitsU32Pointers()) return error.OutOfMemory;
    return fba.allocator().alloc(u8, len);
}

/// Map a protocol Error to a wasm Status. OutOfMemory is kept DISTINCT from the
/// generic protocol_error: the 32 MiB arena can be exhausted by argon2id_owasp's
/// 19 MiB fill (e.g. several concurrent finishes before a resetAllocator), so an
/// honest out_of_memory lets callers tell a resource limit apart from a genuine
/// protocol/authentication failure. Every protocol catch site routes through
/// here so this mapping is the single source of truth.
fn mapProtocolError(err: protocol.Error) i32 {
    return switch (err) {
        error.OutOfMemory => @intFromEnum(Status.out_of_memory),
        else => @intFromEnum(Status.protocol_error),
    };
}

// Map a ResultSink.begin error to a wasm Status: an exhausted arena is
// out_of_memory; a caller slice whose length does not match the result is
// invalid_input.
fn mapSinkError(err: anyerror) i32 {
    return switch (err) {
        error.OutOfMemory => @intFromEnum(Status.out_of_memory),
        else => @intFromEnum(Status.invalid_input),
    };
}

fn validateOutputDescriptor(out_ptr: u32) !void {
    _ = try heapSlice(out_ptr, 8);
}

// Bounds-checked cursor read: returns `len` bytes at `offset` or error.InvalidInput
// if fewer than `len` bytes remain. offset.* <= input.len is an invariant (every
// advance goes through a checked read), so `input.len - offset.*` never underflows.
// Checking here (the single slicing chokepoint) prevents the whole class of
// out-of-bounds reads in the *Input parsers, including the fixed-size readArray
// reads that follow a variable-length opaque16 field.
fn readSlice(input: []const u8, offset: *usize, len: usize) error{InvalidInput}![]const u8 {
    if (input.len - offset.* < len) return error.InvalidInput;
    const out = input[offset.*..][0..len];
    offset.* += len;
    return out;
}

fn readArray(input: []const u8, offset: *usize, comptime len: usize) error{InvalidInput}![len]u8 {
    return (try readSlice(input, offset, len))[0..len].*;
}

fn readOpaque16(input: []const u8, offset: *usize) ![]const u8 {
    if (input.len - offset.* < 2) return error.InvalidInput;
    const len = std.mem.readInt(u16, input[offset.*..][0..2], .big);
    offset.* += 2;
    if (input.len - offset.* < len) return error.InvalidInput;
    return try readSlice(input, offset, len);
}

fn optionalIdentity(bytes: []const u8) ?[]const u8 {
    return if (bytes.len == 0) null else bytes;
}

fn wasmSuite(ksf: protocol.Ksf, context: []const u8) !protocol.Suite {
    if (ksf != .identity_test_only and context.len == 0) return error.InvalidInput;
    // The WASM ABI is uniformly ristretto255 (RFC 9807's RECOMMENDED interop
    // group and the native Suite default). Both the production exports
    // (registrationFinish/loginFinish/serverLoginStart, argon2id) and the gated
    // *IdentityTestVector exports (identity KSF) run on group = ristretto255, so
    // every WASM flow is group-consistent end to end -- there is no group split.
    // The identity-test exports therefore reproduce RFC 9807 Appendix C.1.1
    // (ristretto255 + Identity KSF), not the curve25519 C.1.3 vectors.
    return .{ .context = context, .ksf = ksf, .group = .ristretto255 };
}

fn createRegistrationRequestFromUniform(password: []const u8, blind_uniform: [constants.blind_uniform_len]u8) protocol.Error!protocol.RegistrationResult {
    // Delegate to the public 64-byte-uniform builder; both reduce the uniform
    // bytes via oprf.blindWithRandomBytes, so behavior is unchanged.
    return protocol.createRegistrationRequestFromUniform(password, blind_uniform);
}

fn generateKE1FromUniform(
    password: []const u8,
    blind_uniform: [constants.blind_uniform_len]u8,
    client_nonce: [constants.Nn]u8,
    client_keyshare_seed: [constants.Nseed]u8,
) protocol.Error!protocol.LoginStartResult {
    // loginStart is a SINGLE shared export (it takes no KSF and so cannot pick a
    // group the way wasmSuite does). KE1's client_public_keyshare is derived from
    // suite.group, so it must match the group used by EVERY downstream export that
    // consumes this KE1. The WASM ABI is uniformly ristretto255, so we pin
    // ristretto255 here too: this single loginStart feeds both the production
    // ristretto255 loginFinish/serverLoginStart (argon2id) AND the gated
    // ristretto255 *IdentityTestVector finishes (identity KSF, RFC 9807 C.1.1).
    // Only suite.group is consulted by generateKE1FromUniform (not ksf/context),
    // so the default Suite ksf/context are irrelevant here.
    const suite = protocol.Suite{ .group = .ristretto255 };
    return protocol.generateKE1FromUniform(suite, password, blind_uniform, client_nonce, client_keyshare_seed);
}

fn heapSlice(ptr: u32, len: u32) ![]u8 {
    if (len == 0) {
        if (ptr == 0) return heap_buffer[0..0];
        if (!rangeInHeap(ptr, 0)) return error.InvalidInput;
        const start = @as(usize, ptr) - heapStart();
        return heap_buffer[start..start];
    }
    if (!rangeInHeap(ptr, len)) return error.InvalidInput;
    const start = @as(usize, ptr) - heapStart();
    return heap_buffer[start..][0..len];
}

fn rangeInHeap(ptr: u32, len: u32) bool {
    const start = @as(usize, ptr);
    const end = std.math.add(usize, start, len) catch return false;
    const heap_start = heapStart();
    const heap_end = heap_start + heap_buffer.len;
    return start >= heap_start and end <= heap_end and end >= start;
}

fn heapFitsU32Pointers() bool {
    return heapEnd() <= std.math.maxInt(u32);
}

fn heapStart() usize {
    return @intFromPtr(&heap_buffer[0]);
}

fn heapEnd() usize {
    return heapStart() + heap_buffer.len;
}
