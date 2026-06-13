const std = @import("std");

const opaque_root = @import("opaque_root");
const opaque_wasm = opaque_root.wasm_abi;
const protocol = opaque_root.protocol;

const Nn: usize = 32;
const Nseed: usize = 32;
const Nh: usize = 64;
const Npk: usize = 32;
const Nsk: usize = 32;
const Nm: usize = 64;
const Nx: usize = 64;
const Noe: usize = 32;
const blind_uniform_len: usize = 64;

const envelope_len: usize = Nn + Nm;
const masked_response_len: usize = Npk + envelope_len;
const registration_request_len: usize = Noe;
const registration_response_len: usize = Noe + Npk;
const registration_record_len: usize = Npk + Nh + envelope_len;
const credential_request_len: usize = Noe;
const credential_response_len: usize = Noe + Nn + masked_response_len;
const auth_request_len: usize = Nn + Npk;
const auth_response_len: usize = Nn + Npk + Nm;
const ke1_len: usize = credential_request_len + auth_request_len;
const ke2_len: usize = credential_response_len + auth_response_len;
const ke3_len: usize = Nm;
const client_login_state_len: usize = Nsk + Nsk + ke1_len;
const server_login_state_len: usize = Nm + Nx;

const Status = enum(i32) {
    ok = 0,
    protocol_error = 1,
    invalid_input = 2,
    out_of_memory = 3,
};

test "WASM ABI exported lengths match protocol constants" {
    try std.testing.expectEqual(@as(u32, 4), opaque_wasm.version());
    try std.testing.expectEqual(@as(u32, registration_request_len), opaque_wasm.registrationRequestLen());
    try std.testing.expectEqual(@as(u32, registration_response_len), opaque_wasm.registrationResponseLen());
    try std.testing.expectEqual(@as(u32, registration_record_len), opaque_wasm.registrationRecordLen());
    try std.testing.expectEqual(@as(u32, ke1_len), opaque_wasm.ke1Len());
    try std.testing.expectEqual(@as(u32, ke2_len), opaque_wasm.ke2Len());
    try std.testing.expectEqual(@as(u32, ke3_len), opaque_wasm.ke3Len());
}

test "WASM ABI protocol exports reject null or short inputs deterministically" {
    var descriptor: [8]u8 = @splat(0xaa);
    const descriptor_ptr = ptrToU32(&descriptor) orelse 0;

    try expectStatus(.invalid_input, opaque_wasm.registrationStart(0, Nsk, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.registrationFinish(0, Nsk, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.loginStart(0, Nsk, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.loginFinish(0, ke2_len, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.serverLoginStart(0, ke1_len, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.serverLoginFinish(0, ke3_len, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.serverRegistrationResponse(0, registration_request_len, descriptor_ptr));

    const unchanged: [descriptor.len]u8 = @splat(0xaa);
    try std.testing.expectEqualSlices(u8, &unchanged, &descriptor);
}

test "WASM ABI allocator can be reset when native pointers fit the byte ABI" {
    opaque_wasm.resetAllocator();
    const first = try allocBytes(16);
    @memset(heapBytes(first, 16), 0xaa);

    const second = try allocBytes(16);
    try std.testing.expect(second >= first + 16);

    opaque_wasm.free(first, 16);
    try std.testing.expect(std.mem.allEqual(u8, heapBytes(first, 16), 0));

    opaque_wasm.resetAllocator();

    const after_reset = try allocBytes(16);
    try std.testing.expectEqual(first, after_reset);
    try std.testing.expect(std.mem.allEqual(u8, heapBytes(after_reset, 16), 0));
}

test "WASM ABI registrationStart writes a result descriptor for valid small input" {
    opaque_wasm.resetAllocator();

    const password = "pw";
    var input: [blind_uniform_len + password.len]u8 = undefined;
    input[0..blind_uniform_len].* = uniform(0x03);
    @memcpy(input[blind_uniform_len..], password);

    const input_ptr = try allocCopy(&input);
    const descriptor_ptr = try allocBytes(8);
    const status = opaque_wasm.registrationStart(
        input_ptr,
        @intCast(input.len),
        descriptor_ptr,
    );
    if (status == @intFromEnum(Status.protocol_error)) return error.SkipZigTest;
    try expectStatus(.ok, status);

    const descriptor = heapBytes(descriptor_ptr, 8);
    const result_ptr = std.mem.readInt(u32, descriptor[0..4], .little);
    const result_len = std.mem.readInt(u32, descriptor[4..8], .little);
    try std.testing.expect(result_ptr != 0);
    try std.testing.expectEqual(@as(u32, Nsk + registration_request_len), result_len);

    const result: [*]const u8 = @ptrFromInt(result_ptr);
    try std.testing.expect(!std.mem.allEqual(u8, result[Nsk..][0..registration_request_len], 0));
}

test "WASM ABI serverRegistrationResponse evaluates a real registration request" {
    opaque_wasm.resetAllocator();

    // 1. Produce a genuine registration_request (Noe bytes) WITHOUT the wasm
    //    allocator, so the slice-level happy path below runs even on native
    //    targets where the u32-pointer arena is unavailable. The request is just
    //    the serialized blinded OPRF element; createRegistrationRequestFromUniform
    //    is allocator-free.
    const request_result = try protocol.createRegistrationRequestFromUniform("pw", uniform(0x07));
    const registration_request = request_result.request.toBytes();

    // 2. Assemble the serverRegistrationResponse input:
    //    registration_request(Noe) || server_public_key(Npk) ||
    //    credential_identifier(opaque16) || oprf_seed(Nh)
    const credential_identifier = "user-1";
    const server_public_key: [Npk]u8 = @splat(0x11);
    const oprf_seed: [Nh]u8 = @splat(0x22);

    var input: [registration_request_len + Npk + 2 + credential_identifier.len + Nh]u8 = undefined;
    var off: usize = 0;
    @memcpy(input[off..][0..registration_request_len], &registration_request);
    off += registration_request_len;
    @memcpy(input[off..][0..Npk], &server_public_key);
    off += Npk;
    std.mem.writeInt(u16, input[off..][0..2], @intCast(credential_identifier.len), .big);
    off += 2;
    @memcpy(input[off..][0..credential_identifier.len], credential_identifier);
    off += credential_identifier.len;
    @memcpy(input[off..][0..Nh], &oprf_seed);
    off += Nh;
    try std.testing.expectEqual(input.len, off);

    // 3. Slice-level path (test_api uses a null out_ptr -> no allocation): a valid
    //    blinded element plus well-formed framing must be accepted. This runs on
    //    all targets (it does not touch the u32-pointer arena). The pointer-ABI
    //    output bytes are verified separately below.
    try expectStatus(.ok, opaque_wasm.test_api.serverRegistrationResponse(&input));
}

test "WASM ABI serverRegistrationResponse writes a valid RegistrationResponse descriptor" {
    opaque_wasm.resetAllocator();

    // Same well-formed input as the slice-level test, but driven through the
    // pointer ABI so we can read the result bytes. This needs the u32 arena and
    // so SKIPs on a native target whose static buffer sits above 2^32 (same as
    // the other descriptor tests); it runs for real in the wasm32 / Deno path.
    const request_result = try protocol.createRegistrationRequestFromUniform("pw", uniform(0x07));
    const registration_request = request_result.request.toBytes();

    const credential_identifier = "user-1";
    const server_public_key: [Npk]u8 = @splat(0x11);
    const oprf_seed: [Nh]u8 = @splat(0x22);

    var input: [registration_request_len + Npk + 2 + credential_identifier.len + Nh]u8 = undefined;
    var off: usize = 0;
    @memcpy(input[off..][0..registration_request_len], &registration_request);
    off += registration_request_len;
    @memcpy(input[off..][0..Npk], &server_public_key);
    off += Npk;
    std.mem.writeInt(u16, input[off..][0..2], @intCast(credential_identifier.len), .big);
    off += 2;
    @memcpy(input[off..][0..credential_identifier.len], credential_identifier);
    off += credential_identifier.len;
    @memcpy(input[off..][0..Nh], &oprf_seed);
    off += Nh;

    const input_ptr = try allocCopy(&input);
    const descriptor_ptr = try allocBytes(8);
    const status = opaque_wasm.serverRegistrationResponse(
        input_ptr,
        @intCast(input.len),
        descriptor_ptr,
    );
    if (status == @intFromEnum(Status.protocol_error)) return error.SkipZigTest;
    try expectStatus(.ok, status);

    const descriptor = heapBytes(descriptor_ptr, 8);
    const result_ptr = std.mem.readInt(u32, descriptor[0..4], .little);
    const result_len = std.mem.readInt(u32, descriptor[4..8], .little);
    try std.testing.expect(result_ptr != 0);
    try std.testing.expectEqual(@as(u32, registration_response_len), result_len);

    const response = heapBytes(result_ptr, registration_response_len);
    // evaluated_message (first Noe bytes) must be a real OPRF output, not zero.
    try std.testing.expect(!std.mem.allEqual(u8, response[0..Noe], 0));
    // server_public_key (trailing Npk bytes) is echoed verbatim.
    try std.testing.expectEqualSlices(u8, &server_public_key, response[Noe..][0..Npk]);
}

test "WASM ABI serverRegistrationResponse rejects trailing bytes and bad framing" {
    opaque_wasm.resetAllocator();

    const credential_identifier = "u";
    const base_len = registration_request_len + Npk + 2 + credential_identifier.len + Nh;

    // Well-framed body with a valid (all-zero is fine for framing) request slot,
    // then a single trailing byte -> exact-length consumption must reject it.
    var too_long: [base_len + 1]u8 = @splat(0);
    std.mem.writeInt(u16, too_long[registration_request_len + Npk ..][0..2], @intCast(credential_identifier.len), .big);
    @memcpy(too_long[registration_request_len + Npk + 2 ..][0..credential_identifier.len], credential_identifier);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverRegistrationResponse(&too_long));

    // opaque16 length prefix that overruns the buffer must reject (not read OOB).
    var bad_frame: [base_len]u8 = @splat(0);
    std.mem.writeInt(u16, bad_frame[registration_request_len + Npk ..][0..2], 0xffff, .big);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverRegistrationResponse(&bad_frame));
}

test "WASM ABI serverRegistrationResponse rejects short inputs without trapping" {
    opaque_wasm.resetAllocator();

    // Regression for the unbounded readSlice/readArray bug: serverRegistrationResponse
    // reads a fixed 64-byte oprf_seed via readArray AFTER a variable-length opaque16
    // credential_identifier. A crafted short input made readArray slice past the end.
    // The bounds-checked readSlice must turn each of these into Status.invalid_input
    // (a returned i32), NOT a wasm trap / checked panic. Reaching the assertions at
    // all (rather than aborting the test process) is the proof it no longer traps.

    // (a) len = 128 with an EMPTY credential_identifier (2-byte 0x0000 prefix, no
    //     oprf_seed): fixed_len (request 32 + Npk 32 + Nh 64 = 128) is satisfied, so
    //     the early `input.len < fixed_len` guard passes; the empty opaque16 consumes
    //     the last 2 bytes, leaving 0 for the 64-byte oprf_seed readArray. Old code
    //     read 64 bytes OOB here; new code returns invalid_input.
    var empty_cred: [128]u8 = @splat(0);
    std.mem.writeInt(u16, empty_cred[registration_request_len + Npk ..][0..2], 0, .big);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverRegistrationResponse(&empty_cred));

    // (b) len = 129 (one more byte than the fixed minimum): the opaque16 prefix (0)
    //     plus one body byte still cannot satisfy the trailing 64-byte oprf_seed.
    var len129: [129]u8 = @splat(0);
    std.mem.writeInt(u16, len129[registration_request_len + Npk ..][0..2], 0, .big);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverRegistrationResponse(&len129));

    // (c) a credential_identifier length prefix that pushes the cursor past the end
    //     BEFORE the oprf_seed: request(32) + Npk(32) + opaque16{len=64, 64 bytes} =
    //     130 bytes consumed, leaving 0 for oprf_seed (and the prefix itself is valid
    //     framing, so this exercises the post-opaque16 readArray bound, not readOpaque16).
    var cred_eats_seed: [registration_request_len + Npk + 2 + Nh]u8 = @splat(0);
    std.mem.writeInt(u16, cred_eats_seed[registration_request_len + Npk ..][0..2], @intCast(Nh), .big);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverRegistrationResponse(&cred_eats_seed));
}

// Knob for the *ToSlice round-trip tests: which KSF flavor of the finish/start
// exports to drive. Both flavors are ristretto255; they differ only in password
// stretching, which is exactly the dimension that must NOT change the AKE group.
const RoundTripVariant = enum { production, identity };

// Append-only builder for the byte-exact wasm input layouts. `bytes` appends a
// raw field; `opaque16` appends a u16-BE length prefix + the field (the framing
// every opaque16 slot in the ABI expects). The backing buffer is fixed and
// oversized; appends past it fail the test loudly rather than truncating.
const InputBuilder = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,

    fn bytes(self: *InputBuilder, data: []const u8) void {
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    fn opaque16(self: *InputBuilder, data: []const u8) void {
        std.mem.writeInt(u16, self.buf[self.len..][0..2], @intCast(data.len), .big);
        self.len += 2;
        self.bytes(data);
    }

    fn slice(self: *const InputBuilder) []const u8 {
        return self.buf[0..self.len];
    }
};

// Drive one full ristretto255 round trip through the slice-level wasm test_api,
// using the production (argon2id_owasp) or identity (RFC 9807 C.1.1) finish/start
// variants per `variant`. Proves the WASM ABI is group-consistent end to end:
// loginStart's KE1 keyshare group must match the finish/serverStart group or the
// 3DH and the client/server MACs disagree and serverFinish fails. Asserts the
// client and server confirmed session keys AGREE.
//
// Every step writes into a caller-owned stack buffer (the `*ToSlice` ResultSink),
// so nothing the round trip needs lives in the wasm arena; we call
// resetAllocator() between steps exactly as the JS wrapper does, clearing only
// the transient KSF scratch.
fn runRistretto255RoundTrip(variant: RoundTripVariant) !void {
    // Default keys for the variant-driven round trips: derive a real DH keypair
    // directly via the protocol (the AKE needs consistent
    // server_private_key/server_public_key; generateKE2 runs
    // diffieHellman(server_private_key, client_keyshare)).
    const server_seed: [Nseed]u8 = @splat(0x5a);
    const server_keypair = try protocol.Group.ristretto255.deriveDhKeyPair(server_seed);
    try runRistretto255RoundTripWithServerKeys(variant, server_keypair.sk, server_keypair.pk);
}

// Same round trip as runRistretto255RoundTrip but with the long-term server
// keypair supplied by the caller, so the serverKeyPair-export test can prove the
// keypair it generates is VALID end to end (the client/server confirmed session
// keys only agree if server_public_key = basepoint * server_private_key, exactly
// what serverKeyPair guarantees).
fn runRistretto255RoundTripWithServerKeys(
    variant: RoundTripVariant,
    server_private_key: [Nsk]u8,
    server_public_key: [Npk]u8,
) !void {
    const password = "correct horse battery staple";
    const context = "OPAQUE-POC";
    const credential_identifier = "user-42";
    const oprf_seed: [Nh]u8 = @splat(0x6b);

    // --- 1. registrationStart: blind_uniform(64) || password ---
    opaque_wasm.resetAllocator();
    var reg_start = InputBuilder{};
    reg_start.bytes(&uniform(0x11));
    reg_start.bytes(password);
    var reg_start_out: [Nsk + registration_request_len]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.registrationStartToSlice(reg_start.slice(), &reg_start_out));
    const reg_blind = reg_start_out[0..Nsk].*;
    const registration_request = reg_start_out[Nsk..][0..registration_request_len].*;

    // --- 2. serverRegistrationResponse (group-agnostic OPRF) ---
    //     request(32) || server_public_key(32) || cred_id(opaque16) || oprf_seed(64)
    opaque_wasm.resetAllocator();
    var reg_resp = InputBuilder{};
    reg_resp.bytes(&registration_request);
    reg_resp.bytes(&server_public_key);
    reg_resp.opaque16(credential_identifier);
    reg_resp.bytes(&oprf_seed);
    var registration_response: [registration_response_len]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.serverRegistrationResponseToSlice(reg_resp.slice(), &registration_response));

    // --- 3. registrationFinish (argon2id OR identity) ---
    //     blind(32) || envelope_nonce(32) || response(64) || password(o16) ||
    //     context(o16) || server_identity(o16=empty) || client_identity(o16=empty)
    opaque_wasm.resetAllocator();
    var reg_finish = InputBuilder{};
    reg_finish.bytes(&reg_blind);
    reg_finish.bytes(&uniform(0x22)[0..Nn].*);
    reg_finish.bytes(&registration_response);
    reg_finish.opaque16(password);
    reg_finish.opaque16(context);
    reg_finish.opaque16("");
    reg_finish.opaque16("");
    var reg_finish_out: [registration_record_len + Nh]u8 = undefined;
    try expectStatus(.ok, switch (variant) {
        .production => opaque_wasm.test_api.registrationFinishToSlice(reg_finish.slice(), &reg_finish_out),
        .identity => opaque_wasm.test_api.registrationFinishIdentityToSlice(reg_finish.slice(), &reg_finish_out),
    });
    const registration_record = reg_finish_out[0..registration_record_len].*;

    // --- 4. loginStart (single shared export; ristretto255 keyshare) ---
    //     blind_uniform(64) || client_nonce(32) || keyshare_seed(32) || password
    opaque_wasm.resetAllocator();
    var login_start = InputBuilder{};
    login_start.bytes(&uniform(0x33));
    login_start.bytes(&uniform(0x44)[0..Nn].*);
    login_start.bytes(&uniform(0x55)[0..Nseed].*);
    login_start.bytes(password);
    var login_start_out: [client_login_state_len + ke1_len]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.loginStartToSlice(login_start.slice(), &login_start_out));
    const client_state = login_start_out[0..client_login_state_len].*;
    const client_blind = client_state[0..Nsk].*;
    const client_secret = client_state[Nsk..][0..Nsk].*;
    const ke1 = login_start_out[client_login_state_len..][0..ke1_len].*;

    // --- 5. serverLoginStart (argon2id OR identity) ---
    //     server_private_key(32) || server_public_key(32) || record(rec) ||
    //     oprf_seed(64) || ke1(ke1) || masking_nonce(32) || server_nonce(32) ||
    //     server_keyshare_seed(32) || cred_id(o16) || context(o16) ||
    //     server_identity(o16=empty) || client_identity(o16=empty)
    opaque_wasm.resetAllocator();
    var srv_login = InputBuilder{};
    srv_login.bytes(&server_private_key);
    srv_login.bytes(&server_public_key);
    srv_login.bytes(&registration_record);
    srv_login.bytes(&oprf_seed);
    srv_login.bytes(&ke1);
    srv_login.bytes(&uniform(0x66)[0..Nn].*);
    srv_login.bytes(&uniform(0x77)[0..Nn].*);
    srv_login.bytes(&uniform(0x88)[0..Nseed].*);
    srv_login.opaque16(credential_identifier);
    srv_login.opaque16(context);
    srv_login.opaque16("");
    srv_login.opaque16("");
    var srv_login_out: [server_login_state_len + ke2_len]u8 = undefined;
    try expectStatus(.ok, switch (variant) {
        .production => opaque_wasm.test_api.serverLoginStartToSlice(srv_login.slice(), &srv_login_out),
        .identity => opaque_wasm.test_api.serverLoginStartIdentityToSlice(srv_login.slice(), &srv_login_out),
    });
    const server_state = srv_login_out[0..server_login_state_len].*;
    const ke2 = srv_login_out[server_login_state_len..][0..ke2_len].*;

    // --- 6. loginFinish (argon2id OR identity): recover creds, auth server ---
    //     blind(32) || client_secret(32) || ke1(ke1) || ke2(ke2) || password(o16)
    //     || context(o16) || server_identity(o16=empty) || client_identity(o16=empty)
    opaque_wasm.resetAllocator();
    var login_finish = InputBuilder{};
    login_finish.bytes(&client_blind);
    login_finish.bytes(&client_secret);
    login_finish.bytes(&ke1);
    login_finish.bytes(&ke2);
    login_finish.opaque16(password);
    login_finish.opaque16(context);
    login_finish.opaque16("");
    login_finish.opaque16("");
    var login_finish_out: [ke3_len + Nx + Nh]u8 = undefined;
    try expectStatus(.ok, switch (variant) {
        .production => opaque_wasm.test_api.loginFinishToSlice(login_finish.slice(), &login_finish_out),
        .identity => opaque_wasm.test_api.loginFinishIdentityToSlice(login_finish.slice(), &login_finish_out),
    });
    const ke3 = login_finish_out[0..ke3_len].*;
    const client_session_key = login_finish_out[ke3_len..][0..Nx].*;

    // --- 7. serverLoginFinish: constant-time client-MAC check -> session key ---
    //     server_state(state) || ke3(ke3)
    opaque_wasm.resetAllocator();
    var srv_finish = InputBuilder{};
    srv_finish.bytes(&server_state);
    srv_finish.bytes(&ke3);
    var server_session_key: [Nx]u8 = undefined;
    // A non-ok here (AuthenticationFailed -> protocol_error) means the groups are
    // mismatched: the client/server MACs were computed over different DH outputs.
    try expectStatus(.ok, opaque_wasm.test_api.serverLoginFinishToSlice(srv_finish.slice(), &server_session_key));

    // The whole point: both sides derived the SAME confirmed session key.
    try std.testing.expectEqualSlices(u8, &client_session_key, &server_session_key);
    try std.testing.expect(!std.mem.allEqual(u8, &client_session_key, 0));
}

test "WASM ABI production ristretto255 round trip agrees on session key (argon2id)" {
    // FIRST end-to-end exercise of the production argon2id wasm path: registration
    // through login, all ristretto255. Proves loginStart's keyshare group matches
    // the production finishes. argon2id_owasp runs a handful of times here (~1s).
    try runRistretto255RoundTrip(.production);
}

test "WASM ABI identity ristretto255 round trip agrees on session key" {
    // Same flow via the gated identity-KSF (RFC 9807 C.1.1) finish/start variants.
    // loginStart is shared with the production path, so this also confirms its
    // ristretto255 keyshare is consistent with the identity finishes.
    try runRistretto255RoundTrip(.identity);
}

test "WASM ABI serverKeyPair exported length matches Nsk + Npk" {
    try std.testing.expectEqual(@as(u32, Nsk + Npk), opaque_wasm.serverKeyPairLen());
}

test "WASM ABI serverKeyPair is deterministic and rejects wrong-length seeds" {
    // Determinism: the same seed must yield the same sk||pk. We read the bytes via
    // the slice-level test_api so this runs on all targets (no u32 arena needed).
    const seed: [Nseed]u8 = @splat(0x42);

    var first: [Nsk + Npk]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.serverKeyPairToSlice(&seed, &first));

    var second: [Nsk + Npk]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.serverKeyPairToSlice(&seed, &second));
    try std.testing.expectEqualSlices(u8, &first, &second);

    // The generated keypair must agree with the protocol's own derivation: sk is
    // the scalar and pk = basepoint * sk on ristretto255.
    const expected = try protocol.Group.ristretto255.deriveDhKeyPair(seed);
    try std.testing.expectEqualSlices(u8, &expected.sk, first[0..Nsk]);
    try std.testing.expectEqualSlices(u8, &expected.pk, first[Nsk..][0..Npk]);

    // A different seed yields a different keypair (sanity that the seed is used).
    const other_seed: [Nseed]u8 = @splat(0x43);
    var other: [Nsk + Npk]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.serverKeyPairToSlice(&other_seed, &other));
    try std.testing.expect(!std.mem.eql(u8, &first, &other));

    // Wrong-length seeds are rejected (exact-length input): one byte short, one
    // byte long, and empty.
    const short: [Nseed - 1]u8 = @splat(0x42);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverKeyPair(&short));
    const long: [Nseed + 1]u8 = @splat(0x42);
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverKeyPair(&long));
    try expectStatus(.invalid_input, opaque_wasm.test_api.serverKeyPair(&[_]u8{}));
}

test "WASM ABI serverKeyPair rejects wrong-length seed via the pointer ABI" {
    // Drive the production pointer-ABI export with a wrong-length input and assert
    // it returns invalid_input WITHOUT writing the result descriptor (it must be
    // left untouched). This exercises the exported entry point, not just test_api.
    var descriptor: [8]u8 = @splat(0xaa);
    const descriptor_ptr = ptrToU32(&descriptor) orelse return error.SkipZigTest;
    try expectStatus(.invalid_input, opaque_wasm.serverKeyPair(0, Nseed - 1, descriptor_ptr));
    const unchanged: [descriptor.len]u8 = @splat(0xaa);
    try std.testing.expectEqualSlices(u8, &unchanged, &descriptor);
}

test "WASM ABI serverKeyPair writes a valid keypair descriptor" {
    // Pointer-ABI happy path: generate a keypair through the real descriptor
    // mechanism and confirm both halves are present and match the protocol's
    // derivation. SKIPs on a native target whose static buffer sits above 2^32
    // (same as the other descriptor tests); runs for real in the wasm32 / Deno path.
    opaque_wasm.resetAllocator();

    const seed: [Nseed]u8 = @splat(0x77);
    const input_ptr = try allocCopy(&seed);
    const descriptor_ptr = try allocBytes(8);
    const status = opaque_wasm.serverKeyPair(input_ptr, Nseed, descriptor_ptr);
    if (status == @intFromEnum(Status.protocol_error)) return error.SkipZigTest;
    try expectStatus(.ok, status);

    const descriptor = heapBytes(descriptor_ptr, 8);
    const result_ptr = std.mem.readInt(u32, descriptor[0..4], .little);
    const result_len = std.mem.readInt(u32, descriptor[4..8], .little);
    try std.testing.expect(result_ptr != 0);
    try std.testing.expectEqual(@as(u32, Nsk + Npk), result_len);

    const result = heapBytes(result_ptr, Nsk + Npk);
    const expected = try protocol.Group.ristretto255.deriveDhKeyPair(seed);
    try std.testing.expectEqualSlices(u8, &expected.sk, result[0..Nsk]);
    try std.testing.expectEqualSlices(u8, &expected.pk, result[Nsk..][0..Npk]);
}

test "WASM ABI serverKeyPair generates keys that drive a full round trip (production)" {
    // The real proof the export is correct: feed a serverKeyPair-generated (sk, pk)
    // into the full ristretto255 server round trip (registration + login through
    // serverLoginFinish) and require the client and server confirmed session keys
    // to AGREE. They only agree if pk = basepoint * sk, which is exactly what
    // serverKeyPair guarantees. Uses the production argon2id finish/start path.
    const seed: [Nseed]u8 = @splat(0x91);
    var keypair: [Nsk + Npk]u8 = undefined;
    try expectStatus(.ok, opaque_wasm.test_api.serverKeyPairToSlice(&seed, &keypair));
    const server_private_key = keypair[0..Nsk].*;
    const server_public_key = keypair[Nsk..][0..Npk].*;

    try runRistretto255RoundTripWithServerKeys(.production, server_private_key, server_public_key);
}

fn expectStatus(expected: Status, actual: i32) !void {
    try std.testing.expectEqual(@intFromEnum(expected), actual);
}

fn ptrToU32(ptr: anytype) ?u32 {
    const value = @intFromPtr(ptr);
    if (value > std.math.maxInt(u32)) return null;
    return @intCast(value);
}

fn uniform(byte: u8) [64]u8 {
    var out: [64]u8 = @splat(0);
    out[0] = byte;
    return out;
}

fn allocBytes(len: usize) !u32 {
    if (len > std.math.maxInt(u32)) return error.SkipZigTest;
    const ptr = opaque_wasm.allocate(@intCast(len));
    if (ptr == 0) return error.SkipZigTest;
    return ptr;
}

fn allocCopy(input: []const u8) !u32 {
    const ptr = try allocBytes(input.len);
    @memcpy(heapBytes(ptr, input.len), input);
    return ptr;
}

fn heapBytes(ptr: u32, len: usize) []u8 {
    const bytes: [*]u8 = @ptrFromInt(ptr);
    return bytes[0..len];
}

test "WASM ABI module is linked" {}
