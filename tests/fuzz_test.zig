const std = @import("std");
const root = @import("opaque_root");

const c = root.constants;
const messages = root.messages;
const opaque_mod = root.protocol;
const oprf = root.oprf;
const wasm_abi = root.wasm_abi;
const testing = std.testing;
const Smith = std.testing.Smith;

const max_password_len = 96;
const max_credential_identifier_len = 96;
const max_context_len = 64;
const max_identity_len = 64;
const wasm_input_max_len = 832;

// Fuzz harnesses must not run Argon2id in their inner loop (Suite.default now
// does). Pin the identity KSF; these harnesses exercise protocol logic, not the
// KSF. The dedicated KSF tests cover the argon2id path.
const test_suite = opaque_mod.Suite{ .ksf = .identity_test_only };

const WasmSliceOp = enum(u8) {
    registration_start,
    registration_finish_identity,
    login_start,
    login_finish_identity,
    server_login_start_identity,
    server_login_finish,
};

const message_corpus_empty = sliceCorpus(0, 0x00);
const message_corpus_short = sliceCorpus(1, 0x10);
const message_corpus_envelope = sliceCorpus(c.envelope_len, 0x20);
const message_corpus_registration_request = sliceCorpus(c.registration_request_len, 0x30);
const message_corpus_registration_response = sliceCorpus(c.registration_response_len, 0x40);
const message_corpus_registration_record = sliceCorpus(c.registration_record_len, 0x50);
const message_corpus_credential_response = sliceCorpus(c.credential_response_len, 0x60);
const message_corpus_ke1 = sliceCorpus(c.ke1_len, 0x70);
const message_corpus_ke2 = sliceCorpus(c.ke2_len, 0x80);
const message_corpus_long = sliceCorpus(c.ke2_len + 1, 0x90);

const message_corpus = [_][]const u8{
    &message_corpus_empty,
    &message_corpus_short,
    &message_corpus_envelope,
    &message_corpus_registration_request,
    &message_corpus_registration_response,
    &message_corpus_registration_record,
    &message_corpus_credential_response,
    &message_corpus_ke1,
    &message_corpus_ke2,
    &message_corpus_long,
};

test "fuzz message parsers round trip exact-length encodings" {
    try testing.fuzz({}, fuzzMessageParsers, .{ .corpus = &message_corpus });
}

test "fuzz OPRF blind/evaluate/finalize properties" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    try testing.fuzz({}, fuzzOprfProperties, .{});
}

test "fuzz OPAQUE registration and login round trips" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    try testing.fuzz({}, fuzzOpaqueRoundTrip, .{});
}

test "fuzz OPAQUE authentication rejects MAC tampering" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    try testing.fuzz({}, fuzzOpaqueRejectsTampering, .{});
}

test "fuzz OPAQUE malformed state rejects invalid transitions" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    try testing.fuzz({}, fuzzOpaqueMalformedState, .{});
}

test "fuzz protocol input validation and server finish" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    try testing.fuzz({}, fuzzProtocolInputValidation, .{});
}

test "fuzz WASM ABI byte layouts return valid statuses" {
    try testing.fuzz({}, fuzzWasmAbiByteLayouts, .{});
}

test "fuzz WASM ABI slice parsers return valid statuses" {
    try testing.fuzz({}, fuzzWasmAbiSliceParsers, .{});
}

test "fuzz wide public API surface" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    try testing.fuzz({}, fuzzWidePublicApi, .{ .corpus = &wide_corpus });
}

fn fuzzMessageParsers(_: void, smith: *Smith) !void {
    var bytes_buf: [c.ke2_len + 1]u8 = undefined;
    const bytes = fuzzSlice(smith, bytes_buf[0..]);

    try checkMessageRoundTrip(messages.Envelope, c.envelope_len, bytes);
    try checkMessageRoundTrip(messages.RegistrationRequest, c.registration_request_len, bytes);
    try checkMessageRoundTrip(messages.RegistrationResponse, c.registration_response_len, bytes);
    try checkMessageRoundTrip(messages.RegistrationRecord, c.registration_record_len, bytes);
    try checkMessageRoundTrip(messages.CredentialRequest, c.credential_request_len, bytes);
    try checkMessageRoundTrip(messages.CredentialResponse, c.credential_response_len, bytes);
    try checkMessageRoundTrip(messages.AuthRequest, c.auth_request_len, bytes);
    try checkMessageRoundTrip(messages.AuthResponse, c.auth_response_len, bytes);
    try checkMessageRoundTrip(messages.KE1, c.ke1_len, bytes);
    try checkMessageRoundTrip(messages.KE2, c.ke2_len, bytes);
    try checkMessageRoundTrip(messages.KE3, c.ke3_len, bytes);
}

fn fuzzOprfProperties(_: void, smith: *Smith) !void {
    var seed_value: oprf.Seed = undefined;
    smith.bytes(&seed_value);

    var key_info_buf: [96]u8 = undefined;
    const key_info = fuzzSlice(smith, key_info_buf[0..]);

    var input_buf: [256]u8 = undefined;
    const input = fuzzSlice(smith, input_buf[0..]);

    const blind = try fuzzScalar(smith);
    const key_pair = try oprf.deriveKeyPair(seed_value, key_info);
    const blinded = try oprf.blindWithScalar(input, blind);

    const serialized_blinded = oprf.serializeElement(blinded.blinded_element);
    const parsed_blinded = try oprf.deserializeElement(serialized_blinded);
    try testing.expectEqualSlices(u8, &serialized_blinded, &oprf.serializeElement(parsed_blinded));

    const evaluated = try oprf.blindEvaluate(key_pair.sk, blinded.blinded_element);
    const finalized = try oprf.finalize(input, blinded.blind, evaluated);
    const direct = try oprf.evaluate(key_pair.sk, input);
    try testing.expectEqualSlices(u8, &direct, &finalized);

    try checkArbitraryElementRoundTrip(smith);
    try checkArbitraryScalarRoundTrip(smith);
}

fn fuzzOpaqueRoundTrip(_: void, smith: *Smith) !void {
    var password_buf: [max_password_len]u8 = undefined;
    var credential_identifier_buf: [max_credential_identifier_len]u8 = undefined;
    var context_buf: [max_context_len]u8 = undefined;
    var server_identity_buf: [max_identity_len]u8 = undefined;
    var client_identity_buf: [max_identity_len]u8 = undefined;

    const inputs = try readOpaqueInputs(
        smith,
        password_buf[0..],
        credential_identifier_buf[0..],
        context_buf[0..],
        server_identity_buf[0..],
        client_identity_buf[0..],
    );
    const setup = try setupOpaqueFlow(inputs);

    const login_finish = try opaque_mod.generateKE3(
        setup.suite,
        testing.allocator,
        setup.login_start.state,
        setup.server_start.ke2,
        inputs.password,
        inputs.server_identity,
        inputs.client_identity,
        null,
    );
    const server_session = try opaque_mod.serverFinish(setup.server_start.state, login_finish.ke3);

    try testing.expectEqualSlices(u8, &server_session, &login_finish.session_key);
    try testing.expectEqualSlices(u8, &setup.registration_finish.export_key, &login_finish.export_key);

    try checkEncodedMessageRoundTrip(messages.RegistrationRecord, c.registration_record_len, setup.registration_finish.record);
    try checkEncodedMessageRoundTrip(messages.KE1, c.ke1_len, setup.login_start.ke1);
    try checkEncodedMessageRoundTrip(messages.KE2, c.ke2_len, setup.server_start.ke2);
    try checkEncodedMessageRoundTrip(messages.KE3, c.ke3_len, login_finish.ke3);
}

fn fuzzOpaqueRejectsTampering(_: void, smith: *Smith) !void {
    var password_buf: [max_password_len]u8 = undefined;
    var credential_identifier_buf: [max_credential_identifier_len]u8 = undefined;
    var context_buf: [max_context_len]u8 = undefined;
    var server_identity_buf: [max_identity_len]u8 = undefined;
    var client_identity_buf: [max_identity_len]u8 = undefined;

    const inputs = try readOpaqueInputs(
        smith,
        password_buf[0..],
        credential_identifier_buf[0..],
        context_buf[0..],
        server_identity_buf[0..],
        client_identity_buf[0..],
    );
    const setup = try setupOpaqueFlow(inputs);

    const mask = smith.value(u8) | 1;
    switch (smith.value(enum(u8) { server_mac, client_mac })) {
        .server_mac => {
            var tampered_ke2 = setup.server_start.ke2;
            const index = smith.valueRangeLessThan(u8, 0, @intCast(c.Nm));
            tampered_ke2.auth_response.server_mac[index] ^= mask;

            try testing.expectError(
                error.AuthenticationFailed,
                opaque_mod.generateKE3(
                    setup.suite,
                    testing.allocator,
                    setup.login_start.state,
                    tampered_ke2,
                    inputs.password,
                    inputs.server_identity,
                    inputs.client_identity,
                    null,
                ),
            );
        },
        .client_mac => {
            var login_finish = try opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                setup.server_start.ke2,
                inputs.password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            );
            const index = smith.valueRangeLessThan(u8, 0, @intCast(c.Nm));
            login_finish.ke3.client_mac[index] ^= mask;

            try testing.expectError(
                error.AuthenticationFailed,
                opaque_mod.serverFinish(setup.server_start.state, login_finish.ke3),
            );
        },
    }
}

fn fuzzOpaqueMalformedState(_: void, smith: *Smith) !void {
    var password_buf: [max_password_len]u8 = undefined;
    var credential_identifier_buf: [max_credential_identifier_len]u8 = undefined;
    var context_buf: [max_context_len]u8 = undefined;
    var server_identity_buf: [max_identity_len]u8 = undefined;
    var client_identity_buf: [max_identity_len]u8 = undefined;

    const inputs = try readOpaqueInputs(
        smith,
        password_buf[0..],
        credential_identifier_buf[0..],
        context_buf[0..],
        server_identity_buf[0..],
        client_identity_buf[0..],
    );
    const setup = try setupOpaqueFlow(inputs);

    const Corruption = enum(u8) {
        wrong_password,
        wrong_context,
        wrong_server_identity,
        wrong_client_identity,
        evaluated_message,
        masked_response,
        server_keyshare,
        record_client_public_key,
        record_masking_key,
        record_envelope_nonce,
        record_envelope_tag,
    };

    const mask = smith.value(u8) | 1;
    switch (smith.value(Corruption)) {
        .wrong_password => {
            var wrong_password_buf: [max_password_len]u8 = undefined;
            const wrong_password = distinctFuzzSlice(smith, wrong_password_buf[0..], inputs.password);
            // The password is now an explicit KE3 parameter (not carried in
            // state); supplying a wrong one must fail credential recovery.
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                setup.server_start.ke2,
                wrong_password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            ));
        },
        .wrong_context => {
            var wrong_context_buf: [max_context_len]u8 = undefined;
            const wrong_context = distinctFuzzSlice(smith, wrong_context_buf[0..], inputs.context);
            try expectProtocolFailure(opaque_mod.generateKE3(
                .{ .context = wrong_context, .ksf = .identity_test_only },
                testing.allocator,
                setup.login_start.state,
                setup.server_start.ke2,
                inputs.password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            ));
        },
        .wrong_server_identity => {
            var wrong_identity_buf: [max_identity_len]u8 = undefined;
            const wrong_identity = distinctNonEmptyFuzzSlice(smith, wrong_identity_buf[0..], inputs.server_identity orelse &setup.server_public_key);
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                setup.server_start.ke2,
                inputs.password,
                wrong_identity,
                inputs.client_identity,
                null,
            ));
        },
        .wrong_client_identity => {
            var wrong_identity_buf: [max_identity_len]u8 = undefined;
            const wrong_identity = distinctNonEmptyFuzzSlice(smith, wrong_identity_buf[0..], inputs.client_identity orelse &setup.registration_finish.record.client_public_key);
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                setup.server_start.ke2,
                inputs.password,
                inputs.server_identity,
                wrong_identity,
                null,
            ));
        },
        .evaluated_message => {
            var bad_ke2 = setup.server_start.ke2;
            const index = smith.valueRangeLessThan(u8, 0, @intCast(c.Noe));
            bad_ke2.credential_response.evaluated_message[index] ^= mask;
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                bad_ke2,
                inputs.password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            ));
        },
        .masked_response => {
            var bad_ke2 = setup.server_start.ke2;
            const index = smith.valueRangeLessThan(u8, 0, @intCast(c.masked_response_len));
            bad_ke2.credential_response.masked_response[index] ^= mask;
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                bad_ke2,
                inputs.password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            ));
        },
        .server_keyshare => {
            var bad_ke2 = setup.server_start.ke2;
            const index = smith.valueRangeLessThan(u8, 0, @intCast(c.Npk));
            bad_ke2.auth_response.server_public_keyshare[index] ^= mask;
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                bad_ke2,
                inputs.password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            ));
        },
        .record_client_public_key,
        .record_masking_key,
        .record_envelope_nonce,
        .record_envelope_tag,
        => {
            var bad_record = setup.registration_finish.record;
            switch (smith.value(enum(u8) { client_public_key, masking_key, envelope_nonce, envelope_tag })) {
                .client_public_key => bad_record.client_public_key[smith.valueRangeLessThan(u8, 0, @intCast(c.Npk))] ^= mask,
                .masking_key => bad_record.masking_key[smith.valueRangeLessThan(u8, 0, @intCast(c.Nh))] ^= mask,
                .envelope_nonce => bad_record.envelope.nonce[smith.valueRangeLessThan(u8, 0, @intCast(c.Nn))] ^= mask,
                .envelope_tag => bad_record.envelope.auth_tag[smith.valueRangeLessThan(u8, 0, @intCast(c.Nm))] ^= mask,
            }

            const server_start = opaque_mod.generateKE2(
                setup.suite,
                setup.server_private_key,
                setup.server_public_key,
                bad_record,
                inputs.credential_identifier,
                inputs.oprf_seed,
                setup.login_start.ke1,
                inputs.masking_nonce,
                inputs.server_nonce,
                inputs.server_keyshare_seed,
                inputs.server_identity,
                inputs.client_identity,
            ) catch |err| {
                try expectKnownProtocolError(err);
                return;
            };
            try expectProtocolFailure(opaque_mod.generateKE3(
                setup.suite,
                testing.allocator,
                setup.login_start.state,
                server_start.ke2,
                inputs.password,
                inputs.server_identity,
                inputs.client_identity,
                null,
            ));
        },
    }
}

fn fuzzProtocolInputValidation(_: void, smith: *Smith) !void {
    var bytes: [max_password_len]u8 = undefined;
    const input = fuzzSlice(smith, bytes[0..]);
    var scalar_candidate: oprf.Scalar = undefined;
    smith.bytes(&scalar_candidate);

    switch (smith.value(enum(u8) {
        registration_scalar,
        login_scalar,
        blind_evaluate_scalar,
        server_finish,
        empty_identity,
        invalid_registration_response,
    })) {
        .registration_scalar => {
            _ = opaque_mod.createRegistrationRequest(input, scalar_candidate) catch |err| {
                try expectKnownProtocolError(err);
                return;
            };
        },
        .login_scalar => {
            var nonce: [c.Nn]u8 = undefined;
            var seed_value: [c.Nseed]u8 = undefined;
            smith.bytes(&nonce);
            smith.bytes(&seed_value);
            _ = opaque_mod.generateKE1(test_suite, input, scalar_candidate, nonce, seed_value) catch |err| {
                try expectKnownProtocolError(err);
                return;
            };
        },
        .blind_evaluate_scalar => {
            const element = oprf.hashToGroup(input) catch |err| {
                try expectKnownProtocolError(err);
                return;
            };
            _ = oprf.blindEvaluate(scalar_candidate, element) catch |err| {
                try expectKnownProtocolError(err);
                return;
            };
        },
        .server_finish => {
            var state: opaque_mod.ServerLoginState = undefined;
            var ke3: messages.KE3 = undefined;
            smith.bytes(&state.expected_client_mac);
            smith.bytes(&state.unconfirmed_session_key);
            smith.bytes(&ke3.client_mac);

            const result = opaque_mod.serverFinish(state, ke3);
            if (std.mem.eql(u8, &state.expected_client_mac, &ke3.client_mac)) {
                const session_key = try result;
                try testing.expectEqualSlices(u8, &state.unconfirmed_session_key, &session_key);
            } else {
                try testing.expectError(error.AuthenticationFailed, result);
            }
        },
        .empty_identity => {
            const server_keypair = try opaque_mod.Group.ristretto255.deriveDhKeyPair(seed(0x11));
            const registration_start = try opaque_mod.createRegistrationRequest(input, try fuzzScalar(smith));
            const registration_response = try opaque_mod.createRegistrationResponse(registration_start.request, server_keypair.pk, input, seed64(0x22));
            try testing.expectError(
                error.InvalidInput,
                opaque_mod.finalizeRegistrationRequest(
                    test_suite,
                    testing.allocator,
                    registration_start.state,
                    registration_response,
                    seed(0x33),
                    input,
                    "",
                    null,
                    null,
                ),
            );
        },
        .invalid_registration_response => {
            var response: messages.RegistrationResponse = undefined;
            smith.bytes(&response.evaluated_message);
            smith.bytes(&response.server_public_key);
            const state = opaque_mod.RegistrationClientState{
                .blind = try fuzzScalar(smith),
            };
            _ = opaque_mod.finalizeRegistrationRequest(
                test_suite,
                testing.allocator,
                state,
                response,
                seed(0x44),
                input,
                null,
                null,
                null,
            ) catch |err| {
                try expectKnownProtocolError(err);
                return;
            };
        },
    }
}

fn fuzzWasmAbiByteLayouts(_: void, smith: *Smith) !void {
    var input_buf: [wasm_input_max_len]u8 = undefined;
    const input = fuzzSlice(smith, input_buf[0..]);
    const input_len: u32 = if (smith.boolWeighted(8, 1))
        @intCast(input.len)
    else
        smith.value(u16);

    wasm_abi.resetAllocator();
    const allocated_input_ptr = wasmAllocCopy(input);
    const allocated_descriptor_ptr = wasmAllocBytes(8);
    const input_ptr = if (smith.boolWeighted(1, 4)) allocated_input_ptr orelse smith.value(u32) else smith.value(u32);
    const descriptor_ptr = if (smith.boolWeighted(1, 4)) allocated_descriptor_ptr orelse smith.value(u32) else smith.value(u32);
    const use_slice_api = smith.value(bool);

    const status = switch (smith.value(enum(u8) {
        registration_start,
        registration_finish,
        registration_finish_identity,
        login_start,
        login_finish,
        login_finish_identity,
        server_login_start,
        server_login_start_identity,
        server_login_finish,
    })) {
        .registration_start => if (use_slice_api) wasm_abi.test_api.registrationStart(input) else wasm_abi.registrationStart(input_ptr, input_len, descriptor_ptr),
        .registration_finish => wasm_abi.registrationFinish(input_ptr, input_len, descriptor_ptr),
        .registration_finish_identity => if (use_slice_api) wasm_abi.test_api.registrationFinishIdentity(input) else wasm_abi.registrationFinishIdentityTestVector(input_ptr, input_len, descriptor_ptr),
        .login_start => if (use_slice_api) wasm_abi.test_api.loginStart(input) else wasm_abi.loginStart(input_ptr, input_len, descriptor_ptr),
        .login_finish => wasm_abi.loginFinish(input_ptr, input_len, descriptor_ptr),
        .login_finish_identity => if (use_slice_api) wasm_abi.test_api.loginFinishIdentity(input) else wasm_abi.loginFinishIdentityTestVector(input_ptr, input_len, descriptor_ptr),
        .server_login_start => wasm_abi.serverLoginStart(input_ptr, input_len, descriptor_ptr),
        .server_login_start_identity => if (use_slice_api) wasm_abi.test_api.serverLoginStartIdentity(input) else wasm_abi.serverLoginStartIdentityTestVector(input_ptr, input_len, descriptor_ptr),
        .server_login_finish => if (use_slice_api) wasm_abi.test_api.serverLoginFinish(input) else wasm_abi.serverLoginFinish(input_ptr, input_len, descriptor_ptr),
    };
    try expectWasmStatus(status);
}

fn fuzzWasmAbiSliceParsers(_: void, smith: *Smith) !void {
    const op = smith.value(WasmSliceOp);
    var input_buf: [wasm_input_max_len]u8 = undefined;
    const input = if (smith.boolWeighted(1, 3))
        buildStructuredWasmInput(smith, op, input_buf[0..])
    else
        fuzzSlice(smith, input_buf[0..]);

    try expectWasmStatus(callWasmSliceOp(op, input));
}

fn fuzzWidePublicApi(_: void, smith: *Smith) !void {
    switch (smith.value(enum(u8) {
        messages,
        oprf_properties,
        opaque_round_trip,
        opaque_tamper,
        opaque_malformed,
        input_validation,
        wasm_layouts,
        wasm_slice_parsers,
    })) {
        .messages => try fuzzMessageParsers({}, smith),
        .oprf_properties => try fuzzOprfProperties({}, smith),
        .opaque_round_trip => try fuzzOpaqueRoundTrip({}, smith),
        .opaque_tamper => try fuzzOpaqueRejectsTampering({}, smith),
        .opaque_malformed => try fuzzOpaqueMalformedState({}, smith),
        .input_validation => try fuzzProtocolInputValidation({}, smith),
        .wasm_layouts => try fuzzWasmAbiByteLayouts({}, smith),
        .wasm_slice_parsers => try fuzzWasmAbiSliceParsers({}, smith),
    }
}

fn checkMessageRoundTrip(comptime Message: type, comptime len: usize, bytes: []const u8) !void {
    if (bytes.len != len) {
        try testing.expectError(error.InvalidLength, Message.parse(bytes));
        return;
    }

    const parsed = try Message.parse(bytes);
    var encoded: [len]u8 = undefined;
    writeMessageBytes(Message, len, parsed, &encoded);
    try testing.expectEqualSlices(u8, bytes, &encoded);

    const reparsed = try Message.parse(&encoded);
    var reencoded: [len]u8 = undefined;
    writeMessageBytes(Message, len, reparsed, &reencoded);
    try testing.expectEqualSlices(u8, bytes, &reencoded);
}

fn checkEncodedMessageRoundTrip(comptime Message: type, comptime len: usize, value: Message) !void {
    var encoded: [len]u8 = undefined;
    writeMessageBytes(Message, len, value, &encoded);

    const parsed = try Message.parse(&encoded);
    var reencoded: [len]u8 = undefined;
    writeMessageBytes(Message, len, parsed, &reencoded);
    try testing.expectEqualSlices(u8, &encoded, &reencoded);
}

fn writeMessageBytes(comptime Message: type, comptime len: usize, value: Message, out: *[len]u8) void {
    if (@hasDecl(Message, "toBytes")) {
        out.* = value.toBytes();
    } else {
        value.toBytesInto(out);
    }
}

fn checkArbitraryElementRoundTrip(smith: *Smith) !void {
    var bytes: oprf.SerializedElement = undefined;
    smith.bytes(&bytes);

    const element = oprf.deserializeElement(bytes) catch |err| {
        try testing.expectEqual(error.DeserializeError, err);
        return;
    };
    try testing.expectEqualSlices(u8, &bytes, &oprf.serializeElement(element));
}

fn checkArbitraryScalarRoundTrip(smith: *Smith) !void {
    var bytes: oprf.Scalar = undefined;
    smith.bytes(&bytes);

    const scalar_value = oprf.deserializeScalar(bytes) catch |err| {
        try testing.expectEqual(error.DeserializeError, err);
        return;
    };
    try testing.expectEqualSlices(u8, &bytes, &oprf.serializeScalar(scalar_value));
}

const OpaqueInputs = struct {
    password: []const u8,
    credential_identifier: []const u8,
    context: []const u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    server_key_seed: [c.Nseed]u8,
    oprf_seed: [c.Nh]u8,
    registration_blind: oprf.Scalar,
    login_blind: oprf.Scalar,
    envelope_nonce: [c.Nn]u8,
    client_nonce: [c.Nn]u8,
    client_keyshare_seed: [c.Nseed]u8,
    masking_nonce: [c.Nn]u8,
    server_nonce: [c.Nn]u8,
    server_keyshare_seed: [c.Nseed]u8,
};

const OpaqueFlowSetup = struct {
    suite: opaque_mod.Suite,
    server_private_key: [c.Nsk]u8,
    server_public_key: [c.Npk]u8,
    registration_finish: opaque_mod.RegistrationFinishResult,
    login_start: opaque_mod.LoginStartResult,
    server_start: opaque_mod.ServerLoginStartResult,
};

fn readOpaqueInputs(
    smith: *Smith,
    password_buf: []u8,
    credential_identifier_buf: []u8,
    context_buf: []u8,
    server_identity_buf: []u8,
    client_identity_buf: []u8,
) !OpaqueInputs {
    const server_identity = optionalNonEmpty(fuzzSlice(smith, server_identity_buf));
    const client_identity = optionalNonEmpty(fuzzSlice(smith, client_identity_buf));

    var server_key_seed: [c.Nseed]u8 = undefined;
    smith.bytes(&server_key_seed);

    var oprf_seed: [c.Nh]u8 = undefined;
    smith.bytes(&oprf_seed);

    var envelope_nonce: [c.Nn]u8 = undefined;
    smith.bytes(&envelope_nonce);

    var client_nonce: [c.Nn]u8 = undefined;
    smith.bytes(&client_nonce);

    var client_keyshare_seed: [c.Nseed]u8 = undefined;
    smith.bytes(&client_keyshare_seed);

    var masking_nonce: [c.Nn]u8 = undefined;
    smith.bytes(&masking_nonce);

    var server_nonce: [c.Nn]u8 = undefined;
    smith.bytes(&server_nonce);

    var server_keyshare_seed: [c.Nseed]u8 = undefined;
    smith.bytes(&server_keyshare_seed);

    return .{
        .password = fuzzSlice(smith, password_buf),
        .credential_identifier = fuzzSlice(smith, credential_identifier_buf),
        .context = fuzzSlice(smith, context_buf),
        .server_identity = server_identity,
        .client_identity = client_identity,
        .server_key_seed = server_key_seed,
        .oprf_seed = oprf_seed,
        .registration_blind = try fuzzScalar(smith),
        .login_blind = try fuzzScalar(smith),
        .envelope_nonce = envelope_nonce,
        .client_nonce = client_nonce,
        .client_keyshare_seed = client_keyshare_seed,
        .masking_nonce = masking_nonce,
        .server_nonce = server_nonce,
        .server_keyshare_seed = server_keyshare_seed,
    };
}

fn setupOpaqueFlow(inputs: OpaqueInputs) !OpaqueFlowSetup {
    const suite = opaque_mod.Suite{ .context = inputs.context, .ksf = .identity_test_only };
    const server_keypair = try suite.group.deriveDhKeyPair(inputs.server_key_seed);

    const registration_start = try opaque_mod.createRegistrationRequest(inputs.password, inputs.registration_blind);
    const registration_response = try opaque_mod.createRegistrationResponse(
        registration_start.request,
        server_keypair.pk,
        inputs.credential_identifier,
        inputs.oprf_seed,
    );
    const registration_finish = try opaque_mod.finalizeRegistrationRequest(
        suite,
        testing.allocator,
        registration_start.state,
        registration_response,
        inputs.envelope_nonce,
        inputs.password,
        inputs.server_identity,
        inputs.client_identity,
        null,
    );

    const login_start = try opaque_mod.generateKE1(
        suite,
        inputs.password,
        inputs.login_blind,
        inputs.client_nonce,
        inputs.client_keyshare_seed,
    );
    const server_start = try opaque_mod.generateKE2(
        suite,
        server_keypair.sk,
        server_keypair.pk,
        registration_finish.record,
        inputs.credential_identifier,
        inputs.oprf_seed,
        login_start.ke1,
        inputs.masking_nonce,
        inputs.server_nonce,
        inputs.server_keyshare_seed,
        inputs.server_identity,
        inputs.client_identity,
    );

    return .{
        .suite = suite,
        .server_private_key = server_keypair.sk,
        .server_public_key = server_keypair.pk,
        .registration_finish = registration_finish,
        .login_start = login_start,
        .server_start = server_start,
    };
}

fn fuzzSlice(smith: *Smith, buf: []u8) []const u8 {
    const len: usize = @intCast(smith.slice(buf));
    return buf[0..len];
}

fn optionalNonEmpty(bytes: []const u8) ?[]const u8 {
    return if (bytes.len == 0) null else bytes;
}

fn distinctFuzzSlice(smith: *Smith, buf: []u8, base: []const u8) []const u8 {
    var out = fuzzSlice(smith, buf);
    if (std.mem.eql(u8, out, base)) {
        if (buf.len == 0) return out;
        const len = @max(out.len, 1);
        if (out.len == 0) buf[0] = 0;
        buf[0] ^= 1;
        out = buf[0..len];
    }
    return out;
}

fn distinctNonEmptyFuzzSlice(smith: *Smith, buf: []u8, base: []const u8) []const u8 {
    var out = distinctFuzzSlice(smith, buf, base);
    if (out.len == 0) {
        buf[0] = 1;
        out = buf[0..1];
    }
    return out;
}

fn fuzzScalar(smith: *Smith) !oprf.Scalar {
    var uniform: [oprf.random_scalar_uniform_length]u8 = undefined;
    smith.bytes(&uniform);
    return scalarFromUniform(uniform);
}

fn scalarFromUniform(uniform: [oprf.random_scalar_uniform_length]u8) !oprf.Scalar {
    var adjusted = uniform;
    return oprf.randomScalarFromUniformBytes(adjusted) catch |err| switch (err) {
        error.ZeroScalar => {
            adjusted[0] = 1;
            return oprf.randomScalarFromUniformBytes(adjusted);
        },
        else => return err,
    };
}

fn expectProtocolFailure(result: anytype) !void {
    if (result) |value| {
        _ = value;
        return error.TestExpectedError;
    } else |err| {
        try expectKnownProtocolError(err);
    }
}

fn expectKnownProtocolError(err: anyerror) !void {
    switch (err) {
        error.AuthenticationFailed,
        error.DeriveKeyPairError,
        error.DeserializeError,
        error.IdentityElement,
        error.InputTooLong,
        error.InvalidInput,
        error.InvalidLength,
        error.InvalidMessage,
        error.InvalidPublicKey,
        error.InvalidScalar,
        error.NoSpaceLeft,
        error.OutOfMemory,
        error.ZeroScalar,
        => {},
        else => return err,
    }
}

fn expectWasmStatus(status: i32) !void {
    switch (@as(wasm_abi.Status, @enumFromInt(status))) {
        .ok, .protocol_error, .invalid_input, .out_of_memory => {},
    }
}

fn wasmAllocBytes(len: usize) ?u32 {
    if (len > std.math.maxInt(u32)) return null;
    const ptr = wasm_abi.allocate(@intCast(len));
    return if (ptr == 0) null else ptr;
}

fn wasmAllocCopy(input: []const u8) ?u32 {
    const ptr = wasmAllocBytes(input.len) orelse return null;
    const out: [*]u8 = @ptrFromInt(ptr);
    @memcpy(out[0..input.len], input);
    return ptr;
}

fn callWasmSliceOp(op: WasmSliceOp, input: []const u8) i32 {
    return switch (op) {
        .registration_start => wasm_abi.test_api.registrationStart(input),
        .registration_finish_identity => wasm_abi.test_api.registrationFinishIdentity(input),
        .login_start => wasm_abi.test_api.loginStart(input),
        .login_finish_identity => wasm_abi.test_api.loginFinishIdentity(input),
        .server_login_start_identity => wasm_abi.test_api.serverLoginStartIdentity(input),
        .server_login_finish => wasm_abi.test_api.serverLoginFinish(input),
    };
}

fn buildStructuredWasmInput(smith: *Smith, op: WasmSliceOp, buf: []u8) []const u8 {
    var offset: usize = 0;
    switch (op) {
        .registration_start => {
            fillFuzzBytes(smith, readOutputSlice(buf, &offset, c.blind_uniform_len));
            fillFuzzBytes(smith, readOutputSlice(buf, &offset, smith.valueRangeAtMost(u8, 0, 64)));
        },
        .registration_finish_identity => {
            fillFuzzBytes(smith, readOutputSlice(buf, &offset, c.Nsk + c.Nn + c.registration_response_len));
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
        },
        .login_start => {
            fillFuzzBytes(smith, readOutputSlice(buf, &offset, c.blind_uniform_len + c.Nn + c.Nseed));
            fillFuzzBytes(smith, readOutputSlice(buf, &offset, smith.valueRangeAtMost(u8, 0, 64)));
        },
        .login_finish_identity => {
            fillFuzzBytes(smith, readOutputSlice(buf, &offset, c.client_login_state_len + c.ke2_len));
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
        },
        .server_login_start_identity => {
            fillFuzzBytes(smith, readOutputSlice(
                buf,
                &offset,
                c.Nsk + c.Npk + c.registration_record_len + c.Nh + c.ke1_len + c.Nn + c.Nn + c.Nseed,
            ));
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
            appendFuzzOpaque16(smith, buf, &offset, 64);
        },
        .server_login_finish => {
            const state = readOutputSlice(buf, &offset, c.server_login_state_len);
            fillFuzzBytes(smith, state);
            const ke3 = readOutputSlice(buf, &offset, c.ke3_len);
            if (smith.value(bool)) {
                @memcpy(ke3, state[0..c.Nm]);
            } else {
                fillFuzzBytes(smith, ke3);
            }
        },
    }
    return buf[0..offset];
}

fn readOutputSlice(buf: []u8, offset: *usize, len: usize) []u8 {
    const out = buf[offset.*..][0..len];
    offset.* += len;
    return out;
}

fn appendFuzzOpaque16(smith: *Smith, buf: []u8, offset: *usize, max_len: u8) void {
    const len = smith.valueRangeAtMost(u8, 0, max_len);
    std.mem.writeInt(u16, buf[offset.*..][0..2], len, .big);
    offset.* += 2;
    fillFuzzBytes(smith, readOutputSlice(buf, offset, len));
}

fn fillFuzzBytes(smith: *Smith, bytes: []u8) void {
    smith.bytes(bytes);
}

fn sliceCorpus(comptime len: usize, comptime seed_byte: u8) [4 + len]u8 {
    var out: [4 + len]u8 = undefined;
    out[0] = @truncate(len);
    out[1] = @truncate(len >> 8);
    out[2] = @truncate(len >> 16);
    out[3] = @truncate(len >> 24);
    for (out[4..], 0..) |*byte, i| {
        byte.* = seed_byte +% @as(u8, @truncate(i *% 31));
    }
    return out;
}

fn actionCorpus(comptime action: u64, comptime seed_byte: u8) [256]u8 {
    var out: [256]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], action, .little);
    for (out[8..], 0..) |*byte, i| {
        byte.* = seed_byte +% @as(u8, @truncate(i *% 17));
    }
    return out;
}

const wide_corpus_messages = actionCorpus(0, 0x11);
const wide_corpus_oprf = actionCorpus(1, 0x22);
const wide_corpus_round_trip = actionCorpus(2, 0x33);
const wide_corpus_tamper = actionCorpus(3, 0x44);
const wide_corpus_malformed = actionCorpus(4, 0x55);
const wide_corpus_input_validation = actionCorpus(5, 0x66);
const wide_corpus_wasm = actionCorpus(6, 0x77);
const wide_corpus_wasm_slice = actionCorpus(7, 0x88);
const wide_corpus = [_][]const u8{
    &wide_corpus_messages,
    &wide_corpus_oprf,
    &wide_corpus_round_trip,
    &wide_corpus_tamper,
    &wide_corpus_malformed,
    &wide_corpus_input_validation,
    &wide_corpus_wasm,
    &wide_corpus_wasm_slice,
};

fn seed(byte: u8) [32]u8 {
    return @splat(byte);
}

fn seed64(byte: u8) [64]u8 {
    return @splat(byte);
}

fn scalar(byte: u8) [32]u8 {
    var out: [32]u8 = @splat(0);
    out[0] = byte;
    return out;
}

fn oprfRuntimeSupported() !bool {
    const key_pair = root.oprf.deriveKeyPair(seed(0x11), "probe") catch return false;
    const blinded = root.oprf.blindWithScalar("zig-master-ristretto-probe", scalar(0x02)) catch return false;
    _ = root.oprf.deserializeElement(root.oprf.serializeElement(blinded.blinded_element)) catch return false;
    const evaluated = root.oprf.blindEvaluate(key_pair.sk, blinded.blinded_element) catch return false;
    const finalized = root.oprf.finalize("zig-master-ristretto-probe", scalar(0x02), evaluated) catch return false;
    const direct = root.oprf.evaluate(key_pair.sk, "zig-master-ristretto-probe") catch return false;
    return std.mem.eql(u8, &finalized, &direct);
}
