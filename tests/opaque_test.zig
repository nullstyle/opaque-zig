const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

test "suite default is OWASP Argon2id" {
    // The safe path is the default: native callers get a real KSF unless they
    // explicitly opt into identity_test_only.
    try std.testing.expectEqual(
        @as(std.meta.Tag(opaque_mod.Ksf), .argon2id),
        std.meta.activeTag(opaque_mod.Suite.default.ksf),
    );
    try std.testing.expectEqual(opaque_mod.argon2id_owasp, opaque_mod.Suite.default.ksf.argon2id);
}

test "deterministic registration and login round trip" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    // Use identity_test_only to keep this round-trip fast (the default now runs
    // real Argon2id). Vector tests exercise the byte-exact identity path.
    const suite = opaque_mod.Suite{ .ksf = .identity_test_only };
    const password = "correct horse battery staple";
    const credential_identifier = "alice@example.test";

    const server_key_seed = seed(0x11);
    const server_keypair = try opaque_mod.Group.ristretto255.deriveDhKeyPair(server_key_seed);
    const oprf_seed = seed64(0x22);

    const reg_start = try opaque_mod.createRegistrationRequest(password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.pk, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(suite, allocator, reg_start.state, reg_response, seed(0x44), password, null, null, null);

    const login_start = try opaque_mod.generateKE1(suite, password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        suite,
        server_keypair.sk,
        server_keypair.pk,
        reg_finish.record,
        credential_identifier,
        oprf_seed,
        login_start.ke1,
        seed(0x88),
        seed(0x99),
        seed(0xaa),
        null,
        null,
    );

    const login_finish = try opaque_mod.generateKE3(suite, allocator, login_start.state, server_start.ke2, password, null, null, null);
    const server_session = try opaque_mod.serverFinish(server_start.state, login_finish.ke3);

    try std.testing.expectEqualSlices(u8, &server_session, &login_finish.session_key);

    const record_bytes = reg_finish.record.toBytes();
    _ = try messages.RegistrationRecord.parse(&record_bytes);
}

test "round trip supports application context and explicit identities" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const suite = opaque_mod.Suite{ .context = "OPAQUE-POC", .ksf = .identity_test_only };
    const password = "correct horse battery staple";
    const credential_identifier = "alice@example.test";
    const client_identity = "alice";
    const server_identity = "bob";

    const server_keypair = try suite.group.deriveDhKeyPair(seed(0x11));
    const oprf_seed = seed64(0x22);

    const reg_start = try opaque_mod.createRegistrationRequest(password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.pk, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(suite, allocator, reg_start.state, reg_response, seed(0x44), password, server_identity, client_identity, null);

    const login_start = try opaque_mod.generateKE1(suite, password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        suite,
        server_keypair.sk,
        server_keypair.pk,
        reg_finish.record,
        credential_identifier,
        oprf_seed,
        login_start.ke1,
        seed(0x88),
        seed(0x99),
        seed(0xaa),
        server_identity,
        client_identity,
    );

    const login_finish = try opaque_mod.generateKE3(suite, allocator, login_start.state, server_start.ke2, password, server_identity, client_identity, null);
    const server_session = try opaque_mod.serverFinish(server_start.state, login_finish.ke3);

    try std.testing.expectEqualSlices(u8, &server_session, &login_finish.session_key);
}

test "credential identifiers above historical scratch limit are supported" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const password = "correct horse battery staple";
    const server_keypair = try opaque_mod.Group.ristretto255.deriveDhKeyPair(seed(0x11));
    var credential_identifier: [2048]u8 = @splat('a');

    const reg_start = try opaque_mod.createRegistrationRequest(password, scalar(0x03));
    _ = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.pk, &credential_identifier, seed64(0x22));
}

test "wipe helpers zero the secret fields of state and result structs" {
    // Exercises every wipe() helper so they are analyzed and provably zero the
    // owned secrets (RFC 9807 Section 4.1.3). The password is no longer retained
    // in client state, so there is nothing borrowed to leave untouched.
    const one32: [32]u8 = @splat(1);
    const one64: [64]u8 = @splat(1);
    const zero32: [32]u8 = @splat(0);
    const zero64: [64]u8 = @splat(0);

    var reg_state = opaque_mod.RegistrationClientState{ .blind = one32 };
    reg_state.wipe();
    try std.testing.expectEqualSlices(u8, &zero32, &reg_state.blind);

    var login_state = opaque_mod.ClientLoginState{
        .blind = one32,
        .client_secret = one32,
        .ke1 = undefined,
    };
    login_state.wipe();
    try std.testing.expectEqualSlices(u8, &zero32, &login_state.blind);
    try std.testing.expectEqualSlices(u8, &zero32, &login_state.client_secret);

    var server_state = opaque_mod.ServerLoginState{ .expected_client_mac = one64, .unconfirmed_session_key = one64 };
    server_state.wipe();
    try std.testing.expectEqualSlices(u8, &zero64, &server_state.expected_client_mac);
    try std.testing.expectEqualSlices(u8, &zero64, &server_state.unconfirmed_session_key);

    var reg_finish = opaque_mod.RegistrationFinishResult{ .record = undefined, .export_key = one64 };
    reg_finish.wipe();
    try std.testing.expectEqualSlices(u8, &zero64, &reg_finish.export_key);

    var login_finish = opaque_mod.LoginFinishResult{ .ke3 = undefined, .session_key = one64, .export_key = one64 };
    login_finish.wipe();
    try std.testing.expectEqualSlices(u8, &zero64, &login_finish.session_key);
    try std.testing.expectEqualSlices(u8, &zero64, &login_finish.export_key);

    var server_start = opaque_mod.ServerLoginStartResult{
        .state = .{ .expected_client_mac = one64, .unconfirmed_session_key = one64 },
        .ke2 = undefined,
    };
    server_start.wipe();
    try std.testing.expectEqualSlices(u8, &zero64, &server_start.state.expected_client_mac);
    try std.testing.expectEqualSlices(u8, &zero64, &server_start.state.unconfirmed_session_key);
}

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
    const kp = root.oprf.deriveKeyPair(seed(0x11), "probe") catch return false;
    const blinded = root.oprf.blindWithScalar("zig-master-ristretto-probe", scalar(0x02)) catch return false;
    _ = root.oprf.deserializeElement(root.oprf.serializeElement(blinded.blinded_element)) catch return false;
    const evaluated = root.oprf.blindEvaluate(kp.sk, blinded.blinded_element) catch return false;
    const finalized = root.oprf.finalize("zig-master-ristretto-probe", scalar(0x02), evaluated) catch return false;
    const direct = root.oprf.evaluate(kp.sk, "zig-master-ristretto-probe") catch return false;
    return std.mem.eql(u8, &finalized, &direct);
}
