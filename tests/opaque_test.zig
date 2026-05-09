const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

test "suite default is identity KSF for vector compatibility" {
    try std.testing.expectEqual(opaque_mod.Ksf.identity, opaque_mod.Suite.default.ksf);
}

test "deterministic registration and login round trip" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const suite = opaque_mod.Suite.default;
    const password = "correct horse battery staple";
    const credential_identifier = "alice@example.test";

    const server_key_seed = seed(0x11);
    const server_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(server_key_seed);
    const oprf_seed = seed64(0x22);

    const reg_start = try opaque_mod.createRegistrationRequest(password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.public_key, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(suite, allocator, reg_start.state, reg_response, seed(0x44), null, null, undefined);

    const login_start = try opaque_mod.generateKE1(password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        suite,
        server_keypair.secret_key,
        server_keypair.public_key,
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

    const login_finish = try opaque_mod.generateKE3(suite, allocator, login_start.state, server_start.ke2, null, null, undefined);
    const server_session = try opaque_mod.serverFinish(server_start.state, login_finish.ke3);

    try std.testing.expectEqualSlices(u8, &server_session, &login_finish.session_key);

    const record_bytes = reg_finish.record.toBytes();
    _ = try messages.RegistrationRecord.parse(&record_bytes);
}

test "round trip supports application context and explicit identities" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const suite = opaque_mod.Suite{ .context = "OPAQUE-POC", .ksf = .identity };
    const password = "correct horse battery staple";
    const credential_identifier = "alice@example.test";
    const client_identity = "alice";
    const server_identity = "bob";

    const server_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(seed(0x11));
    const oprf_seed = seed64(0x22);

    const reg_start = try opaque_mod.createRegistrationRequest(password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.public_key, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(suite, allocator, reg_start.state, reg_response, seed(0x44), server_identity, client_identity, undefined);

    const login_start = try opaque_mod.generateKE1(password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        suite,
        server_keypair.secret_key,
        server_keypair.public_key,
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

    const login_finish = try opaque_mod.generateKE3(suite, allocator, login_start.state, server_start.ke2, server_identity, client_identity, undefined);
    const server_session = try opaque_mod.serverFinish(server_start.state, login_finish.ke3);

    try std.testing.expectEqualSlices(u8, &server_session, &login_finish.session_key);
}

test "credential identifiers above historical scratch limit are supported" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const password = "correct horse battery staple";
    const server_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(seed(0x11));
    var credential_identifier: [2048]u8 = @splat('a');

    const reg_start = try opaque_mod.createRegistrationRequest(password, scalar(0x03));
    _ = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.public_key, &credential_identifier, seed64(0x22));
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
