const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

// These negative/round-trip tests assert protocol behavior, not KSF strength.
// Pin the identity KSF so they stay fast (Suite.default now runs real Argon2id).
const test_suite = opaque_mod.Suite{ .ksf = .identity_test_only };

const CredentialFixture = struct {
    server_private_key: [32]u8,
    server_public_key: [32]u8,
    oprf_seed: [64]u8,
    record: messages.RegistrationRecord,
};

const LoginFixture = struct {
    start: opaque_mod.LoginStartResult,
    server: opaque_mod.ServerLoginStartResult,
};

test "login with wrong password fails before KE3" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const fixture = try register(allocator);
    const wrong_password = "not the password";
    const login = try startLogin(allocator, fixture, wrong_password);

    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(test_suite, allocator, login.start.state, login.server.ke2, wrong_password, null, null, null),
    );
}

test "tampered server MAC fails client authentication" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const fixture = try register(allocator);
    var login = try startLogin(allocator, fixture, good_password);
    login.server.ke2.auth_response.server_mac[0] ^= 0x01;

    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(test_suite, allocator, login.start.state, login.server.ke2, good_password, null, null, null),
    );
}

test "tampered registration envelope fails credential recovery" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var fixture = try register(allocator);
    fixture.record.envelope.auth_tag[0] ^= 0x01;
    const login = try startLogin(allocator, fixture, good_password);

    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(test_suite, allocator, login.start.state, login.server.ke2, good_password, null, null, null),
    );
}

test "tampered registration record fails server authentication" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var fixture = try register(allocator);
    fixture.record.client_public_key[0] ^= 0x01;

    // A tampered client_public_key must abort the login. With curve25519 any
    // 32-byte key is accepted by scalarmult, so the corruption surfaces as an
    // AuthenticationFailed during KE3. With ristretto255 the corrupted point is
    // non-canonical and rejected when the server's 3DH deserializes it during
    // KE2 (inside startLogin). Both outcomes mean the tampered record cannot
    // authenticate; accept whichever the active group produces.
    const login = startLogin(allocator, fixture, good_password) catch |err| {
        try std.testing.expect(err == error.DeserializeError or err == error.AuthenticationFailed);
        return;
    };

    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(test_suite, allocator, login.start.state, login.server.ke2, good_password, null, null, null),
    );
}

test "server finish rejects bad KE3" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const fixture = try register(allocator);
    const login = try startLogin(allocator, fixture, good_password);
    var finish = try opaque_mod.generateKE3(test_suite, allocator, login.start.state, login.server.ke2, good_password, null, null, null);
    finish.ke3.client_mac[0] ^= 0x01;

    try std.testing.expectError(error.AuthenticationFailed, opaque_mod.serverFinish(login.server.state, finish.ke3));
}

test "empty explicit identities are rejected" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const server_keypair = try opaque_mod.Group.ristretto255.deriveDhKeyPair(seed(0x11));
    const reg_start = try opaque_mod.createRegistrationRequest(good_password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.pk, credential_identifier, seed64(0x22));

    try std.testing.expectError(
        error.InvalidInput,
        opaque_mod.finalizeRegistrationRequest(test_suite, allocator, reg_start.state, reg_response, seed(0x44), good_password, "", null, null),
    );
}

test "oversized context and credential identifiers are rejected" {
    const allocator = std.testing.allocator;
    var too_long: [std.math.maxInt(u16) + 1]u8 = @splat('x');
    const request = messages.RegistrationRequest{ .blinded_message = @splat(0) };

    try std.testing.expectError(
        error.InvalidInput,
        opaque_mod.createRegistrationResponse(request, @splat(0), &too_long, seed64(0x22)),
    );

    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const fixture = try register(allocator);
    const login_start = try opaque_mod.generateKE1(test_suite, good_password, scalar(0x05), seed(0x66), seed(0x77));
    try std.testing.expectError(
        error.InvalidInput,
        opaque_mod.generateKE2(
            .{ .context = &too_long, .ksf = .identity_test_only },
            fixture.server_private_key,
            fixture.server_public_key,
            fixture.record,
            credential_identifier,
            fixture.oprf_seed,
            login_start.ke1,
            seed(0x88),
            seed(0x99),
            seed(0xaa),
            null,
            null,
        ),
    );
}

const good_password = "correct horse battery staple";
const credential_identifier = "alice@example.test";

fn register(allocator: std.mem.Allocator) !CredentialFixture {
    const server_keypair = try opaque_mod.Group.ristretto255.deriveDhKeyPair(seed(0x11));
    const oprf_seed = seed64(0x22);

    const reg_start = try opaque_mod.createRegistrationRequest(good_password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.pk, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(test_suite, allocator, reg_start.state, reg_response, seed(0x44), good_password, null, null, null);

    return .{
        .server_private_key = server_keypair.sk,
        .server_public_key = server_keypair.pk,
        .oprf_seed = oprf_seed,
        .record = reg_finish.record,
    };
}

fn startLogin(allocator: std.mem.Allocator, fixture: CredentialFixture, password: []const u8) !LoginFixture {
    _ = allocator;
    const login_start = try opaque_mod.generateKE1(test_suite, password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        test_suite,
        fixture.server_private_key,
        fixture.server_public_key,
        fixture.record,
        credential_identifier,
        fixture.oprf_seed,
        login_start.ke1,
        seed(0x88),
        seed(0x99),
        seed(0xaa),
        null,
        null,
    );
    return .{ .start = login_start, .server = server_start };
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
