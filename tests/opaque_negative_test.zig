const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

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
    const login = try startLogin(allocator, fixture, "not the password");

    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(opaque_mod.Suite.default, allocator, login.start.state, login.server.ke2, null, null, undefined),
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
        opaque_mod.generateKE3(opaque_mod.Suite.default, allocator, login.start.state, login.server.ke2, null, null, undefined),
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
        opaque_mod.generateKE3(opaque_mod.Suite.default, allocator, login.start.state, login.server.ke2, null, null, undefined),
    );
}

test "tampered registration record fails server authentication" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var fixture = try register(allocator);
    fixture.record.client_public_key[0] ^= 0x01;
    const login = try startLogin(allocator, fixture, good_password);

    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(opaque_mod.Suite.default, allocator, login.start.state, login.server.ke2, null, null, undefined),
    );
}

test "server finish rejects bad KE3" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const fixture = try register(allocator);
    const login = try startLogin(allocator, fixture, good_password);
    var finish = try opaque_mod.generateKE3(opaque_mod.Suite.default, allocator, login.start.state, login.server.ke2, null, null, undefined);
    finish.ke3.client_mac[0] ^= 0x01;

    try std.testing.expectError(error.AuthenticationFailed, opaque_mod.serverFinish(login.server.state, finish.ke3));
}

const good_password = "correct horse battery staple";
const credential_identifier = "alice@example.test";

fn register(allocator: std.mem.Allocator) !CredentialFixture {
    const server_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(seed(0x11));
    const oprf_seed = seed64(0x22);

    const reg_start = try opaque_mod.createRegistrationRequest(good_password, scalar(0x03));
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.public_key, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(opaque_mod.Suite.default, allocator, reg_start.state, reg_response, seed(0x44), null, null, undefined);

    return .{
        .server_private_key = server_keypair.secret_key,
        .server_public_key = server_keypair.public_key,
        .oprf_seed = oprf_seed,
        .record = reg_finish.record,
    };
}

fn startLogin(allocator: std.mem.Allocator, fixture: CredentialFixture, password: []const u8) !LoginFixture {
    _ = allocator;
    const login_start = try opaque_mod.generateKE1(password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        opaque_mod.Suite.default,
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
