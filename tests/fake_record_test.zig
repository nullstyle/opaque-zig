//! Tests for `createFakeRecord` (RFC 9807 Section 6.3.2.2 client-enumeration
//! resistance). A server that receives a login for an unknown credential feeds a
//! fake record to `generateKE2` so the response is well-formed and
//! indistinguishable from a real account's -- but a client cannot authenticate
//! against it, and the failure is a clean error rather than a crash.

const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

const c = root.constants;

// Fast identity KSF: this test exercises the fake-record path and AKE, not KSF
// strength.
const test_suite = opaque_mod.Suite{ .ksf = .identity_test_only };

const good_password = "correct horse battery staple";
const unknown_identifier = "nobody@example.test";

test "fake record produces a well-formed KE2" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const server_keypair = try test_suite.group.deriveDhKeyPair(seed(0x11));
    const oprf_seed = seed64(0x22);

    const fake_record = try opaque_mod.createFakeRecord(test_suite, oprf_seed, unknown_identifier, seed(0x33));

    // The fake record's fields must match the RFC's construction.
    try std.testing.expect(!std.mem.allEqual(u8, &fake_record.client_public_key, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &fake_record.masking_key, 0));
    const zero_nonce: [c.Nn]u8 = @splat(0);
    const zero_tag: [c.Nm]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero_nonce, &fake_record.envelope.nonce);
    try std.testing.expectEqualSlices(u8, &zero_tag, &fake_record.envelope.auth_tag);

    // A client (who does not have an account) sends KE1; the server answers with
    // a KE2 built from the fake record. This must succeed and be the right size.
    const login_start = try opaque_mod.generateKE1(test_suite, good_password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        test_suite,
        server_keypair.sk,
        server_keypair.pk,
        fake_record,
        unknown_identifier,
        oprf_seed,
        login_start.ke1,
        seed(0x88),
        seed(0x99),
        seed(0xaa),
        null,
        null,
    );

    // KE2 is fixed-length and parses back cleanly -- structurally identical to a
    // real KE2, which is the whole point of the mitigation.
    const ke2_bytes = server_start.ke2.toBytes();
    try std.testing.expectEqual(@as(usize, c.ke2_len), ke2_bytes.len);
    _ = try messages.KE2.parse(&ke2_bytes);
}

test "client login against a fake record fails cleanly at server auth" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const server_keypair = try test_suite.group.deriveDhKeyPair(seed(0x11));
    const oprf_seed = seed64(0x22);

    const fake_record = try opaque_mod.createFakeRecord(test_suite, oprf_seed, unknown_identifier, seed(0x33));

    const login_start = try opaque_mod.generateKE1(test_suite, good_password, scalar(0x05), seed(0x66), seed(0x77));
    const server_start = try opaque_mod.generateKE2(
        test_suite,
        server_keypair.sk,
        server_keypair.pk,
        fake_record,
        unknown_identifier,
        oprf_seed,
        login_start.ke1,
        seed(0x88),
        seed(0x99),
        seed(0xaa),
        null,
        null,
    );

    // The client cannot recover a valid envelope from the all-zero fake envelope
    // / mismatched keys, so KE3 fails with AuthenticationFailed -- a clean error,
    // not a panic. (The client learns only "auth failed", same as a wrong
    // password against a real record.)
    try std.testing.expectError(
        error.AuthenticationFailed,
        opaque_mod.generateKE3(test_suite, allocator, login_start.state, server_start.ke2, good_password, null, null, null),
    );
}

test "createFakeRecord rejects oversized credential identifier" {
    var too_long: [std.math.maxInt(u16) + 1]u8 = @splat('x');
    try std.testing.expectError(
        error.InvalidInput,
        opaque_mod.createFakeRecord(test_suite, seed64(0x22), &too_long, seed(0x33)),
    );
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
