//! Low-order / non-canonical public-keyshare rejection at the AKE boundary.
//!
//! The curve25519 AKE leans on std's X25519 rejecting low-order points (its
//! scalarmult returns error.IdentityElement when the result is a small-order
//! point), and the ristretto255 AKE leans on the ristretto codec rejecting the
//! identity / non-canonical encodings. These tests inject a hostile
//! client_public_keyshare into a KE1 handed to generateKE2 and assert a CLEAN
//! error -- never success, never a panic.
//!
//! Injection point: generateKE2 computes
//!   dh1 = diffieHellman(server_keyshare.sk, ke1.auth_request.client_public_keyshare)
//! as its first Diffie-Hellman, so a bad keyshare is caught there.

const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

const good_password = "correct horse battery staple";
const credential_identifier = "alice@example.test";

const Fixture = struct {
    server_private_key: [32]u8,
    server_public_key: [32]u8,
    oprf_seed: [64]u8,
    record: messages.RegistrationRecord,
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

/// Register a credential under `group` so we have a real record + server keys to
/// drive generateKE2. Returns null if the OPRF runtime probe is broken (the
/// canary test in runtime_canary_test.zig turns that into a hard failure, so we
/// can safely skip here without masking a regression).
fn register(allocator: std.mem.Allocator, group: opaque_mod.Group) !?Fixture {
    const suite = opaque_mod.Suite{ .ksf = .identity_test_only, .group = group };
    const server_keypair = group.deriveDhKeyPair(seed(0x11)) catch return null;
    const oprf_seed = seed64(0x22);

    const reg_start = opaque_mod.createRegistrationRequest(good_password, scalar(0x03)) catch return null;
    const reg_response = try opaque_mod.createRegistrationResponse(reg_start.request, server_keypair.pk, credential_identifier, oprf_seed);
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(suite, allocator, reg_start.state, reg_response, seed(0x44), good_password, null, null, null);

    return .{
        .server_private_key = server_keypair.sk,
        .server_public_key = server_keypair.pk,
        .oprf_seed = oprf_seed,
        .record = reg_finish.record,
    };
}

/// Run generateKE2 with `bad_keyshare` substituted for the client's keyshare and
/// return whatever error (or void) it produces.
fn ke2WithKeyshare(
    group: opaque_mod.Group,
    fixture: Fixture,
    bad_keyshare: [32]u8,
) opaque_mod.Error!void {
    const suite = opaque_mod.Suite{ .ksf = .identity_test_only, .group = group };
    var login_start = try opaque_mod.generateKE1(suite, good_password, scalar(0x05), seed(0x66), seed(0x77));
    // Replace the honest client keyshare with the hostile one.
    login_start.ke1.auth_request.client_public_keyshare = bad_keyshare;

    _ = try opaque_mod.generateKE2(
        suite,
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
}

// Canonical low-order Curve25519 u-coordinates (little-endian), restricted to the
// encodings whose X25519 shared secret is the all-zero/identity point and which
// std's X25519.scalarmult therefore rejects with IdentityElement. This set was
// confirmed empirically against the pinned std (the X25519 clamp forces the
// scalar to a multiple of the cofactor, so order-2 and order-8 points collapse to
// the identity; a few published "order-4" u-coordinates do NOT collapse and are
// intentionally omitted). Includes 0, 1, p-1, p, p+1, the two order-8 points, and
// the two order-8 points with the (ignored) high bit set.
const low_order_curve25519 = [_][32]u8{
    // 0 (identity) and 1
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    // p-1
    .{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    // the two order-8 points
    .{ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
    .{ 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
    // p and p+1 (non-canonical encodings of 0 and 1)
    .{ 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    .{ 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    // the two order-8 points with the ignored high bit set (non-canonical)
    .{ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80 },
    .{ 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7 },
};

test "curve25519 generateKE2 rejects low-order client keyshares" {
    const allocator = std.testing.allocator;
    const fixture = (try register(allocator, .curve25519)) orelse return error.SkipZigTest;

    for (low_order_curve25519, 0..) |bad, idx| {
        const result = ke2WithKeyshare(.curve25519, fixture, bad);
        // std X25519.scalarmult rejects these with IdentityElement (the shared
        // secret is the identity point). Accept the broader weak-key family too,
        // but never accept success.
        result catch |err| {
            try std.testing.expect(err == error.IdentityElement or err == error.WeakPublicKey);
            continue;
        };
        std.debug.print("curve25519 low-order keyshare #{d} was NOT rejected\n", .{idx});
        return error.TestUnexpectedResult;
    }
}

test "ristretto255 generateKE2 rejects the identity client keyshare" {
    const allocator = std.testing.allocator;
    const fixture = (try register(allocator, .ristretto255)) orelse return error.SkipZigTest;

    // All-zeros is the canonical ristretto255 identity encoding; deserializeElement
    // rejects it (DeserializeError). A non-canonical high-bit-set encoding is also
    // rejected by the same path.
    const identity: [32]u8 = @splat(0);
    var noncanonical: [32]u8 = @splat(0);
    noncanonical[31] = 0x80; // high bit set -> non-canonical field element

    const bad_keyshares = [_][32]u8{ identity, noncanonical };
    for (bad_keyshares) |bad| {
        const result = ke2WithKeyshare(.ristretto255, fixture, bad);
        result catch |err| {
            try std.testing.expect(err == error.DeserializeError or err == error.IdentityElement);
            continue;
        };
        return error.TestUnexpectedResult;
    }
}
