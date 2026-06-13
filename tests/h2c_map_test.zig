//! Equivalence test that locks oprf.zig's hand-rolled ristretto255 hash-to-group
//! to the pinned std implementation.
//!
//! src/oprf.zig hand-rolls both halves of RFC 9497 HashToGroup for
//! ristretto255-SHA512:
//!   1. `expand_message_xmd` (RFC 9380 Section 5.3.1) over SHA-512, and
//!   2. the from-uniform map (`fromUniformCompat` / `elligator` / `sqrtRatioM1`),
//!      which mirrors `std.crypto.ecc.Ristretto255.fromUniform`.
//! Until now only the single RFC 9497 OPRF known-answer vector exercised this
//! path, so a subtle divergence from std could slip through.
//!
//! The map (`fromUniformCompat`) is file-private and `oprf.hashToGroup` always
//! runs the expand step first, so there is no public oprf entry point that
//! accepts a raw 64-byte uniform value. We therefore cannot call oprf's map on a
//! known uniform and diff it against std directly. Instead we pin the WHOLE
//! public surface to std: this test re-derives the 64-byte uniform with an
//! INDEPENDENT, from-scratch transcription of expand_message_xmd (it does not
//! call into oprf), feeds that uniform to `std.crypto.ecc.Ristretto255.fromUniform`,
//! and asserts the result equals `oprf.hashToGroup(input)`. If oprf's expand OR
//! its from-uniform map diverged from std/RFC 9380, the two would disagree.
//!
//! Inputs are drawn from a std.Random.DefaultPrng seeded with a FIXED constant,
//! so the test is fully deterministic.

const std = @import("std");
const oprf = @import("opaque_root").oprf;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512;

// DST used by oprf.hashToGroup: "HashToGroup-" ++ contextString, where
// contextString = "OPRFV1-" || I2OSP(modeOPRF=0x00, 1) || "-" || "ristretto255-SHA512".
// (RFC 9497 Section 3.2 / oprf.zig context_string.)
const dst = "HashToGroup-OPRFV1-" ++ [_]u8{0x00} ++ "-ristretto255-SHA512";

/// Independent transcription of expand_message_xmd (RFC 9380 Section 5.3.1) for a
/// 64-byte output over SHA-512. This deliberately does NOT call oprf's expand so
/// it can serve as an independent oracle. For len_in_bytes = 64 and SHA-512
/// (b_in_bytes = 64), ell = 1, so only b_0 and b_1 are computed.
fn expandMessageXmd64(msg: []const u8) [64]u8 {
    const b_in_bytes = Sha512.digest_length; // 64
    const s_in_bytes = Sha512.block_length; // 128 (SHA-512 input block size)
    comptime std.debug.assert(dst.len <= 255);

    // DST_prime = DST || I2OSP(len(DST), 1)
    var dst_prime: [dst.len + 1]u8 = undefined;
    @memcpy(dst_prime[0..dst.len], dst);
    dst_prime[dst.len] = @intCast(dst.len);

    // Z_pad = I2OSP(0, s_in_bytes)
    const z_pad: [s_in_bytes]u8 = @splat(0);
    // l_i_b_str = I2OSP(len_in_bytes = 64, 2)
    const l_i_b_str = [_]u8{ 0x00, 0x40 };

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime)
    var h = Sha512.init(.{});
    h.update(&z_pad);
    h.update(msg);
    h.update(&l_i_b_str);
    h.update(&[_]u8{0});
    h.update(&dst_prime);
    var b0: [b_in_bytes]u8 = undefined;
    h.final(&b0);

    // b_1 = H(b_0 || I2OSP(1,1) || DST_prime)
    h = Sha512.init(.{});
    h.update(&b0);
    h.update(&[_]u8{1});
    h.update(&dst_prime);
    var b1: [b_in_bytes]u8 = undefined;
    h.final(&b1);

    // uniform_bytes = b_1 (since ell == 1)
    return b1;
}

test "oprf hashToGroup matches std Ristretto255.fromUniform over RFC 9380 expand_message_xmd" {
    var prng = std.Random.DefaultPrng.init(0x9807_9497_2718_2818);
    const rand = prng.random();

    var checked: usize = 0;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        // Random input of random length (0..64) to stir both the expand and the
        // U16 length handling.
        var buf: [64]u8 = undefined;
        const len = rand.uintLessThan(usize, buf.len + 1);
        rand.bytes(buf[0..len]);
        const input = buf[0..len];

        // oprf's public hash-to-group.
        const got = oprf.hashToGroup(input) catch |err| {
            // hashToGroup rejects the identity element (astronomically unlikely
            // for random inputs). If std's fromUniform also lands on identity we
            // skip this sample; otherwise the divergence is a real failure.
            const uniform_dbg = expandMessageXmd64(input);
            const ref_dbg = Ristretto255.fromUniform(uniform_dbg);
            if (ref_dbg.rejectIdentity()) |_| {
                // std accepted but oprf rejected -> genuine divergence.
                std.debug.print("oprf.hashToGroup rejected input len={d} (err={s}) but std produced a non-identity point\n", .{ len, @errorName(err) });
                return error.TestUnexpectedResult;
            } else |_| {
                continue; // both treat it as identity; nothing to compare.
            }
        };

        // Independent reference: expand_message_xmd (our transcription) then
        // std's from-uniform map.
        const uniform = expandMessageXmd64(input);
        const reference = Ristretto255.fromUniform(uniform);

        try std.testing.expectEqualSlices(u8, &reference.toBytes(), &oprf.serializeElement(got));
        checked += 1;
    }

    // Sanity: with a fixed seed we must actually compare (near) all 256 samples.
    try std.testing.expect(checked >= 250);
}
