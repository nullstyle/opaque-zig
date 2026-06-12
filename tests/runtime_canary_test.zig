//! Runtime canary for the ristretto255 OPRF.
//!
//! Many tests in this suite guard their bodies with
//!   `if (!try oprfRuntimeSupported()) return error.SkipZigTest;`
//! That probe exists because a regression in the pinned std's ristretto255 /
//! scalar arithmetic can make the OPRF round-trip silently stop matching, and
//! those tests would rather skip than emit a confusing failure. The danger is
//! that such a regression would convert the entire crypto suite into SKIPS while
//! CI stays green.
//!
//! This file holds ONE test that performs the same real OPRF round-trip but
//! asserts success — so a broken runtime is a hard FAILURE here, not a skip. As
//! long as this canary runs, a stdlib regression can no longer hide behind the
//! skip guards. The probe logic is intentionally replicated in-file (rather than
//! importing a shared helper) so the canary itself exercises a genuine
//! deriveKeyPair + blind + blindEvaluate + finalize + evaluate round-trip.

const std = @import("std");
const oprf = @import("opaque_root").oprf;

/// A real ristretto255 OPRF round-trip. Returns true iff every step succeeds and
/// the blinded path (blind -> blindEvaluate -> finalize) reproduces the direct
/// evaluation, which is the property that breaks first under a stdlib regression.
fn oprfRuntimeSupported() !bool {
    const seed: [32]u8 = @splat(0x11);
    var blind: [32]u8 = @splat(0);
    blind[0] = 0x02;
    const input = "zig-master-ristretto-probe";

    const kp = oprf.deriveKeyPair(seed, "probe") catch return false;
    const blinded = oprf.blindWithScalar(input, blind) catch return false;
    // Round-trip the blinded element through serialize/deserialize to catch a
    // broken canonical-encoding check too.
    _ = oprf.deserializeElement(oprf.serializeElement(blinded.blinded_element)) catch return false;
    const evaluated = oprf.blindEvaluate(kp.sk, blinded.blinded_element) catch return false;
    const finalized = oprf.finalize(input, blind, evaluated) catch return false;
    const direct = oprf.evaluate(kp.sk, input) catch return false;
    return std.mem.eql(u8, &finalized, &direct);
}

test "OPRF runtime is supported (canary; fails instead of silently skipping)" {
    try std.testing.expect(try oprfRuntimeSupported());
}
