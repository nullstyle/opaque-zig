//! Tests for the key-stretching function (KSF) layer of src/opaque.zig.
//!
//! These are the FIRST tests to actually execute the Argon2id code path (the
//! protocol round-trip and vector tests all pin `identity_test_only` for speed
//! / byte-exactness). They run unconditionally -- no skip guard -- so a break in
//! the Argon2id wiring or the io contract is a hard failure.

const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;

const c = root.constants;
const Ksf = opaque_mod.Ksf;

test "argon2id_owasp stretch succeeds and is deterministic" {
    const allocator = std.testing.allocator;
    const ksf = Ksf{ .argon2id = opaque_mod.argon2id_owasp };
    const input: [c.Nh]u8 = @splat(0x42);

    // argon2id_owasp is p=1, so the synchronous path is used and io is never
    // dereferenced; pass a real io anyway (std.testing.io) to prove the contract
    // accepts one. This is the first test ever to run the argon2id path.
    var out_a: [c.Nh]u8 = undefined;
    try ksf.stretch(allocator, &out_a, &input, std.testing.io);

    // Determinism: same input + params -> identical 64-byte output (fixed salt).
    var out_b: [c.Nh]u8 = undefined;
    try ksf.stretch(allocator, &out_b, &input, std.testing.io);
    try std.testing.expectEqualSlices(u8, &out_a, &out_b);

    // The KSF must actually transform the input (not pass it through).
    try std.testing.expect(!std.mem.eql(u8, &out_a, &input));
}

test "argon2id stretch accepts null io at p=1 (uses internal failing io)" {
    // The null-io fallback (std.Io.failing) must drive the synchronous path to a
    // result identical to an explicitly-supplied io, since p=1 never touches io.
    const allocator = std.testing.allocator;
    const ksf = Ksf{ .argon2id = .{ .t = 1, .m = 8, .p = 1 } };
    const input: [c.Nh]u8 = @splat(0x17);

    var out_null: [c.Nh]u8 = undefined;
    try ksf.stretch(allocator, &out_null, &input, null);

    var out_io: [c.Nh]u8 = undefined;
    try ksf.stretch(allocator, &out_io, &input, std.testing.io);

    try std.testing.expectEqualSlices(u8, &out_null, &out_io);
}

test "identity_test_only stretch is the documented passthrough" {
    const allocator = std.testing.allocator;
    const ksf: Ksf = .identity_test_only;
    var input: [c.Nh]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate(i);

    var out: [c.Nh]u8 = undefined;
    try ksf.stretch(allocator, &out, &input, null);
    try std.testing.expectEqualSlices(u8, &input, &out);
}

test "identity_test_only stretch rejects wrong-length input" {
    const allocator = std.testing.allocator;
    const ksf: Ksf = .identity_test_only;
    const short_input: [c.Nh - 1]u8 = @splat(0);
    var out: [c.Nh]u8 = undefined;
    try std.testing.expectError(
        error.InvalidInput,
        ksf.stretch(allocator, &out, &short_input, null),
    );
}

test "argon2id with p>1 and null io is rejected" {
    // The contract requires a concurrency-capable io when p>1; a null io must
    // surface as InvalidInput rather than reaching argon2's async path.
    const allocator = std.testing.allocator;
    const ksf = Ksf{ .argon2id = .{ .t = 1, .m = 32, .p = 4 } };
    const input: [c.Nh]u8 = @splat(0x05);
    var out: [c.Nh]u8 = undefined;
    try std.testing.expectError(
        error.InvalidInput,
        ksf.stretch(allocator, &out, &input, null),
    );
}

test "randomizedPassword surfaces OutOfMemory distinctly" {
    // A failing allocator forces the KSF allocation to fail; the error must be
    // OutOfMemory (propagated), not collapsed into InvalidInput, so the wasm
    // layer can map it to its out_of_memory status.
    const ksf = Ksf{ .argon2id = opaque_mod.argon2id_owasp };
    const input: [c.Nh]u8 = @splat(0x99);
    var out: [c.Nh]u8 = undefined;
    try std.testing.expectError(
        error.OutOfMemory,
        ksf.stretch(std.testing.failing_allocator, &out, &input, std.testing.io),
    );
}
