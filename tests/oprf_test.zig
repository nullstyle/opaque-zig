const std = @import("std");
const oprf = @import("opaque_root").oprf;

test "RFC 9497 ristretto255-SHA512 OPRF test vector 1" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const seed = try hex32("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    const key_info = try hex("74657374206b6579", 8);
    const expected_sk = try hex32("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");

    const kp = try oprf.deriveKeyPair(seed, &key_info);
    try std.testing.expectEqualSlices(u8, &expected_sk, &kp.sk);

    const input = try hex("00", 1);
    const blind = try hex32("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
    const expected_blinded = try hex32("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c");
    const expected_evaluated = try hex32("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e");
    const expected_output = try hex64("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6");

    const blinded = try oprf.blindWithScalar(&input, blind);
    try std.testing.expectEqualSlices(u8, &expected_blinded, &oprf.serializeElement(blinded.blinded_element));

    const evaluated = try oprf.blindEvaluate(kp.sk, blinded.blinded_element);
    try std.testing.expectEqualSlices(u8, &expected_evaluated, &oprf.serializeElement(evaluated));

    const output = try oprf.finalize(&input, blinded.blind, evaluated);
    try std.testing.expectEqualSlices(u8, &expected_output, &output);

    const direct_output = try oprf.evaluate(kp.sk, &input);
    try std.testing.expectEqualSlices(u8, &expected_output, &direct_output);
}

test "deterministic roundtrip matches direct evaluation" {
    if (!try oprfRuntimeSupported()) return error.SkipZigTest;

    const seed = try hex32("1111111111111111111111111111111111111111111111111111111111111111");
    const kp = try oprf.deriveKeyPair(seed, "opaque-zig");
    const blind = try hex32("2222222222222222222222222222222222222222222222222222222222222202");
    const input = "correct horse battery staple";

    const blinded = try oprf.blindWithScalar(input, blind);
    const evaluated = try oprf.blindEvaluate(kp.sk, blinded.blinded_element);
    const finalized = try oprf.finalize(input, blind, evaluated);
    const direct = try oprf.evaluate(kp.sk, input);

    try std.testing.expectEqualSlices(u8, &direct, &finalized);
}

test "element and scalar input validation" {
    const zero_element: oprf.SerializedElement = @splat(0);
    try std.testing.expectError(error.DeserializeError, oprf.deserializeElement(zero_element));

    const zero_scalar: oprf.Scalar = @splat(0);
    try std.testing.expectError(error.ZeroScalar, oprf.blindWithScalar("input", zero_scalar));

    var noncanonical_scalar: oprf.Scalar = @splat(0xff);
    noncanonical_scalar[31] = 0x7f;
    try std.testing.expectError(error.DeserializeError, oprf.deserializeScalar(noncanonical_scalar));
}

fn hex32(comptime bytes: []const u8) ![32]u8 {
    return hex(bytes, 32);
}

fn hex64(comptime bytes: []const u8) ![64]u8 {
    return hex(bytes, 64);
}

fn hex(comptime bytes: []const u8, comptime len: usize) ![len]u8 {
    var out: [len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, bytes);
    return out;
}

fn oprfRuntimeSupported() !bool {
    const seed = try hex32("1111111111111111111111111111111111111111111111111111111111111111");
    const blind = try hex32("0200000000000000000000000000000000000000000000000000000000000000");
    const input = "zig-master-ristretto-probe";

    const kp = oprf.deriveKeyPair(seed, "probe") catch return false;
    const blinded = oprf.blindWithScalar(input, blind) catch return false;
    _ = oprf.deserializeElement(oprf.serializeElement(blinded.blinded_element)) catch return false;
    const evaluated = oprf.blindEvaluate(kp.sk, blinded.blinded_element) catch return false;
    const finalized = oprf.finalize(input, blind, evaluated) catch return false;
    const direct = oprf.evaluate(kp.sk, input) catch return false;
    return std.mem.eql(u8, &finalized, &direct);
}
