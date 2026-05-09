const std = @import("std");
const root = @import("opaque_root");
const c = root.constants;
const messages = root.messages;

test "registration record round trips" {
    var bytes: [c.registration_record_len]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    const parsed = try messages.RegistrationRecord.parse(&bytes);
    const encoded = parsed.toBytes();
    try std.testing.expectEqualSlices(u8, &bytes, &encoded);
}

test "KE2 round trips" {
    var bytes: [c.ke2_len]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i * 3);
    const parsed = try messages.KE2.parse(&bytes);
    const encoded = parsed.toBytes();
    try std.testing.expectEqualSlices(u8, &bytes, &encoded);
}

test "malformed size is rejected" {
    try std.testing.expectError(error.InvalidLength, messages.KE1.parse(&[_]u8{1}));
}
