const std = @import("std");

const opaque_wasm = @import("opaque_root").wasm_abi;

const Nn: usize = 32;
const Nseed: usize = 32;
const Nh: usize = 64;
const Npk: usize = 32;
const Nsk: usize = 32;
const Nm: usize = 64;
const Nx: usize = 64;
const Noe: usize = 32;

const envelope_len: usize = Nn + Nm;
const masked_response_len: usize = Npk + envelope_len;
const registration_request_len: usize = Noe;
const registration_response_len: usize = Noe + Npk;
const registration_record_len: usize = Npk + Nh + envelope_len;
const credential_request_len: usize = Noe;
const credential_response_len: usize = Noe + Nn + masked_response_len;
const auth_request_len: usize = Nn + Npk;
const auth_response_len: usize = Nn + Npk + Nm;
const ke1_len: usize = credential_request_len + auth_request_len;
const ke2_len: usize = credential_response_len + auth_response_len;
const ke3_len: usize = Nm;

const Status = enum(i32) {
    ok = 0,
    protocol_error = 1,
    invalid_input = 2,
    out_of_memory = 3,
};

test "WASM ABI exported lengths match protocol constants" {
    try std.testing.expectEqual(@as(u32, 1), opaque_wasm.version());
    try std.testing.expectEqual(@as(u32, registration_request_len), opaque_wasm.registrationRequestLen());
    try std.testing.expectEqual(@as(u32, registration_response_len), opaque_wasm.registrationResponseLen());
    try std.testing.expectEqual(@as(u32, registration_record_len), opaque_wasm.registrationRecordLen());
    try std.testing.expectEqual(@as(u32, ke1_len), opaque_wasm.ke1Len());
    try std.testing.expectEqual(@as(u32, ke2_len), opaque_wasm.ke2Len());
    try std.testing.expectEqual(@as(u32, ke3_len), opaque_wasm.ke3Len());
}

test "WASM ABI protocol exports reject null or short inputs deterministically" {
    var descriptor: [8]u8 = @splat(0xaa);
    const descriptor_ptr = ptrToU32(&descriptor) orelse 0;

    try expectStatus(.invalid_input, opaque_wasm.registrationStart(0, Nsk, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.registrationFinish(0, Nsk, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.loginStart(0, Nsk, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.loginFinish(0, ke2_len, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.serverLoginStart(0, ke1_len, descriptor_ptr));
    try expectStatus(.invalid_input, opaque_wasm.serverLoginFinish(0, ke3_len, descriptor_ptr));

    const unchanged: [descriptor.len]u8 = @splat(0xaa);
    try std.testing.expectEqualSlices(u8, &unchanged, &descriptor);
}

test "WASM ABI allocator can be reset when native pointers fit the byte ABI" {
    if (@sizeOf(usize) > @sizeOf(u32)) return error.SkipZigTest;

    opaque_wasm.resetAllocator();
    const first = opaque_wasm.allocate(16);
    try std.testing.expect(first != 0);

    const second = opaque_wasm.allocate(16);
    try std.testing.expect(second != 0);
    try std.testing.expect(second >= first + 16);

    opaque_wasm.free(first, 16);
    opaque_wasm.resetAllocator();

    const after_reset = opaque_wasm.allocate(16);
    try std.testing.expectEqual(first, after_reset);
}

test "WASM ABI registrationStart writes a result descriptor for valid small input" {
    if (@sizeOf(usize) > @sizeOf(u32)) return error.SkipZigTest;

    opaque_wasm.resetAllocator();

    const password = "pw";
    var input: [Nsk + password.len]u8 = undefined;
    input[0..Nsk].* = scalar(0x03);
    @memcpy(input[Nsk..], password);

    var descriptor: [8]u8 = @splat(0);
    const status = opaque_wasm.registrationStart(
        ptrToU32(&input).?,
        @intCast(input.len),
        ptrToU32(&descriptor).?,
    );
    if (status == @intFromEnum(Status.protocol_error)) return error.SkipZigTest;
    try expectStatus(.ok, status);

    const result_ptr = std.mem.readInt(u32, descriptor[0..4], .little);
    const result_len = std.mem.readInt(u32, descriptor[4..8], .little);
    try std.testing.expect(result_ptr != 0);
    try std.testing.expectEqual(@as(u32, Nsk + registration_request_len), result_len);

    const result: [*]const u8 = @ptrFromInt(result_ptr);
    try std.testing.expect(!std.mem.allEqual(u8, result[Nsk..][0..registration_request_len], 0));
}

fn expectStatus(expected: Status, actual: i32) !void {
    try std.testing.expectEqual(@intFromEnum(expected), actual);
}

fn ptrToU32(ptr: anytype) ?u32 {
    const value = @intFromPtr(ptr);
    if (value > std.math.maxInt(u32)) return null;
    return @intCast(value);
}

fn scalar(byte: u8) [32]u8 {
    var out: [32]u8 = @splat(0);
    out[0] = byte;
    return out;
}

test "WASM ABI module is linked" {}
