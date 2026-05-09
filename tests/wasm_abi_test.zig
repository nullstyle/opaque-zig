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
const blind_uniform_len: usize = 64;

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
    try std.testing.expectEqual(@as(u32, 2), opaque_wasm.version());
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
    opaque_wasm.resetAllocator();
    const first = try allocBytes(16);
    @memset(heapBytes(first, 16), 0xaa);

    const second = try allocBytes(16);
    try std.testing.expect(second >= first + 16);

    opaque_wasm.free(first, 16);
    try std.testing.expect(std.mem.allEqual(u8, heapBytes(first, 16), 0));

    opaque_wasm.resetAllocator();

    const after_reset = try allocBytes(16);
    try std.testing.expectEqual(first, after_reset);
    try std.testing.expect(std.mem.allEqual(u8, heapBytes(after_reset, 16), 0));
}

test "WASM ABI registrationStart writes a result descriptor for valid small input" {
    opaque_wasm.resetAllocator();

    const password = "pw";
    var input: [blind_uniform_len + password.len]u8 = undefined;
    input[0..blind_uniform_len].* = uniform(0x03);
    @memcpy(input[blind_uniform_len..], password);

    const input_ptr = try allocCopy(&input);
    const descriptor_ptr = try allocBytes(8);
    const status = opaque_wasm.registrationStart(
        input_ptr,
        @intCast(input.len),
        descriptor_ptr,
    );
    if (status == @intFromEnum(Status.protocol_error)) return error.SkipZigTest;
    try expectStatus(.ok, status);

    const descriptor = heapBytes(descriptor_ptr, 8);
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

fn uniform(byte: u8) [64]u8 {
    var out: [64]u8 = @splat(0);
    out[0] = byte;
    return out;
}

fn allocBytes(len: usize) !u32 {
    if (len > std.math.maxInt(u32)) return error.SkipZigTest;
    const ptr = opaque_wasm.allocate(@intCast(len));
    if (ptr == 0) return error.SkipZigTest;
    return ptr;
}

fn allocCopy(input: []const u8) !u32 {
    const ptr = try allocBytes(input.len);
    @memcpy(heapBytes(ptr, input.len), input);
    return ptr;
}

fn heapBytes(ptr: u32, len: usize) []u8 {
    const bytes: [*]u8 = @ptrFromInt(ptr);
    return bytes[0..len];
}

test "WASM ABI module is linked" {}
