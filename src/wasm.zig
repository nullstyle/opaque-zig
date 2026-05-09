const std = @import("std");

const constants = @import("constants.zig");
const messages = @import("messages.zig");
const protocol = @import("opaque.zig");

var heap_buffer: [1024 * 1024]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&heap_buffer);

pub const Status = enum(i32) {
    ok = 0,
    protocol_error = 1,
    invalid_input = 2,
    out_of_memory = 3,
};

const login_state_len = constants.client_login_state_len;
const server_state_len = constants.server_login_state_len;

pub export fn allocate(len: u32) u32 {
    const bytes = fba.allocator().alloc(u8, len) catch return 0;
    return @intCast(@intFromPtr(bytes.ptr));
}

pub export fn free(ptr: u32, len: u32) void {
    _ = ptr;
    _ = len;
    // FixedBufferAllocator cannot free individual allocations. The JS wrapper
    // still calls this so the ABI can switch to a real allocator later.
}

pub export fn resetAllocator() void {
    fba.reset();
}

pub export fn version() u32 {
    return constants.wasm_abi_version;
}

pub export fn registrationRequestLen() u32 {
    return @import("constants.zig").registration_request_len;
}

pub export fn registrationResponseLen() u32 {
    return @import("constants.zig").registration_response_len;
}

pub export fn registrationRecordLen() u32 {
    return @import("constants.zig").registration_record_len;
}

pub export fn ke1Len() u32 {
    return @import("constants.zig").ke1_len;
}

pub export fn ke2Len() u32 {
    return @import("constants.zig").ke2_len;
}

pub export fn ke3Len() u32 {
    return @import("constants.zig").ke3_len;
}

pub export fn registrationStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    if (input.len < constants.Nsk) return @intFromEnum(Status.invalid_input);

    const blind = input[0..constants.Nsk].*;
    const password = input[constants.Nsk..];
    const result = protocol.createRegistrationRequest(password, blind) catch return @intFromEnum(Status.protocol_error);

    var out = allocResult(constants.Nsk + constants.registration_request_len) catch return @intFromEnum(Status.out_of_memory);
    @memcpy(out[0..constants.Nsk], &result.state.blind);
    const request_bytes = result.request.toBytes();
    @memcpy(out[constants.Nsk..][0..constants.registration_request_len], &request_bytes);
    return finishResult(out_ptr, out);
}

pub export fn registrationFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    const fixed_len = constants.Nsk + constants.Nn + constants.registration_response_len;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    const blind = input[0..constants.Nsk].*;
    const envelope_nonce = input[constants.Nsk..][0..constants.Nn].*;
    const response = messages.RegistrationResponse.parse(input[constants.Nsk + constants.Nn ..][0..constants.registration_response_len]) catch return @intFromEnum(Status.invalid_input);
    const password = input[fixed_len..];

    const state = protocol.RegistrationClientState{ .password = password, .blind = blind };
    const result = protocol.finalizeRegistrationRequest(protocol.Suite.default, fba.allocator(), state, response, envelope_nonce, null, null, undefined) catch return @intFromEnum(Status.protocol_error);

    var out = allocResult(constants.registration_record_len + constants.Nh) catch return @intFromEnum(Status.out_of_memory);
    const record_bytes = result.record.toBytes();
    @memcpy(out[0..constants.registration_record_len], &record_bytes);
    @memcpy(out[constants.registration_record_len..][0..constants.Nh], &result.export_key);
    return finishResult(out_ptr, out);
}

pub export fn loginStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    const fixed_len = constants.Nsk + constants.Nn + constants.Nseed;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    const blind = input[0..constants.Nsk].*;
    const client_nonce = input[constants.Nsk..][0..constants.Nn].*;
    const keyshare_seed = input[constants.Nsk + constants.Nn ..][0..constants.Nseed].*;
    const password = input[fixed_len..];
    const result = protocol.generateKE1(password, blind, client_nonce, keyshare_seed) catch return @intFromEnum(Status.protocol_error);

    var out = allocResult(login_state_len + constants.ke1_len) catch return @intFromEnum(Status.out_of_memory);
    @memcpy(out[0..constants.Nsk], &result.state.blind);
    @memcpy(out[constants.Nsk..][0..constants.Nsk], &result.state.client_secret);
    const ke1_bytes = result.ke1.toBytes();
    @memcpy(out[constants.Nsk * 2 ..][0..constants.ke1_len], &ke1_bytes);
    @memcpy(out[login_state_len..][0..constants.ke1_len], &ke1_bytes);
    return finishResult(out_ptr, out);
}

pub export fn loginFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    const fixed_len = login_state_len + constants.ke2_len;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    const blind = input[0..constants.Nsk].*;
    const client_secret = input[constants.Nsk..][0..constants.Nsk].*;
    const ke1 = messages.KE1.parse(input[constants.Nsk * 2 ..][0..constants.ke1_len]) catch return @intFromEnum(Status.invalid_input);
    const ke2 = messages.KE2.parse(input[login_state_len..][0..constants.ke2_len]) catch return @intFromEnum(Status.invalid_input);
    const password = input[fixed_len..];

    const state = protocol.ClientLoginState{
        .password = password,
        .blind = blind,
        .client_secret = client_secret,
        .ke1 = ke1,
    };
    const result = protocol.generateKE3(protocol.Suite.default, fba.allocator(), state, ke2, null, null, undefined) catch return @intFromEnum(Status.protocol_error);

    var out = allocResult(constants.ke3_len + constants.Nx + constants.Nh) catch return @intFromEnum(Status.out_of_memory);
    const ke3_bytes = result.ke3.toBytes();
    @memcpy(out[0..constants.ke3_len], &ke3_bytes);
    @memcpy(out[constants.ke3_len..][0..constants.Nx], &result.session_key);
    @memcpy(out[constants.ke3_len + constants.Nx ..][0..constants.Nh], &result.export_key);
    return finishResult(out_ptr, out);
}

pub export fn serverLoginStart(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    const fixed_len = constants.Nsk + constants.Npk + constants.registration_record_len + constants.Nh + constants.ke1_len + constants.Nn + constants.Nn + constants.Nseed + 2;
    if (input.len < fixed_len) return @intFromEnum(Status.invalid_input);

    var offset: usize = 0;
    const server_private_key = readArray(input, &offset, constants.Nsk);
    const server_public_key = readArray(input, &offset, constants.Npk);
    const record = messages.RegistrationRecord.parse(readSlice(input, &offset, constants.registration_record_len)) catch return @intFromEnum(Status.invalid_input);
    const oprf_seed = readArray(input, &offset, constants.Nh);
    const ke1 = messages.KE1.parse(readSlice(input, &offset, constants.ke1_len)) catch return @intFromEnum(Status.invalid_input);
    const masking_nonce = readArray(input, &offset, constants.Nn);
    const server_nonce = readArray(input, &offset, constants.Nn);
    const server_keyshare_seed = readArray(input, &offset, constants.Nseed);
    const credential_identifier_len = std.mem.readInt(u16, input[offset..][0..2], .big);
    offset += 2;
    if (input.len != offset + credential_identifier_len) return @intFromEnum(Status.invalid_input);
    const credential_identifier = input[offset..];

    const result = protocol.generateKE2(
        protocol.Suite.default,
        server_private_key,
        server_public_key,
        record,
        credential_identifier,
        oprf_seed,
        ke1,
        masking_nonce,
        server_nonce,
        server_keyshare_seed,
        null,
        null,
    ) catch return @intFromEnum(Status.protocol_error);

    var out = allocResult(server_state_len + constants.ke2_len) catch return @intFromEnum(Status.out_of_memory);
    @memcpy(out[0..constants.Nm], &result.state.expected_client_mac);
    @memcpy(out[constants.Nm..][0..constants.Nx], &result.state.session_key);
    const ke2_bytes = result.ke2.toBytes();
    @memcpy(out[server_state_len..][0..constants.ke2_len], &ke2_bytes);
    return finishResult(out_ptr, out);
}

pub export fn serverLoginFinish(input_ptr: u32, input_len: u32, out_ptr: u32) i32 {
    const input = inputSlice(input_ptr, input_len) catch return @intFromEnum(Status.invalid_input);
    if (input.len != server_state_len + constants.ke3_len) return @intFromEnum(Status.invalid_input);

    const state = protocol.ServerLoginState{
        .expected_client_mac = input[0..constants.Nm].*,
        .session_key = input[constants.Nm..][0..constants.Nx].*,
    };
    const ke3 = messages.KE3.parse(input[server_state_len..][0..constants.ke3_len]) catch return @intFromEnum(Status.invalid_input);
    const session_key = protocol.serverFinish(state, ke3) catch return @intFromEnum(Status.protocol_error);

    var out = allocResult(constants.Nx) catch return @intFromEnum(Status.out_of_memory);
    @memcpy(out[0..constants.Nx], &session_key);
    return finishResult(out_ptr, out);
}

fn writeResultDescriptor(out_ptr: u32, result_ptr: u32, result_len: u32) !void {
    if (out_ptr == 0) return error.InvalidInput;
    const out: [*]u8 = @ptrFromInt(out_ptr);
    std.mem.writeInt(u32, out[0..4], result_ptr, .little);
    std.mem.writeInt(u32, out[4..8], result_len, .little);
}

fn inputSlice(ptr: u32, len: u32) ![]const u8 {
    if (len != 0 and ptr == 0) return error.InvalidInput;
    const raw: [*]const u8 = @ptrFromInt(ptr);
    return raw[0..len];
}

fn allocResult(len: usize) ![]u8 {
    if (len > std.math.maxInt(u32)) return error.OutOfMemory;
    return fba.allocator().alloc(u8, len);
}

fn finishResult(out_ptr: u32, out: []u8) i32 {
    writeResultDescriptor(out_ptr, @intCast(@intFromPtr(out.ptr)), @intCast(out.len)) catch return @intFromEnum(Status.invalid_input);
    return @intFromEnum(Status.ok);
}

fn readSlice(input: []const u8, offset: *usize, len: usize) []const u8 {
    const out = input[offset.*..][0..len];
    offset.* += len;
    return out;
}

fn readArray(input: []const u8, offset: *usize, comptime len: usize) [len]u8 {
    return readSlice(input, offset, len)[0..len].*;
}
