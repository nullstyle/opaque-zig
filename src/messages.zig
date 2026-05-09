const std = @import("std");
const c = @import("constants.zig");

pub const Error = error{InvalidLength};

pub const Envelope = struct {
    nonce: [c.Nn]u8,
    auth_tag: [c.Nm]u8,

    pub fn fromBytes(bytes: [c.envelope_len]u8) Error!Envelope {
        return .{
            .nonce = bytes[0..c.Nn].*,
            .auth_tag = bytes[c.Nn..][0..c.Nm].*,
        };
    }

    pub fn parse(bytes: []const u8) Error!Envelope {
        if (bytes.len != c.envelope_len) return error.InvalidLength;
        return fromBytes(bytes[0..c.envelope_len].*);
    }

    pub fn toBytes(self: Envelope) [c.envelope_len]u8 {
        var out: [c.envelope_len]u8 = undefined;
        self.toBytesInto(&out);
        return out;
    }

    pub fn toBytesInto(self: Envelope, out: *[c.envelope_len]u8) void {
        @memcpy(out[0..c.Nn], &self.nonce);
        @memcpy(out[c.Nn..][0..c.Nm], &self.auth_tag);
    }
};

pub const RegistrationRequest = fixedStruct("RegistrationRequest", c.registration_request_len, struct {
    blinded_message: [c.Noe]u8,
});

pub const RegistrationResponse = struct {
    evaluated_message: [c.Noe]u8,
    server_public_key: [c.Npk]u8,

    pub fn parse(bytes: []const u8) Error!RegistrationResponse {
        if (bytes.len != c.registration_response_len) return error.InvalidLength;
        return .{
            .evaluated_message = bytes[0..c.Noe].*,
            .server_public_key = bytes[c.Noe..][0..c.Npk].*,
        };
    }

    pub fn toBytes(self: RegistrationResponse) [c.registration_response_len]u8 {
        var out: [c.registration_response_len]u8 = undefined;
        self.toBytesInto(&out);
        return out;
    }

    pub fn toBytesInto(self: RegistrationResponse, out: *[c.registration_response_len]u8) void {
        @memcpy(out[0..c.Noe], &self.evaluated_message);
        @memcpy(out[c.Noe..][0..c.Npk], &self.server_public_key);
    }
};

pub const RegistrationRecord = struct {
    client_public_key: [c.Npk]u8,
    masking_key: [c.Nh]u8,
    envelope: Envelope,

    pub fn parse(bytes: []const u8) Error!RegistrationRecord {
        if (bytes.len != c.registration_record_len) return error.InvalidLength;
        return .{
            .client_public_key = bytes[0..c.Npk].*,
            .masking_key = bytes[c.Npk..][0..c.Nh].*,
            .envelope = try Envelope.parse(bytes[c.Npk + c.Nh ..][0..c.envelope_len]),
        };
    }

    pub fn toBytes(self: RegistrationRecord) [c.registration_record_len]u8 {
        var out: [c.registration_record_len]u8 = undefined;
        self.toBytesInto(&out);
        return out;
    }

    pub fn toBytesInto(self: RegistrationRecord, out: *[c.registration_record_len]u8) void {
        @memcpy(out[0..c.Npk], &self.client_public_key);
        @memcpy(out[c.Npk..][0..c.Nh], &self.masking_key);
        self.envelope.toBytesInto(out[c.Npk + c.Nh ..][0..c.envelope_len]);
    }
};

pub const CredentialRequest = fixedStruct("CredentialRequest", c.credential_request_len, struct {
    blinded_message: [c.Noe]u8,
});

pub const CredentialResponse = struct {
    evaluated_message: [c.Noe]u8,
    masking_nonce: [c.Nn]u8,
    masked_response: [c.masked_response_len]u8,

    pub fn parse(bytes: []const u8) Error!CredentialResponse {
        if (bytes.len != c.credential_response_len) return error.InvalidLength;
        return .{
            .evaluated_message = bytes[0..c.Noe].*,
            .masking_nonce = bytes[c.Noe..][0..c.Nn].*,
            .masked_response = bytes[c.Noe + c.Nn ..][0..c.masked_response_len].*,
        };
    }

    pub fn toBytes(self: CredentialResponse) [c.credential_response_len]u8 {
        var out: [c.credential_response_len]u8 = undefined;
        self.toBytesInto(&out);
        return out;
    }

    pub fn toBytesInto(self: CredentialResponse, out: *[c.credential_response_len]u8) void {
        @memcpy(out[0..c.Noe], &self.evaluated_message);
        @memcpy(out[c.Noe..][0..c.Nn], &self.masking_nonce);
        @memcpy(out[c.Noe + c.Nn ..][0..c.masked_response_len], &self.masked_response);
    }
};

pub const AuthRequest = struct {
    client_nonce: [c.Nn]u8,
    client_public_keyshare: [c.Npk]u8,

    pub fn parse(bytes: []const u8) Error!AuthRequest {
        if (bytes.len != c.auth_request_len) return error.InvalidLength;
        return .{
            .client_nonce = bytes[0..c.Nn].*,
            .client_public_keyshare = bytes[c.Nn..][0..c.Npk].*,
        };
    }

    pub fn toBytesInto(self: AuthRequest, out: *[c.auth_request_len]u8) void {
        @memcpy(out[0..c.Nn], &self.client_nonce);
        @memcpy(out[c.Nn..][0..c.Npk], &self.client_public_keyshare);
    }
};

pub const AuthResponse = struct {
    server_nonce: [c.Nn]u8,
    server_public_keyshare: [c.Npk]u8,
    server_mac: [c.Nm]u8,

    pub fn parse(bytes: []const u8) Error!AuthResponse {
        if (bytes.len != c.auth_response_len) return error.InvalidLength;
        return .{
            .server_nonce = bytes[0..c.Nn].*,
            .server_public_keyshare = bytes[c.Nn..][0..c.Npk].*,
            .server_mac = bytes[c.Nn + c.Npk ..][0..c.Nm].*,
        };
    }

    pub fn toBytesInto(self: AuthResponse, out: *[c.auth_response_len]u8) void {
        @memcpy(out[0..c.Nn], &self.server_nonce);
        @memcpy(out[c.Nn..][0..c.Npk], &self.server_public_keyshare);
        @memcpy(out[c.Nn + c.Npk ..][0..c.Nm], &self.server_mac);
    }
};

pub const KE1 = struct {
    credential_request: CredentialRequest,
    auth_request: AuthRequest,

    pub fn parse(bytes: []const u8) Error!KE1 {
        if (bytes.len != c.ke1_len) return error.InvalidLength;
        return .{
            .credential_request = try CredentialRequest.parse(bytes[0..c.credential_request_len]),
            .auth_request = try AuthRequest.parse(bytes[c.credential_request_len..][0..c.auth_request_len]),
        };
    }

    pub fn toBytes(self: KE1) [c.ke1_len]u8 {
        var out: [c.ke1_len]u8 = undefined;
        self.toBytesInto(&out);
        return out;
    }

    pub fn toBytesInto(self: KE1, out: *[c.ke1_len]u8) void {
        self.credential_request.toBytesInto(out[0..c.credential_request_len]);
        self.auth_request.toBytesInto(out[c.credential_request_len..][0..c.auth_request_len]);
    }
};

pub const KE2 = struct {
    credential_response: CredentialResponse,
    auth_response: AuthResponse,

    pub fn parse(bytes: []const u8) Error!KE2 {
        if (bytes.len != c.ke2_len) return error.InvalidLength;
        return .{
            .credential_response = try CredentialResponse.parse(bytes[0..c.credential_response_len]),
            .auth_response = try AuthResponse.parse(bytes[c.credential_response_len..][0..c.auth_response_len]),
        };
    }

    pub fn toBytes(self: KE2) [c.ke2_len]u8 {
        var out: [c.ke2_len]u8 = undefined;
        self.toBytesInto(&out);
        return out;
    }

    pub fn toBytesInto(self: KE2, out: *[c.ke2_len]u8) void {
        self.credential_response.toBytesInto(out[0..c.credential_response_len]);
        self.auth_response.toBytesInto(out[c.credential_response_len..][0..c.auth_response_len]);
    }
};

pub const KE3 = struct {
    client_mac: [c.Nm]u8,

    pub fn parse(bytes: []const u8) Error!KE3 {
        if (bytes.len != c.ke3_len) return error.InvalidLength;
        return .{ .client_mac = bytes[0..c.Nm].* };
    }

    pub fn toBytes(self: KE3) [c.ke3_len]u8 {
        return self.client_mac;
    }

    pub fn toBytesInto(self: KE3, out: *[c.ke3_len]u8) void {
        @memcpy(out, &self.client_mac);
    }
};

pub const CleartextCredentials = struct {
    server_public_key: [c.Npk]u8,
    server_identity: []const u8,
    client_identity: []const u8,

    pub fn init(server_public_key: [c.Npk]u8, client_public_key: [c.Npk]u8, server_identity: ?[]const u8, client_identity: ?[]const u8) CleartextCredentials {
        return .{
            .server_public_key = server_public_key,
            .server_identity = server_identity orelse &server_public_key,
            .client_identity = client_identity orelse &client_public_key,
        };
    }
};

fn fixedStruct(comptime name: []const u8, comptime len: usize, comptime Fields: type) type {
    _ = name;
    _ = len;
    _ = Fields;
    return struct {
        blinded_message: [c.Noe]u8,

        pub fn parse(bytes: []const u8) Error!@This() {
            if (bytes.len != c.Noe) return error.InvalidLength;
            return .{ .blinded_message = bytes[0..c.Noe].* };
        }

        pub fn toBytes(self: @This()) [c.Noe]u8 {
            return self.blinded_message;
        }

        pub fn toBytesInto(self: @This(), out: *[c.Noe]u8) void {
            @memcpy(out, &self.blinded_message);
        }
    };
}

test "message structs are referenced" {
    _ = RegistrationRequest;
    _ = RegistrationResponse;
    _ = RegistrationRecord;
    _ = CredentialRequest;
    _ = CredentialResponse;
    _ = KE1;
    _ = KE2;
    _ = KE3;
}
