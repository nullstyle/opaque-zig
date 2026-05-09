const std = @import("std");

const c = @import("constants.zig");
const messages = @import("messages.zig");
const oprf = @import("oprf.zig");

const crypto = std.crypto;
const Sha512 = crypto.hash.sha2.Sha512;
const HmacSha512 = crypto.auth.hmac.sha2.HmacSha512;
const HkdfSha512 = crypto.kdf.hkdf.HkdfSha512;
const X25519 = crypto.dh.X25519;

pub const Error = error{
    AuthenticationFailed,
    InvalidInput,
    InvalidMessage,
    InvalidPublicKey,
    NoSpaceLeft,
    OutOfMemory,
} || oprf.Error || std.crypto.errors.IdentityElementError;

pub const Ksf = union(enum) {
    identity,
    argon2id_interactive,

    pub fn stretch(self: Ksf, allocator: std.mem.Allocator, out: *[c.Nh]u8, input: []const u8, io: std.Io) !void {
        switch (self) {
            .identity => {
                if (input.len != c.Nh) return error.InvalidInput;
                @memcpy(out, input[0..c.Nh]);
            },
            .argon2id_interactive => {
                const params = crypto.pwhash.argon2.Params{ .t = 1, .m = 2 << 10, .p = 1 };
                const salt: [16]u8 = @splat(0);
                try crypto.pwhash.argon2.kdf(allocator, out, input, &salt, params, .argon2id, io);
            },
        }
    }
};

pub const Suite = struct {
    context: []const u8 = "",
    ksf: Ksf = .identity,

    pub const default = Suite{};
};

pub const RegistrationClientState = struct {
    password: []const u8,
    blind: [c.Nsk]u8,
};

pub const ClientLoginState = struct {
    password: []const u8,
    blind: [c.Nsk]u8,
    client_secret: [c.Nsk]u8,
    ke1: messages.KE1,
};

pub const ServerLoginState = struct {
    expected_client_mac: [c.Nm]u8,
    session_key: [c.Nx]u8,
};

pub const RegistrationResult = struct {
    state: RegistrationClientState,
    request: messages.RegistrationRequest,
};

pub const RegistrationFinishResult = struct {
    record: messages.RegistrationRecord,
    export_key: [c.Nh]u8,
};

pub const LoginStartResult = struct {
    state: ClientLoginState,
    ke1: messages.KE1,
};

pub const LoginFinishResult = struct {
    ke3: messages.KE3,
    session_key: [c.Nx]u8,
    export_key: [c.Nh]u8,
};

pub const ServerLoginStartResult = struct {
    state: ServerLoginState,
    ke2: messages.KE2,
};

pub fn createRegistrationRequest(password: []const u8, blind: [c.Nsk]u8) Error!RegistrationResult {
    const blind_result = try oprf.blindWithScalar(password, blind);
    return .{
        .state = .{ .password = password, .blind = blind_result.blind },
        .request = .{ .blinded_message = blind_result.serializedBlindedElement() },
    };
}

pub fn createRegistrationResponse(
    request: messages.RegistrationRequest,
    server_public_key: [c.Npk]u8,
    credential_identifier: []const u8,
    oprf_seed: [c.Nh]u8,
) Error!messages.RegistrationResponse {
    const oprf_key = try deriveOprfKey(oprf_seed, credential_identifier);
    const blinded_element = try oprf.deserializeElement(request.blinded_message);
    const evaluated = try oprf.blindEvaluate(oprf_key, blinded_element);
    return .{
        .evaluated_message = oprf.serializeElement(evaluated),
        .server_public_key = server_public_key,
    };
}

pub fn finalizeRegistrationRequest(
    suite: Suite,
    allocator: std.mem.Allocator,
    state: RegistrationClientState,
    response: messages.RegistrationResponse,
    envelope_nonce: [c.Nn]u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    io: std.Io,
) Error!RegistrationFinishResult {
    const evaluated_element = try oprf.deserializeElement(response.evaluated_message);
    const oprf_output = try oprf.finalize(state.password, state.blind, evaluated_element);
    const randomized_password = try randomizedPassword(suite, allocator, oprf_output, io);
    const masking_key = deriveMaskingKey(randomized_password);
    const keys = envelopeKeys(randomized_password, envelope_nonce);
    const client_keypair = try X25519.KeyPair.generateDeterministic(keys.client_private_key);
    const envelope = try createEnvelope(keys.auth_key, envelope_nonce, response.server_public_key, client_keypair.public_key, server_identity, client_identity);
    return .{
        .record = .{
            .client_public_key = client_keypair.public_key,
            .masking_key = masking_key,
            .envelope = envelope,
        },
        .export_key = keys.export_key,
    };
}

pub fn generateKE1(
    password: []const u8,
    blind: [c.Nsk]u8,
    client_nonce: [c.Nn]u8,
    client_keyshare_seed: [c.Nseed]u8,
) Error!LoginStartResult {
    const blind_result = try oprf.blindWithScalar(password, blind);
    const client_keypair = try X25519.KeyPair.generateDeterministic(client_keyshare_seed);
    const ke1 = messages.KE1{
        .credential_request = .{ .blinded_message = blind_result.serializedBlindedElement() },
        .auth_request = .{
            .client_nonce = client_nonce,
            .client_public_keyshare = client_keypair.public_key,
        },
    };
    return .{
        .state = .{
            .password = password,
            .blind = blind_result.blind,
            .client_secret = client_keypair.secret_key,
            .ke1 = ke1,
        },
        .ke1 = ke1,
    };
}

pub fn generateKE2(
    suite: Suite,
    server_private_key: [c.Nsk]u8,
    server_public_key: [c.Npk]u8,
    record: messages.RegistrationRecord,
    credential_identifier: []const u8,
    oprf_seed: [c.Nh]u8,
    ke1: messages.KE1,
    masking_nonce: [c.Nn]u8,
    server_nonce: [c.Nn]u8,
    server_keyshare_seed: [c.Nseed]u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
) Error!ServerLoginStartResult {
    const credential_response = try createCredentialResponse(record, server_public_key, credential_identifier, oprf_seed, ke1.credential_request, masking_nonce);
    const server_keyshare = try X25519.KeyPair.generateDeterministic(server_keyshare_seed);
    const resolved_server_identity = try resolveIdentity(server_identity, &server_public_key);
    const resolved_client_identity = try resolveIdentity(client_identity, &record.client_public_key);
    const preamble_hash = try buildPreambleHash(suite.context, resolved_client_identity, ke1, resolved_server_identity, credential_response, server_nonce, server_keyshare.public_key);

    const dh1 = try X25519.scalarmult(server_keyshare.secret_key, ke1.auth_request.client_public_keyshare);
    const dh2 = try X25519.scalarmult(server_private_key, ke1.auth_request.client_public_keyshare);
    const dh3 = try X25519.scalarmult(server_keyshare.secret_key, record.client_public_key);
    const derived = deriveKeys(&dh1, &dh2, &dh3, preamble_hash);

    var server_mac: [c.Nm]u8 = undefined;
    HmacSha512.create(&server_mac, &preamble_hash, &derived.server_mac_key);
    const mac_hash = try buildClientMacHash(suite.context, resolved_client_identity, ke1, resolved_server_identity, credential_response, server_nonce, server_keyshare.public_key, &server_mac);

    var expected_client_mac: [c.Nm]u8 = undefined;
    HmacSha512.create(&expected_client_mac, &mac_hash, &derived.client_mac_key);

    return .{
        .state = .{
            .expected_client_mac = expected_client_mac,
            .session_key = derived.session_key,
        },
        .ke2 = .{
            .credential_response = credential_response,
            .auth_response = .{
                .server_nonce = server_nonce,
                .server_public_keyshare = server_keyshare.public_key,
                .server_mac = server_mac,
            },
        },
    };
}

pub fn generateKE3(
    suite: Suite,
    allocator: std.mem.Allocator,
    state: ClientLoginState,
    ke2: messages.KE2,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    io: std.Io,
) Error!LoginFinishResult {
    const recovered = try recoverCredentials(suite, allocator, state.password, state.blind, ke2.credential_response, server_identity, client_identity, io);
    const resolved_server_identity = try resolveIdentity(server_identity, &recovered.server_public_key);
    const resolved_client_identity = try resolveIdentity(client_identity, &recovered.client_public_key);
    const preamble_hash = try buildPreambleHash(suite.context, resolved_client_identity, state.ke1, resolved_server_identity, ke2.credential_response, ke2.auth_response.server_nonce, ke2.auth_response.server_public_keyshare);

    const dh1 = try X25519.scalarmult(state.client_secret, ke2.auth_response.server_public_keyshare);
    const dh2 = try X25519.scalarmult(state.client_secret, recovered.server_public_key);
    const dh3 = try X25519.scalarmult(recovered.client_private_key, ke2.auth_response.server_public_keyshare);
    const derived = deriveKeys(&dh1, &dh2, &dh3, preamble_hash);

    var expected_server_mac: [c.Nm]u8 = undefined;
    HmacSha512.create(&expected_server_mac, &preamble_hash, &derived.server_mac_key);
    if (!crypto.timing_safe.eql([c.Nm]u8, expected_server_mac, ke2.auth_response.server_mac)) {
        return error.AuthenticationFailed;
    }

    const mac_hash = try buildClientMacHash(suite.context, resolved_client_identity, state.ke1, resolved_server_identity, ke2.credential_response, ke2.auth_response.server_nonce, ke2.auth_response.server_public_keyshare, &expected_server_mac);

    var client_mac: [c.Nm]u8 = undefined;
    HmacSha512.create(&client_mac, &mac_hash, &derived.client_mac_key);

    return .{
        .ke3 = .{ .client_mac = client_mac },
        .session_key = derived.session_key,
        .export_key = recovered.export_key,
    };
}

pub fn serverFinish(state: ServerLoginState, ke3: messages.KE3) Error![c.Nx]u8 {
    if (!crypto.timing_safe.eql([c.Nm]u8, state.expected_client_mac, ke3.client_mac)) {
        return error.AuthenticationFailed;
    }
    return state.session_key;
}

const RecoveredCredentials = struct {
    client_private_key: [c.Nsk]u8,
    client_public_key: [c.Npk]u8,
    server_public_key: [c.Npk]u8,
    export_key: [c.Nh]u8,
};

fn recoverCredentials(
    suite: Suite,
    allocator: std.mem.Allocator,
    password: []const u8,
    blind: [c.Nsk]u8,
    response: messages.CredentialResponse,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    io: std.Io,
) Error!RecoveredCredentials {
    const evaluated_element = try oprf.deserializeElement(response.evaluated_message);
    const oprf_output = try oprf.finalize(password, blind, evaluated_element);
    const rp = try randomizedPassword(suite, allocator, oprf_output, io);
    const masking_key = deriveMaskingKey(rp);

    var pad: [c.masked_response_len]u8 = undefined;
    var info: [c.Nn + "CredentialResponsePad".len]u8 = undefined;
    @memcpy(info[0..c.Nn], &response.masking_nonce);
    @memcpy(info[c.Nn..], "CredentialResponsePad");
    HkdfSha512.expand(&pad, &info, masking_key);

    var clear_masked: [c.masked_response_len]u8 = undefined;
    for (&clear_masked, response.masked_response, pad) |*dst, a, b| dst.* = a ^ b;

    const server_public_key = clear_masked[0..c.Npk].*;
    const envelope = messages.Envelope.fromBytes(clear_masked[c.Npk..][0..c.envelope_len].*) catch return error.InvalidMessage;
    const keys = envelopeKeys(rp, envelope.nonce);
    const client_keypair = try X25519.KeyPair.generateDeterministic(keys.client_private_key);

    const expected_envelope = try createEnvelope(keys.auth_key, envelope.nonce, server_public_key, client_keypair.public_key, server_identity, client_identity);
    if (!crypto.timing_safe.eql([c.Nm]u8, expected_envelope.auth_tag, envelope.auth_tag)) {
        return error.AuthenticationFailed;
    }

    return .{
        .client_private_key = keys.client_private_key,
        .client_public_key = client_keypair.public_key,
        .server_public_key = server_public_key,
        .export_key = keys.export_key,
    };
}

fn createCredentialResponse(
    record: messages.RegistrationRecord,
    server_public_key: [c.Npk]u8,
    credential_identifier: []const u8,
    oprf_seed: [c.Nh]u8,
    request: messages.CredentialRequest,
    masking_nonce: [c.Nn]u8,
) Error!messages.CredentialResponse {
    const oprf_key = try deriveOprfKey(oprf_seed, credential_identifier);
    const blinded_element = try oprf.deserializeElement(request.blinded_message);
    const evaluated = try oprf.blindEvaluate(oprf_key, blinded_element);

    var pad: [c.masked_response_len]u8 = undefined;
    var info: [c.Nn + "CredentialResponsePad".len]u8 = undefined;
    @memcpy(info[0..c.Nn], &masking_nonce);
    @memcpy(info[c.Nn..], "CredentialResponsePad");
    HkdfSha512.expand(&pad, &info, record.masking_key);

    var plain: [c.masked_response_len]u8 = undefined;
    @memcpy(plain[0..c.Npk], &server_public_key);
    record.envelope.toBytesInto(plain[c.Npk..][0..c.envelope_len]);

    var masked: [c.masked_response_len]u8 = undefined;
    for (&masked, plain, pad) |*dst, a, b| dst.* = a ^ b;

    return .{
        .evaluated_message = oprf.serializeElement(evaluated),
        .masking_nonce = masking_nonce,
        .masked_response = masked,
    };
}

const EnvelopeKeys = struct {
    client_private_key: [c.Nsk]u8,
    auth_key: [c.Nh]u8,
    export_key: [c.Nh]u8,
};

fn deriveMaskingKey(randomized_password_value: [c.Nh]u8) [c.Nh]u8 {
    var masking_key: [c.Nh]u8 = undefined;
    HkdfSha512.expand(&masking_key, "MaskingKey", randomized_password_value);
    return masking_key;
}

fn envelopeKeys(randomized_password_value: [c.Nh]u8, nonce: [c.Nn]u8) EnvelopeKeys {
    var out: EnvelopeKeys = undefined;
    var info: [c.Nn + "PrivateKey".len]u8 = undefined;
    @memcpy(info[0..c.Nn], &nonce);
    @memcpy(info[c.Nn..], "PrivateKey");
    HkdfSha512.expand(&out.client_private_key, &info, randomized_password_value);

    var auth_info: [c.Nn + "AuthKey".len]u8 = undefined;
    @memcpy(auth_info[0..c.Nn], &nonce);
    @memcpy(auth_info[c.Nn..], "AuthKey");
    HkdfSha512.expand(&out.auth_key, &auth_info, randomized_password_value);

    var export_info: [c.Nn + "ExportKey".len]u8 = undefined;
    @memcpy(export_info[0..c.Nn], &nonce);
    @memcpy(export_info[c.Nn..], "ExportKey");
    HkdfSha512.expand(&out.export_key, &export_info, randomized_password_value);
    return out;
}

fn randomizedPassword(suite: Suite, allocator: std.mem.Allocator, oprf_output: [c.Nh]u8, io: std.Io) Error![c.Nh]u8 {
    var stretched: [c.Nh]u8 = undefined;
    suite.ksf.stretch(allocator, &stretched, &oprf_output, io) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidInput,
    };
    var ikm: [c.Nh * 2]u8 = undefined;
    @memcpy(ikm[0..c.Nh], &oprf_output);
    @memcpy(ikm[c.Nh..], &stretched);
    return HkdfSha512.extract("", &ikm);
}

fn deriveOprfKey(oprf_seed: [c.Nh]u8, credential_identifier: []const u8) Error![c.Nsk]u8 {
    if (credential_identifier.len > std.math.maxInt(u16)) return error.InvalidInput;
    var info_buf: [std.math.maxInt(u16) + "OprfKey".len]u8 = undefined;
    @memcpy(info_buf[0..credential_identifier.len], credential_identifier);
    @memcpy(info_buf[credential_identifier.len..][0.."OprfKey".len], "OprfKey");
    var seed: [c.Nok]u8 = undefined;
    HkdfSha512.expand(&seed, info_buf[0 .. credential_identifier.len + "OprfKey".len], oprf_seed);
    return (try oprf.deriveKeyPair(seed, "OPAQUE-DeriveKeyPair")).sk;
}

fn resolveIdentity(explicit: ?[]const u8, fallback: *const [c.Npk]u8) Error![]const u8 {
    if (explicit) |identity| {
        if (identity.len == 0 or identity.len > std.math.maxInt(u16)) return error.InvalidInput;
        return identity;
    }
    return fallback;
}

fn createEnvelope(
    auth_key: [c.Nh]u8,
    nonce: [c.Nn]u8,
    server_public_key: [c.Npk]u8,
    client_public_key: [c.Npk]u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
) Error!messages.Envelope {
    const sid = try resolveIdentity(server_identity, &server_public_key);
    const cid = try resolveIdentity(client_identity, &client_public_key);
    var sid_len: [2]u8 = undefined;
    var cid_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &sid_len, @intCast(sid.len), .big);
    std.mem.writeInt(u16, &cid_len, @intCast(cid.len), .big);
    var mac = HmacSha512.init(&auth_key);
    mac.update(&nonce);
    mac.update(&server_public_key);
    mac.update(&sid_len);
    mac.update(sid);
    mac.update(&cid_len);
    mac.update(cid);
    var auth_tag: [c.Nm]u8 = undefined;
    mac.final(&auth_tag);
    return .{ .nonce = nonce, .auth_tag = auth_tag };
}

const DerivedKeys = struct {
    server_mac_key: [c.Nm]u8,
    client_mac_key: [c.Nm]u8,
    session_key: [c.Nx]u8,
};

fn deriveKeys(dh1: *const [32]u8, dh2: *const [32]u8, dh3: *const [32]u8, preamble_hash: [c.Nh]u8) DerivedKeys {
    var ikm: [96]u8 = undefined;
    @memcpy(ikm[0..32], dh1);
    @memcpy(ikm[32..64], dh2);
    @memcpy(ikm[64..96], dh3);
    const prk = HkdfSha512.extract("", &ikm);
    const handshake_secret = deriveSecret(prk, "HandshakeSecret", &preamble_hash);
    return .{
        .server_mac_key = deriveSecret(handshake_secret, "ServerMAC", ""),
        .client_mac_key = deriveSecret(handshake_secret, "ClientMAC", ""),
        .session_key = deriveSecret(prk, "SessionKey", &preamble_hash),
    };
}

fn deriveSecret(secret: [c.Nh]u8, label: []const u8, transcript_hash: []const u8) [c.Nx]u8 {
    var out: [c.Nx]u8 = undefined;
    var custom_label: [2 + 1 + "OPAQUE-".len + 32 + 1 + c.Nh]u8 = undefined;
    std.mem.writeInt(u16, custom_label[0..2], c.Nx, .big);
    custom_label[2] = @intCast("OPAQUE-".len + label.len);
    @memcpy(custom_label[3..][0.."OPAQUE-".len], "OPAQUE-");
    @memcpy(custom_label[3 + "OPAQUE-".len ..][0..label.len], label);
    const context_off = 3 + "OPAQUE-".len + label.len;
    custom_label[context_off] = @intCast(transcript_hash.len);
    @memcpy(custom_label[context_off + 1 ..][0..transcript_hash.len], transcript_hash);
    HkdfSha512.expand(&out, custom_label[0 .. context_off + 1 + transcript_hash.len], secret);
    return out;
}

fn buildPreambleHash(
    context: []const u8,
    client_identity: []const u8,
    ke1: messages.KE1,
    server_identity: []const u8,
    credential_response: messages.CredentialResponse,
    server_nonce: [c.Nn]u8,
    server_public_keyshare: [c.Npk]u8,
) Error![c.Nh]u8 {
    var h = Sha512.init(.{});
    try hashPreambleFields(&h, context, client_identity, ke1, server_identity, credential_response, server_nonce, server_public_keyshare);
    var out: [c.Nh]u8 = undefined;
    h.final(&out);
    return out;
}

fn buildClientMacHash(
    context: []const u8,
    client_identity: []const u8,
    ke1: messages.KE1,
    server_identity: []const u8,
    credential_response: messages.CredentialResponse,
    server_nonce: [c.Nn]u8,
    server_public_keyshare: [c.Npk]u8,
    server_mac: *const [c.Nm]u8,
) Error![c.Nh]u8 {
    var h = Sha512.init(.{});
    try hashPreambleFields(&h, context, client_identity, ke1, server_identity, credential_response, server_nonce, server_public_keyshare);
    h.update(server_mac);
    var out: [c.Nh]u8 = undefined;
    h.final(&out);
    return out;
}

fn hashPreambleFields(
    h: *Sha512,
    context: []const u8,
    client_identity: []const u8,
    ke1: messages.KE1,
    server_identity: []const u8,
    credential_response: messages.CredentialResponse,
    server_nonce: [c.Nn]u8,
    server_public_keyshare: [c.Npk]u8,
) Error!void {
    try requireOpaque16(context);
    try requireOpaque16(client_identity);
    try requireOpaque16(server_identity);

    h.update("OPAQUEv1-");
    hashOpaque16(h, context);
    hashOpaque16(h, client_identity);
    var ke1_bytes: [c.ke1_len]u8 = undefined;
    ke1.toBytesInto(&ke1_bytes);
    h.update(&ke1_bytes);
    hashOpaque16(h, server_identity);
    var credential_response_bytes: [c.credential_response_len]u8 = undefined;
    credential_response.toBytesInto(&credential_response_bytes);
    h.update(&credential_response_bytes);
    h.update(&server_nonce);
    h.update(&server_public_keyshare);
}

fn requireOpaque16(bytes: []const u8) Error!void {
    if (bytes.len > std.math.maxInt(u16)) return error.InvalidInput;
}

fn hashOpaque16(h: *Sha512, bytes: []const u8) void {
    var len: [2]u8 = undefined;
    std.mem.writeInt(u16, &len, @intCast(bytes.len), .big);
    h.update(&len);
    h.update(bytes);
}
