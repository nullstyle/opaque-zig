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
} || oprf.Error || std.crypto.errors.IdentityElementError || std.crypto.errors.WeakPublicKeyError;

/// Selectable AKE group for the OPAQUE-3DH key exchange. The OPRF is always
/// ristretto255-SHA512 (see oprf.zig) regardless of this choice; only the 3DH
/// Diffie-Hellman differs. Both groups use 32-byte keys (Npk=Nsk=Nseed=32), so
/// no wire sizes, message structs, or constants change between them.
pub const Group = enum {
    ristretto255,
    curve25519,

    /// Returns { sk, pk } where sk is the private value to feed to diffieHellman,
    /// and pk is the serialized public element. (RFC 9807 Section 6.4.1.1)
    pub fn deriveDhKeyPair(self: Group, seed: [c.Nseed]u8) Error!struct { sk: [c.Nsk]u8, pk: [c.Npk]u8 } {
        switch (self) {
            .ristretto255 => {
                const kp = try oprf.deriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair");
                return .{ .sk = kp.sk, .pk = oprf.serializeElement(kp.pk) };
            },
            .curve25519 => {
                const kp = try X25519.KeyPair.generateDeterministic(seed);
                return .{ .sk = kp.secret_key, .pk = kp.public_key };
            },
        }
    }

    /// Computes the shared Diffie-Hellman value between our private scalar `sk`
    /// and the peer's serialized public element. (RFC 9807 Section 6.4.1.3)
    pub fn diffieHellman(self: Group, sk: [c.Nsk]u8, peer_pk: [c.Npk]u8) Error![32]u8 {
        switch (self) {
            .ristretto255 => {
                const peer = try oprf.deserializeElement(peer_pk);
                const shared = try peer.mul(sk);
                return oprf.serializeElement(shared);
            },
            .curve25519 => {
                return try X25519.scalarmult(sk, peer_pk);
            },
        }
    }
};

/// OWASP-recommended Argon2id parameters: 19 MiB memory, 2 passes, single
/// lane (p=1). This is the native `Suite` default. Because p=1, argon2's `kdf`
/// takes its synchronous code path and never touches the `std.Io` argument (see
/// `Ksf.stretch`), so no concurrency runtime is required.
pub const argon2id_owasp = crypto.pwhash.argon2.Params{ .t = 2, .m = 19 * 1024, .p = 1 };

/// RFC 9807 Section 7 reference Argon2id parameters (2 GiB memory, 1 pass, 4
/// lanes). NOT a default: p=4 forces argon2's concurrent path, so callers MUST
/// supply a non-null, concurrency-capable `std.Io` (a single-threaded io will
/// fail at runtime). Exposed for parity with the RFC's stated configuration.
pub const argon2id_rfc9807 = crypto.pwhash.argon2.Params{ .t = 1, .m = 1 << 21, .p = 4 };

/// Key-stretching function applied to the OPRF output before it becomes the
/// randomized password. Choose `argon2id` in production; `identity_test_only`
/// is a passthrough that exists ONLY so the RFC test vectors (which specify
/// KSF = Identity) and fast round-trip tests can run -- it provides NO password
/// hardening and MUST NOT be used with real credentials.
pub const Ksf = union(enum) {
    /// Passthrough: `stretch` copies the input unchanged. Test/vector use only.
    identity_test_only,
    /// Argon2id with caller-supplied cost parameters. Use `argon2id_owasp`.
    argon2id: crypto.pwhash.argon2.Params,

    /// Stretch `input` into `out` (Nh bytes).
    ///
    /// `io` contract (eliminates the prior `undefined` std.Io hazard):
    ///   - `identity_test_only`: `io` is ignored.
    ///   - `argon2id` with `params.p == 1`: argon2's `kdf` provably stays on its
    ///     synchronous path (`processBlocks` branches on `single_threaded or
    ///     threads == 1`) and never dereferences `io`. If the caller passes
    ///     `null` we substitute `std.Io.failing` -- a real, fully-initialized,
    ///     freestanding-safe `std.Io` value (its concurrency vtable entries would
    ///     fail/trap if invoked, but argon2 never invokes them at p=1). Nothing
    ///     `undefined` is ever passed to std.
    ///   - `argon2id` with `params.p > 1`: argon2 multiplexes lanes onto threads
    ///     and requires a concurrency-capable Io; a null `io` is rejected with
    ///     `error.InvalidInput` (passing `std.Io.failing` here would trap).
    pub fn stretch(self: Ksf, allocator: std.mem.Allocator, out: *[c.Nh]u8, input: []const u8, io: ?std.Io) Error!void {
        switch (self) {
            .identity_test_only => {
                if (input.len != c.Nh) return error.InvalidInput;
                @memcpy(out, input[0..c.Nh]);
            },
            .argon2id => |params| {
                // Pick an Io that is always a valid value (never `undefined`).
                // `std.Io.failing` is safe whenever argon2 stays synchronous,
                // which it does iff p == 1 (or the target is single-threaded).
                const resolved_io: std.Io = if (params.p > 1)
                    (io orelse return error.InvalidInput)
                else
                    (io orelse std.Io.failing);
                const salt: [16]u8 = @splat(0);
                crypto.pwhash.argon2.kdf(allocator, out, input, &salt, params, .argon2id, resolved_io) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.InvalidInput,
                };
            },
        }
    }
};

pub const Suite = struct {
    context: []const u8 = "",
    ksf: Ksf = .{ .argon2id = argon2id_owasp },
    group: Group = .ristretto255,

    pub const default = Suite{};
};

/// Client-held state between `createRegistrationRequest` and
/// `finalizeRegistrationRequest`. `blind` is a secret OPRF scalar that MUST be
/// kept until finalize and never reused.
///
/// The password is deliberately NOT retained here: `finalizeRegistrationRequest`
/// takes it again as an explicit parameter. This lets the caller zeroize its
/// password buffer immediately after `createRegistrationRequest` without breaking
/// finalize. Call `wipe` once finalize has run.
pub const RegistrationClientState = struct {
    blind: [c.Nsk]u8,

    /// Zeroize the owned secret (`blind`).
    pub fn wipe(self: *RegistrationClientState) void {
        std.crypto.secureZero(u8, &self.blind);
    }
};

/// Client-held state between `generateKE1` and `generateKE3`. `blind` and
/// `client_secret` (the ephemeral AKE private key) are secrets that MUST persist
/// until KE3 and never be reused across logins.
///
/// The password is deliberately NOT retained here: `generateKE3` takes it again
/// as an explicit parameter. This lets the caller zeroize its password buffer
/// immediately after `generateKE1` without breaking login. Call `wipe` after KE3
/// completes.
pub const ClientLoginState = struct {
    blind: [c.Nsk]u8,
    client_secret: [c.Nsk]u8,
    ke1: messages.KE1,

    /// Zeroize the owned secrets (`blind`, `client_secret`).
    pub fn wipe(self: *ClientLoginState) void {
        std.crypto.secureZero(u8, &self.blind);
        std.crypto.secureZero(u8, &self.client_secret);
    }
};

/// Server-held state between `generateKE2` and `serverFinish`. Both fields are
/// secret: `expected_client_mac` authenticates the client and
/// `unconfirmed_session_key` is the derived shared key for a client that has NOT
/// yet proven knowledge of the password.
///
/// SECURITY: `unconfirmed_session_key` MUST NOT be used as a session key. It is
/// only valid after `serverFinish` returns successfully -- that call performs the
/// constant-time client-MAC check, and ONLY its RETURN value is a confirmed
/// session key. Reading this field before `serverFinish` (or after it has failed)
/// is the classic skipped-MAC misuse and accepts unauthenticated clients. Call
/// `wipe` after `serverFinish`.
pub const ServerLoginState = struct {
    expected_client_mac: [c.Nm]u8,
    unconfirmed_session_key: [c.Nx]u8,

    /// Zeroize both secret fields.
    pub fn wipe(self: *ServerLoginState) void {
        std.crypto.secureZero(u8, &self.expected_client_mac);
        std.crypto.secureZero(u8, &self.unconfirmed_session_key);
    }
};

/// Output of `createRegistrationRequest`: the per-call client `state` and the
/// `request` message to send to the server.
pub const RegistrationResult = struct {
    state: RegistrationClientState,
    request: messages.RegistrationRequest,
};

/// Output of `finalizeRegistrationRequest`: the `record` to upload to the server
/// and the client's `export_key`. `export_key` is a secret derived key the
/// application may use; wipe it (via `wipe`) once consumed.
pub const RegistrationFinishResult = struct {
    record: messages.RegistrationRecord,
    export_key: [c.Nh]u8,

    /// Zeroize `export_key`. The `record` is public (it is uploaded as-is).
    pub fn wipe(self: *RegistrationFinishResult) void {
        std.crypto.secureZero(u8, &self.export_key);
    }
};

/// Output of `generateKE1`: the per-call client `state` and the `ke1` message.
pub const LoginStartResult = struct {
    state: ClientLoginState,
    ke1: messages.KE1,
};

/// Output of `generateKE3`: the `ke3` message to send, plus the secret
/// `session_key` and `export_key`. Wipe both secrets once consumed.
pub const LoginFinishResult = struct {
    ke3: messages.KE3,
    session_key: [c.Nx]u8,
    export_key: [c.Nh]u8,

    /// Zeroize the secret derived keys (`session_key`, `export_key`). `ke3` is
    /// the public MAC sent to the server.
    pub fn wipe(self: *LoginFinishResult) void {
        std.crypto.secureZero(u8, &self.session_key);
        std.crypto.secureZero(u8, &self.export_key);
    }
};

/// Output of `generateKE2`: the server `state` and the `ke2` message to send.
pub const ServerLoginStartResult = struct {
    state: ServerLoginState,
    ke2: messages.KE2,

    /// Zeroize the secrets held in `state` (see `ServerLoginState.wipe`). `ke2`
    /// is the public message sent to the client.
    pub fn wipe(self: *ServerLoginStartResult) void {
        self.state.wipe();
    }
};

/// Client step 1 of registration (RFC 9807 Section 6.3.1.1). Blinds `password`
/// with `blind`, a fresh OPRF scalar that MUST be unique per registration and
/// is retained in the returned state for finalize. `error.InvalidInput`/
/// `error.ZeroScalar` indicate a caller-supplied bad blind, not a protocol
/// failure. The returned `state` holds a secret; wipe it after finalize.
///
/// `blind` is a CANONICAL 32-byte scalar (it must be < the group order); a
/// uniformly-random 32-byte buffer is rejected ~1/16 of the time. Callers that
/// want to supply raw randomness should use `createRegistrationRequestFromUniform`
/// (64 uniform bytes, reduced safely) or, better, `createRegistrationRequestRandom`
/// (supply a std.Random and let it generate everything).
pub fn createRegistrationRequest(password: []const u8, blind: [c.Nsk]u8) Error!RegistrationResult {
    const blind_result = try oprf.blindWithScalar(password, blind);
    return registrationResultFromBlind(blind_result);
}

/// Like `createRegistrationRequest`, but takes 64 uniformly-random bytes and
/// reduces them to a valid OPRF scalar internally (RFC 9807 / RFC 9497's
/// recommended wide-reduction path). This is the misuse-resistant builder for
/// callers that have raw randomness rather than a pre-validated canonical scalar:
/// any 64-byte input yields a valid blind (except the negligible all-reduces-to-
/// zero case, surfaced as `error.ZeroScalar`). The returned `state` holds a
/// secret; wipe it after finalize.
pub fn createRegistrationRequestFromUniform(
    password: []const u8,
    blind_uniform: [oprf.random_scalar_uniform_length]u8,
) Error!RegistrationResult {
    const blind_result = try oprf.blindWithRandomBytes(password, blind_uniform);
    return registrationResultFromBlind(blind_result);
}

/// Safe-by-default registration start: generates the OPRF blind from `random`
/// and runs `createRegistrationRequestFromUniform`, so the caller never
/// hand-manages any randomness. The returned `state` holds a secret; wipe it
/// after finalize.
///
/// `random` MUST be a cryptographically secure RNG (e.g. `std.crypto.random` on
/// a native target). Passing a deterministic/predictable RNG breaks the OPRF
/// blinding and is a security failure.
pub fn createRegistrationRequestRandom(random: std.Random, password: []const u8) Error!RegistrationResult {
    var blind_uniform: [oprf.random_scalar_uniform_length]u8 = undefined;
    random.bytes(&blind_uniform);
    return createRegistrationRequestFromUniform(password, blind_uniform);
}

fn registrationResultFromBlind(blind_result: oprf.BlindResult) RegistrationResult {
    return .{
        .state = .{ .blind = blind_result.blind },
        .request = .{ .blinded_message = blind_result.serializedBlindedElement() },
    };
}

/// Server step of registration (RFC 9807 Section 6.3.1.2). Evaluates the OPRF
/// over the client's blinded message using a per-credential key derived from the
/// long-term secret `oprf_seed` and `credential_identifier`. `oprf_seed` is a
/// long-term server secret; `credential_identifier` must uniquely and stably
/// identify the account (reusing the same identifier yields the same OPRF key).
/// Errors here are deserialization/input failures, not authentication.
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

/// Builds a fake `RegistrationRecord` for client-enumeration resistance, per
/// RFC 9807 Section 6.3.2.2. When a login arrives for an unknown
/// `credential_identifier`, the server feeds this record to `generateKE2` so the
/// response is indistinguishable from one for a real account (to any adversary
/// that cannot guess the password).
///
/// Construction (matches Section 6.3.2.2's "fake client record"):
///   - `client_public_key`: a valid group element, derived deterministically
///     from `seed` via `suite.group.deriveDhKeyPair` (the RFC requires "a
///     randomly generated public key of length Npk"; deriving from a stored seed
///     gives a stable, valid element so the same fake record can be reused).
///   - `masking_key`: Nh pseudorandom bytes from the server's `oprf_seed` keyed
///     by `credential_identifier` (HKDF-Expand, same style as `deriveOprfKey`).
///     The RFC requires "a random byte string of length Nh".
///   - `envelope`: all zeros (nonce + auth_tag), exactly as the RFC specifies.
///
/// Inputs:
///   - `oprf_seed`: the server's long-term OPRF seed (a secret).
///   - `credential_identifier`: the unknown identifier the request targeted.
///   - `seed`: a (preferably stored, reused) seed for the fake public key.
///
/// It is RECOMMENDED to create one fake record at setup and reuse it, so unknown
/// users are served in time comparable to real lookups.
pub fn createFakeRecord(
    suite: Suite,
    oprf_seed: [c.Nh]u8,
    credential_identifier: []const u8,
    seed: [c.Nseed]u8,
) Error!messages.RegistrationRecord {
    if (credential_identifier.len > std.math.maxInt(u16)) return error.InvalidInput;
    const fake_keypair = try suite.group.deriveDhKeyPair(seed);

    const label = "OPAQUE-FakeMaskingKey";
    var info_buf: [std.math.maxInt(u16) + label.len]u8 = undefined;
    @memcpy(info_buf[0..credential_identifier.len], credential_identifier);
    @memcpy(info_buf[credential_identifier.len..][0..label.len], label);
    var masking_key: [c.Nh]u8 = undefined;
    HkdfSha512.expand(&masking_key, info_buf[0 .. credential_identifier.len + label.len], oprf_seed);

    return .{
        .client_public_key = fake_keypair.pk,
        .masking_key = masking_key,
        .envelope = .{
            .nonce = @splat(0),
            .auth_tag = @splat(0),
        },
    };
}

/// Client step 2 of registration (RFC 9807 Section 6.3.1.3). Runs the KSF over
/// the OPRF output and builds the upload record + export key.
///
/// `password` is supplied AGAIN here (it is not retained in `state`); it MUST be
/// the same password passed to `createRegistrationRequest`. Re-taking it means
/// the caller can zeroize its password buffer between start and finalize.
///
/// Inputs that MUST be fresh/unique per call: `envelope_nonce`.
/// `server_identity`/`client_identity` are optional; when null they default to
/// the respective public keys, and whatever is chosen here MUST be reused
/// verbatim at login (the envelope MAC binds them). `io` follows the
/// `Ksf.stretch` contract: pass null for the identity KSF or for argon2id with
/// p==1; argon2id with p>1 requires a real concurrency-capable io.
///
/// Errors: `error.OutOfMemory` (KSF allocation -- a resource limit, propagated
/// distinctly) vs `error.InvalidInput`/deserialization errors (caller mistakes).
/// `allocator` backs the KSF working memory.
pub fn finalizeRegistrationRequest(
    suite: Suite,
    allocator: std.mem.Allocator,
    state: RegistrationClientState,
    response: messages.RegistrationResponse,
    envelope_nonce: [c.Nn]u8,
    password: []const u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    io: ?std.Io,
) Error!RegistrationFinishResult {
    const evaluated_element = try oprf.deserializeElement(response.evaluated_message);
    var oprf_output = try oprf.finalize(password, state.blind, evaluated_element);
    defer std.crypto.secureZero(u8, &oprf_output);
    var randomized_password = try randomizedPassword(suite, allocator, oprf_output, io);
    defer std.crypto.secureZero(u8, &randomized_password);
    const masking_key = deriveMaskingKey(randomized_password);
    var keys = envelopeKeys(randomized_password, envelope_nonce);
    // keys.client_private_key and keys.auth_key are secret; export_key is copied
    // into the returned result below, so only wipe the two secret intermediates.
    defer std.crypto.secureZero(u8, &keys.client_private_key);
    defer std.crypto.secureZero(u8, &keys.auth_key);
    var client_keypair = try suite.group.deriveDhKeyPair(keys.client_private_key);
    // The derived DH private key is secret and only needed to compute the public
    // key + envelope; wipe it before returning (only the public key escapes).
    defer std.crypto.secureZero(u8, &client_keypair.sk);
    const envelope = try createEnvelope(keys.auth_key, envelope_nonce, response.server_public_key, client_keypair.pk, server_identity, client_identity);
    return .{
        .record = .{
            .client_public_key = client_keypair.pk,
            .masking_key = masking_key,
            .envelope = envelope,
        },
        .export_key = keys.export_key,
    };
}

/// Safe-by-default registration finalize: generates the `envelope_nonce` from
/// `random` and forwards to `finalizeRegistrationRequest`, so the caller never
/// hand-manages the nonce. `password` is supplied again here (it is not retained
/// in `state`) and MUST match the registration start. All other parameters and
/// the `io` contract are as in `finalizeRegistrationRequest`.
///
/// `random` MUST be a cryptographically secure RNG (e.g. `std.crypto.random` on
/// a native target); a predictable nonce is a security failure.
pub fn finalizeRegistrationRequestRandom(
    suite: Suite,
    allocator: std.mem.Allocator,
    random: std.Random,
    state: RegistrationClientState,
    response: messages.RegistrationResponse,
    password: []const u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    io: ?std.Io,
) Error!RegistrationFinishResult {
    var envelope_nonce: [c.Nn]u8 = undefined;
    random.bytes(&envelope_nonce);
    return finalizeRegistrationRequest(suite, allocator, state, response, envelope_nonce, password, server_identity, client_identity, io);
}

/// Client step 1 of login (RFC 9807 Section 6.4.2.1 / KE1). Produces the first
/// AKE message and the per-login client state.
///
/// Inputs that MUST be fresh/unique per login: `blind` (OPRF scalar),
/// `client_nonce`, and `client_keyshare_seed` (derives the ephemeral AKE key
/// pair). Reusing any of these across logins is a security failure. Only
/// `suite.group` is consulted here (not ksf/context). The returned state holds
/// secrets; wipe it after KE3. Errors indicate a bad `blind`, not a protocol
/// failure.
///
/// `blind` is a CANONICAL 32-byte scalar (it must be < the group order); a
/// uniformly-random 32-byte buffer is rejected ~1/16 of the time. Callers that
/// want to supply raw randomness should use `generateKE1FromUniform` (64 uniform
/// bytes, reduced safely) or, better, `generateKE1Random` (supply a std.Random
/// and let it generate the blind, nonce, and keyshare seed).
pub fn generateKE1(
    suite: Suite,
    password: []const u8,
    blind: [c.Nsk]u8,
    client_nonce: [c.Nn]u8,
    client_keyshare_seed: [c.Nseed]u8,
) Error!LoginStartResult {
    const blind_result = try oprf.blindWithScalar(password, blind);
    return loginStartResultFromBlind(suite, blind_result, client_nonce, client_keyshare_seed);
}

/// Like `generateKE1`, but takes 64 uniformly-random bytes for the blind and
/// reduces them to a valid OPRF scalar internally. This is the misuse-resistant
/// builder for callers that have raw randomness rather than a pre-validated
/// canonical scalar (`client_nonce`/`client_keyshare_seed` are already used
/// directly, so they remain plain 32-byte inputs). The returned state holds
/// secrets; wipe it after KE3.
pub fn generateKE1FromUniform(
    suite: Suite,
    password: []const u8,
    blind_uniform: [oprf.random_scalar_uniform_length]u8,
    client_nonce: [c.Nn]u8,
    client_keyshare_seed: [c.Nseed]u8,
) Error!LoginStartResult {
    const blind_result = try oprf.blindWithRandomBytes(password, blind_uniform);
    return loginStartResultFromBlind(suite, blind_result, client_nonce, client_keyshare_seed);
}

/// Safe-by-default login start: generates ALL fresh per-login randomness (the
/// OPRF blind from 64 uniform bytes, the `client_nonce`, and the
/// `client_keyshare_seed`) from `random`, so the caller never hand-manages any
/// of it. The returned state holds secrets; wipe it after KE3.
///
/// `random` MUST be a cryptographically secure RNG (e.g. `std.crypto.random` on
/// a native target). Reusing or predicting any of these values across logins is
/// a security failure.
pub fn generateKE1Random(suite: Suite, random: std.Random, password: []const u8) Error!LoginStartResult {
    var blind_uniform: [oprf.random_scalar_uniform_length]u8 = undefined;
    random.bytes(&blind_uniform);
    var client_nonce: [c.Nn]u8 = undefined;
    random.bytes(&client_nonce);
    var client_keyshare_seed: [c.Nseed]u8 = undefined;
    random.bytes(&client_keyshare_seed);
    return generateKE1FromUniform(suite, password, blind_uniform, client_nonce, client_keyshare_seed);
}

fn loginStartResultFromBlind(
    suite: Suite,
    blind_result: oprf.BlindResult,
    client_nonce: [c.Nn]u8,
    client_keyshare_seed: [c.Nseed]u8,
) Error!LoginStartResult {
    const client_keypair = try suite.group.deriveDhKeyPair(client_keyshare_seed);
    const ke1 = messages.KE1{
        .credential_request = .{ .blinded_message = blind_result.serializedBlindedElement() },
        .auth_request = .{
            .client_nonce = client_nonce,
            .client_public_keyshare = client_keypair.pk,
        },
    };
    return .{
        .state = .{
            .blind = blind_result.blind,
            .client_secret = client_keypair.sk,
            .ke1 = ke1,
        },
        .ke1 = ke1,
    };
}

/// Server step of login (RFC 9807 Section 6.4.2.2 / KE2). Processes KE1 and
/// produces KE2 plus the server's per-login state.
///
/// Inputs that MUST be fresh/unique per login: `masking_nonce`, `server_nonce`,
/// and `server_keyshare_seed` (ephemeral server AKE key). `server_private_key`
/// and `oprf_seed` are long-term server secrets. For an UNKNOWN
/// `credential_identifier`, pass a fake `record` from `createFakeRecord` to
/// resist enumeration. `server_identity`/`client_identity` must match what was
/// used at registration. The returned state holds secrets; wipe after
/// serverFinish. Errors are deserialization/input failures (e.g. a
/// non-canonical client public key in `record`), surfaced before any KE2 is
/// produced.
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
    const server_keyshare = try suite.group.deriveDhKeyPair(server_keyshare_seed);
    const resolved_server_identity = try resolveIdentity(server_identity, &server_public_key);
    const resolved_client_identity = try resolveIdentity(client_identity, &record.client_public_key);
    const preamble_hash = try buildPreambleHash(suite.context, resolved_client_identity, ke1, resolved_server_identity, credential_response, server_nonce, server_keyshare.pk);

    var dh1 = try suite.group.diffieHellman(server_keyshare.sk, ke1.auth_request.client_public_keyshare);
    var dh2 = try suite.group.diffieHellman(server_private_key, ke1.auth_request.client_public_keyshare);
    var dh3 = try suite.group.diffieHellman(server_keyshare.sk, record.client_public_key);
    // The three DH shared secrets are the AKE ikm; wipe after key derivation.
    defer std.crypto.secureZero(u8, &dh1);
    defer std.crypto.secureZero(u8, &dh2);
    defer std.crypto.secureZero(u8, &dh3);
    var derived = deriveKeys(&dh1, &dh2, &dh3, preamble_hash);
    // session_key escapes into the returned state (as the still-unconfirmed
    // session key); wipe only the MAC keys.
    defer std.crypto.secureZero(u8, &derived.server_mac_key);
    defer std.crypto.secureZero(u8, &derived.client_mac_key);

    var server_mac: [c.Nm]u8 = undefined;
    HmacSha512.create(&server_mac, &preamble_hash, &derived.server_mac_key);
    const mac_hash = try buildClientMacHash(suite.context, resolved_client_identity, ke1, resolved_server_identity, credential_response, server_nonce, server_keyshare.pk, &server_mac);

    var expected_client_mac: [c.Nm]u8 = undefined;
    HmacSha512.create(&expected_client_mac, &mac_hash, &derived.client_mac_key);

    return .{
        .state = .{
            .expected_client_mac = expected_client_mac,
            .unconfirmed_session_key = derived.session_key,
        },
        .ke2 = .{
            .credential_response = credential_response,
            .auth_response = .{
                .server_nonce = server_nonce,
                .server_public_keyshare = server_keyshare.pk,
                .server_mac = server_mac,
            },
        },
    };
}

/// Safe-by-default server login start: generates ALL fresh per-login server
/// randomness (`masking_nonce`, `server_nonce`, and `server_keyshare_seed`) from
/// `random`, so the caller never hand-manages it. All other parameters match
/// `generateKE2` (including the long-term `server_private_key`/`oprf_seed` and
/// the fake-`record` enumeration-resistance contract). The returned state holds
/// secrets; wipe after serverFinish.
///
/// `random` MUST be a cryptographically secure RNG (e.g. `std.crypto.random` on
/// a native target). Reusing or predicting any of these values across logins is
/// a security failure.
pub fn generateKE2Random(
    suite: Suite,
    random: std.Random,
    server_private_key: [c.Nsk]u8,
    server_public_key: [c.Npk]u8,
    record: messages.RegistrationRecord,
    credential_identifier: []const u8,
    oprf_seed: [c.Nh]u8,
    ke1: messages.KE1,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
) Error!ServerLoginStartResult {
    var masking_nonce: [c.Nn]u8 = undefined;
    random.bytes(&masking_nonce);
    var server_nonce: [c.Nn]u8 = undefined;
    random.bytes(&server_nonce);
    var server_keyshare_seed: [c.Nseed]u8 = undefined;
    random.bytes(&server_keyshare_seed);
    return generateKE2(
        suite,
        server_private_key,
        server_public_key,
        record,
        credential_identifier,
        oprf_seed,
        ke1,
        masking_nonce,
        server_nonce,
        server_keyshare_seed,
        server_identity,
        client_identity,
    );
}

/// Client step 2 of login (RFC 9807 Section 6.4.2.3 / KE3). Recovers the
/// credentials, authenticates the server, and produces KE3 + the session and
/// export keys.
///
/// `password` is supplied AGAIN here (it is not retained in `state`); it MUST be
/// the same password passed to `generateKE1`. Re-taking it means the caller can
/// zeroize its password buffer between KE1 and KE3.
///
/// `server_identity`/`client_identity` MUST match registration (they are bound
/// in the envelope and transcript). `io` follows the `Ksf.stretch` contract
/// (null is fine for identity / argon2id p==1). `allocator` backs the KSF.
///
/// `error.AuthenticationFailed` is returned when the server's MAC does not
/// verify OR the recovered envelope does not authenticate. It deliberately does
/// NOT distinguish a wrong password from server impersonation/tampering -- both
/// are a single, constant error so the failure mode leaks nothing. Other errors
/// (`error.OutOfMemory`, deserialization) reflect resources/inputs.
pub fn generateKE3(
    suite: Suite,
    allocator: std.mem.Allocator,
    state: ClientLoginState,
    ke2: messages.KE2,
    password: []const u8,
    server_identity: ?[]const u8,
    client_identity: ?[]const u8,
    io: ?std.Io,
) Error!LoginFinishResult {
    var recovered = try recoverCredentials(suite, allocator, password, state.blind, ke2.credential_response, server_identity, client_identity, io);
    // recovered.client_private_key is the secret DH scalar; it is consumed by the
    // dh3 computation below. Both client_private_key and export_key are wiped here:
    // on the SUCCESS return below, export_key is copied into the result BEFORE these
    // defers run (so the caller's value is intact); on the server-MAC-failure path
    // (error.AuthenticationFailed) the defer wipes the recovered export_key too.
    defer std.crypto.secureZero(u8, &recovered.client_private_key);
    defer std.crypto.secureZero(u8, &recovered.export_key);
    const resolved_server_identity = try resolveIdentity(server_identity, &recovered.server_public_key);
    const resolved_client_identity = try resolveIdentity(client_identity, &recovered.client_public_key);
    const preamble_hash = try buildPreambleHash(suite.context, resolved_client_identity, state.ke1, resolved_server_identity, ke2.credential_response, ke2.auth_response.server_nonce, ke2.auth_response.server_public_keyshare);

    var dh1 = try suite.group.diffieHellman(state.client_secret, ke2.auth_response.server_public_keyshare);
    var dh2 = try suite.group.diffieHellman(state.client_secret, recovered.server_public_key);
    var dh3 = try suite.group.diffieHellman(recovered.client_private_key, ke2.auth_response.server_public_keyshare);
    // The three DH shared secrets are the AKE ikm; wipe them after key derivation.
    defer std.crypto.secureZero(u8, &dh1);
    defer std.crypto.secureZero(u8, &dh2);
    defer std.crypto.secureZero(u8, &dh3);
    var derived = deriveKeys(&dh1, &dh2, &dh3, preamble_hash);
    // server_mac_key/client_mac_key are secret; session_key is returned, so wipe
    // only the two MAC keys.
    defer std.crypto.secureZero(u8, &derived.server_mac_key);
    defer std.crypto.secureZero(u8, &derived.client_mac_key);

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

/// Server step 2 of login (RFC 9807 Section 6.4.2.4). Verifies the client's KE3
/// MAC (constant-time) against the value computed in `generateKE2` and, on
/// success, returns a copy of the shared session key. ONLY this RETURN value is
/// a confirmed session key; `state.unconfirmed_session_key` MUST NOT be read
/// directly (it is the same bytes but without the password-knowledge proof).
/// `error.AuthenticationFailed` means the client did not prove knowledge of the
/// password (wrong password, fake record, or tampering) -- it deliberately does
/// not distinguish these. `state` should be wiped after this call.
pub fn serverFinish(state: ServerLoginState, ke3: messages.KE3) Error![c.Nx]u8 {
    if (!crypto.timing_safe.eql([c.Nm]u8, state.expected_client_mac, ke3.client_mac)) {
        return error.AuthenticationFailed;
    }
    return state.unconfirmed_session_key;
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
    io: ?std.Io,
) Error!RecoveredCredentials {
    const evaluated_element = try oprf.deserializeElement(response.evaluated_message);
    var oprf_output = try oprf.finalize(password, blind, evaluated_element);
    defer std.crypto.secureZero(u8, &oprf_output);
    var rp = try randomizedPassword(suite, allocator, oprf_output, io);
    defer std.crypto.secureZero(u8, &rp);
    var masking_key = deriveMaskingKey(rp);
    defer std.crypto.secureZero(u8, &masking_key);

    var pad: [c.masked_response_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &pad);
    var info: [c.Nn + "CredentialResponsePad".len]u8 = undefined;
    @memcpy(info[0..c.Nn], &response.masking_nonce);
    @memcpy(info[c.Nn..], "CredentialResponsePad");
    HkdfSha512.expand(&pad, &info, masking_key);

    var clear_masked: [c.masked_response_len]u8 = undefined;
    // clear_masked holds the unmasked server_public_key+envelope; the envelope
    // is public once authenticated, but treat the buffer as secret until done.
    defer std.crypto.secureZero(u8, &clear_masked);
    for (&clear_masked, response.masked_response, pad) |*dst, a, b| dst.* = a ^ b;

    const server_public_key = clear_masked[0..c.Npk].*;
    const envelope = messages.Envelope.fromBytes(clear_masked[c.Npk..][0..c.envelope_len].*) catch return error.InvalidMessage;
    var keys = envelopeKeys(rp, envelope.nonce);
    // All three secret fields of keys (client_private_key, auth_key, export_key)
    // are wiped here. On the SUCCESS return below, `keys.export_key` is copied into
    // the returned struct BEFORE these defers run, so the caller's value is intact;
    // on the error.AuthenticationFailed path the defer wipes the derived export_key
    // too (RFC 9807 Section 4.1.3 MUST: derived intermediates are deleted).
    defer std.crypto.secureZero(u8, &keys.client_private_key);
    defer std.crypto.secureZero(u8, &keys.auth_key);
    defer std.crypto.secureZero(u8, &keys.export_key);
    var client_keypair = try suite.group.deriveDhKeyPair(keys.client_private_key);

    const expected_envelope = try createEnvelope(keys.auth_key, envelope.nonce, server_public_key, client_keypair.pk, server_identity, client_identity);
    if (!crypto.timing_safe.eql([c.Nm]u8, expected_envelope.auth_tag, envelope.auth_tag)) {
        // RFC 9807 Section 4.1.3 MUST: on EnvelopeRecoveryError, the derived
        // intermediates are deleted. The deferred wipes above already cover the
        // KSF/masking material; additionally wipe the derived DH private key
        // before returning so nothing secret survives the failed recovery.
        std.crypto.secureZero(u8, &client_keypair.sk);
        return error.AuthenticationFailed;
    }

    return .{
        // The DH private value: the derived scalar from deriveDhKeyPair, NOT the
        // raw HKDF seed. For curve25519 these are equal (secret_key == seed), but
        // ristretto255 needs the derived scalar for the 3DH computation. The
        // caller (generateKE3) wipes this after the dh3 computation.
        .client_private_key = client_keypair.sk,
        .client_public_key = client_keypair.pk,
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

fn randomizedPassword(suite: Suite, allocator: std.mem.Allocator, oprf_output: [c.Nh]u8, io: ?std.Io) Error![c.Nh]u8 {
    var stretched: [c.Nh]u8 = undefined;
    // Surface OutOfMemory honestly so the WASM layer can map it to its
    // `out_of_memory` status; only genuine misuse becomes InvalidInput.
    // `stretch` already preserves OutOfMemory, so just propagate.
    try suite.ksf.stretch(allocator, &stretched, &oprf_output, io);
    // `stretched` is secret KSF output; the ikm scratch holds both the OPRF
    // output and the stretched value. Wipe both once the randomized password is
    // extracted. RFC 9807 Section 4.1.3.
    defer std.crypto.secureZero(u8, &stretched);
    var ikm: [c.Nh * 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &ikm);
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
    // The per-credential OPRF seed and the derived key pair are long-term-equivalent
    // secrets; wipe the seed scratch after deriving. The returned sk is the value
    // the caller needs, so it is not wiped here (the caller owns its lifetime).
    defer std.crypto.secureZero(u8, &seed);
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
    defer std.crypto.secureZero(u8, &ikm);
    @memcpy(ikm[0..32], dh1);
    @memcpy(ikm[32..64], dh2);
    @memcpy(ikm[64..96], dh3);
    var prk = HkdfSha512.extract("", &ikm);
    defer std.crypto.secureZero(u8, &prk);
    var handshake_secret = deriveSecret(prk, "HandshakeSecret", &preamble_hash);
    defer std.crypto.secureZero(u8, &handshake_secret);
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
