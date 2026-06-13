//! Native Zig OPAQUE CLI.
//!
//! Registers and authenticates against the full-stack OPAQUE HTTP server using
//! the sibling `opaque-zig` library. See ../protocol.md for the exact wire
//! contract (endpoints, base64, crypto config, and the SESSION_KEY proof line).
//!
//! Usage:
//!   opaque-cli register <username> <password>
//!   opaque-cli login    <username> <password>
//!
//! Server base URL comes from the env var OPAQUE_SERVER (default
//! http://127.0.0.1:8787).

const std = @import("std");
const opaque_lib = @import("opaque");

const protocol = opaque_lib.protocol;
const messages = opaque_lib.messages;

/// The single suite shared by every component of the full-stack demo. The
/// `context` MUST be set (it defaults to "" in the library) and MUST match the
/// server byte-for-byte, or the KE2/KE3 MACs silently fail. group + ksf already
/// equal the library defaults; we spell them out for clarity / future-proofing.
const suite = protocol.Suite{
    .group = .ristretto255,
    .context = "opaque-zig-fullstack-v1",
    .ksf = .{ .argon2id = protocol.argon2id_owasp },
};

const default_server = "http://127.0.0.1:8787";

const b64 = std.base64.standard;

const CliError = error{
    Usage,
    HttpStatus,
    BadResponse,
    AuthFailed,
};

/// Adapts an `std.Io` into a `std.Random` whose fill draws from the platform
/// CSPRNG (`io.random`). The library's `*Random` entry points take a
/// `std.Random` and pull all blinds/nonces/seeds from it; this routes every
/// requested byte straight to the OS secure RNG. (`std.crypto.random` was
/// removed in this Zig version; randomness now flows through `std.Io`.)
const IoRandom = struct {
    io: std.Io,

    fn fill(self: *IoRandom, buf: []u8) void {
        self.io.random(buf);
    }

    fn random(self: *IoRandom) std.Random {
        return std.Random.init(self, fill);
    }
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Collect args into a slice for simple positional access.
    var args_list = std.ArrayList([]const u8).empty;
    var it = init.minimal.args.iterate();
    while (it.next()) |a| try args_list.append(arena, a);
    const args = args_list.items;

    if (args.len < 4) {
        try usage();
        return 2;
    }
    const command = args[1];
    const username = args[2];
    const password = args[3];

    const server = init.environ_map.get("OPAQUE_SERVER") orelse default_server;

    if (std.mem.eql(u8, command, "register")) {
        // doRegister reports its own failures (HTTP/connection errors are
        // printed by httpPost); convert any error into a clean non-zero exit so
        // the user does not see a noisy error-return-trace dump.
        doRegister(gpa, io, arena, server, username, password) catch return 1;
        return 0;
    } else if (std.mem.eql(u8, command, "login")) {
        doLogin(gpa, io, arena, server, username, password) catch |err| switch (err) {
            error.AuthFailed => {
                try printErr(io, "login failed: not authenticated\n", .{});
                return 1;
            },
            else => return 1, // already reported at the failure site
        };
        return 0;
    } else {
        try usage();
        return 2;
    }
}

fn usage() !void {
    try printErrRaw(
        \\usage:
        \\  opaque-cli register <username> <password>
        \\  opaque-cli login    <username> <password>
        \\
        \\Server base URL from $OPAQUE_SERVER (default http://127.0.0.1:8787).
        \\
    );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn doRegister(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    server: []const u8,
    username: []const u8,
    password: []const u8,
) !void {
    var io_rand = IoRandom{ .io = io };
    const random = io_rand.random();

    // 1. start: build the registration request.
    const reg = try protocol.createRegistrationRequestRandom(random, password);
    const request_bytes = reg.request.toBytes();
    std.debug.assert(request_bytes.len == 32);

    // POST /register/start { username, registration_request }
    const start_body = try jsonObject(arena, &.{
        .{ .key = "username", .value = username },
        .{ .key = "registration_request", .value = try b64Encode(arena, &request_bytes) },
    });
    const start_resp = try httpPost(gpa, io, arena, server, "/register/start", start_body);
    const reg_resp_b64 = try jsonGetString(arena, start_resp, "registration_response");
    const reg_resp_bytes = try b64DecodeExact(arena, reg_resp_b64, messages.RegistrationResponse);
    const reg_response = try messages.RegistrationResponse.parse(reg_resp_bytes);

    // 2. finish: derive the record (argon2id KSF runs here, ~19 MiB).
    var finish = try protocol.finalizeRegistrationRequestRandom(
        suite,
        gpa,
        random,
        reg.state,
        reg_response,
        password,
        null, // server_identity -> default to server public key
        null, // client_identity -> default to client public key
        null, // io: argon2id_owasp is p=1, so null is valid
    );
    defer finish.wipe();
    const record_bytes = finish.record.toBytes();
    std.debug.assert(record_bytes.len == 192);

    // POST /register/finish { username, registration_record }
    const finish_body = try jsonObject(arena, &.{
        .{ .key = "username", .value = username },
        .{ .key = "registration_record", .value = try b64Encode(arena, &record_bytes) },
    });
    _ = try httpPost(gpa, io, arena, server, "/register/finish", finish_body);

    try printOut(io, "registered {s}\n", .{username});
}

fn doLogin(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    server: []const u8,
    username: []const u8,
    password: []const u8,
) !void {
    var io_rand = IoRandom{ .io = io };
    const random = io_rand.random();

    // 1. KE1
    var login = try protocol.generateKE1Random(suite, random, password);
    defer login.state.wipe();
    const ke1_bytes = login.ke1.toBytes();
    std.debug.assert(ke1_bytes.len == 96);

    // POST /login/start { username, ke1 } -> { login_id, ke2 }
    const start_body = try jsonObject(arena, &.{
        .{ .key = "username", .value = username },
        .{ .key = "ke1", .value = try b64Encode(arena, &ke1_bytes) },
    });
    const start_resp = try httpPost(gpa, io, arena, server, "/login/start", start_body);
    const login_id = try jsonGetString(arena, start_resp, "login_id");
    const ke2_b64 = try jsonGetString(arena, start_resp, "ke2");
    const ke2_bytes = try b64DecodeExact(arena, ke2_b64, messages.KE2);
    const ke2 = try messages.KE2.parse(ke2_bytes);

    // 2. KE3 + session key. AuthenticationFailed here means wrong password,
    // a fake (unknown-user) record, or tampering -- a single opaque failure.
    var finish = protocol.generateKE3(
        suite,
        gpa,
        login.state,
        ke2,
        password,
        null,
        null,
        null,
    ) catch |err| switch (err) {
        error.AuthenticationFailed => return error.AuthFailed,
        else => return err,
    };
    defer finish.wipe();
    const ke3_bytes = finish.ke3.toBytes();
    std.debug.assert(ke3_bytes.len == 64);

    // POST /login/finish { login_id, ke3 } -> 200 {authenticated:true} / 401
    const finish_body = try jsonObject(arena, &.{
        .{ .key = "login_id", .value = login_id },
        .{ .key = "ke3", .value = try b64Encode(arena, &ke3_bytes) },
    });
    const finish_resp = httpPost(gpa, io, arena, server, "/login/finish", finish_body) catch |err| switch (err) {
        // A 401 from /login/finish is the server rejecting the MAC -> not authed.
        error.HttpStatus => return error.AuthFailed,
        else => return err,
    };
    const authed = jsonGetBool(arena, finish_resp, "authenticated") catch false;
    if (!authed) return error.AuthFailed;

    // Proof line: lowercase hex of the 64-byte session key, to stdout.
    var hex_buf: [2 * 64]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{&finish.session_key}) catch unreachable;
    try printOut(io, "SESSION_KEY {s} {s}\n", .{ username, hex });
}

// ---------------------------------------------------------------------------
// HTTP (std.http.Client)
// ---------------------------------------------------------------------------

/// POST `body` as application/json to `server` + `path`. Returns the response
/// body (arena-owned). Non-2xx status -> error.HttpStatus (the caller maps a
/// 401 on /login/finish to a clean auth failure).
fn httpPost(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    server: []const u8,
    path: []const u8,
    body: []const u8,
) ![]const u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    const url = try std.fmt.allocPrint(arena, "{s}{s}", .{ server, path });

    var response_buf = std.Io.Writer.Allocating.init(arena);
    defer response_buf.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
        },
        .response_writer = &response_buf.writer,
    }) catch |err| {
        try printErr(io, "http request to {s} failed: {t}\n", .{ url, err });
        return err;
    };

    const status_code = @intFromEnum(result.status);
    if (status_code < 200 or status_code >= 300) {
        try printErr(io, "server returned {d} for {s}: {s}\n", .{
            status_code, path, response_buf.written(),
        });
        return error.HttpStatus;
    }

    return try arena.dupe(u8, response_buf.written());
}

// ---------------------------------------------------------------------------
// JSON helpers (small, known shapes)
// ---------------------------------------------------------------------------

const KV = struct { key: []const u8, value: []const u8 };

/// Serialize a flat object of string->string pairs to a JSON document.
fn jsonObject(arena: std.mem.Allocator, pairs: []const KV) ![]const u8 {
    var w = std.Io.Writer.Allocating.init(arena);
    errdefer w.deinit();
    var s = std.json.Stringify{ .writer = &w.writer, .options = .{} };
    try s.beginObject();
    for (pairs) |kv| {
        try s.objectField(kv.key);
        try s.write(kv.value);
    }
    try s.endObject();
    return w.toOwnedSlice();
}

fn jsonGetString(arena: std.mem.Allocator, body: []const u8, field: []const u8) ![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch return error.BadResponse;
    const v = parsed.value.object.get(field) orelse return error.BadResponse;
    return switch (v) {
        .string => |str| try arena.dupe(u8, str),
        else => error.BadResponse,
    };
}

fn jsonGetBool(arena: std.mem.Allocator, body: []const u8, field: []const u8) !bool {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch return error.BadResponse;
    const v = parsed.value.object.get(field) orelse return error.BadResponse;
    return switch (v) {
        .bool => |x| x,
        else => error.BadResponse,
    };
}

// ---------------------------------------------------------------------------
// base64 helpers
// ---------------------------------------------------------------------------

fn b64Encode(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const out = try arena.alloc(u8, b64.Encoder.calcSize(bytes.len));
    return b64.Encoder.encode(out, bytes);
}

/// Decode standard-base64 `text` into an arena-owned slice sized to the exact
/// decoded length. The caller passes the message type `T` only for intent;
/// the wire length is validated by `T.parse` at the call site.
fn b64DecodeExact(arena: std.mem.Allocator, text: []const u8, comptime T: type) ![]u8 {
    _ = T; // length is validated by T.parse at the call site
    const n = b64.Decoder.calcSizeForSlice(text) catch return error.BadResponse;
    const buf = try arena.alloc(u8, n);
    b64.Decoder.decode(buf, text) catch return error.BadResponse;
    return buf;
}

// ---------------------------------------------------------------------------
// stdout / stderr
// ---------------------------------------------------------------------------

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const w = &fw.interface;
    try w.print(fmt, args);
    try w.flush();
}

fn printErr(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [1024]u8 = undefined;
    var fw = std.Io.File.stderr().writer(io, &buf);
    const w = &fw.interface;
    try w.print(fmt, args);
    try w.flush();
}

/// Stderr write that does not require an `Io` (used by `usage`, which runs
/// before we thread `io` through). Uses the single-threaded io value, which is
/// valid for a plain blocking stderr write.
fn printErrRaw(comptime text: []const u8) !void {
    var threaded = std.Io.Threaded.init_single_threaded;
    const io = threaded.io();
    try printErr(io, "{s}", .{text});
}

// ===========================================================================
// In-process acceptance test: full register -> login round trip using the
// library's own server functions, asserting the client and server derive the
// SAME 64-byte session key (the OPAQUE mutual-auth guarantee). No HTTP / server.
// ===========================================================================

test "in-process OPAQUE round trip: client session key == server session key" {
    const allocator = std.testing.allocator;
    var io_rand = IoRandom{ .io = std.testing.io };
    const random = io_rand.random();

    const username = "alice@example.com";
    const password = "correct horse battery staple";

    // --- Server long-term setup -------------------------------------------
    // A long-term OPRF seed (Nh = 64 bytes) and a server AKE keypair derived
    // from a 32-byte seed via the suite's group (ristretto255).
    var oprf_seed: [opaque_lib.constants.Nh]u8 = undefined;
    random.bytes(&oprf_seed);
    var server_seed: [opaque_lib.constants.Nseed]u8 = undefined;
    random.bytes(&server_seed);
    const server_kp = try suite.group.deriveDhKeyPair(server_seed);
    const server_private_key = server_kp.sk;
    const server_public_key = server_kp.pk;

    // credential_identifier = the UTF-8 bytes of the username (per contract).
    const credential_identifier: []const u8 = username;

    // --- Registration ------------------------------------------------------
    const reg = try protocol.createRegistrationRequestRandom(random, password);
    try std.testing.expectEqual(@as(usize, 32), reg.request.toBytes().len);

    const reg_response = try protocol.createRegistrationResponse(
        reg.request,
        server_public_key,
        credential_identifier,
        oprf_seed,
    );
    try std.testing.expectEqual(@as(usize, 64), reg_response.toBytes().len);

    var reg_finish = try protocol.finalizeRegistrationRequestRandom(
        suite,
        allocator,
        random,
        reg.state,
        reg_response,
        password,
        null,
        null,
        null,
    );
    defer reg_finish.wipe();
    const record_bytes = reg_finish.record.toBytes();
    try std.testing.expectEqual(@as(usize, 192), record_bytes.len);

    // Round-trip the record through bytes (as the server would, receiving it
    // over the wire) to exercise parse/serialize too.
    const record = try messages.RegistrationRecord.parse(&record_bytes);

    // --- Login: client KE1 -------------------------------------------------
    var login = try protocol.generateKE1Random(suite, random, password);
    defer login.state.wipe();
    const ke1_bytes = login.ke1.toBytes();
    try std.testing.expectEqual(@as(usize, 96), ke1_bytes.len);
    const ke1 = try messages.KE1.parse(&ke1_bytes);

    // --- Login: server KE2 -------------------------------------------------
    var masking_nonce: [opaque_lib.constants.Nn]u8 = undefined;
    random.bytes(&masking_nonce);
    var server_nonce: [opaque_lib.constants.Nn]u8 = undefined;
    random.bytes(&server_nonce);
    var server_keyshare_seed: [opaque_lib.constants.Nseed]u8 = undefined;
    random.bytes(&server_keyshare_seed);

    var server_start = try protocol.generateKE2(
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
        null,
        null,
    );
    defer server_start.wipe();
    const ke2_bytes = server_start.ke2.toBytes();
    try std.testing.expectEqual(@as(usize, 320), ke2_bytes.len);
    const ke2 = try messages.KE2.parse(&ke2_bytes);

    // --- Login: client KE3 + session key -----------------------------------
    var client_finish = try protocol.generateKE3(
        suite,
        allocator,
        login.state,
        ke2,
        password,
        null,
        null,
        null,
    );
    defer client_finish.wipe();
    const ke3_bytes = client_finish.ke3.toBytes();
    try std.testing.expectEqual(@as(usize, 64), ke3_bytes.len);
    try std.testing.expectEqual(@as(usize, 64), client_finish.session_key.len);
    const ke3 = try messages.KE3.parse(&ke3_bytes);

    // --- Server finish: confirm MAC, get the confirmed session key ---------
    const server_session_key = try protocol.serverFinish(server_start.state, ke3);

    // THE assertion: both sides agree on the session key, byte-for-byte.
    try std.testing.expectEqualSlices(u8, &client_finish.session_key, &server_session_key);
}

test "in-process OPAQUE: wrong password fails authentication (no key agreement)" {
    const allocator = std.testing.allocator;

    const username = "bob@example.com";
    const password = "hunter2";
    const wrong_password = "hunter3";

    var io_rand = IoRandom{ .io = std.testing.io };
    const random = io_rand.random();

    var oprf_seed: [opaque_lib.constants.Nh]u8 = undefined;
    random.bytes(&oprf_seed);
    var server_seed: [opaque_lib.constants.Nseed]u8 = undefined;
    random.bytes(&server_seed);
    const server_kp = try suite.group.deriveDhKeyPair(server_seed);
    const credential_identifier: []const u8 = username;

    const reg = try protocol.createRegistrationRequestRandom(random, password);
    const reg_response = try protocol.createRegistrationResponse(reg.request, server_kp.pk, credential_identifier, oprf_seed);
    var reg_finish = try protocol.finalizeRegistrationRequestRandom(suite, allocator, random, reg.state, reg_response, password, null, null, null);
    defer reg_finish.wipe();
    const record = reg_finish.record;

    // Log in with the WRONG password.
    var login = try protocol.generateKE1Random(suite, random, wrong_password);
    defer login.state.wipe();

    var server_start = try protocol.generateKE2Random(suite, random, server_kp.sk, server_kp.pk, record, credential_identifier, oprf_seed, login.ke1, null, null);
    defer server_start.wipe();

    // The client detects the bad server MAC first (it recovered a garbage
    // envelope from the wrong password) -> AuthenticationFailed.
    try std.testing.expectError(error.AuthenticationFailed, protocol.generateKE3(suite, allocator, login.state, server_start.ke2, wrong_password, null, null, null));
}
