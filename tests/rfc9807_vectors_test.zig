//! Byte-exact RFC 9807 (OPAQUE) test vectors for both AKE groups.
//!
//! These exercise the full registration + login flow against the official
//! Appendix C vectors and assert every protocol output matches the RFC
//! byte-for-byte. Unlike the round-trip tests in opaque_test.zig, these run
//! unconditionally (no oprfRuntimeSupported() skip guard) so a regression in the
//! ristretto255 OPRF or either group's 3DH is a hard FAILURE, not a silent skip.
//!
//! Vector source: https://www.rfc-editor.org/rfc/rfc9807.txt
//!   - C.1.1: OPAQUE-3DH Real Test Vector 1 (Group = ristretto255, no identities)
//!   - C.1.2: OPAQUE-3DH Real Test Vector 2 (Group = ristretto255, identities)
//!   - C.1.3: OPAQUE-3DH Real Test Vector 3 (Group = curve25519, no identities)
//!   - C.1.4: OPAQUE-3DH Real Test Vector 4 (Group = curve25519, identities)
//! All use KSF = Identity, Context = "OPAQUE-POC" (hex 4f50415155452d504f43).
//! C.1.1/C.1.3 carry no client_identity/server_identity (they default to the
//! public keys); C.1.2/C.1.4 set client_identity = "alice" / server_identity =
//! "bob", which exercises the explicit identity-binding code path in
//! finalizeRegistrationRequest / generateKE2 / generateKE3 / serverFinish.
//!
//! RFC hex values wrap across multiple lines; they are concatenated into single
//! string literals here and decoded with std.fmt.hexToBytes.

const std = @import("std");
const root = @import("opaque_root");
const opaque_mod = root.protocol;
const messages = root.messages;

const context = "OPAQUE-POC";

/// Decode a compile-time hex literal into a fixed [N]u8 array. The literal must
/// contain exactly 2*N hex digits (no whitespace; RFC continuation lines are
/// pre-concatenated into the literals below).
fn hx(comptime N: usize, comptime hex: []const u8) [N]u8 {
    comptime {
        if (hex.len != 2 * N) @compileError(std.fmt.comptimePrint(
            "hex literal has {d} chars, expected {d} for [{d}]u8",
            .{ hex.len, 2 * N, N },
        ));
    }
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const c = root.constants;

const Vector = struct {
    group: opaque_mod.Group,

    // Optional explicit identities (C.1.2/C.1.4). When null, the protocol falls
    // back to the public keys (C.1.1/C.1.3). These are passed verbatim to
    // finalize/generateKE2/generateKE3 so the identity-binding transcript path is
    // covered.
    client_identity: ?[]const u8 = null,
    server_identity: ?[]const u8 = null,

    // Input Values
    oprf_seed: [c.Nh]u8,
    credential_identifier: []const u8,
    password: []const u8,
    envelope_nonce: [c.Nn]u8,
    masking_nonce: [c.Nn]u8,
    server_private_key: [c.Nsk]u8,
    server_public_key: [c.Npk]u8,
    server_nonce: [c.Nn]u8,
    client_nonce: [c.Nn]u8,
    client_keyshare_seed: [c.Nseed]u8,
    server_keyshare_seed: [c.Nseed]u8,
    blind_registration: [c.Nsk]u8,
    blind_login: [c.Nsk]u8,

    // Intermediate Values (subset used to localize failures)
    client_public_key: [c.Npk]u8,

    // Output Values
    registration_request: [c.registration_request_len]u8,
    registration_response: [c.registration_response_len]u8,
    registration_upload: [c.registration_record_len]u8,
    ke1: [c.ke1_len]u8,
    ke2: [c.ke2_len]u8,
    ke3: [c.ke3_len]u8,
    export_key: [c.Nh]u8,
    session_key: [c.Nx]u8,
};

fn runVector(v: Vector) !void {
    const allocator = std.testing.allocator;
    const suite = opaque_mod.Suite{
        .context = context,
        .ksf = .identity_test_only,
        .group = v.group,
    };

    // --- Registration ---
    const reg_start = try opaque_mod.createRegistrationRequest(v.password, v.blind_registration);
    try std.testing.expectEqualSlices(u8, &v.registration_request, &reg_start.request.toBytes());

    const reg_response = try opaque_mod.createRegistrationResponse(
        reg_start.request,
        v.server_public_key,
        v.credential_identifier,
        v.oprf_seed,
    );
    try std.testing.expectEqualSlices(u8, &v.registration_response, &reg_response.toBytes());

    // Identity KSF never reads io; pass null (io is ?std.Io). The password is
    // supplied again at finalize (it is no longer carried in the state).
    const reg_finish = try opaque_mod.finalizeRegistrationRequest(
        suite,
        allocator,
        reg_start.state,
        reg_response,
        v.envelope_nonce,
        v.password,
        v.server_identity,
        v.client_identity,
        null,
    );
    // Intermediate localizer: the derived client public key must match before we
    // trust the full record / export key.
    try std.testing.expectEqualSlices(u8, &v.client_public_key, &reg_finish.record.client_public_key);
    try std.testing.expectEqualSlices(u8, &v.registration_upload, &reg_finish.record.toBytes());
    try std.testing.expectEqualSlices(u8, &v.export_key, &reg_finish.export_key);

    // --- Login ---
    const login_start = try opaque_mod.generateKE1(
        suite,
        v.password,
        v.blind_login,
        v.client_nonce,
        v.client_keyshare_seed,
    );
    try std.testing.expectEqualSlices(u8, &v.ke1, &login_start.ke1.toBytes());

    const server_start = try opaque_mod.generateKE2(
        suite,
        v.server_private_key,
        v.server_public_key,
        reg_finish.record,
        v.credential_identifier,
        v.oprf_seed,
        login_start.ke1,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
        v.server_identity,
        v.client_identity,
    );
    try std.testing.expectEqualSlices(u8, &v.ke2, &server_start.ke2.toBytes());

    const login_finish = try opaque_mod.generateKE3(
        suite,
        allocator,
        login_start.state,
        server_start.ke2,
        v.password,
        v.server_identity,
        v.client_identity,
        null,
    );
    try std.testing.expectEqualSlices(u8, &v.ke3, &login_finish.ke3.toBytes());
    try std.testing.expectEqualSlices(u8, &v.session_key, &login_finish.session_key);
    try std.testing.expectEqualSlices(u8, &v.export_key, &login_finish.export_key);

    // --- Server confirms client and derives the same session key ---
    const server_session = try opaque_mod.serverFinish(server_start.state, login_finish.ke3);
    try std.testing.expectEqualSlices(u8, &v.session_key, &server_session);
}

test "RFC 9807 C.1.1 OPAQUE-3DH ristretto255 vector (byte-exact)" {
    try runVector(.{
        .group = .ristretto255,

        .oprf_seed = hx(c.Nh, "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),
        .credential_identifier = &hx(4, "31323334"),
        .password = &hx(25, "436f7272656374486f72736542617474657279537461706c65"),
        .envelope_nonce = hx(c.Nn, "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec"),
        .masking_nonce = hx(c.Nn, "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
        .server_private_key = hx(c.Nsk, "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
        .server_public_key = hx(c.Npk, "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
        .server_nonce = hx(c.Nn, "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
        .client_nonce = hx(c.Nn, "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc"),
        .client_keyshare_seed = hx(c.Nseed, "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b"),
        .server_keyshare_seed = hx(c.Nseed, "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
        .blind_registration = hx(c.Nsk, "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01"),
        .blind_login = hx(c.Nsk, "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),

        .client_public_key = hx(c.Npk, "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675"),

        .registration_request = hx(c.registration_request_len, "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71"),
        .registration_response = hx(c.registration_response_len, "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
        .registration_upload = hx(c.registration_record_len, "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5"),
        .ke1 = hx(c.ke1_len, "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326"),
        .ke2 = hx(c.ke2_len, "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90"),
        .ke3 = hx(c.ke3_len, "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442"),
        .export_key = hx(c.Nh, "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16"),
        .session_key = hx(c.Nx, "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f"),
    });
}

test "RFC 9807 C.1.3 OPAQUE-3DH curve25519 vector (byte-exact)" {
    try runVector(.{
        .group = .curve25519,

        .oprf_seed = hx(c.Nh, "a78342ab84d3d30f08d5a9630c79bf311c31ed7f85d9d4959bf492ec67a0eec8a67dfbf4497248eebd49e878aab173e5e4ff76354288fdd53e949a5f7c9f7f1b"),
        .credential_identifier = &hx(4, "31323334"),
        .password = &hx(25, "436f7272656374486f72736542617474657279537461706c65"),
        .envelope_nonce = hx(c.Nn, "40d6b67fdd7da7c49894750754514dbd2070a407166bd2a5237cca9bf44d6e0b"),
        .masking_nonce = hx(c.Nn, "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
        .server_private_key = hx(c.Nsk, "c06139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d564"),
        .server_public_key = hx(c.Npk, "a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031"),
        .server_nonce = hx(c.Nn, "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
        .client_nonce = hx(c.Nn, "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc"),
        .client_keyshare_seed = hx(c.Nseed, "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b"),
        .server_keyshare_seed = hx(c.Nseed, "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
        .blind_registration = hx(c.Nsk, "c575731ffe1cb0ca5ba63b42c4699767b8b9ab78ba39316ee04baddb2034a70a"),
        .blind_login = hx(c.Nsk, "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),

        .client_public_key = hx(c.Npk, "0936ea94ab030ec332e29050d266c520e916731a052d05ced7e0cfe751142b48"),

        .registration_request = hx(c.registration_request_len, "26f3dbfd76b8e5f85b4da604f42889a7d4b1bc919f655381a67de02c59fd5436"),
        .registration_response = hx(c.registration_response_len, "506e8f1b89c098fb89b5b6210a05f7898cafdaea221761e8d5272fc39e0f9f08a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031"),
        .registration_upload = hx(c.registration_record_len, "0936ea94ab030ec332e29050d266c520e916731a052d05ced7e0cfe751142b486d23c6ed818882f9bdfdcf91389fcbc0b7a3faf92bd0bd6be4a1e7730277b694fc7c6ba327fbe786af18487688e0f7c148bbd54dc2fc80c28e7a976d9ef53c3540d6b67fdd7da7c49894750754514dbd2070a407166bd2a5237cca9bf44d6e0b20c1e81fef28e92e897ca8287d49a55075b47c3988ff0fff367d79a3e350ccac150b4a3ff48b4770c8e84e437b3d4e68d2b95833f7788f7eb93fa6a8afb85ecb"),
        .ke1 = hx(c.ke1_len, "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc10a83b9117d3798cb2957fbdb0268a0d63dbf9d66bde5c00c78affd80026c911"),
        .ke2 = hx(c.ke2_len, "9a0e5a1514f62e005ea098b0d8cf6750e358c4389e6add1c52aed9500fa19d0038fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d22cc31127d6f0096755be3c3d2dd6287795c317aeea10c9485bf4f419a786642c19a8f151ceb5e8767d175248c62c017de94057398d28bf0ed00d1b50ee4f812fd9afddf98af8cd58067ca43b0633b6cadd0e9d987f89623fed4d3583bdf6910c425600e90dab3c6b3513188a465461a67f6bbc47aeba808f7f7e2c6d66f5c3271cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a141f55f0bef355cfb34ccd468fdacad75865ee7efef95f4cb6c25d477f720502676f06a3b806da262139bf3fa76a1090b94dac78bc3bc6f8747d5b35acf94eff3ec2ebe7d49b8cf16be64120b279fe92664e47be5da7e60f08f12e91192652f79"),
        .ke3 = hx(c.ke3_len, "550e923829a544496d8316c490da2b979b78c730dd75be3a17f237a26432c19fbba54b6a0467b1c22ecbd6794bc5fa5b04215ba1ef974c6b090baa42c5bb984f"),
        .export_key = hx(c.Nh, "9dec51d6d0f6ce7e4345f10961053713b07310cc2e45872f57bbd2fe5070fdf0fb5b77c7ddaa2f3dc5c35132df7417ad7fefe0f690ad266e5a54a21d045c9c38"),
        .session_key = hx(c.Nx, "fd2fdd07c1bcc88e81c1b1d1de5ad62dfdef1c0b8209ff9d671e1fac55ce9c34d381c1fb2703ff53a797f77daccbe33047ccc167b8105171e10ec962eea203aa"),
    });
}

test "RFC 9807 C.1.2 OPAQUE-3DH ristretto255 vector with identities (byte-exact)" {
    // Same group/keys/blinds as C.1.1, but with explicit client_identity ("alice")
    // and server_identity ("bob"). The identities feed the envelope / auth
    // transcript, so the registration_upload, KE2, KE3, and session_key differ
    // from C.1.1 even though the registration_request/response and KE1 match.
    try runVector(.{
        .group = .ristretto255,

        .client_identity = &hx(5, "616c696365"),
        .server_identity = &hx(3, "626f62"),

        .oprf_seed = hx(c.Nh, "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),
        .credential_identifier = &hx(4, "31323334"),
        .password = &hx(25, "436f7272656374486f72736542617474657279537461706c65"),
        .envelope_nonce = hx(c.Nn, "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec"),
        .masking_nonce = hx(c.Nn, "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
        .server_private_key = hx(c.Nsk, "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
        .server_public_key = hx(c.Npk, "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
        .server_nonce = hx(c.Nn, "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
        .client_nonce = hx(c.Nn, "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc"),
        .client_keyshare_seed = hx(c.Nseed, "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b"),
        .server_keyshare_seed = hx(c.Nseed, "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
        .blind_registration = hx(c.Nsk, "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01"),
        .blind_login = hx(c.Nsk, "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),

        .client_public_key = hx(c.Npk, "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675"),

        .registration_request = hx(c.registration_request_len, "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71"),
        .registration_response = hx(c.registration_response_len, "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
        .registration_upload = hx(c.registration_record_len, "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b680b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c"),
        .ke1 = hx(c.ke1_len, "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326"),
        .ke2 = hx(c.ke2_len, "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fea502150b67fe36795dd8914f164e49f81c7688a38928372134b7dccd50e09f8fed9518b7b2f94835b3c4fe4c8475e7513f20eb97ff0568a39caee3fd6251876f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a292371e7809a9031743e943fb3b56f51de903552fc91fba4e7419029951c3970b2e2f0a9dea218d22e9e4e0000855bb6421aa3610d6fc0f4033a6517030d4341"),
        .ke3 = hx(c.ke3_len, "7a026de1d6126905736c3f6d92463a08d209833eb793e46d0f7f15b3e0f62c7643763c02bbc6b8d3d15b63250cae98171e9260f1ffa789750f534ac11a0176d5"),
        .export_key = hx(c.Nh, "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16"),
        .session_key = hx(c.Nx, "ae7951123ab5befc27e62e63f52cf472d6236cb386c968cc47b7e34f866aa4bc7638356a73cfce92becf39d6a7d32a1861f12130e824241fe6cab34fbd471a57"),
    });
}

test "RFC 9807 C.1.4 OPAQUE-3DH curve25519 vector with identities (byte-exact)" {
    // curve25519 group WITH explicit client_identity ("alice") and
    // server_identity ("bob"). This is the only vector that exercises the
    // identity-binding path on the curve25519 3DH (C.1.3 has no identities).
    try runVector(.{
        .group = .curve25519,

        .client_identity = &hx(5, "616c696365"),
        .server_identity = &hx(3, "626f62"),

        .oprf_seed = hx(c.Nh, "a78342ab84d3d30f08d5a9630c79bf311c31ed7f85d9d4959bf492ec67a0eec8a67dfbf4497248eebd49e878aab173e5e4ff76354288fdd53e949a5f7c9f7f1b"),
        .credential_identifier = &hx(4, "31323334"),
        .password = &hx(25, "436f7272656374486f72736542617474657279537461706c65"),
        .envelope_nonce = hx(c.Nn, "40d6b67fdd7da7c49894750754514dbd2070a407166bd2a5237cca9bf44d6e0b"),
        .masking_nonce = hx(c.Nn, "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
        .server_private_key = hx(c.Nsk, "c06139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d564"),
        .server_public_key = hx(c.Npk, "a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031"),
        .server_nonce = hx(c.Nn, "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
        .client_nonce = hx(c.Nn, "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc"),
        .client_keyshare_seed = hx(c.Nseed, "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b"),
        .server_keyshare_seed = hx(c.Nseed, "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
        .blind_registration = hx(c.Nsk, "c575731ffe1cb0ca5ba63b42c4699767b8b9ab78ba39316ee04baddb2034a70a"),
        .blind_login = hx(c.Nsk, "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),

        .client_public_key = hx(c.Npk, "0936ea94ab030ec332e29050d266c520e916731a052d05ced7e0cfe751142b48"),

        .registration_request = hx(c.registration_request_len, "26f3dbfd76b8e5f85b4da604f42889a7d4b1bc919f655381a67de02c59fd5436"),
        .registration_response = hx(c.registration_response_len, "506e8f1b89c098fb89b5b6210a05f7898cafdaea221761e8d5272fc39e0f9f08a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031"),
        .registration_upload = hx(c.registration_record_len, "0936ea94ab030ec332e29050d266c520e916731a052d05ced7e0cfe751142b486d23c6ed818882f9bdfdcf91389fcbc0b7a3faf92bd0bd6be4a1e7730277b694fc7c6ba327fbe786af18487688e0f7c148bbd54dc2fc80c28e7a976d9ef53c3540d6b67fdd7da7c49894750754514dbd2070a407166bd2a5237cca9bf44d6e0bb4c0eab6143959a650c5f6b32acf162b1fbe95bb36c5c4f99df53865c4d3537d69061d80522d772cd0efdbe91f817f6bf7259a56e20b4eb9cbe9443702f4b759"),
        .ke1 = hx(c.ke1_len, "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc10a83b9117d3798cb2957fbdb0268a0d63dbf9d66bde5c00c78affd80026c911"),
        .ke2 = hx(c.ke2_len, "9a0e5a1514f62e005ea098b0d8cf6750e358c4389e6add1c52aed9500fa19d0038fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d22cc31127d6f0096755be3c3d2dd6287795c317aeea10c9485bf4f419a786642c19a8f151ceb5e8767d175248c62c017de94057398d28bf0ed00d1b50ee4f812699bff7663be3c5d59de94d8e7e58817c7da005b39c25d25555c929e1c5cf6c1b82837b1367c839aab56a422c0d97719426a79a16f9869cf852100597b23b5a071cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a141f55f0bef355cfb34ccd468fdacad75865ee7efef95f4cb6c25d477f72050267cc22c87edbf3ecaca64cb33bc60dc3bfc551e365f0d46a7fed0e09d96f9afbb48868f5bb3c3e05a86ed8c9476fc22c58306c5a291be34388e09548ba9d70f39"),
        .ke3 = hx(c.ke3_len, "d16344e791c3f18594d22ba068984fa18ec1e9bead662b75f66826ffd627932fcd1ec40cd01dcf5f63f4055ebe45c7717a57a833aad360256cf1e1c20c0eae1c"),
        .export_key = hx(c.Nh, "9dec51d6d0f6ce7e4345f10961053713b07310cc2e45872f57bbd2fe5070fdf0fb5b77c7ddaa2f3dc5c35132df7417ad7fefe0f690ad266e5a54a21d045c9c38"),
        .session_key = hx(c.Nx, "f6116d3aa0e4089a179713bad4d98ed5cb57e5443cae8d36ef78996fa60f3dc6e9fcdd63c001596b06dbc1285d80211035cc0e485506b3f7a650cbf78c5bffc9"),
    });
}
