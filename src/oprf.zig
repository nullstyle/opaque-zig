const std = @import("std");

const Sha512 = std.crypto.hash.sha2.Sha512;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Curve = Ristretto255.Curve;
const Fe = Ristretto255.Fe;
const ScalarOps = Ristretto255.scalar;

pub const mode_oprf: u8 = 0x00;
pub const modeOPRF: u8 = mode_oprf;
pub const identifier = "ristretto255-SHA512";
pub const context_string = "OPRFV1-" ++ [_]u8{mode_oprf} ++ "-" ++ identifier;

pub const scalar_length = 32;
pub const element_length = 32;
pub const output_length = Sha512.digest_length;
pub const seed_length = 32;
pub const random_scalar_uniform_length = 64;

pub const Scalar = [scalar_length]u8;
pub const SerializedElement = [element_length]u8;
pub const Output = [output_length]u8;
pub const Seed = [seed_length]u8;
pub const Element = Ristretto255;

pub const Error = error{
    DeriveKeyPairError,
    DeserializeError,
    InputTooLong,
    InvalidInput,
    InvalidScalar,
    ZeroScalar,
};

pub const KeyPair = struct {
    sk: Scalar,
    pk: Element,

    pub fn serializedPublicKey(self: KeyPair) SerializedElement {
        return serializeElement(self.pk);
    }
};

pub const BlindResult = struct {
    blind: Scalar,
    blinded_element: Element,

    pub fn serializedBlindedElement(self: BlindResult) SerializedElement {
        return serializeElement(self.blinded_element);
    }
};

pub fn createContextString() []const u8 {
    return context_string;
}

pub fn deriveKeyPair(seed: Seed, info: []const u8) Error!KeyPair {
    try requireU16Length(info);

    var info_len: [2]u8 = undefined;
    writeU16(&info_len, info.len);

    var counter: u16 = 0;
    while (counter <= 255) : (counter += 1) {
        const counter_byte = [_]u8{@intCast(counter)};
        const parts = [_][]const u8{ seed[0..], info_len[0..], info, counter_byte[0..] };
        const sk = hashToScalarWithDstParts(&parts, "DeriveKeyPair" ++ context_string);
        if (!isZeroScalar(sk)) {
            const pk = scalarMultGenerator(sk) catch return error.InvalidScalar;
            return .{ .sk = sk, .pk = pk };
        }
    }

    return error.DeriveKeyPairError;
}

pub fn DeriveKeyPair(seed: Seed, info: []const u8) Error!KeyPair {
    return deriveKeyPair(seed, info);
}

pub fn blindWithScalar(input: []const u8, blind: Scalar) Error!BlindResult {
    try requireU16Length(input);
    try validateNonZeroScalar(blind);

    const input_element = try hashToGroup(input);
    const blinded_element = input_element.mul(blind) catch return error.InvalidInput;
    return .{ .blind = blind, .blinded_element = blinded_element };
}

pub fn Blind(input: []const u8, blind: Scalar) Error!BlindResult {
    return blindWithScalar(input, blind);
}

pub fn blindWithRandomBytes(input: []const u8, uniform_bytes: [random_scalar_uniform_length]u8) Error!BlindResult {
    const blind = try randomScalarFromUniformBytes(uniform_bytes);
    return blindWithScalar(input, blind);
}

pub fn BlindWithRandomBytes(input: []const u8, uniform_bytes: [random_scalar_uniform_length]u8) Error!BlindResult {
    return blindWithRandomBytes(input, uniform_bytes);
}

pub fn randomScalarFromIo(io: std.Io) Scalar {
    return ScalarOps.random(io);
}

pub fn blindEvaluate(sk: Scalar, blinded_element: Element) Error!Element {
    try validateNonZeroScalar(sk);
    return blinded_element.mul(sk) catch return error.InvalidInput;
}

pub fn BlindEvaluate(sk: Scalar, blinded_element: Element) Error!Element {
    return blindEvaluate(sk, blinded_element);
}

pub fn finalize(input: []const u8, blind: Scalar, evaluated_element: Element) Error!Output {
    try requireU16Length(input);
    try validateNonZeroScalar(blind);

    const inverse = invertScalar(blind);
    const unblinded = evaluated_element.mul(inverse) catch return error.InvalidInput;
    const unblinded_bytes = serializeElement(unblinded);

    var h = Sha512.init(.{});
    hashLengthPrefixed(&h, input);
    hashLengthPrefixed(&h, &unblinded_bytes);
    h.update("Finalize");

    var out: Output = undefined;
    h.final(&out);
    return out;
}

pub fn Finalize(input: []const u8, blind: Scalar, evaluated_element: Element) Error!Output {
    return finalize(input, blind, evaluated_element);
}

pub fn evaluate(sk: Scalar, input: []const u8) Error!Output {
    try requireU16Length(input);
    try validateNonZeroScalar(sk);

    const input_element = try hashToGroup(input);
    const evaluated = input_element.mul(sk) catch return error.InvalidInput;
    const evaluated_bytes = serializeElement(evaluated);

    var h = Sha512.init(.{});
    hashLengthPrefixed(&h, input);
    hashLengthPrefixed(&h, &evaluated_bytes);
    h.update("Finalize");

    var out: Output = undefined;
    h.final(&out);
    return out;
}

pub fn Evaluate(sk: Scalar, input: []const u8) Error!Output {
    return evaluate(sk, input);
}

pub fn hashToGroup(input: []const u8) Error!Element {
    try requireU16Length(input);

    var uniform: [64]u8 = undefined;
    expandMessageXmd(&uniform, input, "HashToGroup-" ++ context_string) catch return error.InvalidInput;
    const element = fromUniformCompat(uniform);
    element.rejectIdentity() catch return error.InvalidInput;
    return element;
}

pub fn HashToGroup(input: []const u8) Error!Element {
    return hashToGroup(input);
}

pub fn hashToScalar(input: []const u8) Scalar {
    return hashToScalarWithDst(input, "HashToScalar-" ++ context_string);
}

pub fn HashToScalar(input: []const u8) Scalar {
    return hashToScalar(input);
}

pub fn randomScalarFromUniformBytes(uniform_bytes: [random_scalar_uniform_length]u8) Error!Scalar {
    const scalar = reduceUniformScalar(uniform_bytes);
    if (isZeroScalar(scalar)) return error.ZeroScalar;
    return scalar;
}

pub fn serializeElement(element: Element) SerializedElement {
    return element.toBytes();
}

pub fn SerializeElement(element: Element) SerializedElement {
    return serializeElement(element);
}

pub fn deserializeElement(bytes: SerializedElement) Error!Element {
    const element = Ristretto255.fromBytes(bytes) catch return error.DeserializeError;
    element.rejectIdentity() catch return error.DeserializeError;
    return element;
}

pub fn DeserializeElement(bytes: SerializedElement) Error!Element {
    return deserializeElement(bytes);
}

pub fn serializeScalar(scalar: Scalar) Scalar {
    return scalar;
}

pub fn SerializeScalar(scalar: Scalar) Scalar {
    return serializeScalar(scalar);
}

pub fn deserializeScalar(bytes: Scalar) Error!Scalar {
    ScalarOps.rejectNonCanonical(bytes) catch return error.DeserializeError;
    return bytes;
}

pub fn DeserializeScalar(bytes: Scalar) Error!Scalar {
    return deserializeScalar(bytes);
}

fn scalarMultGenerator(scalar: Scalar) !Element {
    return Ristretto255.basePoint.mul(scalar);
}

fn validateNonZeroScalar(scalar: Scalar) Error!void {
    _ = try deserializeScalar(scalar);
    if (isZeroScalar(scalar)) return error.ZeroScalar;
}

fn isZeroScalar(scalar: Scalar) bool {
    var acc: u8 = 0;
    for (scalar) |b| acc |= b;
    return acc == 0;
}

fn hashToScalarWithDst(input: []const u8, comptime dst: []const u8) Scalar {
    return hashToScalarWithDstParts(&[_][]const u8{input}, dst);
}

fn hashToScalarWithDstParts(parts: []const []const u8, comptime dst: []const u8) Scalar {
    var uniform: [64]u8 = undefined;
    expandMessageXmdParts(&uniform, parts, dst) catch unreachable;
    return reduceUniformScalar(uniform);
}

fn reduceUniformScalar(uniform: [64]u8) Scalar {
    const value = std.mem.readInt(u512, &uniform, .little);
    const reduced: u256 = @intCast(value % ScalarOps.field_order);
    var out: Scalar = undefined;
    std.mem.writeInt(u256, &out, reduced, .little);
    return out;
}

fn scalarToInt(scalar: Scalar) u256 {
    return std.mem.readInt(u256, &scalar, .little);
}

fn intToScalar(n: u256) Scalar {
    var out: Scalar = undefined;
    std.mem.writeInt(u256, &out, n, .little);
    return out;
}

fn invertScalar(scalar: Scalar) Scalar {
    const order = ScalarOps.field_order;
    var base = scalarToInt(scalar);
    var exponent = order - 2;
    var result: u256 = 1;
    while (exponent != 0) : (exponent >>= 1) {
        if ((exponent & 1) == 1) result = modMul(result, base);
        base = modMul(base, base);
    }
    return intToScalar(result);
}

fn modMul(a: u256, b: u256) u256 {
    return @intCast((@as(u512, a) * @as(u512, b)) % ScalarOps.field_order);
}

fn fromUniformCompat(h: [64]u8) Ristretto255 {
    const p0 = elligator(Fe.fromBytes(h[0..32].*));
    const p1 = elligator(Fe.fromBytes(h[32..64].*));
    return Ristretto255{ .p = p0.add(p1) };
}

fn sqrtRatioM1(u: Fe, v: Fe) struct { ratio_is_square: u32, root: Fe } {
    const v3 = v.sq().mul(v);
    var x = v3.sq().mul(u).mul(v).pow2523().mul(v3).mul(u);
    const vxx = x.sq().mul(v);
    const m_root_check = vxx.sub(u);
    const p_root_check = vxx.add(u);
    const f_root_check = u.mul(Fe.sqrtm1).add(vxx);
    const has_m_root = m_root_check.isZero();
    const has_p_root = p_root_check.isZero();
    const has_f_root = f_root_check.isZero();
    const x_sqrtm1 = x.mul(Fe.sqrtm1);
    x.cMov(x_sqrtm1, @intFromBool(has_p_root) | @intFromBool(has_f_root));
    return .{ .ratio_is_square = @intFromBool(has_m_root) | @intFromBool(has_p_root), .root = x.abs() };
}

fn elligator(t: Fe) Curve {
    const r = t.sq().mul(Fe.sqrtm1);
    const u = r.add(Fe.one).mul(Fe.edwards25519eonemsqd);
    var c = comptime Fe.one.neg();
    const v = c.sub(r.mul(Fe.edwards25519d)).mul(r.add(Fe.edwards25519d));
    const ratio_sqrt = sqrtRatioM1(u, v);
    const wasnt_square = 1 - ratio_sqrt.ratio_is_square;
    var s = ratio_sqrt.root;
    const s_prime = s.mul(t).abs().neg();
    s.cMov(s_prime, wasnt_square);
    c.cMov(r, wasnt_square);

    const n = r.sub(Fe.one).mul(c).mul(Fe.edwards25519sqdmone).sub(v);
    const w0 = s.add(s).mul(v);
    const w1 = n.mul(Fe.edwards25519sqrtadm1);
    const ss = s.sq();
    const w2 = Fe.one.sub(ss);
    const w3 = Fe.one.add(ss);

    return .{ .x = w0.mul(w3), .y = w2.mul(w1), .z = w1.mul(w3), .t = w0.mul(w2) };
}

fn expandMessageXmd(out: []u8, msg: []const u8, comptime dst: []const u8) !void {
    return expandMessageXmdParts(out, &[_][]const u8{msg}, dst);
}

fn expandMessageXmdParts(out: []u8, msg_parts: []const []const u8, comptime dst: []const u8) !void {
    comptime {
        if (dst.len > 255) @compileError("OPRF DST is too long for expand_message_xmd short DST encoding");
    }
    if (out.len > 255 * Sha512.digest_length) return error.InvalidInput;

    const ell = (out.len + Sha512.digest_length - 1) / Sha512.digest_length;
    var dst_prime: [dst.len + 1]u8 = undefined;
    @memcpy(dst_prime[0..dst.len], dst);
    dst_prime[dst.len] = dst.len;

    var len_bytes: [2]u8 = undefined;
    writeU16(&len_bytes, out.len);

    var h = Sha512.init(.{});
    h.update(&@as([Sha512.block_length]u8, @splat(0)));
    for (msg_parts) |part| h.update(part);
    h.update(&len_bytes);
    h.update(&[_]u8{0});
    h.update(&dst_prime);

    var b0: [Sha512.digest_length]u8 = undefined;
    h.final(&b0);

    h = Sha512.init(.{});
    h.update(&b0);
    h.update(&[_]u8{1});
    h.update(&dst_prime);

    var bi: [Sha512.digest_length]u8 = undefined;
    h.final(&bi);
    appendDigest(out, 0, &bi);

    var i: usize = 2;
    while (i <= ell) : (i += 1) {
        var xored: [Sha512.digest_length]u8 = undefined;
        for (&xored, b0, bi) |*x, b0_byte, bi_byte| {
            x.* = b0_byte ^ bi_byte;
        }

        h = Sha512.init(.{});
        h.update(&xored);
        h.update(&[_]u8{@intCast(i)});
        h.update(&dst_prime);
        h.final(&bi);
        appendDigest(out, (i - 1) * Sha512.digest_length, &bi);
    }
}

fn appendDigest(out: []u8, offset: usize, digest: *const [Sha512.digest_length]u8) void {
    if (offset >= out.len) return;
    const n = @min(Sha512.digest_length, out.len - offset);
    @memcpy(out[offset..][0..n], digest[0..n]);
}

fn hashLengthPrefixed(h: *Sha512, bytes: []const u8) void {
    var len_bytes: [2]u8 = undefined;
    writeU16(&len_bytes, bytes.len);
    h.update(&len_bytes);
    h.update(bytes);
}

fn requireU16Length(bytes: []const u8) Error!void {
    if (bytes.len > 65535) return error.InputTooLong;
}

fn writeU16(out: *[2]u8, n: usize) void {
    std.mem.writeInt(u16, out, @intCast(n), .big);
}
