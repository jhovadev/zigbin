const std = @import("std");
const Io = std.Io;

// ─── ID Generation ──────────────────────────────────────────────────────────

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Fills `buf` with random alphanumeric characters and returns it as a slice.
pub fn generateId(io: Io, buf: []u8) []const u8 {
    return fillRandom(io, buf);
}

/// Generates a random password of the given length into `buf`.
pub fn generatePassword(io: Io, buf: []u8) []const u8 {
    return fillRandom(io, buf);
}

fn fillRandom(io: Io, buf: []u8) []const u8 {
    // Use OS-backed CSPRNG via std.Io for cryptographically secure randomness.
    // This replaces the previous timestamp-seeded PRNG which was predictable
    // and could produce duplicate outputs within the same millisecond.
    const source: std.Random.IoSource = .{ .io = io };
    const random = source.interface();

    for (buf) |*c| {
        c.* = charset[random.intRangeAtMost(usize, 0, charset.len - 1)];
    }
    return buf;
}

// ─── Password Hashing (SHA-256 hex) ─────────────────────────────────────────

/// Hashes a plaintext password with SHA-256 and writes the hex digest into `out`.
/// Returns the 64-byte hex string slice.
pub fn hashPassword(password: []const u8, out: *[64]u8) []const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(password, &hash, .{});
    return bytesToHex(&hash, out);
}

/// Verifies that a plaintext password matches a stored hex hash.
pub fn verifyPassword(password: []const u8, stored_hash: []const u8) bool {
    var computed: [64]u8 = undefined;
    const hex = hashPassword(password, &computed);
    return std.mem.eql(u8, hex, stored_hash);
}

// ─── Hex Encoding / Decoding ────────────────────────────────────────────────

const hex_chars = "0123456789abcdef";

/// Encodes raw bytes into lowercase hex. `out` must be `data.len * 2` bytes.
pub fn bytesToHex(data: []const u8, out: []u8) []const u8 {
    for (data, 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return out[0 .. data.len * 2];
}

fn hexCharToNibble(c: u8) !u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => error.InvalidHexChar,
    };
}

/// Decodes hex string to raw bytes. `out` must be `hex.len / 2` bytes.
pub fn hexToBytes(hex: []const u8, out: []u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const len = hex.len / 2;
    for (0..len) |i| {
        const hi: u8 = @intCast(try hexCharToNibble(hex[i * 2]));
        const lo: u8 = @intCast(try hexCharToNibble(hex[i * 2 + 1]));
        out[i] = (hi << 4) | lo;
    }
    return out[0..len];
}

// ─── Content Encryption (AES-256-GCM) ───────────────────────────────────────

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const nonce_len = Aes256Gcm.nonce_length; // 12
pub const tag_len = Aes256Gcm.tag_length; // 16
pub const overhead = nonce_len + tag_len; // 28

/// Derives a 32-byte encryption key from a passphrase using SHA-256.
pub fn deriveKey(passphrase: []const u8) [32]u8 {
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(passphrase, &key, .{});
    return key;
}

/// Encrypts plaintext with AES-256-GCM.
/// Writes nonce (12) || ciphertext (plaintext.len) || tag (16) into `out`.
/// `out` must be at least `plaintext.len + overhead` bytes.
pub fn encryptContent(plaintext: []const u8, key: [32]u8, out: []u8, io: Io) void {
    // Generate nonce using OS-backed CSPRNG for cryptographic security.
    // AES-256-GCM requires unique nonces — reuse completely breaks security.
    var nonce: [nonce_len]u8 = undefined;
    io.random(&nonce);

    // Copy nonce to output prefix
    @memcpy(out[0..nonce_len], &nonce);

    // Encrypt into output buffer after the nonce
    var tag: [tag_len]u8 = undefined;
    Aes256Gcm.encrypt(
        out[nonce_len .. nonce_len + plaintext.len],
        &tag,
        plaintext,
        "",
        nonce,
        key,
    );

    // Append tag
    @memcpy(out[nonce_len + plaintext.len ..][0..tag_len], &tag);
}

/// Decrypts content that was encrypted with `encryptContent`.
/// Input: nonce (12) || ciphertext || tag (16).
/// Writes plaintext into `out`. Returns the plaintext slice.
pub fn decryptContent(encrypted: []const u8, key: [32]u8, out: []u8) ![]const u8 {
    if (encrypted.len < overhead) return error.InvalidEncryptedData;

    const ct_len = encrypted.len - overhead;
    const nonce: [nonce_len]u8 = encrypted[0..nonce_len].*;
    const ciphertext = encrypted[nonce_len .. nonce_len + ct_len];
    const tag: [tag_len]u8 = encrypted[nonce_len + ct_len ..][0..tag_len].*;

    Aes256Gcm.decrypt(
        out[0..ct_len],
        ciphertext,
        tag,
        "",
        nonce,
        key,
    ) catch return error.DecryptionFailed;

    return out[0..ct_len];
}

/// Returns the size needed for the encrypted blob (before hex encoding).
pub fn encryptedSize(plaintext_len: usize) usize {
    return plaintext_len + overhead;
}

/// Returns the hex-encoded size of an encrypted blob.
pub fn encryptedHexSize(plaintext_len: usize) usize {
    return encryptedSize(plaintext_len) * 2;
}

// ─── Timestamp Helpers ──────────────────────────────────────────────────────

/// Returns the current time in milliseconds since epoch.
pub fn nowMs(io: Io) i64 {
    return Io.Timestamp.now(io, Io.Clock.awake).toMilliseconds();
}

/// Parses a string containing a decimal integer. Returns null on failure.
pub fn parseInt(s: []const u8) ?i64 {
    return std.fmt.parseInt(i64, s, 10) catch null;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "hashPassword produces 64-char hex string" {
    var out: [64]u8 = undefined;
    const hex = hashPassword("hello", &out);
    try std.testing.expectEqual(@as(usize, 64), hex.len);
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    try std.testing.expectEqualStrings(expected, hex);
}

test "hashPassword different inputs produce different hashes" {
    var out1: [64]u8 = undefined;
    var out2: [64]u8 = undefined;
    const h1 = hashPassword("password1", &out1);
    const h2 = hashPassword("password2", &out2);
    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}

test "verifyPassword correct password" {
    var out: [64]u8 = undefined;
    const hash = hashPassword("secret", &out);
    try std.testing.expect(verifyPassword("secret", hash));
}

test "verifyPassword wrong password" {
    var out: [64]u8 = undefined;
    const hash = hashPassword("secret", &out);
    try std.testing.expect(!verifyPassword("wrong", hash));
}

test "hexToBytes and bytesToHex roundtrip" {
    const original = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var hex_buf: [8]u8 = undefined;
    const hex = bytesToHex(&original, &hex_buf);
    try std.testing.expectEqualStrings("deadbeef", hex);

    var decoded: [4]u8 = undefined;
    const result = try hexToBytes(hex, &decoded);
    try std.testing.expectEqualSlices(u8, &original, result);
}

test "deriveKey produces 32 bytes" {
    const key = deriveKey("my-secret-passphrase");
    try std.testing.expectEqual(@as(usize, 32), key.len);
}

test "deriveKey same input same output" {
    const k1 = deriveKey("test");
    const k2 = deriveKey("test");
    try std.testing.expectEqualSlices(u8, &k1, &k2);
}

test "deriveKey different input different output" {
    const k1 = deriveKey("key1");
    const k2 = deriveKey("key2");
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
}

test "parseInt valid number" {
    try std.testing.expectEqual(@as(?i64, 3600000), parseInt("3600000"));
}

test "parseInt invalid string returns null" {
    try std.testing.expectEqual(@as(?i64, null), parseInt("not_a_number"));
}

test "parseInt empty string returns null" {
    try std.testing.expectEqual(@as(?i64, null), parseInt(""));
}
