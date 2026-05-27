const std = @import("std");
const zqlite = @import("zqlite");
const Io = std.Io;

pub const utils = @import("utils.zig");
pub const db = @import("db.zig");
pub const rate_limiter = @import("rate_limiter.zig");
pub const PasteRepository = db.PasteRepository;
pub const RateLimiter = rate_limiter.RateLimiter;

// ─── Domain Model ───────────────────────────────────────────────────────────

/// Represents a single paste entry stored in the database.
pub const Paste = struct {
    id: []const u8,
    content: []const u8,
    filename: ?[]const u8,
    password_hash: ?[]const u8,
    encrypted: bool,
    created_at: i64,
    available_at: ?i64, // timestamp (ms) from which the paste is accessible
    expires_at: ?i64, // timestamp (ms) after which the paste is expired

    /// Constructs a `Paste` from a zqlite row.
    /// Row columns: 0=content, 1=filename, 2=password_hash, 3=encrypted,
    ///              4=created_at, 5=available_at, 6=expires_at
    pub fn fromRow(row: *zqlite.Row) Paste {
        const raw_content = row.text(0);
        const raw_filename = row.nullableText(1);
        const raw_pw_hash = row.nullableText(2);

        return .{
            .id = "",
            .content = std.mem.sliceTo(raw_content, 0),
            .filename = if (raw_filename) |f| std.mem.sliceTo(f, 0) else null,
            .password_hash = if (raw_pw_hash) |p| std.mem.sliceTo(p, 0) else null,
            .encrypted = row.boolean(3),
            .created_at = row.int(4),
            .available_at = row.nullableInt(5),
            .expires_at = row.nullableInt(6),
        };
    }

    /// Returns true if this paste is password-protected.
    pub fn isProtected(self: Paste) bool {
        return self.password_hash != null;
    }

    /// Returns true if the paste has expired relative to `now_ms`.
    pub fn isExpired(self: Paste, now_ms: i64) bool {
        if (self.expires_at) |exp| {
            return now_ms >= exp;
        }
        return false;
    }

    /// Returns true if the paste is not yet available relative to `now_ms`.
    pub fn isNotYetAvailable(self: Paste, now_ms: i64) bool {
        if (self.available_at) |avail| {
            return now_ms < avail;
        }
        return false;
    }
};

/// Request payload for creating a new paste.
pub const CreatePasteRequest = struct {
    content: []const u8,
    filename: ?[]const u8 = null,
    password: ?[]const u8 = null,
    expires_in_ms: ?i64 = null, // duration in ms from now until expiry
    available_at: ?i64 = null, // absolute timestamp ms
};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Server and application configuration.
pub const Config = struct {
    port: u16 = 5882,
    db_path: [:0]const u8 = "./zigbin.db",
    id_length: usize = 8,
    password_length: usize = 12,
    max_content_size: usize = 1_048_576, // 1 MB

    /// Default expiration for all pastes (ms). null = no default expiry.
    /// 86_400_000 ms = 24 hours.
    default_expires_in_ms: ?i64 = 86_400_000,

    /// AES-256-GCM encryption key. null = encryption disabled.
    /// Use `utils.deriveKey("your-passphrase")` to generate from a passphrase.
    encryption_key: ?[32]u8 = null,

    // ─── Rate Limiting ──────────────────────────────────────────────────

    /// Maximum burst of requests allowed per IP.
    rate_limit_max_tokens: u32 = 10,

    /// Token refill rate in tokens per millisecond.
    /// Default: 10 tokens / 60_000ms ≈ 0.000167 tokens/ms.
    rate_limit_refill_rate: f64 = 10.0 / 60_000.0,

    /// Window (ms) after which inactive buckets are purged.
    rate_limit_window_ms: i64 = 120_000, // 2 minutes

    /// If true, trust X-Forwarded-For header for client IP (for reverse proxies).
    trust_forwarded_for: bool = false,

    /// Allowed CORS origin. Defaults to "*" if null.
    cors_origin: ?[]const u8 = null,

    pub const default: Config = .{};
};

// ─── Application Service ────────────────────────────────────────────────────

/// High-level application that orchestrates paste operations.
/// This is the type that HTTP handlers receive as context.
pub const App = struct {
    io: Io,
    repo: PasteRepository,
    config: Config,
    rate_limiter: RateLimiter,
    allocator: std.mem.Allocator,

    pub fn init(io: Io, config: Config, allocator: std.mem.Allocator) !App {
        return .{
            .io = io,
            .repo = try PasteRepository.init(config.db_path),
            .config = config,
            .rate_limiter = RateLimiter.init(
                allocator,
                @floatFromInt(config.rate_limit_max_tokens),
                config.rate_limit_refill_rate,
                config.rate_limit_window_ms,
            ),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *App) void {
        self.rate_limiter.deinit();
        self.repo.deinit();
    }

    /// Creates a new paste with all optional features.
    /// Content is encrypted server-side if `config.encryption_key` is set.
    /// Uses `config.default_expires_in_ms` when no explicit expiry is given.
    ///
    /// **Memory contract**: `allocator` should be an arena allocator (e.g. `res.arena`)
    /// that is freed at the end of the HTTP request. The returned `Paste.content` slice
    /// (when encrypted) points to memory owned by `allocator`. If a non-arena allocator
    /// is used, the caller must manually free `paste.content` when `paste.encrypted` is true.
    pub fn createPaste(self: *App, req: CreatePasteRequest, id_buf: []u8, allocator: std.mem.Allocator) !Paste {
        const id = utils.generateId(self.io, id_buf);
        const now = utils.nowMs(self.io);

        // Hash the password if provided
        var hash_buf: [64]u8 = undefined;
        const pw_hash: ?[]const u8 = if (req.password) |pw|
            utils.hashPassword(pw, &hash_buf)
        else
            null;

        // Calculate expiry: explicit > default > none
        const expires_in = req.expires_in_ms orelse self.config.default_expires_in_ms;
        const expires_at: ?i64 = if (expires_in) |dur| now + dur else null;

        // Encrypt content if key is configured
        var content_to_store: []const u8 = req.content;
        var is_encrypted = false;

        if (self.config.encryption_key) |key| {
            // Allocate buffer for encrypted blob
            const enc_size = utils.encryptedSize(req.content.len);
            const enc_buf = try allocator.alloc(u8, enc_size);
            defer allocator.free(enc_buf);
            utils.encryptContent(req.content, key, enc_buf, self.io);

            // Hex-encode the encrypted blob
            const hex_buf = try allocator.alloc(u8, enc_size * 2);
            content_to_store = utils.bytesToHex(enc_buf, hex_buf);
            is_encrypted = true;
        }

        const paste: Paste = .{
            .id = id,
            .content = content_to_store,
            .filename = req.filename,
            .password_hash = pw_hash,
            .encrypted = is_encrypted,
            .created_at = now,
            .available_at = req.available_at,
            .expires_at = expires_at,
        };

        try self.repo.insert(paste);
        return paste;
    }

    /// Retrieves a paste by ID. Returns `null` when not found.
    /// Caller owns the returned row and must call `row.deinit()`.
    pub fn getPaste(self: *App, id: []const u8) !?zqlite.Row {
        return try self.repo.findById(id);
    }

    /// Decrypts paste content if it was encrypted. Returns plaintext slice.
    ///
    /// **Memory contract**: `allocator` should be an arena allocator (e.g. `res.arena`)
    /// that is freed at the end of the HTTP request. The returned slice points to memory
    /// owned by `allocator`. If a non-arena allocator is used, the caller must manually
    /// free the returned slice.
    pub fn decryptPasteContent(self: *App, paste: Paste, allocator: std.mem.Allocator) ![]const u8 {
        if (!paste.encrypted) return paste.content;

        const key = self.config.encryption_key orelse return error.NoEncryptionKey;

        // Hex-decode to get the raw encrypted blob
        const raw_buf = try allocator.alloc(u8, paste.content.len / 2);
        defer allocator.free(raw_buf);
        const raw = try utils.hexToBytes(paste.content, raw_buf);

        // Decrypt
        const pt_buf = try allocator.alloc(u8, raw.len - utils.overhead);
        return try utils.decryptContent(raw, key, pt_buf);
    }

    /// Purges all expired pastes from the database.
    pub fn purgeExpired(self: *App) !void {
        const now = utils.nowMs(self.io);
        try self.repo.deleteExpired(now);
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "Paste: isProtected" {
    const unprotected: Paste = .{
        .id = "a", .content = "x", .filename = null, .password_hash = null,
        .encrypted = false, .created_at = 0, .available_at = null, .expires_at = null,
    };
    try std.testing.expect(!unprotected.isProtected());

    const protected: Paste = .{
        .id = "b", .content = "y", .filename = null, .password_hash = "abc",
        .encrypted = false, .created_at = 0, .available_at = null, .expires_at = null,
    };
    try std.testing.expect(protected.isProtected());
}

test "Paste: isExpired" {
    const no_expiry: Paste = .{
        .id = "a", .content = "x", .filename = null, .password_hash = null,
        .encrypted = false, .created_at = 0, .available_at = null, .expires_at = null,
    };
    try std.testing.expect(!no_expiry.isExpired(9999));

    const expired: Paste = .{
        .id = "b", .content = "y", .filename = null, .password_hash = null,
        .encrypted = false, .created_at = 0, .available_at = null, .expires_at = 1000,
    };
    try std.testing.expect(expired.isExpired(1000));
    try std.testing.expect(expired.isExpired(2000));
    try std.testing.expect(!expired.isExpired(999));
}

test "Paste: isNotYetAvailable" {
    const immediate: Paste = .{
        .id = "a", .content = "x", .filename = null, .password_hash = null,
        .encrypted = false, .created_at = 0, .available_at = null, .expires_at = null,
    };
    try std.testing.expect(!immediate.isNotYetAvailable(0));

    const scheduled: Paste = .{
        .id = "b", .content = "y", .filename = null, .password_hash = null,
        .encrypted = false, .created_at = 0, .available_at = 5000, .expires_at = null,
    };
    try std.testing.expect(scheduled.isNotYetAvailable(4999));
    try std.testing.expect(!scheduled.isNotYetAvailable(5000));
    try std.testing.expect(!scheduled.isNotYetAvailable(6000));
}

test "Config: default expiry is 24 hours" {
    const config: Config = .{};
    try std.testing.expectEqual(@as(?i64, 86_400_000), config.default_expires_in_ms);
}

test "Config: encryption disabled by default" {
    const config: Config = .{};
    try std.testing.expect(config.encryption_key == null);
}

test "App: createPaste uses default 24h expiration" {
    var app = try App.init(std.testing.io, .{
        .db_path = ":memory:",
        .default_expires_in_ms = 86_400_000,
    }, std.testing.allocator);
    defer app.deinit();

    var id_buf: [8]u8 = undefined;
    const paste = try app.createPaste(.{
        .content = "hello default expiry",
    }, &id_buf, std.testing.allocator);

    try std.testing.expect(paste.expires_at != null);
    // expiry should be around 24h from now
    const now = utils.nowMs(app.io);
    const diff = paste.expires_at.? - now;
    // allow a 5-second window due to test execution delay
    try std.testing.expect(diff >= 86_395_000 and diff <= 86_405_000);
}

test "App: createPaste with encryption" {
    const key = utils.deriveKey("test-passphrase");
    var app = try App.init(std.testing.io, .{
        .db_path = ":memory:",
        .encryption_key = key,
    }, std.testing.allocator);
    defer app.deinit();

    var id_buf: [8]u8 = undefined;
    const plaintext = "This is extremely confidential data!";
    const paste = try app.createPaste(.{
        .content = plaintext,
    }, &id_buf, std.testing.allocator);

    // The stored content should be encrypted and hex-encoded (hence not equal to plaintext)
    try std.testing.expect(paste.encrypted);
    try std.testing.expect(!std.mem.eql(u8, paste.content, plaintext));

    // Try decrypting
    const decrypted = try app.decryptPasteContent(paste, std.testing.allocator);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);

    if (paste.encrypted) {
        std.testing.allocator.free(paste.content);
    }
}

