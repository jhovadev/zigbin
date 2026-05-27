const std = @import("std");
const httpz = @import("httpz");
const zigbin = @import("zigbin");

const App = zigbin.App;
const Config = zigbin.Config;
const utils = zigbin.utils;
const handlers = @import("handlers.zig");

// ─── Entry Point ────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Build configuration from environment variables with sensible defaults
    const config = loadConfig();

    // Initialize the service layer (App owns the rate limiter and DB connection)
    var app = try App.init(io, config, gpa);
    defer app.deinit();

    // Setup the HTTP server (controller layer)
    var server = try httpz.Server(*App).init(io, gpa, .{
        .address = .all(config.port),
    }, &app);
    defer {
        server.stop();
        server.deinit();
    }

    // Configure CORS middleware to support client requests
    const cors = try server.middleware(httpz.middleware.Cors, .{
        .origin = config.cors_origin orelse "*",
        .methods = "GET,POST,OPTIONS",
        .headers = "Content-Type,X-Filename,X-Password,X-Expires-In,X-Available-At",
    });

    // Register routes
    var router = try server.router(.{
        .middlewares = &.{cors},
    });
    router.get("/", handlers.handleIndex, .{});
    router.head("/", handlers.handleIndex, .{});
    router.post("/p", handlers.handleCreatePaste, .{});
    router.get("/p/:id", handlers.handleGetPaste, .{});

    std.debug.print(
        \\
        \\ ╔══════════════════════════════════════╗
        \\ ║  Zigbin text storage API             ║
        \\ ║  http://localhost:{d:<19} ║
        \\ ╚══════════════════════════════════════╝
        \\
        \\  Endpoints:
        \\    GET  /        → health check
        \\    POST /p       → create paste
        \\    GET  /p/:id   → retrieve paste
        \\
        \\  Headers (POST /p):
        \\    X-Filename     → original filename
        \\    X-Password     → password protection
        \\    X-Expires-In   → expiry duration (ms)
        \\    X-Available-At → availability date (ms epoch)
        \\
        \\  Rate Limit: {d} req/window per IP
        \\
        \\    @jhovadev:jhoan.dev
        \\    https://github.com/jhovadev/zigbin
    , .{ config.port, config.rate_limit_max_tokens });

    try server.listen();
}

// ─── Configuration from Environment Variables ───────────────────────────────

/// Loads configuration from environment variables with fallback to defaults.
///
/// Supported environment variables:
///   ZIGBIN_PORT            → server port (default: 5882)
///   ZIGBIN_DB_PATH         → SQLite database path (default: ./zigbin.db)
///   ZIGBIN_ENCRYPTION_KEY  → passphrase for AES-256-GCM encryption (default: built-in key)
///   ZIGBIN_DEFAULT_EXPIRY  → default paste expiry in ms (default: 86400000 = 24h)
///   ZIGBIN_RATE_LIMIT      → max requests per window per IP (default: 10)
///   ZIGBIN_RATE_WINDOW     → rate limit window in ms (default: 60000 = 1 min)
///   ZIGBIN_TRUST_PROXY     → set to "true" to trust X-Forwarded-For (default: false)
fn loadConfig() Config {
    var config: Config = .{};

    // Port
    if (getEnv("ZIGBIN_PORT")) |port_str| {
        if (std.fmt.parseInt(u16, port_str, 10) catch null) |port| {
            config.port = port;
        }
    }

    // Database path — must be a sentinel-terminated string literal or static
    // For env vars we use a few well-known paths
    if (getEnv("ZIGBIN_DB_PATH")) |db_path| {
        config.db_path = toSentinel(db_path);
    }

    // Encryption key (derived from passphrase)
    if (getEnv("ZIGBIN_ENCRYPTION_KEY")) |passphrase| {
        config.encryption_key = utils.deriveKey(passphrase);
    } else {
        // Default encryption key
        config.encryption_key = utils.deriveKey("super-secret-zigbin-default-passphrase-2026");
    }

    // Default expiry
    if (getEnv("ZIGBIN_DEFAULT_EXPIRY")) |expiry_str| {
        config.default_expires_in_ms = std.fmt.parseInt(i64, expiry_str, 10) catch 86_400_000;
    }

    // Rate limiting
    if (getEnv("ZIGBIN_RATE_LIMIT")) |limit_str| {
        if (std.fmt.parseInt(u32, limit_str, 10) catch null) |limit| {
            config.rate_limit_max_tokens = limit;
            // Recalculate refill rate based on the new limit and window
            config.rate_limit_refill_rate = @as(f64, @floatFromInt(limit)) /
                @as(f64, @floatFromInt(config.rate_limit_window_ms));
        }
    }

    if (getEnv("ZIGBIN_RATE_WINDOW")) |window_str| {
        if (std.fmt.parseInt(i64, window_str, 10) catch null) |window| {
            config.rate_limit_window_ms = window;
            // Recalculate refill rate
            config.rate_limit_refill_rate = @as(f64, @floatFromInt(config.rate_limit_max_tokens)) /
                @as(f64, @floatFromInt(window));
        }
    }

    // Trust X-Forwarded-For (for reverse proxy / Docker setups)
    if (getEnv("ZIGBIN_TRUST_PROXY")) |val| {
        config.trust_forwarded_for = std.mem.eql(u8, val, "true") or
            std.mem.eql(u8, val, "1") or
            std.mem.eql(u8, val, "yes");
    }

    // CORS Origin
    if (getEnv("ZIGBIN_CORS_ORIGIN")) |origin| {
        config.cors_origin = origin;
    }

    return config;
}

/// Safe wrapper around std.posix.getenv that returns an optional slice.
fn getEnv(key: [*:0]const u8) ?[]const u8 {
    const val = std.c.getenv(key) orelse return null;
    return std.mem.sliceTo(val, 0);
}

/// Converts a regular slice to a sentinel-terminated slice.
/// This is safe only for env var strings which are null-terminated by the OS.
fn toSentinel(s: []const u8) [:0]const u8 {
    return @ptrCast(s.ptr[0..s.len :0]);
}
