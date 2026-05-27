const std = @import("std");
const httpz = @import("httpz");
const zigbin = @import("zigbin");

const App = zigbin.App;
const Paste = zigbin.Paste;
const utils = zigbin.utils;
const RateLimiter = zigbin.RateLimiter;

// ─── HTTP Handlers (Controller Layer) ───────────────────────────────────────

/// GET / — Health check
pub fn handleIndex(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    res.status = 200;
    try res.json(.{
        .status = "ok",
        .message = "welcome to zigbin",
        .endpoints = .{
            .create = "POST /p",
            .get = "GET /p/:id",
        },
    }, .{});
}

/// POST /p — Create a new paste
///
/// Headers (all optional):
///   X-Filename:      original filename (for file uploads)
///   X-Password:      password to protect the paste
///   X-Expires-In:    expiration duration in milliseconds from now
///   X-Available-At:  unix timestamp (ms) from which the paste is accessible
///
/// Body: raw paste content (text or file contents)
///
/// Rate limited per IP address. Returns 429 Too Many Requests when exceeded.
pub fn handleCreatePaste(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    // ── Rate Limiting ──
    const client_ip = getClientIp(app, req);
    const now = utils.nowMs(app.io);

    if (!app.rate_limiter.check(client_ip, now)) {
        res.status = 429;
        try res.json(.{
            .status = "error",
            .message = "too many requests — please try again later",
        }, .{});
        return;
    }

    const body = req.body() orelse {
        res.status = 400;
        try res.json(.{ .status = "error", .message = "missing content" }, .{});
        return;
    };

    // Parse optional metadata headers
    const filename = req.header("x-filename");
    const password = req.header("x-password");

    const expires_in_ms: ?i64 = if (req.header("x-expires-in")) |val|
        utils.parseInt(val)
    else
        null;

    const available_at: ?i64 = if (req.header("x-available-at")) |val|
        utils.parseInt(val)
    else
        null;

    var id_buf: [8]u8 = undefined;
    const paste = try app.createPaste(.{
        .content = body,
        .filename = filename,
        .password = password,
        .expires_in_ms = expires_in_ms,
        .available_at = available_at,
    }, &id_buf, res.arena);

    res.status = 201;
    try res.json(.{
        .id = paste.id,
        .filename = paste.filename,
        .protected = paste.isProtected(),
        .encrypted = paste.encrypted,
        .created_at = paste.created_at,
        .available_at = paste.available_at,
        .expires_at = paste.expires_at,
        .status = "created",
    }, .{});
}

/// GET /p/:id — Retrieve a paste
///
/// If password-protected, send the password via:
///   Header: X-Password: <password>
///   or query: ?pw=<password>
pub fn handleGetPaste(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const id = req.param("id").?;

    var row = try app.getPaste(id) orelse {
        res.status = 404;
        try res.json(.{ .status = "error", .message = "paste not found" }, .{});
        return;
    };
    defer row.deinit();

    const paste = Paste.fromRow(&row);
    const now = utils.nowMs(app.io);

    // Check expiration
    if (paste.isExpired(now)) {
        res.status = 410;
        try res.json(.{ .status = "error", .message = "paste has expired" }, .{});
        return;
    }

    // Check availability window
    if (paste.isNotYetAvailable(now)) {
        res.status = 425;
        try res.json(.{
            .status = "error",
            .message = "paste is not yet available",
            .available_at = paste.available_at,
        }, .{});
        return;
    }

    // Check password protection
    if (paste.isProtected()) {
        const provided_pw = req.header("x-password") orelse blk: {
            const qs = try req.query();
            break :blk qs.get("pw");
        };

        if (provided_pw) |pw| {
            if (!utils.verifyPassword(pw, paste.password_hash.?)) {
                res.status = 403;
                try res.json(.{ .status = "error", .message = "invalid password" }, .{});
                return;
            }
        } else {
            res.status = 401;
            try res.json(.{
                .status = "error",
                .message = "this paste is password-protected",
                .hint = "send password via X-Password header or ?pw= query param",
            }, .{});
            return;
        }
    }

    // Decrypt content if encrypted
    const content = app.decryptPasteContent(paste, res.arena) catch |err| {
        res.status = 500;
        try res.json(.{
            .status = "error",
            .message = "failed to decrypt paste content",
            .error_code = @errorName(err),
        }, .{});
        return;
    };

    // Success — return paste content as plain text
    res.body = content;
    res.status = 200;
    res.content_type = .TEXT;

    // Set filename header if present (for file uploads)
    if (paste.filename) |fname| {
        const fname_dup = try res.arena.dupe(u8, fname);
        res.header("X-Filename", fname_dup);
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Extracts the client IP address. When `trust_forwarded_for` is enabled,
/// checks the `X-Forwarded-For` header first (useful behind reverse proxies).
/// Falls back to the direct peer address from the socket.
fn getClientIp(app: *App, req: *httpz.Request) []const u8 {
    // If we trust the X-Forwarded-For header (reverse proxy scenario)
    if (app.config.trust_forwarded_for) {
        if (req.header("x-forwarded-for")) |xff| {
            // X-Forwarded-For may contain: "client, proxy1, proxy2"
            // The first IP is the original client
            if (std.mem.indexOfScalar(u8, xff, ',')) |comma| {
                return std.mem.trim(u8, xff[0..comma], " ");
            }
            return std.mem.trim(u8, xff, " ");
        }
    }

    // Fall back to peer address from the socket
    return formatAddress(req.address);
}

/// Formats an IpAddress into a stable string for use as a rate limiter key.
/// Uses a thread-local buffer since the IP only needs to live for the duration
/// of the rate limiter lookup (which copies/dupes the key internally).
fn formatAddress(addr: std.Io.net.IpAddress) []const u8 {
    const S = struct {
        threadlocal var buf: [64]u8 = undefined;
    };

    return switch (addr) {
        .ip4 => |ip4| std.fmt.bufPrint(&S.buf, "{d}.{d}.{d}.{d}", .{
            ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
        }) catch "unknown",
        .ip6 => |ip6| blk: {
            // Simple hex representation of IPv6 for hashing purposes
            var pos: usize = 0;
            for (ip6.bytes, 0..) |byte, i| {
                const hex = "0123456789abcdef";
                S.buf[pos] = hex[byte >> 4];
                pos += 1;
                S.buf[pos] = hex[byte & 0x0f];
                pos += 1;
                if (i % 2 == 1 and i < 15) {
                    S.buf[pos] = ':';
                    pos += 1;
                }
            }
            break :blk S.buf[0..pos];
        },
    };
}
