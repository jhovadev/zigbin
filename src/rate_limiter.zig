const std = @import("std");

// ─── Token Bucket Rate Limiter ──────────────────────────────────────────────

/// Per-IP token bucket for rate limiting.
const TokenBucket = struct {
    tokens: f64,
    last_refill_ms: i64,
};

/// In-memory rate limiter using the token bucket algorithm.
/// Tracks requests per IP address and enforces configurable limits.
pub const RateLimiter = struct {
    buckets: std.StringHashMap(TokenBucket),
    allocator: std.mem.Allocator,
    max_tokens: f64,
    refill_rate: f64, // tokens per millisecond
    window_ms: i64,

    pub fn init(allocator: std.mem.Allocator, max_tokens: f64, refill_rate: f64, window_ms: i64) RateLimiter {
        return .{
            .buckets = std.StringHashMap(TokenBucket).init(allocator),
            .allocator = allocator,
            .max_tokens = max_tokens,
            .refill_rate = refill_rate,
            .window_ms = window_ms,
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.buckets.deinit();
    }

    /// Checks if a request from `ip` is allowed. Returns `true` if allowed.
    /// Consumes one token from the bucket. Creates a new bucket if the IP is new.
    pub fn check(self: *RateLimiter, ip: []const u8, now_ms: i64) bool {
        if (self.buckets.getPtr(ip)) |bucket| {
            // Refill tokens based on elapsed time
            const elapsed_ms = now_ms - bucket.last_refill_ms;
            if (elapsed_ms > 0) {
                const refill = @as(f64, @floatFromInt(elapsed_ms)) * self.refill_rate;
                bucket.tokens = @min(self.max_tokens, bucket.tokens + refill);
                bucket.last_refill_ms = now_ms;
            }

            if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        } else {
            // New IP — create bucket with (max_tokens - 1) since this request consumes one
            const owned_ip = self.allocator.dupe(u8, ip) catch return true;
            self.buckets.put(owned_ip, .{
                .tokens = self.max_tokens - 1.0,
                .last_refill_ms = now_ms,
            }) catch {
                self.allocator.free(owned_ip);
                return true; // allow on allocation failure
            };
            return true;
        }
    }

    /// Removes entries that have been inactive for longer than `window_ms`.
    pub fn cleanup(self: *RateLimiter, now_ms: i64) void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            if (now_ms - entry.value_ptr.last_refill_ms > self.window_ms) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            _ = self.buckets.fetchRemove(key);
            self.allocator.free(key);
        }
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "RateLimiter: new IP is allowed" {
    var rl = RateLimiter.init(std.testing.allocator, 10.0, 0.01, 60_000);
    defer rl.deinit();

    try std.testing.expect(rl.check("192.168.1.1", 1000));
}

test "RateLimiter: exhausting tokens causes rate limiting" {
    var rl = RateLimiter.init(std.testing.allocator, 3.0, 0.0, 60_000); // 0 refill = no recovery
    defer rl.deinit();

    try std.testing.expect(rl.check("10.0.0.1", 1000)); // 3 -> 2
    try std.testing.expect(rl.check("10.0.0.1", 1000)); // 2 -> 1
    try std.testing.expect(rl.check("10.0.0.1", 1000)); // 1 -> 0
    try std.testing.expect(!rl.check("10.0.0.1", 1000)); // 0 -> blocked
}

test "RateLimiter: tokens refill over time" {
    // 1 token per second = 0.001 per ms
    var rl = RateLimiter.init(std.testing.allocator, 2.0, 0.001, 60_000);
    defer rl.deinit();

    try std.testing.expect(rl.check("10.0.0.2", 0)); // 2 -> 1
    try std.testing.expect(rl.check("10.0.0.2", 0)); // 1 -> 0
    try std.testing.expect(!rl.check("10.0.0.2", 0)); // 0 -> blocked

    // After 1000ms, should have 1 token refilled
    try std.testing.expect(rl.check("10.0.0.2", 1000)); // refill 1 -> 0
    try std.testing.expect(!rl.check("10.0.0.2", 1000)); // 0 -> blocked
}

test "RateLimiter: cleanup removes old entries" {
    var rl = RateLimiter.init(std.testing.allocator, 10.0, 0.01, 5_000);
    defer rl.deinit();

    _ = rl.check("old-ip", 1000);
    _ = rl.check("new-ip", 8000);

    // At time 10000, "old-ip" (last seen at 1000) is 9000ms old > 5000 window
    // "new-ip" (last seen at 8000) is 2000ms old < 5000 window
    rl.cleanup(10_000);

    try std.testing.expect(rl.buckets.get("old-ip") == null);
    try std.testing.expect(rl.buckets.get("new-ip") != null);
}

test "RateLimiter: different IPs are independent" {
    var rl = RateLimiter.init(std.testing.allocator, 1.0, 0.0, 60_000);
    defer rl.deinit();

    try std.testing.expect(rl.check("ip-a", 1000)); // allowed
    try std.testing.expect(!rl.check("ip-a", 1000)); // blocked
    try std.testing.expect(rl.check("ip-b", 1000)); // different IP, allowed
}
