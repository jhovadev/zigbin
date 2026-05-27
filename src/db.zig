const std = @import("std");
const zqlite = @import("zqlite");
const Paste = @import("root.zig").Paste;

// ─── Paste Repository (Data Access Layer) ───────────────────────────────────

/// Handles all direct database operations for pastes.
/// Encapsulates the SQL schema and CRUD queries.
pub const PasteRepository = struct {
    conn: zqlite.Conn,

    const create_table_sql =
        \\ CREATE TABLE IF NOT EXISTS pastes (
        \\     id            TEXT PRIMARY KEY,
        \\     content       TEXT    NOT NULL,
        \\     filename      TEXT,
        \\     password_hash TEXT,
        \\     encrypted     INTEGER DEFAULT 0,
        \\     created_at    INTEGER NOT NULL,
        \\     available_at  INTEGER,
        \\     expires_at    INTEGER
        \\ )
    ;

    /// Opens the database connection and ensures the schema exists.
    pub fn init(db_path: [:0]const u8) !PasteRepository {
        const flags = zqlite.OpenFlags.Create | zqlite.OpenFlags.EXResCode;
        const conn = try zqlite.open(db_path, flags);
        try conn.exec(create_table_sql, .{});
        return .{ .conn = conn };
    }

    pub fn deinit(self: *PasteRepository) void {
        self.conn.close();
    }

    /// Inserts a new paste record into the database.
    pub fn insert(self: *PasteRepository, paste: Paste) !void {
        try self.conn.exec(
            "INSERT INTO pastes (id, content, filename, password_hash, encrypted, created_at, available_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            .{
                paste.id,
                paste.content,
                paste.filename,
                paste.password_hash,
                paste.encrypted,
                paste.created_at,
                paste.available_at,
                paste.expires_at,
            },
        );
    }

    /// Looks up a paste by its ID. Returns `null` when not found.
    /// Caller owns the returned row and must call `row.deinit()`.
    pub fn findById(self: *PasteRepository, id: []const u8) !?zqlite.Row {
        return try self.conn.row(
            "SELECT content, filename, password_hash, encrypted, created_at, available_at, expires_at FROM pastes WHERE id = ?1",
            .{id},
        );
    }

    /// Deletes expired pastes from the database.
    pub fn deleteExpired(self: *PasteRepository, now_ms: i64) !void {
        try self.conn.exec(
            "DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            .{now_ms},
        );
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test "PasteRepository: init creates table" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();

    const paste: Paste = .{
        .id = "test123", .content = "hello world", .filename = null,
        .password_hash = null, .encrypted = false, .created_at = 1000,
        .available_at = null, .expires_at = null,
    };
    try repo.insert(paste);
}

test "PasteRepository: insert and findById" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();

    const paste: Paste = .{
        .id = "abc", .content = "test content", .filename = "readme.txt",
        .password_hash = null, .encrypted = false, .created_at = 42,
        .available_at = null, .expires_at = null,
    };
    try repo.insert(paste);

    var row = try repo.findById("abc") orelse return error.TestUnexpectedResult;
    defer row.deinit();

    try std.testing.expectEqualStrings("test content", row.text(0));
    try std.testing.expectEqualStrings("readme.txt", row.text(1));
}

test "PasteRepository: findById returns null for missing paste" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();
    const result = try repo.findById("nonexistent");
    try std.testing.expect(result == null);
}

test "PasteRepository: insert with encryption flag" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();

    const paste: Paste = .{
        .id = "enc1", .content = "aabbccdd", .filename = null,
        .password_hash = null, .encrypted = true, .created_at = 100,
        .available_at = null, .expires_at = null,
    };
    try repo.insert(paste);

    var row = try repo.findById("enc1") orelse return error.TestUnexpectedResult;
    defer row.deinit();

    try std.testing.expect(row.boolean(3)); // encrypted = true
}

test "PasteRepository: insert with all optional fields" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();

    const paste: Paste = .{
        .id = "full", .content = "full paste", .filename = "data.json",
        .password_hash = "hash123", .encrypted = true, .created_at = 500,
        .available_at = 1000, .expires_at = 2000,
    };
    try repo.insert(paste);

    var row = try repo.findById("full") orelse return error.TestUnexpectedResult;
    defer row.deinit();

    try std.testing.expectEqualStrings("full paste", row.text(0));
    try std.testing.expectEqualStrings("data.json", row.text(1));
    try std.testing.expectEqualStrings("hash123", row.text(2));
    try std.testing.expect(row.boolean(3));
    try std.testing.expectEqual(@as(i64, 500), row.int(4));
    try std.testing.expectEqual(@as(i64, 1000), row.int(5));
    try std.testing.expectEqual(@as(i64, 2000), row.int(6));
}

test "PasteRepository: deleteExpired removes old pastes" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();

    try repo.insert(.{
        .id = "old", .content = "expired", .filename = null,
        .password_hash = null, .encrypted = false, .created_at = 100,
        .available_at = null, .expires_at = 500,
    });
    try repo.insert(.{
        .id = "new", .content = "valid", .filename = null,
        .password_hash = null, .encrypted = false, .created_at = 100,
        .available_at = null, .expires_at = 9999,
    });

    try repo.deleteExpired(600);

    try std.testing.expect((try repo.findById("old")) == null);
    var row = try repo.findById("new") orelse return error.TestUnexpectedResult;
    defer row.deinit();
    try std.testing.expectEqualStrings("valid", row.text(0));
}

test "PasteRepository: deleteExpired does not touch eternal pastes" {
    var repo = try PasteRepository.init(":memory:");
    defer repo.deinit();

    try repo.insert(.{
        .id = "forever", .content = "lives forever", .filename = null,
        .password_hash = null, .encrypted = false, .created_at = 100,
        .available_at = null, .expires_at = null,
    });

    try repo.deleteExpired(999999);

    var row = try repo.findById("forever") orelse return error.TestUnexpectedResult;
    defer row.deinit();
    try std.testing.expectEqualStrings("lives forever", row.text(0));
}
