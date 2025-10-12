//! SSH Known Hosts Management
//!
//! Manages the ~/.ssh/known_hosts file for SSH host key verification.
//! Provides functionality to:
//! - Add new host keys
//! - Verify host keys
//! - Remove host keys
//! - Hash hostnames for security
//!
//! Supports both hashed and plain hostname formats.

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = std.crypto;

pub const KnownHostsError = error{
    FileNotFound,
    ParseError,
    InvalidFormat,
    KeyMismatch,
    HostNotFound,
} || Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || std.fs.File.WriteError;

/// Type of SSH host key
pub const KeyType = enum {
    ssh_rsa,
    ssh_dss,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,
    ssh_ed25519,

    pub fn fromString(s: []const u8) ?KeyType {
        if (std.mem.eql(u8, s, "ssh-rsa")) return .ssh_rsa;
        if (std.mem.eql(u8, s, "ssh-dss")) return .ssh_dss;
        if (std.mem.eql(u8, s, "ecdsa-sha2-nistp256")) return .ecdsa_sha2_nistp256;
        if (std.mem.eql(u8, s, "ecdsa-sha2-nistp384")) return .ecdsa_sha2_nistp384;
        if (std.mem.eql(u8, s, "ecdsa-sha2-nistp521")) return .ecdsa_sha2_nistp521;
        if (std.mem.eql(u8, s, "ssh-ed25519")) return .ssh_ed25519;
        return null;
    }

    pub fn toString(self: KeyType) []const u8 {
        return switch (self) {
            .ssh_rsa => "ssh-rsa",
            .ssh_dss => "ssh-dss",
            .ecdsa_sha2_nistp256 => "ecdsa-sha2-nistp256",
            .ecdsa_sha2_nistp384 => "ecdsa-sha2-nistp384",
            .ecdsa_sha2_nistp521 => "ecdsa-sha2-nistp521",
            .ssh_ed25519 => "ssh-ed25519",
        };
    }
};

/// A single entry in the known_hosts file
pub const HostEntry = struct {
    hostname_pattern: []const u8,  // Can be plain or hashed
    key_type: KeyType,
    key_data: []const u8,  // Base64 encoded
    hashed: bool,

    pub fn deinit(self: *HostEntry, allocator: Allocator) void {
        allocator.free(self.hostname_pattern);
        allocator.free(self.key_data);
    }

    /// Check if this entry matches the given hostname
    pub fn matches(self: *const HostEntry, hostname: []const u8) bool {
        if (!self.hashed) {
            return std.mem.eql(u8, self.hostname_pattern, hostname) or
                matchPattern(self.hostname_pattern, hostname);
        }

        // Hashed hostname comparison
        // Format: |1|salt|hash
        return matchHashedHostname(self.hostname_pattern, hostname);
    }
};

/// Known hosts database
pub const KnownHosts = struct {
    allocator: Allocator,
    entries: std.ArrayList(HostEntry),
    path: []const u8,

    pub fn init(allocator: Allocator, path: []const u8) !KnownHosts {
        return .{
            .allocator = allocator,
            .entries = std.ArrayList(HostEntry).init(allocator),
            .path = try allocator.dupe(u8, path),
        };
    }

    pub fn deinit(self: *KnownHosts) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit();
        self.allocator.free(self.path);
    }

    /// Load known hosts from file
    pub fn load(self: *KnownHosts) !void {
        const file = std.fs.cwd().openFile(self.path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                // File doesn't exist yet, that's ok
                return;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024); // 10MB max
        defer self.allocator.free(content);

        try self.parse(content);
    }

    /// Parse known hosts file content
    fn parse(self: *KnownHosts, content: []const u8) !void {
        var lines = std.mem.split(u8, content, "\n");

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

            // Skip empty lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            const entry = parseEntry(self.allocator, trimmed) catch continue;
            try self.entries.append(entry);
        }
    }

    /// Save known hosts to file
    pub fn save(self: *const KnownHosts) !void {
        const file = try std.fs.cwd().createFile(self.path, .{ .truncate = true });
        defer file.close();

        var buf_writer = std.io.bufferedWriter(file.writer());
        const writer = buf_writer.writer();

        for (self.entries.items) |*entry| {
            try writer.print("{s} {s} {s}\n", .{
                entry.hostname_pattern,
                entry.key_type.toString(),
                entry.key_data,
            });
        }

        try buf_writer.flush();
    }

    /// Add a new host entry
    pub fn add(self: *KnownHosts, hostname: []const u8, key_type: KeyType, key_data: []const u8, hash: bool) !void {
        const hostname_pattern = if (hash)
            try hashHostname(self.allocator, hostname)
        else
            try self.allocator.dupe(u8, hostname);

        const entry = HostEntry{
            .hostname_pattern = hostname_pattern,
            .key_type = key_type,
            .key_data = try self.allocator.dupe(u8, key_data),
            .hashed = hash,
        };

        try self.entries.append(entry);
    }

    /// Verify a host key
    pub fn verify(self: *const KnownHosts, hostname: []const u8, key_type: KeyType, key_data: []const u8) !bool {
        for (self.entries.items) |*entry| {
            if (entry.matches(hostname) and entry.key_type == key_type) {
                return std.mem.eql(u8, entry.key_data, key_data);
            }
        }

        return false; // Host not found
    }

    /// Remove entries for a hostname
    pub fn remove(self: *KnownHosts, hostname: []const u8) !usize {
        var removed: usize = 0;
        var i: usize = 0;

        while (i < self.entries.items.len) {
            if (self.entries.items[i].matches(hostname)) {
                var entry = self.entries.swapRemove(i);
                entry.deinit(self.allocator);
                removed += 1;
            } else {
                i += 1;
            }
        }

        return removed;
    }

    /// Find all entries matching a hostname
    pub fn find(self: *const KnownHosts, hostname: []const u8) std.ArrayList(*const HostEntry) {
        var result = std.ArrayList(*const HostEntry).init(self.allocator);

        for (self.entries.items) |*entry| {
            if (entry.matches(hostname)) {
                result.append(entry) catch {};
            }
        }

        return result;
    }
};

/// Parse a single known_hosts entry line
fn parseEntry(allocator: Allocator, line: []const u8) !HostEntry {
    var parts = std.mem.tokenize(u8, line, &std.ascii.whitespace);

    const hostname_pattern = parts.next() orelse return error.InvalidFormat;
    const key_type_str = parts.next() orelse return error.InvalidFormat;
    const key_data = parts.next() orelse return error.InvalidFormat;

    const key_type = KeyType.fromString(key_type_str) orelse return error.InvalidFormat;

    const hashed = std.mem.startsWith(u8, hostname_pattern, "|1|");

    return HostEntry{
        .hostname_pattern = try allocator.dupe(u8, hostname_pattern),
        .key_type = key_type,
        .key_data = try allocator.dupe(u8, key_data),
        .hashed = hashed,
    };
}

/// Simple pattern matching for hostname
fn matchPattern(pattern: []const u8, hostname: []const u8) bool {
    // Support wildcards
    if (std.mem.indexOf(u8, pattern, "*")) |_| {
        return wildcardMatch(pattern, hostname);
    }

    return std.mem.eql(u8, pattern, hostname);
}

fn wildcardMatch(pattern: []const u8, text: []const u8) bool {
    var p_idx: usize = 0;
    var t_idx: usize = 0;
    var star_idx: ?usize = null;
    var match_idx: usize = 0;

    while (t_idx < text.len) {
        if (p_idx < pattern.len and (pattern[p_idx] == text[t_idx] or pattern[p_idx] == '?')) {
            p_idx += 1;
            t_idx += 1;
        } else if (p_idx < pattern.len and pattern[p_idx] == '*') {
            star_idx = p_idx;
            match_idx = t_idx;
            p_idx += 1;
        } else if (star_idx) |star| {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.len and pattern[p_idx] == '*') {
        p_idx += 1;
    }

    return p_idx == pattern.len;
}

/// Hash a hostname for known_hosts storage
/// Format: |1|salt|hash
fn hashHostname(allocator: Allocator, hostname: []const u8) ![]const u8 {
    // Generate random salt
    var salt: [20]u8 = undefined;
    crypto.random.bytes(&salt);

    // Compute HMAC-SHA1 of hostname with salt
    var hmac: [20]u8 = undefined;
    crypto.auth.hmac.sha1.Hmac.create(&hmac, hostname, &salt);

    // Base64 encode salt and hash
    const encoder = std.base64.standard.Encoder;
    const salt_b64_len = encoder.calcSize(salt.len);
    const hash_b64_len = encoder.calcSize(hmac.len);

    var result = try allocator.alloc(u8, 3 + salt_b64_len + 1 + hash_b64_len);
    std.mem.copy(u8, result[0..], "|1|");

    var pos: usize = 3;
    const salt_b64 = encoder.encode(result[pos .. pos + salt_b64_len], &salt);
    pos += salt_b64.len;

    result[pos] = '|';
    pos += 1;

    _ = encoder.encode(result[pos .. pos + hash_b64_len], &hmac);

    return result;
}

/// Check if a hashed hostname matches
fn matchHashedHostname(hashed: []const u8, hostname: []const u8) bool {
    // Format: |1|salt_base64|hash_base64
    if (!std.mem.startsWith(u8, hashed, "|1|")) {
        return false;
    }

    var parts = std.mem.split(u8, hashed[3..], "|");
    const salt_b64 = parts.next() orelse return false;
    const expected_hash_b64 = parts.rest();

    // Decode salt
    var salt: [20]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    decoder.decode(&salt, salt_b64) catch return false;

    // Compute hash
    var computed_hash: [20]u8 = undefined;
    crypto.auth.hmac.sha1.Hmac.create(&computed_hash, hostname, &salt);

    // Encode and compare
    var computed_hash_b64: [28]u8 = undefined; // Base64 of 20 bytes
    const encoder = std.base64.standard.Encoder;
    const encoded = encoder.encode(&computed_hash_b64, &computed_hash);

    return std.mem.eql(u8, encoded, expected_hash_b64);
}

// Tests

test "known_hosts entry parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcd1234567890abcdefghijklmnopqrstuvwxyz";
    var entry = try parseEntry(allocator, line);
    defer entry.deinit(allocator);

    try testing.expectEqualStrings("example.com", entry.hostname_pattern);
    try testing.expectEqual(KeyType.ssh_ed25519, entry.key_type);
    try testing.expect(!entry.hashed);
}

test "known_hosts matching" {
    const testing = std.testing;

    const entry = HostEntry{
        .hostname_pattern = "*.example.com",
        .key_type = .ssh_ed25519,
        .key_data = "testkey",
        .hashed = false,
    };

    try testing.expect(entry.matches("host.example.com"));
    try testing.expect(entry.matches("sub.host.example.com"));
    try testing.expect(!entry.matches("other.com"));
}

test "known_hosts add and verify" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var known_hosts = try KnownHosts.init(allocator, "/tmp/test_known_hosts");
    defer known_hosts.deinit();

    try known_hosts.add("test.example.com", .ssh_ed25519, "AAAAC3test", false);

    const verified = try known_hosts.verify("test.example.com", .ssh_ed25519, "AAAAC3test");
    try testing.expect(verified);

    const not_verified = try known_hosts.verify("test.example.com", .ssh_ed25519, "differentkey");
    try testing.expect(!not_verified);
}
