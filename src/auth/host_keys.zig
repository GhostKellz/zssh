//! Host Key Management and Verification
//!
//! Implements SSH host key verification and known hosts database
//! management according to RFC 4251 and OpenSSH practices.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const HostKeyError = error{
    HostKeyNotFound,
    HostKeyMismatch,
    InvalidKeyFormat,
    DatabaseCorrupted,
} || Allocator.Error;

pub const HostKeyAlgorithm = enum {
    ssh_rsa,
    ssh_ed25519,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,

    pub fn toString(self: HostKeyAlgorithm) []const u8 {
        return switch (self) {
            .ssh_rsa => "ssh-rsa",
            .ssh_ed25519=> "ssh-ed25519",
            .ecdsa_sha2_nistp256 => "ecdsa-sha2-nistp256",
            .ecdsa_sha2_nistp384 => "ecdsa-sha2-nistp384",
            .ecdsa_sha2_nistp521 => "ecdsa-sha2-nistp521",
        };
    }

    pub fn fromString(algorithm: []const u8) ?HostKeyAlgorithm {
        if (std.mem.eql(u8, algorithm, "ssh-rsa")) return .ssh_rsa;
        if (std.mem.eql(u8, algorithm, "ssh-ed25519")) return .ssh_ed25519;
        if (std.mem.eql(u8, algorithm, "ecdsa-sha2-nistp256")) return .ecdsa_sha2_nistp256;
        if (std.mem.eql(u8, algorithm, "ecdsa-sha2-nistp384")) return .ecdsa_sha2_nistp384;
        if (std.mem.eql(u8, algorithm, "ecdsa-sha2-nistp521")) return .ecdsa_sha2_nistp521;
        return null;
    }
};

pub const HostKey = struct {
    host: []const u8,
    port: u16,
    algorithm: HostKeyAlgorithm,
    key_data: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, host: []const u8, port: u16, algorithm: HostKeyAlgorithm, key_data: []const u8) !Self {
        return Self{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .algorithm = algorithm,
            .key_data = try allocator.dupe(u8, key_data),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.host);
        allocator.free(self.key_data);
    }

    pub fn matches(self: *const Self, host: []const u8, port: u16) bool {
        return std.mem.eql(u8, self.host, host) and self.port == port;
    }

    pub fn verify(self: *const Self, candidate_key: []const u8) bool {
        return std.mem.eql(u8, self.key_data, candidate_key);
    }
};

pub const KnownHosts = struct {
    allocator: Allocator,
    host_keys: std.ArrayList(HostKey),
    file_path: ?[]const u8,
    strict_mode: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, file_path: ?[]const u8) !Self {
        var known_hosts = Self{
            .allocator = allocator,
            .host_keys = std.ArrayList(HostKey).init(allocator),
            .file_path = if (file_path) |path| try allocator.dupe(u8, path) else null,
            .strict_mode = true,
        };

        if (file_path) |path| {
            known_hosts.loadFromFile(path) catch |err| {
                // Non-fatal error - file might not exist yet
                std.log.warn("Could not load known hosts from {s}: {}", .{ path, err });
            };
        }

        return known_hosts;
    }

    pub fn deinit(self: *Self) void {
        for (self.host_keys.items) |*host_key| {
            host_key.deinit(self.allocator);
        }
        self.host_keys.deinit();

        if (self.file_path) |path| {
            self.allocator.free(path);
        }
    }

    pub fn verifyHostKey(self: *Self, host: []const u8, port: u16, algorithm: HostKeyAlgorithm, key_data: []const u8) !bool {
        // Check if we have an existing key for this host
        for (self.host_keys.items) |*host_key| {
            if (host_key.matches(host, port) and host_key.algorithm == algorithm) {
                if (host_key.verify(key_data)) {
                    return true; // Key matches
                } else {
                    return HostKeyError.HostKeyMismatch; // Key exists but doesn't match
                }
            }
        }

        // No existing key found
        if (self.strict_mode) {
            return HostKeyError.HostKeyNotFound;
        } else {
            // Add new key automatically
            try self.addHostKey(host, port, algorithm, key_data);
            return true;
        }
    }

    pub fn addHostKey(self: *Self, host: []const u8, port: u16, algorithm: HostKeyAlgorithm, key_data: []const u8) !void {
        const host_key = try HostKey.init(self.allocator, host, port, algorithm, key_data);
        try self.host_keys.append(host_key);

        // Save to file if configured
        if (self.file_path) |path| {
            self.saveToFile(path) catch |err| {
                std.log.warn("Could not save known hosts to {s}: {}", .{ path, err });
            };
        }
    }

    pub fn removeHostKey(self: *Self, host: []const u8, port: u16) void {
        var i: usize = 0;
        while (i < self.host_keys.items.len) {
            if (self.host_keys.items[i].matches(host, port)) {
                var removed = self.host_keys.swapRemove(i);
                removed.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    pub fn setStrictMode(self: *Self, strict: bool) void {
        self.strict_mode = strict;
    }

    fn loadFromFile(self: *Self, file_path: []const u8) !void {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return, // File doesn't exist yet, that's OK
            else => return err,
        };
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var in_stream = buf_reader.reader();

        var line_buffer: [1024]u8 = undefined;
        while (try in_stream.readUntilDelimiterOrEof(line_buffer[0..], '\n')) |line| {
            try self.parseLine(line);
        }
    }

    fn parseLine(self: *Self, line: []const u8) !void {
        // Skip empty lines and comments
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] == '#') return;

        // Split line into components: host algorithm key
        var parts = std.mem.split(u8, trimmed, " ");
        const host_part = parts.next() orelse return;
        const algorithm_str = parts.next() orelse return;
        const key_str = parts.next() orelse return;

        // Parse host and port
        var host: []const u8 = undefined;
        var port: u16 = 22;

        if (std.mem.indexOf(u8, host_part, ":")) |colon_index| {
            host = host_part[0..colon_index];
            port = std.fmt.parseInt(u16, host_part[colon_index + 1 ..], 10) catch 22;
        } else {
            host = host_part;
        }

        // Parse algorithm
        const algorithm = HostKeyAlgorithm.fromString(algorithm_str) orelse return;

        // Decode base64 key (simplified - would need proper base64 decoder)
        // For now, just store the base64 string
        const key_data = key_str;

        try self.addHostKey(host, port, algorithm, key_data);
    }

    fn saveToFile(self: *Self, file_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        var buf_writer = std.io.bufferedWriter(file.writer());
        var out_stream = buf_writer.writer();

        for (self.host_keys.items) |host_key| {
            try out_stream.print("{s}:{d} {s} {s}\n", .{
                host_key.host,
                host_key.port,
                host_key.algorithm.toString(),
                host_key.key_data, // Would be base64-encoded in real implementation
            });
        }

        try buf_writer.flush();
    }
};

test "HostKey creation and verification" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var host_key = try HostKey.init(allocator, "example.com", 22, .ssh_ed25519, "test_key_data");
    defer host_key.deinit(allocator);

    try testing.expect(host_key.matches("example.com", 22));
    try testing.expect(!host_key.matches("example.com", 2222));
    try testing.expect(!host_key.matches("other.com", 22));

    try testing.expect(host_key.verify("test_key_data"));
    try testing.expect(!host_key.verify("wrong_key_data"));
}

test "KnownHosts host key verification" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var known_hosts = try KnownHosts.init(allocator, null);
    defer known_hosts.deinit();

    // Add a host key
    try known_hosts.addHostKey("example.com", 22, .ssh_ed25519, "test_key_data");

    // Verify with correct key
    try testing.expect(try known_hosts.verifyHostKey("example.com", 22, .ssh_ed25519, "test_key_data"));

    // Verify with wrong key should fail
    try testing.expectError(HostKeyError.HostKeyMismatch, known_hosts.verifyHostKey("example.com", 22, .ssh_ed25519, "wrong_key"));

    // Unknown host in strict mode should fail
    known_hosts.setStrictMode(true);
    try testing.expectError(HostKeyError.HostKeyNotFound, known_hosts.verifyHostKey("unknown.com", 22, .ssh_ed25519, "any_key"));

    // Unknown host in non-strict mode should succeed and add key
    known_hosts.setStrictMode(false);
    try testing.expect(try known_hosts.verifyHostKey("unknown.com", 22, .ssh_ed25519, "any_key"));
}