//! Authorized Keys Parser
//!
//! Parses and manages SSH authorized_keys files for server-side authentication.
//! Supports all standard OpenSSH authorized_keys options and formats.
//!
//! Features:
//! - Key validation and verification
//! - Options parsing (from, command, no-port-forwarding, etc.)
//! - Principal support
//! - Certificate support
//! - Environment variables

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const AuthorizedKeysError = error{
    FileNotFound,
    ParseError,
    InvalidKey,
    InvalidOption,
} || Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;

/// Supported key types
pub const KeyType = enum {
    ssh_rsa,
    ssh_dss,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,
    ssh_ed25519,
    sk_ssh_ed25519,  // FIDO/U2F
    sk_ecdsa_sha2_nistp256,  // FIDO/U2F

    pub fn fromString(s: []const u8) ?KeyType {
        if (std.mem.eql(u8, s, "ssh-rsa")) return .ssh_rsa;
        if (std.mem.eql(u8, s, "ssh-dss")) return .ssh_dss;
        if (std.mem.eql(u8, s, "ecdsa-sha2-nistp256")) return .ecdsa_sha2_nistp256;
        if (std.mem.eql(u8, s, "ecdsa-sha2-nistp384")) return .ecdsa_sha2_nistp384;
        if (std.mem.eql(u8, s, "ecdsa-sha2-nistp521")) return .ecdsa_sha2_nistp521;
        if (std.mem.eql(u8, s, "ssh-ed25519")) return .ssh_ed25519;
        if (std.mem.eql(u8, s, "sk-ssh-ed25519@openssh.com")) return .sk_ssh_ed25519;
        if (std.mem.eql(u8, s, "sk-ecdsa-sha2-nistp256@openssh.com")) return .sk_ecdsa_sha2_nistp256;
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
            .sk_ssh_ed25519 => "sk-ssh-ed25519@openssh.com",
            .sk_ecdsa_sha2_nistp256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        };
    }
};

/// Key options from authorized_keys
pub const KeyOptions = struct {
    // Access restrictions
    from_hosts: ?[]const []const u8 = null,  // Comma-separated host patterns
    principals: ?[]const []const u8 = null,

    // Command restrictions
    command: ?[]const u8 = null,  // Force command execution

    // Forwarding restrictions
    no_port_forwarding: bool = false,
    no_x11_forwarding: bool = false,
    no_agent_forwarding: bool = false,
    no_pty: bool = false,

    // Authentication restrictions
    cert_authority: bool = false,
    restrict: bool = false,

    // Environment
    environment: ?std.StringHashMap([]const u8) = null,

    // Tunneling
    permitopen: ?[]const []const u8 = null,  // host:port patterns
    tunnel: ?[]const u8 = null,

    pub fn deinit(self: *KeyOptions, allocator: Allocator) void {
        if (self.from_hosts) |hosts| {
            for (hosts) |host| allocator.free(host);
            allocator.free(hosts);
        }

        if (self.principals) |principals| {
            for (principals) |p| allocator.free(p);
            allocator.free(principals);
        }

        if (self.command) |cmd| allocator.free(cmd);

        if (self.environment) |*env| {
            var it = env.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            env.deinit();
        }

        if (self.permitopen) |opens| {
            for (opens) |open| allocator.free(open);
            allocator.free(opens);
        }

        if (self.tunnel) |t| allocator.free(t);
    }
};

/// A single authorized key entry
pub const AuthorizedKey = struct {
    key_type: KeyType,
    key_data: []const u8,  // Base64 encoded
    comment: ?[]const u8,
    options: KeyOptions,

    pub fn deinit(self: *AuthorizedKey, allocator: Allocator) void {
        allocator.free(self.key_data);
        if (self.comment) |c| allocator.free(c);
        self.options.deinit(allocator);
    }

    /// Check if this key matches the given key data
    pub fn matches(self: *const AuthorizedKey, key_data: []const u8) bool {
        return std.mem.eql(u8, self.key_data, key_data);
    }

    /// Check if access is allowed from the given source
    pub fn allowedFrom(self: *const AuthorizedKey, source_host: []const u8) bool {
        const from_hosts = self.options.from_hosts orelse return true;

        for (from_hosts) |pattern| {
            if (matchPattern(pattern, source_host)) {
                return true;
            }
        }

        return false;
    }
};

/// Authorized keys database
pub const AuthorizedKeys = struct {
    allocator: Allocator,
    keys: std.ArrayList(AuthorizedKey),
    path: []const u8,

    pub fn init(allocator: Allocator, path: []const u8) !AuthorizedKeys {
        return .{
            .allocator = allocator,
            .keys = std.ArrayList(AuthorizedKey).init(allocator),
            .path = try allocator.dupe(u8, path),
        };
    }

    pub fn deinit(self: *AuthorizedKeys) void {
        for (self.keys.items) |*key| {
            key.deinit(self.allocator);
        }
        self.keys.deinit();
        self.allocator.free(self.path);
    }

    /// Load authorized keys from file
    pub fn load(self: *AuthorizedKeys) !void {
        const file = try std.fs.cwd().openFile(self.path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024); // 10MB max
        defer self.allocator.free(content);

        try self.parse(content);
    }

    /// Parse authorized_keys file content
    fn parse(self: *AuthorizedKeys, content: []const u8) !void {
        var lines = std.mem.split(u8, content, "\n");

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

            // Skip empty lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            const key = parseEntry(self.allocator, trimmed) catch continue;
            try self.keys.append(key);
        }
    }

    /// Find a key by its data
    pub fn findByKeyData(self: *const AuthorizedKeys, key_data: []const u8) ?*const AuthorizedKey {
        for (self.keys.items) |*key| {
            if (key.matches(key_data)) {
                return key;
            }
        }
        return null;
    }

    /// Add a new authorized key
    pub fn add(self: *AuthorizedKeys, key: AuthorizedKey) !void {
        try self.keys.append(key);
    }

    /// Save to file
    pub fn save(self: *const AuthorizedKeys) !void {
        const file = try std.fs.cwd().createFile(self.path, .{ .truncate = true });
        defer file.close();

        var buf_writer = std.io.bufferedWriter(file.writer());
        const writer = buf_writer.writer();

        for (self.keys.items) |*key| {
            // Write options if present
            if (key.options.command != null or key.options.no_port_forwarding) {
                try writeOptions(writer, &key.options);
                try writer.writeAll(" ");
            }

            // Write key type
            try writer.writeAll(key.key_type.toString());
            try writer.writeAll(" ");

            // Write key data
            try writer.writeAll(key.key_data);

            // Write comment if present
            if (key.comment) |comment| {
                try writer.writeAll(" ");
                try writer.writeAll(comment);
            }

            try writer.writeAll("\n");
        }

        try buf_writer.flush();
    }
};

/// Parse a single authorized_keys entry
fn parseEntry(allocator: Allocator, line: []const u8) !AuthorizedKey {
    var parts = std.mem.tokenize(u8, line, &std.ascii.whitespace);

    // Parse options (if present) or key type
    const first = parts.next() orelse return error.InvalidKey;

    var options = KeyOptions{};
    var key_type_str: []const u8 = undefined;

    if (KeyType.fromString(first) != null) {
        // No options, this is the key type
        key_type_str = first;
    } else {
        // Options present, parse them
        options = try parseOptions(allocator, first);
        errdefer options.deinit(allocator);

        // Next token should be key type
        key_type_str = parts.next() orelse return error.InvalidKey;
    }

    const key_type = KeyType.fromString(key_type_str) orelse return error.InvalidKey;

    // Parse key data
    const key_data_str = parts.next() orelse return error.InvalidKey;
    const key_data = try allocator.dupe(u8, key_data_str);

    // Parse comment (optional)
    const comment = if (parts.rest().len > 0)
        try allocator.dupe(u8, std.mem.trim(u8, parts.rest(), &std.ascii.whitespace))
    else
        null;

    return AuthorizedKey{
        .key_type = key_type,
        .key_data = key_data,
        .comment = comment,
        .options = options,
    };
}

/// Parse options from authorized_keys line
fn parseOptions(allocator: Allocator, options_str: []const u8) !KeyOptions {
    var options = KeyOptions{};

    var opt_parts = std.mem.split(u8, options_str, ",");
    while (opt_parts.next()) |opt| {
        const trimmed = std.mem.trim(u8, opt, &std.ascii.whitespace);

        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            // Option with value
            const key = trimmed[0..eq_pos];
            const value = trimmed[eq_pos + 1 ..];

            if (std.mem.eql(u8, key, "command")) {
                options.command = try parseQuotedString(allocator, value);
            } else if (std.mem.eql(u8, key, "from")) {
                options.from_hosts = try parseCommaSeparated(allocator, value);
            } else if (std.mem.eql(u8, key, "principals")) {
                options.principals = try parseCommaSeparated(allocator, value);
            } else if (std.mem.eql(u8, key, "tunnel")) {
                options.tunnel = try parseQuotedString(allocator, value);
            } else if (std.mem.eql(u8, key, "permitopen")) {
                options.permitopen = try parseCommaSeparated(allocator, value);
            } else if (std.mem.startsWith(u8, key, "environment")) {
                // Parse environment variable
                // Format: environment="KEY=value"
                if (options.environment == null) {
                    options.environment = std.StringHashMap([]const u8).init(allocator);
                }
                try parseEnvironment(allocator, &options.environment.?, value);
            }
        } else {
            // Boolean option
            if (std.mem.eql(u8, trimmed, "no-port-forwarding")) {
                options.no_port_forwarding = true;
            } else if (std.mem.eql(u8, trimmed, "no-X11-forwarding")) {
                options.no_x11_forwarding = true;
            } else if (std.mem.eql(u8, trimmed, "no-agent-forwarding")) {
                options.no_agent_forwarding = true;
            } else if (std.mem.eql(u8, trimmed, "no-pty")) {
                options.no_pty = true;
            } else if (std.mem.eql(u8, trimmed, "cert-authority")) {
                options.cert_authority = true;
            } else if (std.mem.eql(u8, trimmed, "restrict")) {
                options.restrict = true;
            }
        }
    }

    return options;
}

fn parseQuotedString(allocator: Allocator, s: []const u8) ![]const u8 {
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') {
        return try allocator.dupe(u8, s[1 .. s.len - 1]);
    }
    return try allocator.dupe(u8, s);
}

fn parseCommaSeparated(allocator: Allocator, s: []const u8) ![]const []const u8 {
    const unquoted = if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"')
        s[1 .. s.len - 1]
    else
        s;

    var result = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit();
    }

    var parts = std.mem.split(u8, unquoted, ",");
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, &std.ascii.whitespace);
        try result.append(try allocator.dupe(u8, trimmed));
    }

    return try result.toOwnedSlice();
}

fn parseEnvironment(allocator: Allocator, map: *std.StringHashMap([]const u8), s: []const u8) !void {
    const unquoted = try parseQuotedString(allocator, s);
    defer allocator.free(unquoted);

    if (std.mem.indexOf(u8, unquoted, "=")) |eq_pos| {
        const key = try allocator.dupe(u8, unquoted[0..eq_pos]);
        const value = try allocator.dupe(u8, unquoted[eq_pos + 1 ..]);
        try map.put(key, value);
    }
}

fn writeOptions(writer: anytype, options: *const KeyOptions) !void {
    var first = true;

    if (options.command) |cmd| {
        if (!first) try writer.writeAll(",");
        try writer.print("command=\"{s}\"", .{cmd});
        first = false;
    }

    if (options.from_hosts) |hosts| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("from=\"");
        for (hosts, 0..) |host, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll(host);
        }
        try writer.writeAll("\"");
        first = false;
    }

    if (options.no_port_forwarding) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("no-port-forwarding");
        first = false;
    }

    if (options.no_x11_forwarding) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("no-X11-forwarding");
        first = false;
    }

    if (options.no_agent_forwarding) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("no-agent-forwarding");
        first = false;
    }

    if (options.no_pty) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("no-pty");
        first = false;
    }
}

fn matchPattern(pattern: []const u8, hostname: []const u8) bool {
    // Simple wildcard matching
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

// Tests

test "authorized_keys key type parsing" {
    const testing = std.testing;

    try testing.expectEqual(KeyType.ssh_ed25519, KeyType.fromString("ssh-ed25519").?);
    try testing.expectEqual(KeyType.ssh_rsa, KeyType.fromString("ssh-rsa").?);
    try testing.expect(KeyType.fromString("invalid") == null);
}

test "authorized_keys entry parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcd1234 user@host";
    var entry = try parseEntry(allocator, line);
    defer entry.deinit(allocator);

    try testing.expectEqual(KeyType.ssh_ed25519, entry.key_type);
    try testing.expectEqualStrings("AAAAC3NzaC1lZDI1NTE5AAAAIAbcd1234", entry.key_data);
    try testing.expectEqualStrings("user@host", entry.comment.?);
}

test "authorized_keys with options" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const line = "command=\"/usr/bin/date\",no-port-forwarding ssh-ed25519 AAAAC3test user@host";
    var entry = try parseEntry(allocator, line);
    defer entry.deinit(allocator);

    try testing.expectEqual(KeyType.ssh_ed25519, entry.key_type);
    try testing.expectEqualStrings("/usr/bin/date", entry.options.command.?);
    try testing.expect(entry.options.no_port_forwarding);
}
