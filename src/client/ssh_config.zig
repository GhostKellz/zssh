//! SSH Config File Parser
//!
//! Parses OpenSSH client configuration files (~/.ssh/config, /etc/ssh/ssh_config)
//! and provides a clean API for looking up connection settings.
//!
//! Supports all major SSH config directives including:
//! - Host patterns and matching
//! - ProxyJump and ProxyCommand
//! - Port and User settings
//! - IdentityFile specifications
//! - ForwardAgent, ForwardX11
//! - And many more...

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ConfigError = error{
    FileNotFound,
    ParseError,
    InvalidDirective,
} || Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;

/// A single directive in the SSH config
pub const Directive = struct {
    key: []const u8,
    value: []const u8,

    pub fn deinit(self: *Directive, allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

/// A Host block in the SSH config
pub const HostBlock = struct {
    patterns: []const []const u8,  // Host patterns (can be multiple)
    directives: std.ArrayList(Directive),

    pub fn init(allocator: Allocator, patterns: []const []const u8) !HostBlock {
        return HostBlock{
            .patterns = patterns,
            .directives = std.ArrayList(Directive).init(allocator),
        };
    }

    pub fn deinit(self: *HostBlock, allocator: Allocator) void {
        for (self.patterns) |pattern| {
            allocator.free(pattern);
        }
        allocator.free(self.patterns);

        for (self.directives.items) |*directive| {
            directive.deinit(allocator);
        }
        self.directives.deinit();
    }

    pub fn addDirective(self: *HostBlock, key: []const u8, value: []const u8) !void {
        try self.directives.append(.{
            .key = key,
            .value = value,
        });
    }

    pub fn get(self: *const HostBlock, key: []const u8) ?[]const u8 {
        for (self.directives.items) |directive| {
            if (std.ascii.eqlIgnoreCase(directive.key, key)) {
                return directive.value;
            }
        }
        return null;
    }

    pub fn matches(self: *const HostBlock, hostname: []const u8) bool {
        for (self.patterns) |pattern| {
            if (matchPattern(pattern, hostname)) {
                return true;
            }
        }
        return false;
    }
};

/// SSH configuration
pub const SshConfig = struct {
    allocator: Allocator,
    host_blocks: std.ArrayList(HostBlock),
    global_directives: std.ArrayList(Directive),

    pub fn init(allocator: Allocator) SshConfig {
        return .{
            .allocator = allocator,
            .host_blocks = std.ArrayList(HostBlock).init(allocator),
            .global_directives = std.ArrayList(Directive).init(allocator),
        };
    }

    pub fn deinit(self: *SshConfig) void {
        for (self.host_blocks.items) |*block| {
            block.deinit(self.allocator);
        }
        self.host_blocks.deinit();

        for (self.global_directives.items) |*directive| {
            directive.deinit(self.allocator);
        }
        self.global_directives.deinit();
    }

    /// Parse SSH config from a file
    pub fn parseFile(allocator: Allocator, path: []const u8) !SshConfig {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
        defer allocator.free(content);

        return try parse(allocator, content);
    }

    /// Parse SSH config from memory
    pub fn parse(allocator: Allocator, content: []const u8) !SshConfig {
        var config = SshConfig.init(allocator);
        errdefer config.deinit();

        var lines = std.mem.split(u8, content, "\n");
        var current_host_block: ?*HostBlock = null;

        while (lines.next()) |line| {
            // Trim whitespace
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

            // Skip empty lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            // Parse directive
            var parts = std.mem.tokenize(u8, trimmed, &std.ascii.whitespace);
            const key = parts.next() orelse continue;

            if (std.ascii.eqlIgnoreCase(key, "Host")) {
                // Start new Host block
                var patterns = std.ArrayList([]const u8).init(allocator);
                errdefer {
                    for (patterns.items) |p| allocator.free(p);
                    patterns.deinit();
                }

                while (parts.next()) |pattern| {
                    try patterns.append(try allocator.dupe(u8, pattern));
                }

                const host_block = try config.host_blocks.addOne();
                host_block.* = try HostBlock.init(allocator, try patterns.toOwnedSlice());
                current_host_block = host_block;
            } else if (std.ascii.eqlIgnoreCase(key, "Match")) {
                // Match blocks not yet supported
                current_host_block = null;
            } else {
                // Regular directive
                const remaining = parts.rest();
                const value = std.mem.trim(u8, remaining, &std.ascii.whitespace);

                const key_copy = try allocator.dupe(u8, key);
                const value_copy = try allocator.dupe(u8, value);

                if (current_host_block) |block| {
                    try block.addDirective(key_copy, value_copy);
                } else {
                    try config.global_directives.append(.{
                        .key = key_copy,
                        .value = value_copy,
                    });
                }
            }
        }

        return config;
    }

    /// Get configuration for a specific hostname
    pub fn getConfigForHost(self: *const SshConfig, hostname: []const u8) HostConfig {
        var result = HostConfig{
            .hostname = hostname,
            .port = 22,
            .user = null,
            .identity_files = std.ArrayList([]const u8).init(self.allocator),
            .proxy_jump = null,
            .proxy_command = null,
            .forward_agent = false,
            .forward_x11 = false,
            .compression = false,
        };

        // Apply global directives first
        for (self.global_directives.items) |directive| {
            applyDirective(&result, directive.key, directive.value) catch {};
        }

        // Apply matching host blocks (in order)
        for (self.host_blocks.items) |*block| {
            if (block.matches(hostname)) {
                for (block.directives.items) |directive| {
                    applyDirective(&result, directive.key, directive.value) catch {};
                }
            }
        }

        return result;
    }
};

/// Configuration resolved for a specific host
pub const HostConfig = struct {
    hostname: []const u8,
    port: u16,
    user: ?[]const u8,
    identity_files: std.ArrayList([]const u8),
    proxy_jump: ?[]const u8,
    proxy_command: ?[]const u8,
    forward_agent: bool,
    forward_x11: bool,
    compression: bool,

    pub fn deinit(self: *HostConfig) void {
        self.identity_files.deinit();
    }
};

fn applyDirective(config: *HostConfig, key: []const u8, value: []const u8) !void {
    if (std.ascii.eqlIgnoreCase(key, "Port")) {
        config.port = try std.fmt.parseInt(u16, value, 10);
    } else if (std.ascii.eqlIgnoreCase(key, "User")) {
        config.user = value;
    } else if (std.ascii.eqlIgnoreCase(key, "IdentityFile")) {
        try config.identity_files.append(value);
    } else if (std.ascii.eqlIgnoreCase(key, "ProxyJump")) {
        config.proxy_jump = value;
    } else if (std.ascii.eqlIgnoreCase(key, "ProxyCommand")) {
        config.proxy_command = value;
    } else if (std.ascii.eqlIgnoreCase(key, "ForwardAgent")) {
        config.forward_agent = yesOrNo(value);
    } else if (std.ascii.eqlIgnoreCase(key, "ForwardX11")) {
        config.forward_x11 = yesOrNo(value);
    } else if (std.ascii.eqlIgnoreCase(key, "Compression")) {
        config.compression = yesOrNo(value);
    }
}

fn yesOrNo(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "yes") or std.ascii.eqlIgnoreCase(value, "true");
}

/// Match a hostname against an SSH config pattern
/// Supports wildcards: * and ?
fn matchPattern(pattern: []const u8, hostname: []const u8) bool {
    // Handle negation patterns (starting with !)
    if (pattern.len > 0 and pattern[0] == '!') {
        return !matchPattern(pattern[1..], hostname);
    }

    // Simple wildcard matching
    if (std.mem.indexOf(u8, pattern, "*")) |_| {
        return wildcardMatch(pattern, hostname);
    }

    // Exact match
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

test "SSH config pattern matching" {
    const testing = std.testing;

    try testing.expect(matchPattern("example.com", "example.com"));
    try testing.expect(matchPattern("*.example.com", "host.example.com"));
    try testing.expect(matchPattern("*.example.com", "sub.host.example.com"));
    try testing.expect(matchPattern("192.168.1.*", "192.168.1.1"));
    try testing.expect(matchPattern("server?", "server1"));
    try testing.expect(!matchPattern("example.com", "other.com"));
}

test "SSH config parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config_text =
        \\# Test SSH config
        \\Host prod-*
        \\    User admin
        \\    Port 2222
        \\    IdentityFile ~/.ssh/prod_key
        \\
        \\Host dev-*
        \\    User developer
        \\    ForwardAgent yes
        \\
        \\Host *
        \\    Port 22
        \\    Compression yes
    ;

    var config = try SshConfig.parse(allocator, config_text);
    defer config.deinit();

    try testing.expectEqual(@as(usize, 3), config.host_blocks.items.len);

    // Check prod-* block
    const prod_block = &config.host_blocks.items[0];
    try testing.expect(prod_block.matches("prod-db"));
    try testing.expect(!prod_block.matches("dev-server"));

    const user = prod_block.get("User");
    try testing.expect(user != null);
    try testing.expectEqualStrings("admin", user.?);
}

test "SSH config for host" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config_text =
        \\Host prod-db
        \\    User admin
        \\    Port 2222
        \\    IdentityFile ~/.ssh/prod_key
        \\    ForwardAgent yes
    ;

    var config = try SshConfig.parse(allocator, config_text);
    defer config.deinit();

    var host_config = config.getConfigForHost("prod-db");
    defer host_config.deinit();

    try testing.expectEqual(@as(u16, 2222), host_config.port);
    try testing.expectEqualStrings("admin", host_config.user.?);
    try testing.expect(host_config.forward_agent);
    try testing.expectEqual(@as(usize, 1), host_config.identity_files.items.len);
}
