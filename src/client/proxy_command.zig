//! ProxyCommand Support
//!
//! Implements SSH ProxyCommand functionality for establishing connections
//! through arbitrary external commands. This enables complex connection
//! scenarios like HTTP proxies, custom jump hosts, or netcat tunneling.
//!
//! Features:
//! - Execute arbitrary proxy commands
//! - Stdin/stdout communication with proxy
//! - Environment variable expansion
//! - Token substitution (%h, %p, %r)
//! - Integration with SSH config

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ProxyCommandError = error{
    CommandFailed,
    InvalidCommand,
    SpawnFailed,
    PipeCreationFailed,
    TokenSubstitutionFailed,
} || Allocator.Error;

/// Proxy command configuration
pub const ProxyCommandConfig = struct {
    command: []const u8,
    hostname: []const u8,
    port: u16,
    username: []const u8,
};

/// ProxyCommand executor
pub const ProxyCommand = struct {
    allocator: Allocator,
    config: ProxyCommandConfig,
    process: ?std.process.Child,
    stdin: ?std.fs.File,
    stdout: ?std.fs.File,

    const Self = @This();

    pub fn init(allocator: Allocator, config: ProxyCommandConfig) !Self {
        return .{
            .allocator = allocator,
            .config = .{
                .command = try allocator.dupe(u8, config.command),
                .hostname = try allocator.dupe(u8, config.hostname),
                .port = config.port,
                .username = try allocator.dupe(u8, config.username),
            },
            .process = null,
            .stdin = null,
            .stdout = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.process) |*proc| {
            _ = proc.kill() catch {};
        }

        if (self.stdin) |f| f.close();
        if (self.stdout) |f| f.close();

        self.allocator.free(self.config.command);
        self.allocator.free(self.config.hostname);
        self.allocator.free(self.config.username);
    }

    /// Execute proxy command and return communication pipes
    pub fn execute(self: *Self) !void {
        // Perform token substitution
        const expanded_command = try self.expandTokens();
        defer self.allocator.free(expanded_command);

        // Parse command into argv
        const argv = try self.parseCommand(expanded_command);
        defer {
            for (argv) |arg| self.allocator.free(arg);
            self.allocator.free(argv);
        }

        // Spawn process with stdin/stdout pipes
        var child = std.process.Child.init(argv, self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Inherit;

        try child.spawn();

        self.process = child;
        self.stdin = child.stdin.?;
        self.stdout = child.stdout.?;
    }

    /// Expand tokens in command string
    /// %h = hostname
    /// %p = port
    /// %r = remote username
    /// %% = literal %
    fn expandTokens(self: *Self) ![]const u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        var i: usize = 0;
        while (i < self.config.command.len) {
            if (self.config.command[i] == '%' and i + 1 < self.config.command.len) {
                const token = self.config.command[i + 1];
                switch (token) {
                    'h' => try result.appendSlice(self.config.hostname),
                    'p' => {
                        var buf: [16]u8 = undefined;
                        const port_str = try std.fmt.bufPrint(&buf, "{d}", .{self.config.port});
                        try result.appendSlice(port_str);
                    },
                    'r' => try result.appendSlice(self.config.username),
                    '%' => try result.append('%'),
                    else => {
                        try result.append('%');
                        try result.append(token);
                    },
                }
                i += 2;
            } else {
                try result.append(self.config.command[i]);
                i += 1;
            }
        }

        return try result.toOwnedSlice();
    }

    /// Parse command string into argv array
    fn parseCommand(self: *Self, command: []const u8) ![][]const u8 {
        var argv = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (argv.items) |arg| self.allocator.free(arg);
            argv.deinit();
        }

        var in_quote = false;
        var current = std.ArrayList(u8).init(self.allocator);
        defer current.deinit();

        var i: usize = 0;
        while (i < command.len) {
            const ch = command[i];

            if (ch == '"') {
                in_quote = !in_quote;
                i += 1;
                continue;
            }

            if (ch == ' ' and !in_quote) {
                if (current.items.len > 0) {
                    try argv.append(try current.toOwnedSlice());
                    current.clearRetainingCapacity();
                }
                i += 1;
                continue;
            }

            try current.append(ch);
            i += 1;
        }

        if (current.items.len > 0) {
            try argv.append(try current.toOwnedSlice());
        }

        return try argv.toOwnedSlice();
    }

    /// Read from proxy stdout
    pub fn read(self: *Self, buffer: []u8) !usize {
        if (self.stdout) |f| {
            return try f.read(buffer);
        }
        return 0;
    }

    /// Write to proxy stdin
    pub fn write(self: *Self, data: []const u8) !usize {
        if (self.stdin) |f| {
            return try f.write(data);
        }
        return 0;
    }

    /// Wait for proxy process to complete
    pub fn wait(self: *Self) !std.process.Child.Term {
        if (self.process) |*proc| {
            return try proc.wait();
        }
        return .{ .Exited = 0 };
    }

    /// Kill proxy process
    pub fn kill(self: *Self) !void {
        if (self.process) |*proc| {
            try proc.kill();
        }
    }
};

/// Common proxy command templates
pub const ProxyTemplates = struct {
    /// Netcat through HTTP proxy
    pub const http_connect = "nc -X connect -x proxy.example.com:8080 %h %p";

    /// Netcat direct connection
    pub const netcat = "nc %h %p";

    /// Through SSH jump host
    pub const ssh_jump = "ssh -W %h:%p jumphost.example.com";

    /// Through socat
    pub const socat = "socat - TCP:%h:%p";

    /// OpenSSH ProxyCommand for testing
    pub const openssh_stdio = "ssh -W %h:%p proxy.example.com";
};

// Tests

test "ProxyCommand token expansion" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = ProxyCommandConfig{
        .command = "nc -X connect -x proxy:8080 %h %p",
        .hostname = "example.com",
        .port = 22,
        .username = "user",
    };

    var proxy = try ProxyCommand.init(allocator, config);
    defer proxy.deinit();

    const expanded = try proxy.expandTokens();
    defer allocator.free(expanded);

    try testing.expectEqualStrings("nc -X connect -x proxy:8080 example.com 22", expanded);
}

test "ProxyCommand parse command" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = ProxyCommandConfig{
        .command = "nc -X connect",
        .hostname = "example.com",
        .port = 22,
        .username = "user",
    };

    var proxy = try ProxyCommand.init(allocator, config);
    defer proxy.deinit();

    const argv = try proxy.parseCommand("nc -X connect -x proxy:8080");
    defer {
        for (argv) |arg| allocator.free(arg);
        allocator.free(argv);
    }

    try testing.expectEqual(@as(usize, 5), argv.len);
    try testing.expectEqualStrings("nc", argv[0]);
    try testing.expectEqualStrings("-X", argv[1]);
    try testing.expectEqualStrings("connect", argv[2]);
}

test "ProxyCommand quoted arguments" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = ProxyCommandConfig{
        .command = "test",
        .hostname = "example.com",
        .port = 22,
        .username = "user",
    };

    var proxy = try ProxyCommand.init(allocator, config);
    defer proxy.deinit();

    const argv = try proxy.parseCommand("nc \"my host\" 22");
    defer {
        for (argv) |arg| allocator.free(arg);
        allocator.free(argv);
    }

    try testing.expectEqual(@as(usize, 3), argv.len);
    try testing.expectEqualStrings("nc", argv[0]);
    try testing.expectEqualStrings("my host", argv[1]);
    try testing.expectEqualStrings("22", argv[2]);
}

test "ProxyCommand all tokens" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = ProxyCommandConfig{
        .command = "test %h %p %r %%",
        .hostname = "test.example.com",
        .port = 2222,
        .username = "testuser",
    };

    var proxy = try ProxyCommand.init(allocator, config);
    defer proxy.deinit();

    const expanded = try proxy.expandTokens();
    defer allocator.free(expanded);

    try testing.expectEqualStrings("test test.example.com 2222 testuser %", expanded);
}
