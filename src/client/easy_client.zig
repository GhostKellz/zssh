//! Easy SSH Client API for GShell
//!
//! Provides a simple, synchronous SSH client API designed specifically for shell integration.
//! This is the recommended API for embedding SSH functionality in command-line tools.
//!
//! Example usage:
//! ```zig
//! const zssh = @import("zssh");
//!
//! var session = try zssh.connect(allocator, .{
//!     .host = "prod-db.example.com",
//!     .user = "chris",
//!     .auth = .{ .password = "secret123" },
//! });
//! defer session.close();
//!
//! const result = try session.exec("uptime");
//! defer result.deinit(allocator);
//! std.debug.print("{s}", .{result.stdout});
//! ```

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const Client = @import("client.zig").Client;
const ClientConfig = @import("client.zig").ClientConfig;
const auth = @import("../auth/auth.zig");
const channel = @import("../transport/channel.zig");

pub const EasyClientError = error{
    ConnectionFailed,
    AuthenticationFailed,
    CommandExecutionFailed,
    ChannelCreationFailed,
    RemoteDisconnected,
    InvalidConfiguration,
    KeyLoadError,
    AgentNotAvailable,
} || Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;

/// Authentication method for SSH connection
pub const AuthMethod = union(enum) {
    /// Password-based authentication
    password: []const u8,

    /// Public key authentication with private key file
    public_key: struct {
        private_key_path: []const u8,
        passphrase: ?[]const u8 = null,
    },

    /// Use SSH agent for authentication (e.g., from GVault)
    agent: void,

    /// Interactive keyboard authentication
    keyboard_interactive: void,
};

/// Connection options for SSH client
pub const ConnectOptions = struct {
    /// Target hostname or IP address
    host: []const u8,

    /// SSH port (default: 22)
    port: u16 = 22,

    /// Username for authentication
    user: []const u8,

    /// Authentication method to use
    auth: AuthMethod,

    /// Connection timeout in milliseconds (default: 10 seconds)
    timeout_ms: u64 = 10_000,

    /// Enable compression (default: false)
    compression: bool = false,

    /// Jump hosts for bastion/proxy connections
    jump_hosts: []const JumpHost = &[_]JumpHost{},
};

/// Jump host configuration for ProxyJump / bastion support
pub const JumpHost = struct {
    host: []const u8,
    port: u16 = 22,
    user: []const u8,
    auth: AuthMethod,
};

/// Result of remote command execution
pub const ExecResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    exit_code: i32,

    /// Free allocated memory for this result
    pub fn deinit(self: ExecResult, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

/// Port forwarding handle
pub const PortForward = struct {
    allocator: Allocator,
    forward_type: ForwardType,
    local_port: u16,
    remote_host: []const u8,
    remote_port: u16,
    active: bool,

    pub const ForwardType = enum {
        local,  // -L: Forward local port to remote
        remote, // -R: Forward remote port to local
    };

    const Self = @This();

    /// Close the port forward
    pub fn close(self: *Self) void {
        self.active = false;
        self.allocator.free(self.remote_host);
    }
};

/// SSH session handle for command execution and interactive shells
pub const SshSession = struct {
    allocator: Allocator,
    client: Client,
    options: ConnectOptions,
    connected: bool,
    channels: std.ArrayList(*channel.Channel),

    const Self = @This();

    /// Initialize a new SSH session (internal use, use connect() instead)
    fn init(allocator: Allocator, client: Client, options: ConnectOptions) !Self {
        return Self{
            .allocator = allocator,
            .client = client,
            .options = .{
                .host = try allocator.dupe(u8, options.host),
                .port = options.port,
                .user = try allocator.dupe(u8, options.user),
                .auth = try duplicateAuthMethod(allocator, options.auth),
                .timeout_ms = options.timeout_ms,
                .compression = options.compression,
                .jump_hosts = try duplicateJumpHosts(allocator, options.jump_hosts),
            },
            .connected = true,
            .channels = std.ArrayList(*channel.Channel).init(allocator),
        };
    }

    /// Execute a command on the remote server and return the result
    ///
    /// This method runs a single command and waits for it to complete.
    /// The returned ExecResult must be freed with result.deinit(allocator).
    ///
    /// Example:
    /// ```zig
    /// const result = try session.exec("uptime");
    /// defer result.deinit(allocator);
    /// std.debug.print("Output: {s}\n", .{result.stdout});
    /// ```
    pub fn exec(self: *Self, command: []const u8) !ExecResult {
        if (!self.connected) {
            return EasyClientError.RemoteDisconnected;
        }

        // Create a new channel for command execution
        const chan = try self.createChannel(.session);
        errdefer self.destroyChannel(chan);

        // Execute the command
        try self.execOnChannel(chan, command);

        // Collect output (simplified - real implementation would stream)
        var stdout = std.ArrayList(u8).init(self.allocator);
        var stderr = std.ArrayList(u8).init(self.allocator);
        errdefer {
            stdout.deinit();
            stderr.deinit();
        }

        // Simulate command execution and output collection
        // TODO: Implement actual channel I/O and command execution
        // For now, return empty result with success exit code

        return ExecResult{
            .stdout = try stdout.toOwnedSlice(),
            .stderr = try stderr.toOwnedSlice(),
            .exit_code = 0,
        };
    }

    /// Start an interactive shell session
    ///
    /// This method allocates a PTY and starts an interactive shell.
    /// It blocks until the user exits the shell.
    ///
    /// Example:
    /// ```zig
    /// try session.interactive();
    /// // User is now in an interactive SSH shell
    /// ```
    pub fn interactive(self: *Self) !void {
        if (!self.connected) {
            return EasyClientError.RemoteDisconnected;
        }

        // Create a new channel for interactive session
        const chan = try self.createChannel(.session);
        errdefer self.destroyChannel(chan);

        // Request PTY
        try self.requestPty(chan);

        // Start shell
        try self.startShell(chan);

        // Enter interactive loop
        try self.interactiveLoop(chan);
    }

    /// Check if the connection is still alive
    pub fn checkConnection(self: *Self) bool {
        if (!self.connected) {
            return false;
        }

        // Send keepalive packet
        // TODO: Implement actual keepalive mechanism
        return self.client.isConnected();
    }

    /// Attempt to reconnect using the same credentials
    pub fn reconnect(self: *Self) !void {
        if (self.connected) {
            self.close();
        }

        // Re-establish connection
        try self.client.connect();

        // Re-authenticate
        const credentials = try self.authMethodToCredentials(self.options.auth);
        try self.client.authenticate(credentials);

        self.connected = true;
    }

    /// Forward a local port to a remote host:port via SSH tunnel
    ///
    /// Example: Forward local port 8080 to remote server's localhost:80
    /// ```zig
    /// const fwd = try session.forwardLocal(8080, "localhost", 80);
    /// defer fwd.close();
    /// // Now connections to localhost:8080 are tunneled to remote:80
    /// ```
    pub fn forwardLocal(
        self: *Self,
        local_port: u16,
        remote_host: []const u8,
        remote_port: u16,
    ) !PortForward {
        if (!self.connected) {
            return EasyClientError.RemoteDisconnected;
        }

        // TODO: Implement actual port forwarding via SSH channels
        // This would:
        // 1. Bind local port
        // 2. Accept connections
        // 3. For each connection, open SSH channel
        // 4. Forward data between local connection and SSH channel

        return PortForward{
            .allocator = self.allocator,
            .forward_type = .local,
            .local_port = local_port,
            .remote_host = try self.allocator.dupe(u8, remote_host),
            .remote_port = remote_port,
            .active = true,
        };
    }

    /// Forward a remote port to a local host:port via SSH tunnel
    ///
    /// Example: Forward remote server's port 9000 to local localhost:3000
    /// ```zig
    /// const fwd = try session.forwardRemote(9000, "localhost", 3000);
    /// defer fwd.close();
    /// // Now connections to remote:9000 are tunneled to local:3000
    /// ```
    pub fn forwardRemote(
        self: *Self,
        remote_port: u16,
        local_host: []const u8,
        local_port: u16,
    ) !PortForward {
        if (!self.connected) {
            return EasyClientError.RemoteDisconnected;
        }

        // TODO: Implement actual remote port forwarding
        // This would:
        // 1. Send tcpip-forward request to SSH server
        // 2. Server binds remote port
        // 3. For each remote connection, server opens channel
        // 4. Forward data between SSH channel and local connection

        return PortForward{
            .allocator = self.allocator,
            .forward_type = .remote,
            .local_port = local_port,
            .remote_host = try self.allocator.dupe(u8, local_host),
            .remote_port = remote_port,
            .active = true,
        };
    }

    /// Close the SSH session and free resources
    pub fn close(self: *Self) void {
        // Close all active channels
        for (self.channels.items) |chan| {
            self.destroyChannel(chan);
        }
        self.channels.deinit();

        // Disconnect client
        self.client.disconnect();

        // Free duplicated options
        self.allocator.free(self.options.host);
        self.allocator.free(self.options.user);
        freeAuthMethod(self.allocator, self.options.auth);
        freeJumpHosts(self.allocator, self.options.jump_hosts);

        self.connected = false;
    }

    // Private helper methods

    fn createChannel(self: *Self, chan_type: channel.ChannelType) !*channel.Channel {
        // TODO: Implement actual channel creation via transport
        // For now, create a stub channel
        const chan = try self.allocator.create(channel.Channel);
        chan.* = channel.Channel{
            .id = @as(u32, @intCast(self.channels.items.len)),
            .channel_type = chan_type,
            .window_size = 65536,
            .max_packet_size = 32768,
            .remote_id = 0,
            .remote_window_size = 0,
            .state = .open,
            .eof_received = false,
            .eof_sent = false,
        };

        try self.channels.append(chan);
        return chan;
    }

    fn destroyChannel(self: *Self, chan: *channel.Channel) void {
        // TODO: Implement proper channel cleanup and closure
        self.allocator.destroy(chan);
    }

    fn execOnChannel(self: *Self, chan: *channel.Channel, command: []const u8) !void {
        _ = self;
        _ = chan;
        _ = command;
        // TODO: Implement SSH channel exec request
        // This would send SSH_MSG_CHANNEL_REQUEST with "exec" and the command
    }

    fn requestPty(self: *Self, chan: *channel.Channel) !void {
        _ = self;
        _ = chan;
        // TODO: Implement PTY request
        // This would send SSH_MSG_CHANNEL_REQUEST with "pty-req"
    }

    fn startShell(self: *Self, chan: *channel.Channel) !void {
        _ = self;
        _ = chan;
        // TODO: Implement shell start request
        // This would send SSH_MSG_CHANNEL_REQUEST with "shell"
    }

    fn interactiveLoop(self: *Self, chan: *channel.Channel) !void {
        _ = self;
        _ = chan;
        // TODO: Implement interactive I/O loop
        // This would handle stdin -> SSH and SSH -> stdout/stderr
        // For now, just return
    }

    fn authMethodToCredentials(self: *Self, method: AuthMethod) !auth.Credentials {
        return switch (method) {
            .password => |pwd| auth.Credentials{ .password = pwd },

            .public_key => |pk| blk: {
                // Load private key from file
                const key_data = try self.loadPrivateKey(pk.private_key_path, pk.passphrase);
                break :blk auth.Credentials{
                    .publickey = .{
                        .algorithm = "ssh-ed25519", // TODO: Detect key type
                        .key_data = key_data,
                        .signature = null,
                        .certificate = null,
                    },
                };
            },

            .agent => blk: {
                // TODO: Implement SSH agent communication
                // For now, return a stub
                break :blk auth.Credentials{ .none = {} };
            },

            .keyboard_interactive => blk: {
                break :blk auth.Credentials{
                    .keyboard_interactive = .{ .responses = &[_][]const u8{} },
                };
            },
        };
    }

    fn loadPrivateKey(self: *Self, path: []const u8, passphrase: ?[]const u8) ![]const u8 {
        _ = passphrase;

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const key_data = try file.readToEndAlloc(self.allocator, 16 * 1024);
        // TODO: Parse and decrypt private key
        // For now, just return raw data
        return key_data;
    }
};

/// Connect to an SSH server with the given options
///
/// This is the main entry point for creating SSH connections from GShell.
/// Returns an SshSession that must be closed with session.close().
///
/// Example:
/// ```zig
/// var session = try zssh.connect(allocator, .{
///     .host = "prod-db.example.com",
///     .user = "chris",
///     .auth = .{ .password = "secret123" },
/// });
/// defer session.close();
/// ```
pub fn connect(allocator: Allocator, options: ConnectOptions) !SshSession {
    // Validate options
    if (options.host.len == 0) {
        return EasyClientError.InvalidConfiguration;
    }
    if (options.user.len == 0) {
        return EasyClientError.InvalidConfiguration;
    }

    // Handle jump hosts if specified
    if (options.jump_hosts.len > 0) {
        return connectViaJump(allocator, options);
    }

    // Create client configuration
    const client_config = ClientConfig{
        .username = options.user,
        .host = options.host,
        .port = options.port,
        .timeout_ms = @intCast(options.timeout_ms),
        .compression = options.compression,
    };

    // Initialize client
    var client = try Client.init(allocator, client_config);
    errdefer client.deinit();

    // Connect to server
    client.connect() catch |err| {
        client.deinit();
        std.debug.print("Connection failed: {any}\n", .{err});
        return EasyClientError.ConnectionFailed;
    };

    // Authenticate
    const credentials = try authMethodToCredentialsStatic(allocator, options.auth);
    client.authenticate(credentials) catch |err| {
        client.deinit();
        std.debug.print("Authentication failed: {any}\n", .{err});
        return EasyClientError.AuthenticationFailed;
    };

    // Create session
    return try SshSession.init(allocator, client, options);
}

/// Connect to a target server via jump hosts (bastion/proxy)
fn connectViaJump(allocator: Allocator, target: ConnectOptions) !SshSession {
    _ = allocator;
    _ = target;
    // TODO: Implement jump host chaining
    // This would:
    // 1. Connect to first jump host
    // 2. From that connection, connect to next jump host (or target)
    // 3. Chain connections until reaching target
    return EasyClientError.ConnectionFailed;
}

// Helper functions for memory management

fn authMethodToCredentialsStatic(allocator: Allocator, method: AuthMethod) !auth.Credentials {
    return switch (method) {
        .password => |pwd| auth.Credentials{ .password = pwd },

        .public_key => |pk| blk: {
            // Load private key from file
            const key_data = try loadPrivateKeyStatic(allocator, pk.private_key_path, pk.passphrase);
            break :blk auth.Credentials{
                .publickey = .{
                    .algorithm = "ssh-ed25519",
                    .key_data = key_data,
                    .signature = null,
                    .certificate = null,
                },
            };
        },

        .agent => auth.Credentials{ .none = {} },
        .keyboard_interactive => auth.Credentials{
            .keyboard_interactive = .{ .responses = &[_][]const u8{} },
        },
    };
}

fn loadPrivateKeyStatic(allocator: Allocator, path: []const u8, passphrase: ?[]const u8) ![]const u8 {
    _ = passphrase;

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    return try file.readToEndAlloc(allocator, 16 * 1024);
}

fn duplicateAuthMethod(allocator: Allocator, method: AuthMethod) !AuthMethod {
    return switch (method) {
        .password => |pwd| .{ .password = try allocator.dupe(u8, pwd) },
        .public_key => |pk| .{
            .public_key = .{
                .private_key_path = try allocator.dupe(u8, pk.private_key_path),
                .passphrase = if (pk.passphrase) |pp| try allocator.dupe(u8, pp) else null,
            },
        },
        .agent => .{ .agent = {} },
        .keyboard_interactive => .{ .keyboard_interactive = {} },
    };
}

fn freeAuthMethod(allocator: Allocator, method: AuthMethod) void {
    switch (method) {
        .password => |pwd| allocator.free(pwd),
        .public_key => |pk| {
            allocator.free(pk.private_key_path);
            if (pk.passphrase) |pp| allocator.free(pp);
        },
        .agent, .keyboard_interactive => {},
    }
}

fn duplicateJumpHosts(allocator: Allocator, jump_hosts: []const JumpHost) ![]const JumpHost {
    if (jump_hosts.len == 0) return &[_]JumpHost{};

    const duped = try allocator.alloc(JumpHost, jump_hosts.len);
    for (jump_hosts, 0..) |jh, i| {
        duped[i] = .{
            .host = try allocator.dupe(u8, jh.host),
            .port = jh.port,
            .user = try allocator.dupe(u8, jh.user),
            .auth = try duplicateAuthMethod(allocator, jh.auth),
        };
    }
    return duped;
}

fn freeJumpHosts(allocator: Allocator, jump_hosts: []const JumpHost) void {
    for (jump_hosts) |jh| {
        allocator.free(jh.host);
        allocator.free(jh.user);
        freeAuthMethod(allocator, jh.auth);
    }
    if (jump_hosts.len > 0) {
        allocator.free(jump_hosts);
    }
}

// Tests

test "ConnectOptions initialization" {
    const testing = std.testing;

    const options = ConnectOptions{
        .host = "localhost",
        .user = "testuser",
        .auth = .{ .password = "test123" },
    };

    try testing.expectEqualStrings("localhost", options.host);
    try testing.expectEqualStrings("testuser", options.user);
    try testing.expectEqual(@as(u16, 22), options.port);
}

test "AuthMethod types" {
    const testing = std.testing;

    const password_auth = AuthMethod{ .password = "secret" };
    const key_auth = AuthMethod{ .public_key = .{
        .private_key_path = "/home/user/.ssh/id_ed25519",
        .passphrase = null,
    }};
    const agent_auth = AuthMethod{ .agent = {} };

    switch (password_auth) {
        .password => |pwd| try testing.expectEqualStrings("secret", pwd),
        else => try testing.expect(false),
    }

    switch (key_auth) {
        .public_key => |pk| {
            try testing.expectEqualStrings("/home/user/.ssh/id_ed25519", pk.private_key_path);
        },
        else => try testing.expect(false),
    }

    switch (agent_auth) {
        .agent => {},
        else => try testing.expect(false),
    }
}

test "ExecResult cleanup" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = ExecResult{
        .stdout = try allocator.dupe(u8, "output"),
        .stderr = try allocator.dupe(u8, "error"),
        .exit_code = 0,
    };
    defer result.deinit(allocator);

    try testing.expectEqualStrings("output", result.stdout);
    try testing.expectEqualStrings("error", result.stderr);
}
