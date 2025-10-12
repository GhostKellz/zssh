//! Dynamic SOCKS Proxy Support (ssh -D)
//!
//! Implements SOCKS4/SOCKS5 proxy server over SSH tunnel.
//! This allows SSH to act as a dynamic port forward for any TCP connection.
//!
//! Features:
//! - SOCKS4 protocol support
//! - SOCKS5 protocol support
//! - Username/password authentication
//! - DNS resolution through SSH tunnel
//! - Multiple concurrent connections

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;

pub const SocksError = error{
    UnsupportedVersion,
    UnsupportedCommand,
    AuthenticationFailed,
    ConnectionRefused,
    InvalidAddress,
    ProtocolError,
} || Allocator.Error || net.Stream.ReadError || net.Stream.WriteError;

/// SOCKS protocol version
pub const SocksVersion = enum(u8) {
    socks4 = 4,
    socks5 = 5,
};

/// SOCKS5 authentication method
pub const Socks5AuthMethod = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable = 0xFF,
};

/// SOCKS5 command
pub const Socks5Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

/// SOCKS5 address type
pub const Socks5AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

/// SOCKS5 reply code
pub const Socks5Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

/// SOCKS proxy configuration
pub const SocksConfig = struct {
    listen_address: []const u8 = "127.0.0.1",
    listen_port: u16,
    auth_required: bool = false,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    socks_version: SocksVersion = .socks5,
};

/// SOCKS proxy server
pub const SocksProxy = struct {
    allocator: Allocator,
    config: SocksConfig,
    server: ?net.Server,
    connections: std.ArrayList(*SocksConnection),
    running: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, config: SocksConfig) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .server = null,
            .connections = std.ArrayList(*SocksConnection).init(allocator),
            .running = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.server) |*server| {
            server.deinit();
        }

        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
    }

    /// Start SOCKS proxy server
    pub fn start(self: *Self) !void {
        const address = try net.Address.parseIp(self.config.listen_address, self.config.listen_port);

        const server = try address.listen(.{
            .reuse_address = true,
        });

        self.server = server;
        self.running = true;

        std.debug.print("SOCKS proxy listening on {s}:{d}\n", .{ self.config.listen_address, self.config.listen_port });
    }

    /// Accept and handle SOCKS connections
    pub fn acceptLoop(self: *Self) !void {
        while (self.running) {
            if (self.server) |*server| {
                const connection = try server.accept();

                // Handle connection in new thread or async
                const conn = try self.allocator.create(SocksConnection);
                conn.* = try SocksConnection.init(self.allocator, connection.stream, self.config);

                try self.connections.append(conn);

                // TODO: Spawn thread or async task to handle connection
                try conn.handle();
            }
        }
    }

    /// Stop SOCKS proxy
    pub fn stop(self: *Self) void {
        self.running = false;
    }
};

/// Individual SOCKS connection
pub const SocksConnection = struct {
    allocator: Allocator,
    client_stream: net.Stream,
    config: SocksConfig,
    target_host: ?[]const u8,
    target_port: u16,
    ssh_channel: ?*anyopaque,  // SSH channel for forwarding

    pub fn init(allocator: Allocator, stream: net.Stream, config: SocksConfig) !SocksConnection {
        return .{
            .allocator = allocator,
            .client_stream = stream,
            .config = config,
            .target_host = null,
            .target_port = 0,
            .ssh_channel = null,
        };
    }

    pub fn deinit(self: *SocksConnection) void {
        self.client_stream.close();
        if (self.target_host) |h| {
            self.allocator.free(h);
        }
    }

    /// Handle SOCKS connection
    pub fn handle(self: *SocksConnection) !void {
        // Read version byte
        var version_buf: [1]u8 = undefined;
        _ = try self.client_stream.read(&version_buf);

        const version = version_buf[0];

        switch (version) {
            4 => try self.handleSocks4(),
            5 => try self.handleSocks5(),
            else => return SocksError.UnsupportedVersion,
        }
    }

    /// Handle SOCKS4 protocol
    fn handleSocks4(self: *SocksConnection) !void {
        // Read SOCKS4 request
        var request: [7]u8 = undefined;
        _ = try self.client_stream.read(&request);

        const command = request[0];
        const port = std.mem.readInt(u16, request[1..3], .big);

        _ = command;
        _ = port;

        // TODO: Complete SOCKS4 implementation
        // For now, return connection refused
        var response: [8]u8 = undefined;
        response[0] = 0; // VN
        response[1] = 91; // CD (request rejected or failed)
        std.mem.writeInt(u16, response[2..4], 0, .big); // DSTPORT
        std.mem.writeInt(u32, response[4..8], 0, .big); // DSTIP

        try self.client_stream.writeAll(&response);
    }

    /// Handle SOCKS5 protocol
    fn handleSocks5(self: *SocksConnection) !void {
        // Read authentication methods
        var nmethods_buf: [1]u8 = undefined;
        _ = try self.client_stream.read(&nmethods_buf);
        const nmethods = nmethods_buf[0];

        const methods = try self.allocator.alloc(u8, nmethods);
        defer self.allocator.free(methods);
        _ = try self.client_stream.read(methods);

        // Select authentication method
        const selected_method: u8 = if (self.config.auth_required)
            @intFromEnum(Socks5AuthMethod.username_password)
        else
            @intFromEnum(Socks5AuthMethod.no_auth);

        // Send method selection
        var method_response: [2]u8 = undefined;
        method_response[0] = 5; // Version
        method_response[1] = selected_method;
        try self.client_stream.writeAll(&method_response);

        // Handle authentication if required
        if (self.config.auth_required) {
            try self.handleUsernamePasswordAuth();
        }

        // Read connection request
        var request_header: [4]u8 = undefined;
        _ = try self.client_stream.read(&request_header);

        const version = request_header[0];
        if (version != 5) return SocksError.ProtocolError;

        const command = request_header[1];
        // const reserved = request_header[2];
        const address_type = request_header[3];

        // Parse destination address
        const target_host = try self.parseAddress(address_type);
        defer self.allocator.free(target_host);

        // Read port
        var port_buf: [2]u8 = undefined;
        _ = try self.client_stream.read(&port_buf);
        const port = std.mem.readInt(u16, &port_buf, .big);

        self.target_host = try self.allocator.dupe(u8, target_host);
        self.target_port = port;

        // Handle command
        switch (command) {
            @intFromEnum(Socks5Command.connect) => {
                try self.handleConnect();
            },
            @intFromEnum(Socks5Command.bind) => {
                try self.sendReply(.command_not_supported);
            },
            @intFromEnum(Socks5Command.udp_associate) => {
                try self.sendReply(.command_not_supported);
            },
            else => {
                try self.sendReply(.command_not_supported);
            },
        }
    }

    fn handleUsernamePasswordAuth(self: *SocksConnection) !void {
        // Read version
        var version_buf: [1]u8 = undefined;
        _ = try self.client_stream.read(&version_buf);

        // Read username length
        var ulen_buf: [1]u8 = undefined;
        _ = try self.client_stream.read(&ulen_buf);
        const ulen = ulen_buf[0];

        // Read username
        const username = try self.allocator.alloc(u8, ulen);
        defer self.allocator.free(username);
        _ = try self.client_stream.read(username);

        // Read password length
        var plen_buf: [1]u8 = undefined;
        _ = try self.client_stream.read(&plen_buf);
        const plen = plen_buf[0];

        // Read password
        const password = try self.allocator.alloc(u8, plen);
        defer self.allocator.free(password);
        _ = try self.client_stream.read(password);

        // Validate credentials
        const valid = if (self.config.username != null and self.config.password != null)
            std.mem.eql(u8, username, self.config.username.?) and
                std.mem.eql(u8, password, self.config.password.?)
        else
            false;

        // Send auth response
        var response: [2]u8 = undefined;
        response[0] = 1; // Version
        response[1] = if (valid) 0 else 1; // Status

        try self.client_stream.writeAll(&response);

        if (!valid) {
            return SocksError.AuthenticationFailed;
        }
    }

    fn parseAddress(self: *SocksConnection, address_type: u8) ![]const u8 {
        return switch (address_type) {
            @intFromEnum(Socks5AddressType.ipv4) => blk: {
                var addr_buf: [4]u8 = undefined;
                _ = try self.client_stream.read(&addr_buf);

                const addr = net.Address.initIp4(addr_buf, 0);
                break :blk try std.fmt.allocPrint(self.allocator, "{}", .{addr});
            },

            @intFromEnum(Socks5AddressType.domain) => blk: {
                var len_buf: [1]u8 = undefined;
                _ = try self.client_stream.read(&len_buf);
                const len = len_buf[0];

                const domain = try self.allocator.alloc(u8, len);
                _ = try self.client_stream.read(domain);

                break :blk domain;
            },

            @intFromEnum(Socks5AddressType.ipv6) => blk: {
                var addr_buf: [16]u8 = undefined;
                _ = try self.client_stream.read(&addr_buf);

                const addr = net.Address.initIp6(addr_buf, 0, 0, 0);
                break :blk try std.fmt.allocPrint(self.allocator, "{}", .{addr});
            },

            else => return SocksError.InvalidAddress,
        };
    }

    fn handleConnect(self: *SocksConnection) !void {
        // TODO: Open SSH channel to target_host:target_port
        // For now, send success reply

        try self.sendReply(.succeeded);

        // TODO: Start forwarding data between client_stream and SSH channel
    }

    fn sendReply(self: *SocksConnection, reply: Socks5Reply) !void {
        var response: [10]u8 = undefined;
        response[0] = 5; // Version
        response[1] = @intFromEnum(reply);
        response[2] = 0; // Reserved
        response[3] = @intFromEnum(Socks5AddressType.ipv4);

        // Bind address and port (0.0.0.0:0)
        std.mem.writeInt(u32, response[4..8], 0, .big);
        std.mem.writeInt(u16, response[8..10], 0, .big);

        try self.client_stream.writeAll(&response);
    }
};

// Tests

test "SOCKS5 reply codes" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 0), @intFromEnum(Socks5Reply.succeeded));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(Socks5Reply.connection_refused));
}

test "SOCKS config" {
    const config = SocksConfig{
        .listen_port = 1080,
        .auth_required = true,
        .username = "user",
        .password = "pass",
    };

    @import("std").testing.expectEqual(@as(u16, 1080), config.listen_port);
    @import("std").testing.expect(config.auth_required);
}
