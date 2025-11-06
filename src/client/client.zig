//! SSH Client Implementation
//!
//! Provides high-level SSH client functionality including connection establishment,
//! authentication, and channel management.

const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;
const transport = @import("../transport/transport.zig");
const auth = @import("../auth/auth.zig");

pub const ClientError = error{
    ConnectionFailed,
    AuthenticationFailed,
    ChannelCreationFailed,
    RemoteDisconnected,
} || transport.TransportError || auth.AuthError;

pub const ClientConfig = struct {
    username: []const u8,
    host: []const u8,
    port: u16 = 22,
    timeout_ms: u32 = 30000,
    compression: bool = false,
};

pub const Client = struct {
    allocator: Allocator,
    config: ClientConfig,
    transport: ?transport.Transport,
    auth_context: ?auth.AuthContext,
    connected: bool,
    authenticated: bool,
    io_runtime: std.Io.Threaded,

    const Self = @This();
    
    pub fn init(allocator: Allocator, config: ClientConfig) !Self {
        return Self{
            .allocator = allocator,
            .config = .{
                .username = try allocator.dupe(u8, config.username),
                .host = try allocator.dupe(u8, config.host),
                .port = config.port,
                .timeout_ms = config.timeout_ms,
                .compression = config.compression,
            },
            .transport = null,
            .auth_context = null,
            .connected = false,
            .authenticated = false,
            .io_runtime = std.Io.Threaded.init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.transport) |*t| {
            t.deinit();
        }
        if (self.auth_context) |*a| {
            a.deinit();
        }
        self.io_runtime.deinit();
        self.allocator.free(self.config.username);
        self.allocator.free(self.config.host);
    }
    
    pub fn connect(self: *Self) !void {
        const address = try net.IpAddress.parse(self.config.host, self.config.port);
        const io = self.io_runtime.io();
        const stream = try address.connect(io, .{ .mode = .stream });

        self.transport = try transport.Transport.init(self.allocator, stream, io);

        try self.performVersionExchange();

        self.connected = true;
    }
    
    pub fn authenticate(self: *Self, credentials: auth.Credentials) !void {
        if (!self.connected) {
            return ClientError.ConnectionFailed;
        }
        
        if (self.auth_context == null) {
            self.auth_context = try auth.AuthContext.init(
                self.allocator,
                self.config.username,
                "ssh-connection"
            );
        }
        
        const result = self.auth_context.?.authenticate(credentials);
        switch (result) {
            .success => {
                self.authenticated = true;
            },
            .failure, .partial_success => {
                return ClientError.AuthenticationFailed;
            },
            .continue_required => {
                return ClientError.AuthenticationFailed;
            },
        }
    }
    
    pub fn disconnect(self: *Self) void {
        if (self.transport) |*t| {
            t.deinit();
            self.transport = null;
        }
        self.connected = false;
        self.authenticated = false;
    }
    
    pub fn isConnected(self: *const Self) bool {
        return self.connected;
    }
    
    pub fn isAuthenticated(self: *const Self) bool {
        return self.authenticated;
    }
    
    fn performVersionExchange(self: *Self) !void {
        if (self.transport) |*t| {
            const version = @import("../root.zig").SSH_VERSION;
            try t.sendVersionString(version);
            
            const server_version = try t.receiveVersionString();
            defer self.allocator.free(server_version);
            
            if (!transport.Transport.isValidSshVersion(server_version)) {
                return ClientError.ConnectionFailed;
            }
            
            t.state = .key_exchange_init;
        }
    }
};

test "Client initialization and cleanup" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = ClientConfig{
        .username = "testuser",
        .host = "localhost",
        .port = 2222,
    };
    
    var client = try Client.init(allocator, config);
    defer client.deinit();
    
    try testing.expectEqualStrings("testuser", client.config.username);
    try testing.expectEqualStrings("localhost", client.config.host);
    try testing.expectEqual(@as(u16, 2222), client.config.port);
    try testing.expect(!client.isConnected());
    try testing.expect(!client.isAuthenticated());
}