//! SSH Server Implementation
//!
//! Provides high-level SSH server functionality including connection handling,
//! authentication, and session management.

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const transport = @import("../transport/transport.zig");
const auth = @import("../auth/auth.zig");

pub const ServerError = error{
    BindFailed,
    AcceptFailed,
    ClientHandlingFailed,
} || transport.TransportError || auth.AuthError;

pub const ServerConfig = struct {
    host: []const u8 = "0.0.0.0",
    port: u16 = 22,
    max_connections: u32 = 100,
    host_key_path: ?[]const u8 = null,
    allow_password_auth: bool = true,
    allow_pubkey_auth: bool = true,
};

pub const ClientConnection = struct {
    transport: transport.Transport,
    auth_context: ?auth.AuthContext,
    authenticated: bool,
    
    const Self = @This();
    
    pub fn init(stream: net.Stream, allocator: Allocator) Self {
        return Self{
            .transport = transport.Transport.init(allocator, stream),
            .auth_context = null,
            .authenticated = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.auth_context) |*a| {
            a.deinit();
        }
        self.transport.deinit();
    }
};

pub const Server = struct {
    allocator: Allocator,
    config: ServerConfig,
    listener: ?net.Server,
    running: bool,
    connections: std.ArrayListUnmanaged(*ClientConnection),
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, config: ServerConfig) !Self {        
        return Self{
            .allocator = allocator,
            .config = .{
                .host = try allocator.dupe(u8, config.host),
                .port = config.port,
                .max_connections = config.max_connections,
                .host_key_path = if (config.host_key_path) |path| try allocator.dupe(u8, path) else null,
                .allow_password_auth = config.allow_password_auth,
                .allow_pubkey_auth = config.allow_pubkey_auth,
            },
            .listener = null,
            .running = false,
            .connections = std.ArrayListUnmanaged(*ClientConnection){},
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stop();
        
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
        
        self.allocator.free(self.config.host);
        if (self.config.host_key_path) |path| {
            self.allocator.free(path);
        }
    }
    
    pub fn listen(self: *Self) !void {
        const address = try net.Address.resolveIp(self.config.host, self.config.port);
        self.listener = try address.listen(.{
            .reuse_address = true,
        });
        
        self.running = true;
        
        std.log.info("SSH server listening on {s}:{d}", .{ self.config.host, self.config.port });
    }
    
    pub fn accept(self: *Self) !void {
        if (self.listener == null or !self.running) {
            return ServerError.AcceptFailed;
        }
        
        const connection = try self.listener.?.accept();
        try self.handleClient(connection);
    }
    
    pub fn stop(self: *Self) void {
        self.running = false;
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
    }
    
    pub fn isRunning(self: *const Self) bool {
        return self.running;
    }
    
    pub fn getConnectionCount(self: *const Self) usize {
        return self.connections.items.len;
    }
    
    fn handleClient(self: *Self, connection: net.Server.Connection) !void {
        if (self.connections.items.len >= self.config.max_connections) {
            connection.stream.close();
            return ServerError.ClientHandlingFailed;
        }
        
        const client_conn = try self.allocator.create(ClientConnection);
        client_conn.* = ClientConnection.init(connection.stream, self.allocator);
        
        try self.connections.append(self.allocator, client_conn);
        
        try self.performVersionExchange(client_conn);
        
        std.log.info("Client connected from {any}", .{connection.address});
    }
    
    fn performVersionExchange(self: *Self, client: *ClientConnection) !void {
        _ = self;
        const version = @import("../root.zig").SSH_VERSION;
        try client.transport.sendVersionString(version);
        
        const client_version = try client.transport.receiveVersionString();
        defer client.transport.allocator.free(client_version);
        
        if (!transport.Transport.isValidSshVersion(client_version)) {
            return ServerError.ClientHandlingFailed;
        }
        
        client.transport.state = .key_exchange_init;
    }
};

test "Server initialization and cleanup" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = ServerConfig{
        .host = "127.0.0.1",
        .port = 2223,
        .max_connections = 50,
    };
    
    var server = try Server.init(allocator, config);
    defer server.deinit();
    
    try testing.expectEqualStrings("127.0.0.1", server.config.host);
    try testing.expectEqual(@as(u16, 2223), server.config.port);
    try testing.expectEqual(@as(u32, 50), server.config.max_connections);
    try testing.expect(!server.isRunning());
    try testing.expectEqual(@as(usize, 0), server.getConnectionCount());
}