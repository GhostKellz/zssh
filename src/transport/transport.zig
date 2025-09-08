//! SSH Transport Layer Protocol
//!
//! Implements the SSH 2.0 transport layer as defined in RFC 4253.
//! Handles protocol version exchange, key exchange, encryption/MAC, and packet processing.

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;

pub const TransportError = error{
    InvalidProtocolVersion,
    InvalidPacketLength,
    InvalidMacSignature,
    KeyExchangeFailure,
    EncryptionError,
    CompressionError,
} || Allocator.Error || net.Stream.ReadError || net.Stream.WriteError;

pub const SSH_MSG = struct {
    pub const DISCONNECT = 1;
    pub const IGNORE = 2;
    pub const UNIMPLEMENTED = 3;
    pub const DEBUG = 4;
    pub const SERVICE_REQUEST = 5;
    pub const SERVICE_ACCEPT = 6;
    pub const KEXINIT = 20;
    pub const NEWKEYS = 21;
};

pub const TransportState = enum {
    version_exchange,
    key_exchange_init,
    key_exchange,
    encrypted,
    disconnected,
};

pub const Transport = struct {
    allocator: Allocator,
    stream: net.Stream,
    state: TransportState,
    client_version: []const u8,
    server_version: []const u8,
    sequence_number_send: u32,
    sequence_number_recv: u32,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, stream: net.Stream) Self {
        return Self{
            .allocator = allocator,
            .stream = stream,
            .state = .version_exchange,
            .client_version = "",
            .server_version = "",
            .sequence_number_send = 0,
            .sequence_number_recv = 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stream.close();
    }
    
    pub fn sendVersionString(self: *Self, version: []const u8) !void {
        const version_line = try std.fmt.allocPrint(self.allocator, "{s}\r\n", .{version});
        defer self.allocator.free(version_line);
        _ = try self.stream.writeAll(version_line);
    }
    
    pub fn receiveVersionString(self: *Self) ![]u8 {
        var buf: [255]u8 = undefined;
        const bytes_read = try self.stream.read(buf[0..]);
        if (bytes_read == 0) return TransportError.InvalidProtocolVersion;
        
        const version_str = try self.allocator.dupe(u8, buf[0..bytes_read]);
        return version_str;
    }
    
    pub fn isValidSshVersion(version: []const u8) bool {
        return std.mem.startsWith(u8, version, "SSH-2.0-");
    }
};

test "Transport initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const address = try net.Address.parseIp("127.0.0.1", 0);
    var server = try address.listen(.{});
    defer server.deinit();
    
    const server_addr = server.listen_address;
    
    const client_stream = try net.tcpConnectToAddress(server_addr);
    var transport = Transport.init(allocator, client_stream);
    defer transport.deinit();
    
    try testing.expect(transport.state == .version_exchange);
    try testing.expect(transport.sequence_number_send == 0);
    try testing.expect(transport.sequence_number_recv == 0);
}

test "SSH version validation" {
    try std.testing.expect(Transport.isValidSshVersion("SSH-2.0-zssh_0.1"));
    try std.testing.expect(Transport.isValidSshVersion("SSH-2.0-OpenSSH_8.9"));
    try std.testing.expect(!Transport.isValidSshVersion("SSH-1.99-"));
    try std.testing.expect(!Transport.isValidSshVersion("HTTP/1.1"));
}