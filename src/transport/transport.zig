//! SSH Transport Layer Protocol
//!
//! Implements the SSH 2.0 transport layer as defined in RFC 4253.
//! Handles protocol version exchange, key exchange, encryption/MAC, and packet processing.

const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;

pub const TransportError = error{
    InvalidProtocolVersion,
    InvalidPacketLength,
    InvalidMacSignature,
    KeyExchangeFailure,
    EncryptionError,
    CompressionError,
} || Allocator.Error || net.Stream.Reader.Error || net.Stream.Writer.Error;

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
    io: std.Io,
    reader: net.Stream.Reader,
    writer: net.Stream.Writer,
    state: TransportState,
    client_version: []const u8,
    server_version: []const u8,
    sequence_number_send: u32,
    sequence_number_recv: u32,
    last_heartbeat: i64,
    heartbeat_interval_ms: u32,
    keep_alive_enabled: bool,
    read_buffer: []u8,
    write_buffer: []u8,

    const Self = @This();
    const default_buffer_size = 8192;

    pub fn init(allocator: Allocator, stream: net.Stream, io: std.Io) !Self {
        const read_buf = try allocator.alloc(u8, default_buffer_size);
        errdefer allocator.free(read_buf);
        const write_buf = try allocator.alloc(u8, default_buffer_size);
        errdefer allocator.free(write_buf);

        return Self{
            .allocator = allocator,
            .stream = stream,
            .io = io,
            .reader = net.Stream.Reader.init(stream, io, read_buf),
            .writer = net.Stream.Writer.init(stream, io, write_buf),
            .state = .version_exchange,
            .client_version = "",
            .server_version = "",
            .sequence_number_send = 0,
            .sequence_number_recv = 0,
            .last_heartbeat = 0,
            .heartbeat_interval_ms = 30000, // 30 seconds
            .keep_alive_enabled = true,
            .read_buffer = read_buf,
            .write_buffer = write_buf,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.read_buffer);
        self.allocator.free(self.write_buffer);
        self.stream.close(self.io);
    }

    pub fn sendVersionString(self: *Self, version: []const u8) !void {
        const version_line = try std.fmt.allocPrint(self.allocator, "{s}\r\n", .{version});
        defer self.allocator.free(version_line);

        try self.writer.interface.writeAll(version_line);
        try self.writer.interface.flush();
    }

    pub fn receiveVersionString(self: *Self) ![]u8 {
        var buf: [255]u8 = undefined;
        var pos: usize = 0;

        // Read until we get \r\n
        while (pos < buf.len) {
            const bytes_read = try self.reader.interface.readSliceShort(buf[pos..pos+1]);
            if (bytes_read == 0) break;
            pos += bytes_read;

            if (pos >= 2 and buf[pos - 2] == '\r' and buf[pos - 1] == '\n') {
                break;
            }
        }

        if (pos == 0) return TransportError.InvalidProtocolVersion;

        // Remove \r\n
        const version_len = if (pos >= 2) pos - 2 else pos;
        const version_str = try self.allocator.dupe(u8, buf[0..version_len]);
        return version_str;
    }

    pub fn isValidSshVersion(version: []const u8) bool {
        return std.mem.startsWith(u8, version, "SSH-2.0-");
    }

    pub fn sendHeartbeat(self: *Self) !void {
        if (!self.keep_alive_enabled) return;

        // Send SSH_MSG_IGNORE for heartbeat
        const payload = [_]u8{ SSH_MSG.IGNORE, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
        try self.writer.interface.writeAll(&payload);
        try self.writer.interface.flush();
        self.last_heartbeat = 0; // TODO: Use proper timestamp when we integrate ztime
    }

    pub fn needsHeartbeat(self: *const Self) bool {
        // TODO: Implement proper timestamp checking with ztime
        _ = self.last_heartbeat;
        _ = self.heartbeat_interval_ms;
        if (!self.keep_alive_enabled) return false;
        return false;
    }

    pub fn setHeartbeatInterval(self: *Self, interval_ms: u32) void {
        self.heartbeat_interval_ms = interval_ms;
    }

    pub fn enableKeepAlive(self: *Self, enabled: bool) void {
        self.keep_alive_enabled = enabled;
    }

    pub fn sendPacket(self: *Self, packet_data: []const u8) !void {
        try self.writer.interface.writeAll(packet_data);
        try self.writer.interface.flush();
        self.sequence_number_send += 1;
    }

    pub fn receivePacket(self: *Self, buffer: []u8) !usize {
        const bytes_read = try self.reader.interface.read(buffer);
        if (bytes_read > 0) {
            self.sequence_number_recv += 1;
        }
        return bytes_read;
    }
};

test "SSH version validation" {
    try std.testing.expect(Transport.isValidSshVersion("SSH-2.0-zssh_0.1"));
    try std.testing.expect(Transport.isValidSshVersion("SSH-2.0-OpenSSH_8.9"));
    try std.testing.expect(!Transport.isValidSshVersion("SSH-1.99-"));
    try std.testing.expect(!Transport.isValidSshVersion("HTTP/1.1"));
}
