//! QUIC-based SSH Transport Layer
//!
//! Implements SSH 2.0 transport over QUIC for improved performance and connection management.
//! Provides multiplexing, 0-RTT connections, and better network resilience.

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const zquic = @import("zquic");

pub const QuicTransportError = error{
    ConnectionFailed,
    StreamCreationFailed,
    CertificateVerificationFailed,
    HandshakeFailed,
    StreamReset,
} || Allocator.Error;

pub const QuicTransportState = enum {
    disconnected,
    connecting,
    handshake,
    ready,
    error_state,
};

pub const QuicStream = struct {
    id: u64,
    quic_stream: zquic.Stream,
    sequence_number_send: u32,
    sequence_number_recv: u32,

    const Self = @This();

    pub fn init(id: u64, quic_stream: zquic.Stream) Self {
        return Self{
            .id = id,
            .quic_stream = quic_stream,
            .sequence_number_send = 0,
            .sequence_number_recv = 0,
        };
    }

    pub fn sendData(self: *Self, data: []const u8) !void {
        try self.quic_stream.write(data);
        self.sequence_number_send += 1;
    }

    pub fn receiveData(self: *Self, buffer: []u8) !usize {
        const bytes_read = try self.quic_stream.read(buffer);
        if (bytes_read > 0) {
            self.sequence_number_recv += 1;
        }
        return bytes_read;
    }

    pub fn close(self: *Self) void {
        self.quic_stream.close();
    }
};

pub const QuicTransport = struct {
    allocator: Allocator,
    connection: zquic.Connection,
    state: QuicTransportState,
    streams: std.HashMap(u64, QuicStream),
    next_stream_id: u64,
    multiplex_enabled: bool,
    connection_migration_enabled: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .connection = undefined,
            .state = .disconnected,
            .streams = std.HashMap(u64, QuicStream).init(allocator),
            .next_stream_id = 0,
            .multiplex_enabled = true,
            .connection_migration_enabled = true,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.close();
        }
        self.streams.deinit();
        if (self.state != .disconnected) {
            self.connection.close();
        }
    }

    pub fn connect(self: *Self, address: net.Address, server_name: []const u8) !void {
        self.state = .connecting;

        const config = zquic.ClientConfig{
            .alpn_protocols = &[_][]const u8{"ssh/2.0"},
            .verify_peer = true,
            .server_name = server_name,
        };

        self.connection = zquic.Connection.connectTo(address, config) catch |err| {
            self.state = .error_state;
            return switch (err) {
                error.ConnectionRefused => QuicTransportError.ConnectionFailed,
                error.HandshakeFailed => QuicTransportError.HandshakeFailed,
                else => err,
            };
        };

        try self.performHandshake();
        self.state = .ready;
    }

    pub fn listen(self: *Self, address: net.Address, cert_path: []const u8, key_path: []const u8) !void {
        const config = zquic.ServerConfig{
            .alpn_protocols = &[_][]const u8{"ssh/2.0"},
            .cert_file = cert_path,
            .key_file = key_path,
        };

        self.connection = zquic.Connection.listenOn(address, config) catch |err| {
            self.state = .error_state;
            return switch (err) {
                error.AddressInUse => QuicTransportError.ConnectionFailed,
                error.CertificateLoadFailed => QuicTransportError.CertificateVerificationFailed,
                else => err,
            };
        };

        self.state = .ready;
    }

    fn performHandshake(self: *Self) !void {
        self.state = .handshake;

        // Wait for QUIC handshake completion
        while (!self.connection.isHandshakeComplete()) {
            try self.connection.processEvents();
            std.time.sleep(1000000); // 1ms
        }
    }

    pub fn createStream(self: *Self) !*QuicStream {
        if (self.state != .ready) return QuicTransportError.ConnectionFailed;

        const stream_id = self.next_stream_id;
        self.next_stream_id += 1;

        const quic_stream = self.connection.openStream() catch |err| {
            return switch (err) {
                error.TooManyStreams => QuicTransportError.StreamCreationFailed,
                error.ConnectionClosed => QuicTransportError.ConnectionFailed,
                else => err,
            };
        };

        const stream = QuicStream.init(stream_id, quic_stream);
        try self.streams.put(stream_id, stream);

        return self.streams.getPtr(stream_id).?;
    }

    pub fn getStream(self: *Self, stream_id: u64) ?*QuicStream {
        return self.streams.getPtr(stream_id);
    }

    pub fn closeStream(self: *Self, stream_id: u64) void {
        if (self.streams.getPtr(stream_id)) |stream| {
            stream.close();
            _ = self.streams.remove(stream_id);
        }
    }

    pub fn enableMultiplexing(self: *Self, enabled: bool) void {
        self.multiplex_enabled = enabled;
    }

    pub fn enableConnectionMigration(self: *Self, enabled: bool) void {
        self.connection_migration_enabled = enabled;
        if (self.state == .ready) {
            self.connection.setConnectionMigration(enabled);
        }
    }

    pub fn getConnectionStats(self: *const Self) zquic.ConnectionStats {
        return self.connection.getStats();
    }

    pub fn setTrafficShaping(self: *Self, max_bandwidth_bps: u64) !void {
        try self.connection.setMaxBandwidth(max_bandwidth_bps);
    }

    pub fn supportsEarlyData(self: *const Self) bool {
        return self.connection.supportsEarlyData();
    }

    pub fn send0RTTData(self: *Self, data: []const u8) !void {
        if (!self.supportsEarlyData()) return QuicTransportError.ConnectionFailed;
        try self.connection.sendEarlyData(data);
    }
};

test "QUIC transport initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var transport = QuicTransport.init(allocator);
    defer transport.deinit();

    try testing.expect(transport.state == .disconnected);
    try testing.expect(transport.multiplex_enabled == true);
    try testing.expect(transport.next_stream_id == 0);
}

test "QUIC stream management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var transport = QuicTransport.init(allocator);
    defer transport.deinit();

    // Simulate ready state for testing
    transport.state = .ready;
    transport.connection = @as(zquic.Connection, undefined); // Mock for test

    // Note: This test would need actual QUIC connection for full functionality
    // For now, just test the state management
    try testing.expect(transport.streams.count() == 0);
}