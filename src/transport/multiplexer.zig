//! SSH Connection Multiplexer
//!
//! Implements connection multiplexing over single TCP/QUIC connections.
//! Allows multiple SSH sessions and channels over one transport connection.

const std = @import("std");
const Allocator = std.mem.Allocator;
const transport = @import("transport.zig");
const quic_transport = @import("quic_transport.zig");

pub const MultiplexerError = error{
    ChannelLimitExceeded,
    ChannelNotFound,
    ConnectionClosed,
    InvalidChannelType,
} || Allocator.Error;

pub const ChannelType = enum {
    session,
    direct_tcpip,
    forwarded_tcpip,
    x11,
    auth_agent,
    subsystem,
};

pub const Channel = struct {
    id: u32,
    channel_type: ChannelType,
    local_id: u32,
    remote_id: u32,
    local_window: u32,
    remote_window: u32,
    local_packet_size: u32,
    remote_packet_size: u32,
    is_open: bool,
    is_eof_received: bool,
    is_eof_sent: bool,

    const Self = @This();

    pub fn init(id: u32, channel_type: ChannelType, local_id: u32) Self {
        return Self{
            .id = id,
            .channel_type = channel_type,
            .local_id = local_id,
            .remote_id = 0,
            .local_window = 65536,
            .remote_window = 0,
            .local_packet_size = 32768,
            .remote_packet_size = 0,
            .is_open = false,
            .is_eof_received = false,
            .is_eof_sent = false,
        };
    }

    pub fn updateWindow(self: *Self, bytes_consumed: u32) void {
        if (self.local_window >= bytes_consumed) {
            self.local_window -= bytes_consumed;
        }
    }

    pub fn addToWindow(self: *Self, bytes_to_add: u32) void {
        self.local_window += bytes_to_add;
    }

    pub fn canSendData(self: *const Self, data_size: u32) bool {
        return self.is_open and
               !self.is_eof_sent and
               self.remote_window >= data_size and
               data_size <= self.remote_packet_size;
    }

    pub fn markEofReceived(self: *Self) void {
        self.is_eof_received = true;
    }

    pub fn markEofSent(self: *Self) void {
        self.is_eof_sent = true;
    }

    pub fn close(self: *Self) void {
        self.is_open = false;
        self.is_eof_received = true;
        self.is_eof_sent = true;
    }
};

pub const ConnectionMultiplexer = struct {
    allocator: Allocator,
    channels: std.HashMap(u32, Channel),
    next_channel_id: u32,
    max_channels: u32,
    transport_type: enum { tcp, quic },
    tcp_transport: ?*transport.Transport,
    quic_transport: ?*quic_transport.QuicTransport,
    global_window_size: u32,
    packet_queue: std.ArrayList([]const u8),

    const Self = @This();

    pub fn init(allocator: Allocator, max_channels: u32) Self {
        return Self{
            .allocator = allocator,
            .channels = std.HashMap(u32, Channel).init(allocator),
            .next_channel_id = 0,
            .max_channels = max_channels,
            .transport_type = .tcp,
            .tcp_transport = null,
            .quic_transport = null,
            .global_window_size = 1048576, // 1MB
            .packet_queue = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // Close all channels
        var iterator = self.channels.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.close();
        }
        self.channels.deinit();

        // Free queued packets
        for (self.packet_queue.items) |packet| {
            self.allocator.free(packet);
        }
        self.packet_queue.deinit();
    }

    pub fn attachTcpTransport(self: *Self, tcp_transport_ptr: *transport.Transport) void {
        self.transport_type = .tcp;
        self.tcp_transport = tcp_transport_ptr;
        self.quic_transport = null;
    }

    pub fn attachQuicTransport(self: *Self, quic_transport_ptr: *quic_transport.QuicTransport) void {
        self.transport_type = .quic;
        self.quic_transport = quic_transport_ptr;
        self.tcp_transport = null;
    }

    pub fn openChannel(self: *Self, channel_type: ChannelType) !*Channel {
        if (self.channels.count() >= self.max_channels) {
            return MultiplexerError.ChannelLimitExceeded;
        }

        const channel_id = self.next_channel_id;
        self.next_channel_id += 1;

        var channel = Channel.init(channel_id, channel_type, channel_id);

        // Send SSH_MSG_CHANNEL_OPEN
        try self.sendChannelOpen(&channel);

        try self.channels.put(channel_id, channel);
        return self.channels.getPtr(channel_id).?;
    }

    pub fn closeChannel(self: *Self, channel_id: u32) !void {
        if (self.channels.getPtr(channel_id)) |channel| {
            if (channel.is_open) {
                try self.sendChannelClose(channel);
            }
            channel.close();
            _ = self.channels.remove(channel_id);
        }
    }

    pub fn getChannel(self: *Self, channel_id: u32) ?*Channel {
        return self.channels.getPtr(channel_id);
    }

    pub fn sendChannelData(self: *Self, channel_id: u32, data: []const u8) !void {
        const channel = self.channels.getPtr(channel_id) orelse return MultiplexerError.ChannelNotFound;

        if (!channel.canSendData(@intCast(data.len))) {
            return MultiplexerError.ConnectionClosed;
        }

        // Build SSH_MSG_CHANNEL_DATA packet
        const packet_size = 9 + data.len; // 1 + 4 + 4 + data.len
        var packet = try self.allocator.alloc(u8, packet_size);
        defer self.allocator.free(packet);

        packet[0] = 94; // SSH_MSG_CHANNEL_DATA
        std.mem.writeInt(u32, packet[1..5], channel.remote_id, .big);
        std.mem.writeInt(u32, packet[5..9], @intCast(data.len), .big);
        @memcpy(packet[9..], data);

        try self.sendPacket(packet);
        channel.remote_window -= @intCast(data.len);
    }

    pub fn sendChannelExtendedData(self: *Self, channel_id: u32, data_type: u32, data: []const u8) !void {
        const channel = self.channels.getPtr(channel_id) orelse return MultiplexerError.ChannelNotFound;

        if (!channel.canSendData(@intCast(data.len))) {
            return MultiplexerError.ConnectionClosed;
        }

        // Build SSH_MSG_CHANNEL_EXTENDED_DATA packet
        const packet_size = 13 + data.len; // 1 + 4 + 4 + 4 + data.len
        var packet = try self.allocator.alloc(u8, packet_size);
        defer self.allocator.free(packet);

        packet[0] = 95; // SSH_MSG_CHANNEL_EXTENDED_DATA
        std.mem.writeInt(u32, packet[1..5], channel.remote_id, .big);
        std.mem.writeInt(u32, packet[5..9], data_type, .big);
        std.mem.writeInt(u32, packet[9..13], @intCast(data.len), .big);
        @memcpy(packet[13..], data);

        try self.sendPacket(packet);
        channel.remote_window -= @intCast(data.len);
    }

    pub fn adjustWindow(self: *Self, channel_id: u32, bytes_to_add: u32) !void {
        const channel = self.channels.getPtr(channel_id) orelse return MultiplexerError.ChannelNotFound;

        channel.addToWindow(bytes_to_add);

        // Send SSH_MSG_CHANNEL_WINDOW_ADJUST
        var packet: [9]u8 = undefined;
        packet[0] = 93; // SSH_MSG_CHANNEL_WINDOW_ADJUST
        std.mem.writeInt(u32, packet[1..5], channel.remote_id, .big);
        std.mem.writeInt(u32, packet[5..9], bytes_to_add, .big);

        try self.sendPacket(&packet);
    }

    fn sendChannelOpen(self: *Self, channel: *Channel) !void {
        const channel_type_str = switch (channel.channel_type) {
            .session => "session",
            .direct_tcpip => "direct-tcpip",
            .forwarded_tcpip => "forwarded-tcpip",
            .x11 => "x11",
            .auth_agent => "auth-agent@openssh.com",
            .subsystem => "subsystem",
        };

        const type_len = channel_type_str.len;
        const packet_size = 17 + type_len; // 1 + 4 + type + 4 + 4 + 4
        var packet = try self.allocator.alloc(u8, packet_size);
        defer self.allocator.free(packet);

        var offset: usize = 0;
        packet[offset] = 90; // SSH_MSG_CHANNEL_OPEN
        offset += 1;

        std.mem.writeInt(u32, packet[offset..offset+4], @intCast(type_len), .big);
        offset += 4;

        @memcpy(packet[offset..offset+type_len], channel_type_str);
        offset += type_len;

        std.mem.writeInt(u32, packet[offset..offset+4], channel.local_id, .big);
        offset += 4;

        std.mem.writeInt(u32, packet[offset..offset+4], channel.local_window, .big);
        offset += 4;

        std.mem.writeInt(u32, packet[offset..offset+4], channel.local_packet_size, .big);

        try self.sendPacket(packet);
    }

    fn sendChannelClose(self: *Self, channel: *Channel) !void {
        var packet: [5]u8 = undefined;
        packet[0] = 97; // SSH_MSG_CHANNEL_CLOSE
        std.mem.writeInt(u32, packet[1..5], channel.remote_id, .big);
        try self.sendPacket(&packet);
    }

    fn sendPacket(self: *Self, packet: []const u8) !void {
        switch (self.transport_type) {
            .tcp => {
                if (self.tcp_transport) |tcp| {
                    try tcp.sendPacket(packet);
                } else {
                    return MultiplexerError.ConnectionClosed;
                }
            },
            .quic => {
                if (self.quic_transport) |quic| {
                    const stream = try quic.createStream();
                    try stream.sendData(packet);
                } else {
                    return MultiplexerError.ConnectionClosed;
                }
            },
        }
    }

    pub fn processIncomingPacket(self: *Self, packet_data: []const u8) !void {
        if (packet_data.len == 0) return;

        const msg_type = packet_data[0];
        switch (msg_type) {
            90 => try self.handleChannelOpen(packet_data[1..]),     // SSH_MSG_CHANNEL_OPEN
            91 => try self.handleChannelOpenConfirmation(packet_data[1..]), // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            92 => try self.handleChannelOpenFailure(packet_data[1..]),      // SSH_MSG_CHANNEL_OPEN_FAILURE
            93 => try self.handleChannelWindowAdjust(packet_data[1..]),     // SSH_MSG_CHANNEL_WINDOW_ADJUST
            94 => try self.handleChannelData(packet_data[1..]),             // SSH_MSG_CHANNEL_DATA
            95 => try self.handleChannelExtendedData(packet_data[1..]),     // SSH_MSG_CHANNEL_EXTENDED_DATA
            96 => try self.handleChannelEof(packet_data[1..]),              // SSH_MSG_CHANNEL_EOF
            97 => try self.handleChannelClose(packet_data[1..]),            // SSH_MSG_CHANNEL_CLOSE
            else => {
                // Unknown message type, ignore or log
            },
        }
    }

    fn handleChannelOpenConfirmation(self: *Self, data: []const u8) !void {
        if (data.len < 16) return;

        const local_id = std.mem.readInt(u32, data[0..4], .big);
        const remote_id = std.mem.readInt(u32, data[4..8], .big);
        const remote_window = std.mem.readInt(u32, data[8..12], .big);
        const remote_packet_size = std.mem.readInt(u32, data[12..16], .big);

        if (self.channels.getPtr(local_id)) |channel| {
            channel.remote_id = remote_id;
            channel.remote_window = remote_window;
            channel.remote_packet_size = remote_packet_size;
            channel.is_open = true;
        }
    }

    fn handleChannelData(self: *Self, data: []const u8) !void {
        if (data.len < 8) return;

        const local_id = std.mem.readInt(u32, data[0..4], .big);
        const data_len = std.mem.readInt(u32, data[4..8], .big);

        if (data.len < 8 + data_len) return;

        if (self.channels.getPtr(local_id)) |channel| {
            channel.updateWindow(data_len);
            // Process the actual data (data[8..8+data_len])
            // This would typically be forwarded to the application layer
        }
    }

    fn handleChannelWindowAdjust(self: *Self, data: []const u8) !void {
        if (data.len < 8) return;

        const local_id = std.mem.readInt(u32, data[0..4], .big);
        const bytes_to_add = std.mem.readInt(u32, data[4..8], .big);

        if (self.channels.getPtr(local_id)) |channel| {
            channel.remote_window += bytes_to_add;
        }
    }

    fn handleChannelOpen(self: *Self, data: []const u8) !void {
        // Implementation for handling incoming channel open requests
        _ = self;
        _ = data;
        // This would parse the channel type and create a new channel
    }

    fn handleChannelOpenFailure(self: *Self, data: []const u8) !void {
        // Implementation for handling channel open failures
        _ = self;
        _ = data;
    }

    fn handleChannelExtendedData(self: *Self, data: []const u8) !void {
        // Implementation for handling extended data (stderr, etc.)
        _ = self;
        _ = data;
    }

    fn handleChannelEof(self: *Self, data: []const u8) !void {
        if (data.len < 4) return;
        const local_id = std.mem.readInt(u32, data[0..4], .big);

        if (self.channels.getPtr(local_id)) |channel| {
            channel.markEofReceived();
        }
    }

    fn handleChannelClose(self: *Self, data: []const u8) !void {
        if (data.len < 4) return;
        const local_id = std.mem.readInt(u32, data[0..4], .big);

        if (self.channels.getPtr(local_id)) |channel| {
            channel.close();
            _ = self.channels.remove(local_id);
        }
    }
};

test "Connection multiplexer initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var multiplexer = ConnectionMultiplexer.init(allocator, 10);
    defer multiplexer.deinit();

    try testing.expect(multiplexer.channels.count() == 0);
    try testing.expect(multiplexer.next_channel_id == 0);
    try testing.expect(multiplexer.max_channels == 10);
}

test "Channel management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var multiplexer = ConnectionMultiplexer.init(allocator, 10);
    defer multiplexer.deinit();

    // Test channel creation
    const channel = try multiplexer.openChannel(.session);
    try testing.expect(channel.id == 0);
    try testing.expect(channel.channel_type == .session);
    try testing.expect(multiplexer.channels.count() == 1);

    // Test channel retrieval
    const retrieved = multiplexer.getChannel(0);
    try testing.expect(retrieved != null);
    try testing.expect(retrieved.?.id == 0);

    // Test channel closure
    try multiplexer.closeChannel(0);
    try testing.expect(multiplexer.channels.count() == 0);
}