//! SSH Channel Implementation
//!
//! Implements SSH connection protocol channels as defined in RFC 4254.
//! Supports multiplexed channels for various SSH services including shell, exec, SFTP, etc.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ChannelError = error{
    InvalidChannelNumber,
    ChannelClosed,
    InvalidRequest,
    WindowExceeded,
    ChannelOpenFailed,
} || Allocator.Error;

pub const ChannelState = enum {
    closed,
    opening,
    open,
    closing,
    error_state,
};

pub const ChannelType = enum {
    session,
    x11,
    forwarded_tcpip,
    direct_tcpip,
    sftp,
    
    pub fn toString(self: ChannelType) []const u8 {
        return switch (self) {
            .session => "session",
            .x11 => "x11",
            .forwarded_tcpip => "forwarded-tcpip",
            .direct_tcpip => "direct-tcpip",
            .sftp => "sftp",
        };
    }
    
    pub fn fromString(s: []const u8) ?ChannelType {
        if (std.mem.eql(u8, s, "session")) return .session;
        if (std.mem.eql(u8, s, "x11")) return .x11;
        if (std.mem.eql(u8, s, "forwarded-tcpip")) return .forwarded_tcpip;
        if (std.mem.eql(u8, s, "direct-tcpip")) return .direct_tcpip;
        if (std.mem.eql(u8, s, "sftp")) return .sftp;
        return null;
    }
};

pub const SSH_MSG_CHANNEL = struct {
    pub const GLOBAL_REQUEST = 80;
    pub const REQUEST_SUCCESS = 81;
    pub const REQUEST_FAILURE = 82;
    pub const CHANNEL_OPEN = 90;
    pub const CHANNEL_OPEN_CONFIRMATION = 91;
    pub const CHANNEL_OPEN_FAILURE = 92;
    pub const CHANNEL_WINDOW_ADJUST = 93;
    pub const CHANNEL_DATA = 94;
    pub const CHANNEL_EXTENDED_DATA = 95;
    pub const CHANNEL_EOF = 96;
    pub const CHANNEL_CLOSE = 97;
    pub const CHANNEL_REQUEST = 98;
    pub const CHANNEL_SUCCESS = 99;
    pub const CHANNEL_FAILURE = 100;
};

pub const ChannelOpenFailureReason = enum(u32) {
    administratively_prohibited = 1,
    connect_failed = 2,
    unknown_channel_type = 3,
    resource_shortage = 4,
};

pub const WindowManager = struct {
    window_size: u32,
    max_packet_size: u32,
    bytes_received: u32,
    
    const Self = @This();
    
    pub fn init(window_size: u32, max_packet_size: u32) Self {
        return Self{
            .window_size = window_size,
            .max_packet_size = max_packet_size,
            .bytes_received = 0,
        };
    }
    
    pub fn canReceive(self: *const Self, data_len: u32) bool {
        return data_len <= self.max_packet_size and 
               self.bytes_received + data_len <= self.window_size;
    }
    
    pub fn consumeWindow(self: *Self, data_len: u32) !void {
        if (!self.canReceive(data_len)) {
            return ChannelError.WindowExceeded;
        }
        self.bytes_received += data_len;
    }
    
    pub fn adjustWindow(self: *Self, adjust_size: u32) void {
        self.bytes_received = if (adjust_size >= self.bytes_received) 0 else self.bytes_received - adjust_size;
    }
    
    pub fn needsAdjustment(self: *const Self) bool {
        return self.bytes_received > (self.window_size / 2);
    }
    
    pub fn getAdjustmentSize(self: *const Self) u32 {
        return self.window_size - self.bytes_received;
    }
};

pub const Channel = struct {
    allocator: Allocator,
    local_id: u32,
    remote_id: ?u32,
    channel_type: ChannelType,
    state: ChannelState,
    local_window: WindowManager,
    remote_window: WindowManager,
    pty_allocated: bool,
    environment: std.StringHashMapUnmanaged([]const u8),
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, local_id: u32, channel_type: ChannelType) Self {
        return Self{
            .allocator = allocator,
            .local_id = local_id,
            .remote_id = null,
            .channel_type = channel_type,
            .state = .closed,
            .local_window = WindowManager.init(32768, 16384), // 32KB window, 16KB max packet
            .remote_window = WindowManager.init(32768, 16384),
            .pty_allocated = false,
            .environment = std.StringHashMapUnmanaged([]const u8){},
        };
    }
    
    pub fn deinit(self: *Self) void {
        var iterator = self.environment.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.environment.deinit(self.allocator);
    }
    
    pub fn open(self: *Self, remote_id: u32) void {
        self.remote_id = remote_id;
        self.state = .open;
    }
    
    pub fn close(self: *Self) void {
        self.state = .closing;
    }
    
    pub fn isClosed(self: *const Self) bool {
        return self.state == .closed;
    }
    
    pub fn isOpen(self: *const Self) bool {
        return self.state == .open;
    }
    
    pub fn canSendData(self: *const Self, data_len: u32) bool {
        return self.isOpen() and self.remote_window.canReceive(data_len);
    }
    
    pub fn sendData(self: *Self, data_len: u32) !void {
        if (!self.canSendData(data_len)) {
            return ChannelError.WindowExceeded;
        }
        try self.remote_window.consumeWindow(data_len);
    }
    
    pub fn receiveData(self: *Self, data_len: u32) !void {
        try self.local_window.consumeWindow(data_len);
    }
    
    pub fn setEnvironment(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.environment.put(self.allocator, owned_name, owned_value);
    }
    
    pub fn getEnvironment(self: *const Self, name: []const u8) ?[]const u8 {
        return self.environment.get(name);
    }
};

pub const ChannelManager = struct {
    allocator: Allocator,
    channels: std.HashMapUnmanaged(u32, *Channel, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage),
    next_channel_id: u32,
    max_channels: u32,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, max_channels: u32) Self {
        return Self{
            .allocator = allocator,
            .channels = std.HashMapUnmanaged(u32, *Channel, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage){},
            .next_channel_id = 0,
            .max_channels = max_channels,
        };
    }
    
    pub fn deinit(self: *Self) void {
        var iterator = self.channels.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.channels.deinit(self.allocator);
    }
    
    pub fn createChannel(self: *Self, channel_type: ChannelType) !*Channel {
        if (self.channels.count() >= self.max_channels) {
            return ChannelError.ChannelOpenFailed;
        }
        
        const channel_id = self.next_channel_id;
        self.next_channel_id += 1;
        
        const channel = try self.allocator.create(Channel);
        channel.* = Channel.init(self.allocator, channel_id, channel_type);
        channel.state = .opening;
        
        try self.channels.put(self.allocator, channel_id, channel);
        return channel;
    }
    
    pub fn getChannel(self: *Self, channel_id: u32) ?*Channel {
        return self.channels.get(channel_id);
    }
    
    pub fn removeChannel(self: *Self, channel_id: u32) !void {
        const channel = self.channels.get(channel_id) orelse return ChannelError.InvalidChannelNumber;
        _ = self.channels.remove(channel_id);
        channel.deinit();
        self.allocator.destroy(channel);
    }
    
    pub fn openChannel(self: *Self, channel_id: u32, remote_id: u32) !void {
        const channel = self.channels.get(channel_id) orelse return ChannelError.InvalidChannelNumber;
        channel.open(remote_id);
    }
    
    pub fn closeChannel(self: *Self, channel_id: u32) !void {
        const channel = self.channels.get(channel_id) orelse return ChannelError.InvalidChannelNumber;
        channel.close();
    }
    
    pub fn getChannelCount(self: *const Self) u32 {
        return @intCast(self.channels.count());
    }
    
    pub fn processChannelData(self: *Self, channel_id: u32, data: []const u8) !void {
        const channel = self.channels.get(channel_id) orelse return ChannelError.InvalidChannelNumber;
        
        if (!channel.isOpen()) {
            return ChannelError.ChannelClosed;
        }
        
        try channel.receiveData(@intCast(data.len));
        
        // In a real implementation, this would forward the data to the appropriate handler
        // (shell, SFTP, etc.) based on the channel type
    }
    
    pub fn sendChannelData(self: *Self, channel_id: u32, data: []const u8) !void {
        const channel = self.channels.get(channel_id) orelse return ChannelError.InvalidChannelNumber;
        
        if (!channel.canSendData(@intCast(data.len))) {
            return ChannelError.WindowExceeded;
        }
        
        try channel.sendData(@intCast(data.len));
        
        // In a real implementation, this would format and send the SSH_MSG_CHANNEL_DATA packet
    }
    
    pub fn adjustChannelWindow(self: *Self, channel_id: u32, adjust_size: u32) !void {
        const channel = self.channels.get(channel_id) orelse return ChannelError.InvalidChannelNumber;
        channel.remote_window.adjustWindow(adjust_size);
    }
};

pub const ChannelRequest = struct {
    channel_id: u32,
    request_type: []const u8,
    want_reply: bool,
    request_data: ?[]const u8,
    
    pub fn createPtyRequest(allocator: Allocator, channel_id: u32, term: []const u8, width: u32, height: u32) !ChannelRequest {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        // Serialize pty-req data
        try buffer.writer().writeInt(u32, @intCast(term.len), .big);
        try buffer.appendSlice(term);
        try buffer.writer().writeInt(u32, width, .big);
        try buffer.writer().writeInt(u32, height, .big);
        try buffer.writer().writeInt(u32, 0, .big); // pixel width
        try buffer.writer().writeInt(u32, 0, .big); // pixel height
        try buffer.writer().writeInt(u32, 0, .big); // terminal modes length
        
        return ChannelRequest{
            .channel_id = channel_id,
            .request_type = "pty-req",
            .want_reply = true,
            .request_data = try buffer.toOwnedSlice(),
        };
    }
    
    pub fn createShellRequest(channel_id: u32) ChannelRequest {
        return ChannelRequest{
            .channel_id = channel_id,
            .request_type = "shell",
            .want_reply = true,
            .request_data = null,
        };
    }
    
    pub fn createExecRequest(allocator: Allocator, channel_id: u32, command: []const u8) !ChannelRequest {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, @intCast(command.len), .big);
        try buffer.appendSlice(command);
        
        return ChannelRequest{
            .channel_id = channel_id,
            .request_type = "exec",
            .want_reply = true,
            .request_data = try buffer.toOwnedSlice(),
        };
    }
    
    pub fn deinit(self: *ChannelRequest, allocator: Allocator) void {
        if (self.request_data) |data| {
            allocator.free(data);
        }
    }
};

test "Channel creation and lifecycle" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var manager = ChannelManager.init(allocator, 10);
    defer manager.deinit();
    
    const channel = try manager.createChannel(.session);
    try testing.expectEqual(@as(u32, 0), channel.local_id);
    try testing.expectEqual(ChannelState.opening, channel.state);
    try testing.expectEqual(@as(u32, 1), manager.getChannelCount());
    
    try manager.openChannel(0, 42);
    try testing.expectEqual(@as(?u32, 42), channel.remote_id);
    try testing.expect(channel.isOpen());
    
    try manager.closeChannel(0);
    try testing.expectEqual(ChannelState.closing, channel.state);
}

test "Window management" {
    const testing = std.testing;
    
    var window = WindowManager.init(1000, 500);
    
    try testing.expect(window.canReceive(400));
    try testing.expect(!window.canReceive(600)); // exceeds max packet size
    
    try window.consumeWindow(400);
    try testing.expectEqual(@as(u32, 400), window.bytes_received);
    
    try testing.expect(window.canReceive(500));
    try testing.expect(!window.canReceive(601)); // would exceed window
    
    window.adjustWindow(200);
    try testing.expectEqual(@as(u32, 200), window.bytes_received);
}

test "Channel request creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const shell_req = ChannelRequest.createShellRequest(123);
    try testing.expectEqual(@as(u32, 123), shell_req.channel_id);
    try testing.expectEqualStrings("shell", shell_req.request_type);
    try testing.expect(shell_req.want_reply);
    try testing.expect(shell_req.request_data == null);
    
    var exec_req = try ChannelRequest.createExecRequest(allocator, 456, "ls -la");
    defer exec_req.deinit(allocator);
    
    try testing.expectEqual(@as(u32, 456), exec_req.channel_id);
    try testing.expectEqualStrings("exec", exec_req.request_type);
    try testing.expect(exec_req.request_data != null);
}