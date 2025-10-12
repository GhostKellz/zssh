//! SSH Agent Protocol Implementation
//!
//! Implements the SSH agent protocol (RFC 4253) for communication with ssh-agent
//! or GVault's SSH agent implementation.
//!
//! Provides functionality to:
//! - Request list of identities
//! - Sign data with agent-stored keys
//! - Add/remove keys from agent
//! - Lock/unlock agent
//!
//! This enables seamless integration with GVault for secure key storage.

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;

pub const AgentError = error{
    AgentNotAvailable,
    ConnectionFailed,
    ProtocolError,
    UnsupportedOperation,
    SignatureFailed,
    KeyNotFound,
} || Allocator.Error || std.fs.File.OpenError;

/// SSH agent protocol message types
pub const MessageType = enum(u8) {
    // Requests
    request_identities = 11,
    sign_request = 13,
    add_identity = 17,
    remove_identity = 18,
    remove_all_identities = 19,
    add_id_constrained = 25,
    add_smartcard_key = 20,
    remove_smartcard_key = 21,
    lock = 22,
    unlock = 23,
    add_smartcard_key_constrained = 26,
    extension = 27,

    // Responses
    failure = 5,
    success = 6,
    identities_answer = 12,
    sign_response = 14,
    extension_failure = 28,

    pub fn fromU8(val: u8) ?MessageType {
        return std.meta.intToEnum(MessageType, val) catch null;
    }
};

/// SSH key signature flags
pub const SignatureFlags = packed struct {
    rsa_sha2_256: bool = false,
    rsa_sha2_512: bool = false,
    _reserved: u30 = 0,

    pub fn toU32(self: SignatureFlags) u32 {
        return @bitCast(self);
    }

    pub fn fromU32(val: u32) SignatureFlags {
        return @bitCast(val);
    }
};

/// An SSH identity from the agent
pub const Identity = struct {
    key_blob: []const u8,
    comment: []const u8,

    pub fn deinit(self: *Identity, allocator: Allocator) void {
        allocator.free(self.key_blob);
        allocator.free(self.comment);
    }
};

/// SSH Agent client
pub const SshAgent = struct {
    allocator: Allocator,
    socket_path: []const u8,
    stream: ?net.Stream,

    const Self = @This();

    /// Initialize SSH agent client
    /// If socket_path is null, uses SSH_AUTH_SOCK environment variable
    pub fn init(allocator: Allocator, socket_path: ?[]const u8) !Self {
        const path = if (socket_path) |p|
            try allocator.dupe(u8, p)
        else
            try getAgentSocketPath(allocator);

        return .{
            .allocator = allocator,
            .socket_path = path,
            .stream = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.stream) |stream| {
            stream.close();
        }
        self.allocator.free(self.socket_path);
    }

    /// Connect to SSH agent
    pub fn connect(self: *Self) !void {
        const stream = try net.connectUnixSocket(self.socket_path);
        self.stream = stream;
    }

    /// Request list of identities from agent
    pub fn requestIdentities(self: *Self) !std.ArrayList(Identity) {
        if (self.stream == null) {
            try self.connect();
        }

        // Build request message
        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.request_identities));

        // Send request
        try self.sendMessage(request.items);

        // Read response
        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0 or MessageType.fromU8(response[0]) != .identities_answer) {
            return AgentError.ProtocolError;
        }

        // Parse identities
        return try parseIdentities(self.allocator, response[1..]);
    }

    /// Sign data with a key from the agent
    pub fn sign(self: *Self, key_blob: []const u8, data: []const u8, flags: SignatureFlags) ![]const u8 {
        if (self.stream == null) {
            try self.connect();
        }

        // Build sign request
        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.sign_request));

        // Write key blob (with length prefix)
        try writeString(&request, key_blob);

        // Write data to sign (with length prefix)
        try writeString(&request, data);

        // Write flags
        try writeU32(&request, flags.toU32());

        // Send request
        try self.sendMessage(request.items);

        // Read response
        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0) {
            return AgentError.ProtocolError;
        }

        const msg_type = MessageType.fromU8(response[0]) orelse return AgentError.ProtocolError;

        if (msg_type == .failure) {
            return AgentError.SignatureFailed;
        }

        if (msg_type != .sign_response) {
            return AgentError.ProtocolError;
        }

        // Parse signature
        return try parseString(self.allocator, response[1..]);
    }

    /// Add a key to the agent
    pub fn addIdentity(
        self: *Self,
        key_type: []const u8,
        public_key: []const u8,
        private_key: []const u8,
        comment: []const u8,
    ) !void {
        if (self.stream == null) {
            try self.connect();
        }

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.add_identity));

        // Write key type
        try writeString(&request, key_type);

        // Write public key data
        try writeString(&request, public_key);

        // Write private key data
        try writeString(&request, private_key);

        // Write comment
        try writeString(&request, comment);

        // Send request
        try self.sendMessage(request.items);

        // Read response
        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0 or MessageType.fromU8(response[0]) != .success) {
            return AgentError.ProtocolError;
        }
    }

    /// Remove a key from the agent
    pub fn removeIdentity(self: *Self, key_blob: []const u8) !void {
        if (self.stream == null) {
            try self.connect();
        }

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.remove_identity));
        try writeString(&request, key_blob);

        try self.sendMessage(request.items);

        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0 or MessageType.fromU8(response[0]) != .success) {
            return AgentError.ProtocolError;
        }
    }

    /// Remove all keys from the agent
    pub fn removeAllIdentities(self: *Self) !void {
        if (self.stream == null) {
            try self.connect();
        }

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.remove_all_identities));

        try self.sendMessage(request.items);

        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0 or MessageType.fromU8(response[0]) != .success) {
            return AgentError.ProtocolError;
        }
    }

    /// Lock the agent with a password
    pub fn lock(self: *Self, password: []const u8) !void {
        if (self.stream == null) {
            try self.connect();
        }

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.lock));
        try writeString(&request, password);

        try self.sendMessage(request.items);

        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0 or MessageType.fromU8(response[0]) != .success) {
            return AgentError.ProtocolError;
        }
    }

    /// Unlock the agent with a password
    pub fn unlock(self: *Self, password: []const u8) !void {
        if (self.stream == null) {
            try self.connect();
        }

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        try request.append(@intFromEnum(MessageType.unlock));
        try writeString(&request, password);

        try self.sendMessage(request.items);

        const response = try self.readMessage();
        defer self.allocator.free(response);

        if (response.len == 0 or MessageType.fromU8(response[0]) != .success) {
            return AgentError.ProtocolError;
        }
    }

    // Private helper methods

    fn sendMessage(self: *Self, data: []const u8) !void {
        const stream = self.stream orelse return AgentError.ConnectionFailed;

        // Write length prefix (4 bytes, big-endian)
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
        try stream.writeAll(&len_buf);

        // Write message data
        try stream.writeAll(data);
    }

    fn readMessage(self: *Self) ![]const u8 {
        const stream = self.stream orelse return AgentError.ConnectionFailed;

        // Read length prefix
        var len_buf: [4]u8 = undefined;
        const len_read = try stream.readAll(&len_buf);
        if (len_read != 4) {
            return AgentError.ProtocolError;
        }

        const msg_len = std.mem.readInt(u32, &len_buf, .big);
        if (msg_len == 0 or msg_len > 256 * 1024) { // Max 256KB
            return AgentError.ProtocolError;
        }

        // Read message data
        const data = try self.allocator.alloc(u8, msg_len);
        errdefer self.allocator.free(data);

        const data_read = try stream.readAll(data);
        if (data_read != msg_len) {
            return AgentError.ProtocolError;
        }

        return data;
    }
};

// Protocol helper functions

fn getAgentSocketPath(allocator: Allocator) ![]const u8 {
    const env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    const path = env_map.get("SSH_AUTH_SOCK") orelse return AgentError.AgentNotAvailable;
    return try allocator.dupe(u8, path);
}

fn parseIdentities(allocator: Allocator, data: []const u8) !std.ArrayList(Identity) {
    var identities = std.ArrayList(Identity).init(allocator);
    errdefer {
        for (identities.items) |*id| {
            id.deinit(allocator);
        }
        identities.deinit();
    }

    // Read number of identities
    if (data.len < 4) return AgentError.ProtocolError;

    const count = std.mem.readInt(u32, data[0..4], .big);
    var pos: usize = 4;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        // Read key blob
        const key_blob = try parseStringAt(allocator, data, &pos);
        errdefer allocator.free(key_blob);

        // Read comment
        const comment = try parseStringAt(allocator, data, &pos);
        errdefer allocator.free(comment);

        try identities.append(.{
            .key_blob = key_blob,
            .comment = comment,
        });
    }

    return identities;
}

fn parseString(allocator: Allocator, data: []const u8) ![]const u8 {
    if (data.len < 4) return AgentError.ProtocolError;

    const str_len = std.mem.readInt(u32, data[0..4], .big);
    if (str_len + 4 > data.len) return AgentError.ProtocolError;

    return try allocator.dupe(u8, data[4 .. 4 + str_len]);
}

fn parseStringAt(allocator: Allocator, data: []const u8, pos: *usize) ![]const u8 {
    if (pos.* + 4 > data.len) return AgentError.ProtocolError;

    const str_len = std.mem.readInt(u32, data[pos.* .. pos.* + 4], .big);
    pos.* += 4;

    if (pos.* + str_len > data.len) return AgentError.ProtocolError;

    const result = try allocator.dupe(u8, data[pos.* .. pos.* + str_len]);
    pos.* += str_len;

    return result;
}

fn writeString(list: *std.ArrayList(u8), str: []const u8) !void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(str.len), .big);
    try list.appendSlice(&len_buf);
    try list.appendSlice(str);
}

fn writeU32(list: *std.ArrayList(u8), val: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, val, .big);
    try list.appendSlice(&buf);
}

// Tests

test "SSH agent message types" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 11), @intFromEnum(MessageType.request_identities));
    try testing.expectEqual(@as(u8, 13), @intFromEnum(MessageType.sign_request));
    try testing.expectEqual(@as(u8, 12), @intFromEnum(MessageType.identities_answer));
}

test "SSH agent protocol helpers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test writeString
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();

    try writeString(&list, "test");
    try testing.expectEqual(@as(usize, 8), list.items.len); // 4 bytes length + 4 bytes data

    // Test parseString
    const parsed = try parseString(allocator, list.items);
    defer allocator.free(parsed);
    try testing.expectEqualStrings("test", parsed);
}

test "SSH agent signature flags" {
    const testing = std.testing;

    const flags = SignatureFlags{
        .rsa_sha2_256 = true,
        .rsa_sha2_512 = false,
    };

    const val = flags.toU32();
    const restored = SignatureFlags.fromU32(val);

    try testing.expectEqual(flags.rsa_sha2_256, restored.rsa_sha2_256);
    try testing.expectEqual(flags.rsa_sha2_512, restored.rsa_sha2_512);
}
