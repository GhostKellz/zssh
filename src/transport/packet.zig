//! SSH Packet Handling
//!
//! Implements SSH packet structure and parsing as defined in RFC 4253.
//! Handles packet length, padding, compression, and basic packet operations.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const PacketError = error{
    InvalidPacketLength,
    InvalidPadding,
    PacketTooLarge,
    InsufficientData,
} || Allocator.Error;

pub const MAX_PACKET_LENGTH = 35000;
pub const MIN_PACKET_LENGTH = 16;
pub const MIN_PADDING_LENGTH = 4;

pub const Packet = struct {
    packet_length: u32,
    padding_length: u8,
    payload: []u8,
    padding: []u8,
    mac: ?[]u8,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, payload: []const u8) !Self {
        if (payload.len > MAX_PACKET_LENGTH - MIN_PADDING_LENGTH - 5) {
            return PacketError.PacketTooLarge;
        }
        
        const padding_length = calculatePaddingLength(payload.len);
        const total_length = 1 + payload.len + padding_length;
        
        const packet = Self{
            .packet_length = @intCast(total_length),
            .padding_length = padding_length,
            .payload = try allocator.dupe(u8, payload),
            .padding = try allocator.alloc(u8, padding_length),
            .mac = null,
        };
        
        std.crypto.random.bytes(packet.padding);
        
        return packet;
    }
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.payload);
        allocator.free(self.padding);
        if (self.mac) |mac| {
            allocator.free(mac);
        }
    }
    
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        const total_size = 4 + 1 + self.payload.len + self.padding.len;
        var buffer = try allocator.alloc(u8, total_size);
        var pos: usize = 0;
        
        std.mem.writeInt(u32, buffer[pos..pos+4][0..4], self.packet_length, .big);
        pos += 4;
        
        buffer[pos] = self.padding_length;
        pos += 1;
        
        @memcpy(buffer[pos..pos+self.payload.len], self.payload);
        pos += self.payload.len;
        
        @memcpy(buffer[pos..pos+self.padding.len], self.padding);
        
        return buffer;
    }
    
    pub fn deserialize(allocator: Allocator, data: []const u8) !Self {
        if (data.len < 5) {
            return PacketError.InsufficientData;
        }
        
        const packet_length = std.mem.readInt(u32, data[0..4], .big);
        if (packet_length < MIN_PACKET_LENGTH or packet_length > MAX_PACKET_LENGTH) {
            return PacketError.InvalidPacketLength;
        }
        
        const padding_length = data[4];
        if (padding_length < MIN_PADDING_LENGTH) {
            return PacketError.InvalidPadding;
        }
        
        const expected_total = 4 + packet_length;
        if (data.len < expected_total) {
            return PacketError.InsufficientData;
        }
        
        const payload_length = packet_length - 1 - padding_length;
        const payload_start = 5;
        const padding_start = payload_start + payload_length;
        
        return Self{
            .packet_length = packet_length,
            .padding_length = padding_length,
            .payload = try allocator.dupe(u8, data[payload_start..padding_start]),
            .padding = try allocator.dupe(u8, data[padding_start..padding_start + padding_length]),
            .mac = null,
        };
    }
    
    fn calculatePaddingLength(payload_len: usize) u8 {
        const block_size = 8;
        const packet_len = 1 + payload_len;
        const padding_needed = block_size - (packet_len % block_size);
        const final_padding = if (padding_needed < MIN_PADDING_LENGTH) padding_needed + block_size else padding_needed;
        return @intCast(final_padding);
    }
};

test "Packet creation and serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const payload = "Hello, SSH!";
    var packet = try Packet.init(allocator, payload);
    defer packet.deinit(allocator);
    
    try testing.expect(packet.payload.len == payload.len);
    try testing.expect(packet.padding_length >= MIN_PADDING_LENGTH);
    try testing.expectEqualStrings(packet.payload, payload);
    
    const serialized = try packet.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len >= 5 + payload.len + MIN_PADDING_LENGTH);
}

test "Packet deserialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const payload = "Test payload";
    var original = try Packet.init(allocator, payload);
    defer original.deinit(allocator);
    
    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);
    
    var deserialized = try Packet.deserialize(allocator, serialized);
    defer deserialized.deinit(allocator);
    
    try testing.expectEqual(original.packet_length, deserialized.packet_length);
    try testing.expectEqual(original.padding_length, deserialized.padding_length);
    try testing.expectEqualSlices(u8, original.payload, deserialized.payload);
}

test "Invalid packet handling" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    try testing.expectError(PacketError.InsufficientData, Packet.deserialize(allocator, &[_]u8{1, 2, 3}));
    
    const invalid_length_data = [_]u8{0, 0, 0, 8, 4, 1, 2, 3, 4, 5, 6, 7};
    try testing.expectError(PacketError.InvalidPacketLength, Packet.deserialize(allocator, &invalid_length_data));
}