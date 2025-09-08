//! SFTP (SSH File Transfer Protocol) Implementation
//!
//! Implements SFTP v3 as defined in draft-ietf-secsh-filexfer-02.txt.
//! Provides secure file transfer capabilities over SSH connections.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const SftpError = error{
    UnsupportedVersion,
    InvalidPacketType,
    InvalidHandle,
    FileNotFound,
    PermissionDenied,
    InvalidPath,
    OperationUnsupported,
    BadMessage,
} || Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || std.fs.File.WriteError;

pub const SFTP_VERSION = 3;

pub const SftpPacketType = enum(u8) {
    init = 1,
    version = 2,
    open = 3,
    close = 4,
    read = 5,
    write = 6,
    lstat = 7,
    fstat = 8,
    setstat = 9,
    fsetstat = 10,
    opendir = 11,
    readdir = 12,
    remove = 13,
    mkdir = 14,
    rmdir = 15,
    realpath = 16,
    stat = 17,
    rename = 18,
    readlink = 19,
    symlink = 20,
    status = 101,
    handle = 102,
    data = 103,
    name = 104,
    attrs = 105,
};

pub const SftpStatusCode = enum(u32) {
    ok = 0,
    eof = 1,
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,
};

pub const FileFlags = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    append: bool = false,
    create: bool = false,
    truncate: bool = false,
    exclusive: bool = false,
    _padding: u26 = 0,
};

pub const FileAttributes = struct {
    size: ?u64 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    permissions: ?u32 = null,
    atime: ?u32 = null,
    mtime: ?u32 = null,
    
    const Self = @This();
    
    pub fn fromFileInfo(file_info: std.fs.File.Stat) Self {
        return Self{
            .size = @intCast(file_info.size),
            .permissions = @intCast(file_info.mode),
            .atime = @intCast(@divFloor(file_info.atime, std.time.ns_per_s)),
            .mtime = @intCast(@divFloor(file_info.mtime, std.time.ns_per_s)),
            .uid = null,
            .gid = null,
        };
    }
    
    pub fn serialize(self: *const Self, writer: anytype) !void {
        var flags: u32 = 0;
        
        if (self.size != null) flags |= 0x00000001;
        if (self.uid != null and self.gid != null) flags |= 0x00000002;
        if (self.permissions != null) flags |= 0x00000004;
        if (self.atime != null and self.mtime != null) flags |= 0x00000008;
        
        try writer.writeInt(u32, flags, .big);
        
        if (self.size) |size| {
            try writer.writeInt(u64, size, .big);
        }
        
        if (self.uid) |uid| {
            try writer.writeInt(u32, uid, .big);
            try writer.writeInt(u32, self.gid.?, .big);
        }
        
        if (self.permissions) |perms| {
            try writer.writeInt(u32, perms, .big);
        }
        
        if (self.atime) |atime| {
            try writer.writeInt(u32, atime, .big);
            try writer.writeInt(u32, self.mtime.?, .big);
        }
    }
    
    pub fn deserialize(reader: anytype) !Self {
        const flags = try reader.readInt(u32, .big);
        
        var attrs = Self{};
        
        if (flags & 0x00000001 != 0) {
            attrs.size = try reader.readInt(u64, .big);
        }
        
        if (flags & 0x00000002 != 0) {
            attrs.uid = try reader.readInt(u32, .big);
            attrs.gid = try reader.readInt(u32, .big);
        }
        
        if (flags & 0x00000004 != 0) {
            attrs.permissions = try reader.readInt(u32, .big);
        }
        
        if (flags & 0x00000008 != 0) {
            attrs.atime = try reader.readInt(u32, .big);
            attrs.mtime = try reader.readInt(u32, .big);
        }
        
        return attrs;
    }
};

pub const SftpPacket = struct {
    packet_type: SftpPacketType,
    data: []u8,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, packet_type: SftpPacketType, data: []const u8) !Self {
        return Self{
            .packet_type = packet_type,
            .data = try allocator.dupe(u8, data),
        };
    }
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.data);
    }
    
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var buffer = try allocator.alloc(u8, 5 + self.data.len);
        
        std.mem.writeInt(u32, buffer[0..4], @intCast(1 + self.data.len), .big);
        buffer[4] = @intFromEnum(self.packet_type);
        @memcpy(buffer[5..], self.data);
        
        return buffer;
    }
    
    pub fn deserialize(allocator: Allocator, data: []const u8) !Self {
        if (data.len < 5) return SftpError.BadMessage;
        
        const length = std.mem.readInt(u32, data[0..4], .big);
        if (length != data.len - 4) return SftpError.BadMessage;
        
        const packet_type_raw = data[4];
        const packet_type = std.meta.intToEnum(SftpPacketType, packet_type_raw) catch {
            return SftpError.InvalidPacketType;
        };
        
        const packet_data = try allocator.dupe(u8, data[5..]);
        
        return Self{
            .packet_type = packet_type,
            .data = packet_data,
        };
    }
};

pub const FileHandle = struct {
    id: []u8,
    file: std.fs.File,
    path: []u8,
    flags: FileFlags,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, handle_id: []const u8, file: std.fs.File, path: []const u8, flags: FileFlags) !Self {
        return Self{
            .id = try allocator.dupe(u8, handle_id),
            .file = file,
            .path = try allocator.dupe(u8, path),
            .flags = flags,
        };
    }
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.file.close();
        allocator.free(self.id);
        allocator.free(self.path);
    }
};

pub const SftpServer = struct {
    allocator: Allocator,
    root_path: []const u8,
    handles: std.HashMapUnmanaged(u64, FileHandle, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    next_handle_id: u64,
    version: u32,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, root_path: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .root_path = try allocator.dupe(u8, root_path),
            .handles = std.HashMapUnmanaged(u64, FileHandle, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage){},
            .next_handle_id = 1,
            .version = SFTP_VERSION,
        };
    }
    
    pub fn deinit(self: *Self) void {
        var iterator = self.handles.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.handles.deinit(self.allocator);
        self.allocator.free(self.root_path);
    }
    
    pub fn processPacket(self: *Self, packet_data: []const u8) ![]u8 {
        var packet = try SftpPacket.deserialize(self.allocator, packet_data);
        defer packet.deinit(self.allocator);
        
        return switch (packet.packet_type) {
            .init => try self.handleInit(packet.data),
            .open => try self.handleOpen(packet.data),
            .close => try self.handleClose(packet.data),
            .read => try self.handleRead(packet.data),
            .write => try self.handleWrite(packet.data),
            .stat, .lstat => try self.handleStat(packet.data),
            .fstat => try self.handleFstat(packet.data),
            .opendir => try self.handleOpendir(packet.data),
            .readdir => try self.handleReaddir(packet.data),
            .realpath => try self.handleRealpath(packet.data),
            else => try self.sendStatus(0, .op_unsupported, "Operation not supported", ""),
        };
    }
    
    fn handleInit(self: *Self, data: []const u8) ![]u8 {
        _ = data;
        
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, self.version, .big);
        
        const response_packet = try SftpPacket.init(self.allocator, .version, buffer.items);
        defer response_packet.deinit(self.allocator);
        
        return try response_packet.serialize(self.allocator);
    }
    
    fn handleOpen(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const path_len = try reader.readInt(u32, .big);
        
        if (path_len > data.len - 12) return SftpError.BadMessage;
        
        const path = data[12..12 + path_len];
        const flags_raw = try reader.readInt(u32, .big);
        const flags: FileFlags = @bitCast(flags_raw);
        
        const attrs = try FileAttributes.deserialize(reader);
        _ = attrs; // TODO: Use attributes when creating file
        
        const full_path = try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.root_path, path });
        defer self.allocator.free(full_path);
        
        var open_flags: std.fs.File.OpenFlags = .{};
        if (flags.read) open_flags.mode = .read_write;
        if (flags.write) open_flags.mode = .read_write;
        
        const file = std.fs.cwd().openFile(full_path, open_flags) catch |err| switch (err) {
            error.FileNotFound => return try self.sendStatus(request_id, .no_such_file, "File not found", ""),
            error.AccessDenied => return try self.sendStatus(request_id, .permission_denied, "Permission denied", ""),
            else => return try self.sendStatus(request_id, .failure, "Open failed", ""),
        };
        
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;
        
        const handle = try FileHandle.init(self.allocator, std.mem.asBytes(&handle_id), file, path, flags);
        try self.handles.put(self.allocator, handle_id, handle);
        
        return try self.sendHandle(request_id, handle.id);
    }
    
    fn handleClose(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const handle_len = try reader.readInt(u32, .big);
        
        if (handle_len != 8) return try self.sendStatus(request_id, .bad_message, "Invalid handle", "");
        
        const handle_bytes = data[8..16];
        const handle_id = std.mem.readInt(u64, handle_bytes, .big);
        
        if (self.handles.fetchRemove(handle_id)) |entry| {
            entry.value.deinit(self.allocator);
            return try self.sendStatus(request_id, .ok, "", "");
        } else {
            return try self.sendStatus(request_id, .failure, "Invalid handle", "");
        }
    }
    
    fn handleRead(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const handle_len = try reader.readInt(u32, .big);
        
        if (handle_len != 8) return try self.sendStatus(request_id, .bad_message, "Invalid handle", "");
        
        const handle_bytes = data[8..16];
        const handle_id = std.mem.readInt(u64, handle_bytes, .big);
        const offset = try reader.readInt(u64, .big);
        const length = try reader.readInt(u32, .big);
        
        const handle = self.handles.get(handle_id) orelse {
            return try self.sendStatus(request_id, .failure, "Invalid handle", "");
        };
        
        var buffer = try self.allocator.alloc(u8, length);
        defer self.allocator.free(buffer);
        
        _ = try handle.file.seekTo(offset);
        const bytes_read = try handle.file.read(buffer);
        
        if (bytes_read == 0) {
            return try self.sendStatus(request_id, .eof, "", "");
        }
        
        return try self.sendData(request_id, buffer[0..bytes_read]);
    }
    
    fn handleWrite(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const handle_len = try reader.readInt(u32, .big);
        
        if (handle_len != 8) return try self.sendStatus(request_id, .bad_message, "Invalid handle", "");
        
        const handle_bytes = data[8..16];
        const handle_id = std.mem.readInt(u64, handle_bytes, .big);
        const offset = try reader.readInt(u64, .big);
        const write_data_len = try reader.readInt(u32, .big);
        
        if (write_data_len > data.len - 24) return try self.sendStatus(request_id, .bad_message, "Invalid data length", "");
        
        const write_data = data[24..24 + write_data_len];
        
        const handle = self.handles.getPtr(handle_id) orelse {
            return try self.sendStatus(request_id, .failure, "Invalid handle", "");
        };
        
        _ = try handle.file.seekTo(offset);
        _ = try handle.file.writeAll(write_data);
        
        return try self.sendStatus(request_id, .ok, "", "");
    }
    
    fn handleStat(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const path_len = try reader.readInt(u32, .big);
        
        if (path_len > data.len - 8) return try self.sendStatus(request_id, .bad_message, "Invalid path length", "");
        
        const path = data[8..8 + path_len];
        
        const full_path = try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.root_path, path });
        defer self.allocator.free(full_path);
        
        const file_info = std.fs.cwd().statFile(full_path) catch |err| switch (err) {
            error.FileNotFound => return try self.sendStatus(request_id, .no_such_file, "File not found", ""),
            error.AccessDenied => return try self.sendStatus(request_id, .permission_denied, "Permission denied", ""),
            else => return try self.sendStatus(request_id, .failure, "Stat failed", ""),
        };
        
        const attrs = FileAttributes.fromFileInfo(file_info);
        return try self.sendAttrs(request_id, attrs);
    }
    
    fn handleFstat(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const handle_len = try reader.readInt(u32, .big);
        
        if (handle_len != 8) return try self.sendStatus(request_id, .bad_message, "Invalid handle", "");
        
        const handle_bytes = data[8..16];
        const handle_id = std.mem.readInt(u64, handle_bytes, .big);
        
        const handle = self.handles.get(handle_id) orelse {
            return try self.sendStatus(request_id, .failure, "Invalid handle", "");
        };
        
        const file_info = handle.file.stat() catch {
            return try self.sendStatus(request_id, .failure, "Fstat failed", "");
        };
        
        const attrs = FileAttributes.fromFileInfo(file_info);
        return try self.sendAttrs(request_id, attrs);
    }
    
    fn handleOpendir(self: *Self, data: []const u8) ![]u8 {
        // For simplicity, opendir is not fully implemented here
        const request_id = std.mem.readInt(u32, data[0..4], .big);
        return try self.sendStatus(request_id, .op_unsupported, "opendir not implemented", "");
    }
    
    fn handleReaddir(self: *Self, data: []const u8) ![]u8 {
        // For simplicity, readdir is not fully implemented here
        const request_id = std.mem.readInt(u32, data[0..4], .big);
        return try self.sendStatus(request_id, .op_unsupported, "readdir not implemented", "");
    }
    
    fn handleRealpath(self: *Self, data: []const u8) ![]u8 {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        
        const request_id = try reader.readInt(u32, .big);
        const path_len = try reader.readInt(u32, .big);
        
        if (path_len > data.len - 8) return try self.sendStatus(request_id, .bad_message, "Invalid path length", "");
        
        const path = data[8..8 + path_len];
        
        const real_path = try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.root_path, path });
        defer self.allocator.free(real_path);
        
        return try self.sendName(request_id, &[_][]const u8{real_path});
    }
    
    fn sendStatus(self: *Self, request_id: u32, status: SftpStatusCode, message: []const u8, language: []const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, request_id, .big);
        try buffer.writer().writeInt(u32, @intFromEnum(status), .big);
        try buffer.writer().writeInt(u32, @intCast(message.len), .big);
        try buffer.appendSlice(message);
        try buffer.writer().writeInt(u32, @intCast(language.len), .big);
        try buffer.appendSlice(language);
        
        const response_packet = try SftpPacket.init(self.allocator, .status, buffer.items);
        defer response_packet.deinit(self.allocator);
        
        return try response_packet.serialize(self.allocator);
    }
    
    fn sendHandle(self: *Self, request_id: u32, handle: []const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, request_id, .big);
        try buffer.writer().writeInt(u32, @intCast(handle.len), .big);
        try buffer.appendSlice(handle);
        
        const response_packet = try SftpPacket.init(self.allocator, .handle, buffer.items);
        defer response_packet.deinit(self.allocator);
        
        return try response_packet.serialize(self.allocator);
    }
    
    fn sendData(self: *Self, request_id: u32, data: []const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, request_id, .big);
        try buffer.writer().writeInt(u32, @intCast(data.len), .big);
        try buffer.appendSlice(data);
        
        const response_packet = try SftpPacket.init(self.allocator, .data, buffer.items);
        defer response_packet.deinit(self.allocator);
        
        return try response_packet.serialize(self.allocator);
    }
    
    fn sendAttrs(self: *Self, request_id: u32, attrs: FileAttributes) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, request_id, .big);
        try attrs.serialize(buffer.writer());
        
        const response_packet = try SftpPacket.init(self.allocator, .attrs, buffer.items);
        defer response_packet.deinit(self.allocator);
        
        return try response_packet.serialize(self.allocator);
    }
    
    fn sendName(self: *Self, request_id: u32, names: [][]const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        
        try buffer.writer().writeInt(u32, request_id, .big);
        try buffer.writer().writeInt(u32, @intCast(names.len), .big);
        
        for (names) |name| {
            try buffer.writer().writeInt(u32, @intCast(name.len), .big);
            try buffer.appendSlice(name);
            try buffer.writer().writeInt(u32, @intCast(name.len), .big); // longname (same as filename for simplicity)
            try buffer.appendSlice(name);
            // Empty attributes
            try buffer.writer().writeInt(u32, 0, .big);
        }
        
        const response_packet = try SftpPacket.init(self.allocator, .name, buffer.items);
        defer response_packet.deinit(self.allocator);
        
        return try response_packet.serialize(self.allocator);
    }
};

test "SFTP packet serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const data = "test data";
    var packet = try SftpPacket.init(allocator, .data, data);
    defer packet.deinit(allocator);
    
    const serialized = try packet.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len > 0);
    try testing.expectEqual(@as(u8, @intFromEnum(SftpPacketType.data)), serialized[4]);
}

test "File attributes serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const attrs = FileAttributes{
        .size = 1024,
        .permissions = 0o755,
        .mtime = 1234567890,
        .atime = 1234567890,
    };
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try attrs.serialize(buffer.writer());
    try testing.expect(buffer.items.len > 0);
    
    var stream = std.io.fixedBufferStream(buffer.items);
    const deserialized = try FileAttributes.deserialize(stream.reader());
    
    try testing.expectEqual(attrs.size, deserialized.size);
    try testing.expectEqual(attrs.permissions, deserialized.permissions);
    try testing.expectEqual(attrs.mtime, deserialized.mtime);
    try testing.expectEqual(attrs.atime, deserialized.atime);
}