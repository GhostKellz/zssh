//! SSH Connection Multiplexing (ControlMaster)
//!
//! Implements OpenSSH-compatible connection multiplexing for sharing a single
//! SSH connection across multiple sessions. This dramatically speeds up
//! subsequent connections to the same host.
//!
//! Features:
//! - Control socket management
//! - Master connection lifecycle
//! - Client connection requests
//! - Session sharing
//! - Control commands (check, exit, stop)

const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;

pub const MultiplexError = error{
    SocketCreationFailed,
    MasterNotRunning,
    ConnectionFailed,
    ProtocolError,
    PermissionDenied,
} || Allocator.Error || std.fs.File.OpenError;

/// Multiplexing mode
pub const MuxMode = enum {
    no,          // No multiplexing
    auto,        // Automatically create master if none exists
    ask,         // Ask before creating master
    auto_ask,    // Try auto, fall back to ask
    yes,         // Always use multiplexing
};

/// Control command
pub const MuxCommand = enum(u32) {
    hello = 0x00000001,
    new_session = 0x00000002,
    alive_check = 0x00000003,
    terminate = 0x00000004,
    open_fwd = 0x00000005,
    close_fwd = 0x00000006,
    new_stdio_fwd = 0x00000007,
    stop_listening = 0x00000008,
    proxy = 0x0000000f,

    pub fn fromU32(val: u32) ?MuxCommand {
        return std.meta.intToEnum(MuxCommand, val) catch null;
    }
};

/// Multiplexing configuration
pub const MuxConfig = struct {
    socket_path: []const u8,
    persist_seconds: u32 = 0,  // 0 = forever, N = auto-close after N seconds
    mode: MuxMode = .auto,
    permissions: u32 = 0o600,
};

/// Master connection manager
pub const MuxMaster = struct {
    allocator: Allocator,
    config: MuxConfig,
    socket: ?net.Server,
    clients: std.ArrayList(*MuxClient),
    ssh_connection: ?*anyopaque,  // Underlying SSH connection
    last_activity: i64,
    running: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, config: MuxConfig) !Self {
        // Zig 0.16.0-dev: std.time.timestamp() removed
        var io_threaded = std.Io.Threaded.init_single_threaded;
        const io = io_threaded.io();
        const now_ts = try std.Io.Clock.now(.real, io);
        const timestamp: i64 = @divFloor(now_ts.nanoseconds, std.time.ns_per_s);

        return .{
            .allocator = allocator,
            .config = config,
            .socket = null,
            .clients = std.ArrayList(*MuxClient).init(allocator),
            .ssh_connection = null,
            .last_activity = timestamp,
            .running = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.socket) |*sock| {
            sock.deinit();
        }

        for (self.clients.items) |client| {
            client.deinit();
            self.allocator.destroy(client);
        }
        self.clients.deinit();

        // Clean up socket file
        std.fs.cwd().deleteFile(self.config.socket_path) catch {};
    }

    /// Start master connection
    pub fn start(self: *Self, ssh_connection: *anyopaque) !void {
        self.ssh_connection = ssh_connection;

        // Create Unix domain socket
        // First, ensure parent directory exists
        if (std.fs.path.dirname(self.config.socket_path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }

        // Remove old socket if it exists
        std.fs.cwd().deleteFile(self.config.socket_path) catch {};

        // Create socket
        const socket_path_z = try self.allocator.dupeZ(u8, self.config.socket_path);
        defer self.allocator.free(socket_path_z);

        var addr = try net.Address.initUnix(socket_path_z);
        const server = try addr.listen(.{});

        self.socket = server;
        self.running = true;

        // Set socket permissions
        try std.posix.chmod(self.config.socket_path, self.config.permissions);

        std.debug.print("Control socket: {s}\n", .{self.config.socket_path});
    }

    /// Accept client connections
    pub fn acceptLoop(self: *Self) !void {
        while (self.running) {
            if (self.socket) |*server| {
                const connection = try server.accept();

                const client = try self.allocator.create(MuxClient);
                client.* = try MuxClient.init(self.allocator, connection.stream, self);

                try self.clients.append(client);

                // Handle client request
                client.handle() catch |err| {
                    std.debug.print("Client error: {any}\n", .{err});
                    client.deinit();
                };

                // Zig 0.16.0-dev: std.time.timestamp() removed
                var io_threaded = std.Io.Threaded.init_single_threaded;
                const io = io_threaded.io();
                const now_ts = try std.Io.Clock.now(.real, io);
                self.last_activity = @divFloor(now_ts.nanoseconds, std.time.ns_per_s);
            }

            // Check if we should auto-close
            if (self.config.persist_seconds > 0) {
                // Zig 0.16.0-dev: std.time.timestamp() removed
                var io_threaded2 = std.Io.Threaded.init_single_threaded;
                const io2 = io_threaded2.io();
                const now_ts2 = try std.Io.Clock.now(.real, io2);
                const current_time: i64 = @divFloor(now_ts2.nanoseconds, std.time.ns_per_s);
                const elapsed = current_time - self.last_activity;
                if (elapsed > self.config.persist_seconds) {
                    std.debug.print("Auto-closing master after {d}s of inactivity\n", .{elapsed});
                    self.stop();
                }
            }
        }
    }

    /// Stop master connection
    pub fn stop(self: *Self) void {
        self.running = false;

        // Close all client connections
        for (self.clients.items) |client| {
            client.close();
        }
    }

    /// Check if master is still alive
    pub fn isAlive(self: *const Self) bool {
        return self.running and self.ssh_connection != null;
    }
};

/// Client connection to master
pub const MuxClient = struct {
    allocator: Allocator,
    stream: net.Stream,
    master: *MuxMaster,
    session_id: u32,

    pub fn init(allocator: Allocator, stream: net.Stream, master: *MuxMaster) !MuxClient {
        return .{
            .allocator = allocator,
            .stream = stream,
            .master = master,
            .session_id = 0,
        };
    }

    pub fn deinit(self: *MuxClient) void {
        self.stream.close();
    }

    pub fn close(self: *MuxClient) void {
        self.stream.close();
    }

    /// Handle client request
    pub fn handle(self: *MuxClient) !void {
        // Read command header
        var header: [8]u8 = undefined;
        const bytes_read = try self.stream.read(&header);

        if (bytes_read < 8) {
            return MultiplexError.ProtocolError;
        }

        const msg_len = std.mem.readInt(u32, header[0..4], .big);
        const command_val = std.mem.readInt(u32, header[4..8], .big);

        const command = MuxCommand.fromU32(command_val) orelse return MultiplexError.ProtocolError;

        // Read rest of message
        const payload = if (msg_len > 8) blk: {
            const p = try self.allocator.alloc(u8, msg_len - 8);
            _ = try self.stream.read(p);
            break :blk p;
        } else null;
        defer if (payload) |p| self.allocator.free(p);

        // Handle command
        try self.handleCommand(command, payload);
    }

    fn handleCommand(self: *MuxClient, command: MuxCommand, payload: ?[]const u8) !void {
        switch (command) {
            .hello => try self.handleHello(payload),
            .alive_check => try self.handleAliveCheck(),
            .new_session => try self.handleNewSession(payload),
            .terminate => try self.handleTerminate(),
            .stop_listening => try self.handleStopListening(),
            else => {
                std.debug.print("Unsupported command: {any}\n", .{command});
                try self.sendError("Command not supported");
            },
        }
    }

    fn handleHello(self: *MuxClient, payload: ?[]const u8) !void {
        _ = payload;

        // Send hello response
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        // Message length (will fill in later)
        try response.appendNTimes(0, 4);

        // Command (hello response)
        try writeU32(&response, @intFromEnum(MuxCommand.hello));

        // Protocol version
        try writeU32(&response, 4); // SSH multiplex protocol v4

        // Session ID
        // Zig 0.16.0-dev: std.time.timestamp() removed
        var io_threaded = std.Io.Threaded.init_single_threaded;
        const io = io_threaded.io();
        const now_ts = try std.Io.Clock.now(.real, io);
        const timestamp_i64: i64 = @divFloor(now_ts.nanoseconds, std.time.ns_per_s);
        self.session_id = @as(u32, @intCast(timestamp_i64));
        try writeU32(&response, self.session_id);

        // Write message length
        const msg_len: u32 = @intCast(response.items.len);
        std.mem.writeInt(u32, response.items[0..4], msg_len, .big);

        try self.stream.writeAll(response.items);
    }

    fn handleAliveCheck(self: *MuxClient) !void {
        // Check if master is alive
        const alive = self.master.isAlive();

        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        try response.appendNTimes(0, 4);
        try writeU32(&response, @intFromEnum(MuxCommand.alive_check));
        try writeU32(&response, self.session_id);
        try writeU32(&response, if (alive) 0 else 1); // 0 = alive, 1 = dead

        const msg_len: u32 = @intCast(response.items.len);
        std.mem.writeInt(u32, response.items[0..4], msg_len, .big);

        try self.stream.writeAll(response.items);
    }

    fn handleNewSession(self: *MuxClient, payload: ?[]const u8) !void {
        _ = payload;

        // TODO: Create new session using master's SSH connection

        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        try response.appendNTimes(0, 4);
        try writeU32(&response, @intFromEnum(MuxCommand.new_session));
        try writeU32(&response, self.session_id);
        try writeU32(&response, 0); // Success

        const msg_len: u32 = @intCast(response.items.len);
        std.mem.writeInt(u32, response.items[0..4], msg_len, .big);

        try self.stream.writeAll(response.items);
    }

    fn handleTerminate(self: *MuxClient) !void {
        self.master.stop();

        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        try response.appendNTimes(0, 4);
        try writeU32(&response, @intFromEnum(MuxCommand.terminate));
        try writeU32(&response, self.session_id);

        const msg_len: u32 = @intCast(response.items.len);
        std.mem.writeInt(u32, response.items[0..4], msg_len, .big);

        try self.stream.writeAll(response.items);
    }

    fn handleStopListening(self: *MuxClient) !void {
        self.master.stop();

        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        try response.appendNTimes(0, 4);
        try writeU32(&response, @intFromEnum(MuxCommand.stop_listening));

        const msg_len: u32 = @intCast(response.items.len);
        std.mem.writeInt(u32, response.items[0..4], msg_len, .big);

        try self.stream.writeAll(response.items);
    }

    fn sendError(self: *MuxClient, message: []const u8) !void {
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        try response.appendNTimes(0, 4);
        try writeU32(&response, 0x80000000); // Error marker
        try writeString(&response, message);

        const msg_len: u32 = @intCast(response.items.len);
        std.mem.writeInt(u32, response.items[0..4], msg_len, .big);

        try self.stream.writeAll(response.items);
    }
};

/// Check if a control master is running at the given socket
pub fn checkMaster(allocator: Allocator, socket_path: []const u8) !bool {
    // Try to connect to socket
    const stream = net.connectUnixSocket(socket_path) catch {
        return false;
    };
    defer stream.close();

    // Send alive check
    var request = std.ArrayList(u8).init(allocator);
    defer request.deinit();

    try request.appendNTimes(0, 4); // Length placeholder
    try writeU32(&request, @intFromEnum(MuxCommand.alive_check));

    const msg_len: u32 = @intCast(request.items.len);
    std.mem.writeInt(u32, request.items[0..4], msg_len, .big);

    try stream.writeAll(request.items);

    // Read response
    var header: [8]u8 = undefined;
    _ = try stream.read(&header);

    const resp_command = std.mem.readInt(u32, header[4..8], .big);

    return resp_command == @intFromEnum(MuxCommand.alive_check);
}

// Helper functions

fn writeU32(list: *std.ArrayList(u8), val: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, val, .big);
    try list.appendSlice(&buf);
}

fn writeString(list: *std.ArrayList(u8), str: []const u8) !void {
    try writeU32(list, @intCast(str.len));
    try list.appendSlice(str);
}

// Tests

test "Mux command values" {
    const testing = std.testing;

    try testing.expectEqual(@as(u32, 1), @intFromEnum(MuxCommand.hello));
    try testing.expectEqual(@as(u32, 3), @intFromEnum(MuxCommand.alive_check));
}

test "Mux config" {
    const config = MuxConfig{
        .socket_path = "/tmp/ssh-mux-test",
        .persist_seconds = 600,
        .mode = .auto,
    };

    @import("std").testing.expectEqual(@as(u32, 600), config.persist_seconds);
}
