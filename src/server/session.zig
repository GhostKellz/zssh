//! SSH Session Management
//!
//! Implements SSH session handling including PTY allocation, shell/exec commands,
//! and terminal interaction as defined in RFC 4254.

const std = @import("std");
const channel = @import("../transport/channel.zig");
const Allocator = std.mem.Allocator;

pub const SessionError = error{
    PtyAllocationFailed,
    ProcessSpawnFailed,
    InvalidTerminalMode,
    SessionClosed,
    IoError,
} || Allocator.Error;

pub const TerminalMode = enum(u8) {
    TTY_OP_END = 0,
    VINTR = 1,
    VQUIT = 2,
    VERASE = 3,
    VKILL = 4,
    VEOF = 5,
    VEOL = 6,
    VEOL2 = 7,
    VSTART = 8,
    VSTOP = 9,
    VSUSP = 10,
    VDSUSP = 11,
    VREPRINT = 12,
    VWERASE = 13,
    VLNEXT = 14,
    VFLUSH = 15,
    VSWTCH = 16,
    VSTATUS = 17,
    VDISCARD = 18,
    IGNPAR = 30,
    PARMRK = 31,
    INPCK = 32,
    ISTRIP = 33,
    INLCR = 34,
    IGNCR = 35,
    ICRNL = 36,
    IUCLC = 37,
    IXON = 38,
    IXANY = 39,
    IXOFF = 40,
    IMAXBEL = 41,
    ISIG = 50,
    ICANON = 51,
    XCASE = 52,
    ECHO = 53,
    ECHOE = 54,
    ECHOK = 55,
    ECHONL = 56,
    NOFLSH = 57,
    TOSTOP = 58,
    IEXTEN = 59,
    ECHOCTL = 60,
    ECHOKE = 61,
    PENDIN = 62,
    OPOST = 70,
    OLCUC = 71,
    ONLCR = 72,
    OCRNL = 73,
    ONOCR = 74,
    ONLRET = 75,
    CS7 = 90,
    CS8 = 91,
    PARENB = 92,
    PARODD = 93,
    TTY_OP_ISPEED = 128,
    TTY_OP_OSPEED = 129,
};

pub const PtyInfo = struct {
    term: []const u8,
    width_chars: u32,
    height_rows: u32,
    width_pixels: u32,
    height_pixels: u32,
    terminal_modes: std.HashMapUnmanaged(TerminalMode, u32, std.hash_map.AutoContext(TerminalMode), std.hash_map.default_max_load_percentage),
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, term: []const u8, width: u32, height: u32) !Self {
        return Self{
            .term = try allocator.dupe(u8, term),
            .width_chars = width,
            .height_rows = height,
            .width_pixels = 0,
            .height_pixels = 0,
            .terminal_modes = std.HashMapUnmanaged(TerminalMode, u32, std.hash_map.AutoContext(TerminalMode), std.hash_map.default_max_load_percentage){},
        };
    }
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.term);
        self.terminal_modes.deinit(allocator);
    }
    
    pub fn setMode(self: *Self, allocator: Allocator, mode: TerminalMode, value: u32) !void {
        try self.terminal_modes.put(allocator, mode, value);
    }
    
    pub fn getMode(self: *const Self, mode: TerminalMode) ?u32 {
        return self.terminal_modes.get(mode);
    }
    
    pub fn parseTerminalModes(self: *Self, allocator: Allocator, modes_data: []const u8) !void {
        var pos: usize = 0;
        
        while (pos < modes_data.len) {
            if (pos + 1 > modes_data.len) break;
            
            const opcode = modes_data[pos];
            pos += 1;
            
            if (opcode == @intFromEnum(TerminalMode.TTY_OP_END)) {
                break;
            }
            
            if (pos + 4 > modes_data.len) return SessionError.InvalidTerminalMode;
            
            const value = std.mem.readInt(u32, modes_data[pos..][0..4], .big);
            pos += 4;
            
            if (std.meta.intToEnum(TerminalMode, opcode)) |mode| {
                try self.setMode(allocator, mode, value);
            } else |_| {
                // Ignore unknown terminal modes
                continue;
            }
        }
    }
};

pub const SessionState = enum {
    created,
    pty_allocated,
    shell_started,
    exec_running,
    closed,
};

pub const Session = struct {
    allocator: Allocator,
    channel_id: u32,
    state: SessionState,
    pty_info: ?PtyInfo,
    process: ?std.process.Child,
    command: ?[]const u8,
    exit_code: ?u32,
    environment: std.StringHashMapUnmanaged([]const u8),
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, channel_id: u32) Self {
        return Self{
            .allocator = allocator,
            .channel_id = channel_id,
            .state = .created,
            .pty_info = null,
            .process = null,
            .command = null,
            .exit_code = null,
            .environment = std.StringHashMapUnmanaged([]const u8){},
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.pty_info) |*pty| {
            pty.deinit(self.allocator);
        }
        
        if (self.process) |*proc| {
            _ = proc.kill() catch {};
        }
        
        if (self.command) |cmd| {
            self.allocator.free(cmd);
        }
        
        var env_iterator = self.environment.iterator();
        while (env_iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.environment.deinit(self.allocator);
    }
    
    pub fn allocatePty(self: *Self, term: []const u8, width: u32, height: u32, modes_data: []const u8) !void {
        if (self.state != .created) {
            return SessionError.PtyAllocationFailed;
        }
        
        var pty = try PtyInfo.init(self.allocator, term, width, height);
        try pty.parseTerminalModes(self.allocator, modes_data);
        
        self.pty_info = pty;
        self.state = .pty_allocated;
    }
    
    pub fn startShell(self: *Self, shell_path: ?[]const u8) !void {
        if (self.state != .pty_allocated and self.state != .created) {
            return SessionError.ProcessSpawnFailed;
        }
        
        const shell = shell_path orelse "/bin/sh";
        
        var process = std.process.Child.init(&[_][]const u8{shell}, self.allocator);
        
        // Set up process environment
        var env_list = std.ArrayList([]const u8).init(self.allocator);
        defer env_list.deinit();
        
        var env_iterator = self.environment.iterator();
        while (env_iterator.next()) |entry| {
            const env_var = try std.fmt.allocPrint(self.allocator, "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
            try env_list.append(env_var);
        }
        
        if (self.pty_info) |pty| {
            const term_env = try std.fmt.allocPrint(self.allocator, "TERM={s}", .{pty.term});
            try env_list.append(term_env);
        }
        
        process.env_map = &std.process.EnvMap.init(self.allocator);
        defer process.env_map.?.deinit();
        
        // Configure stdio
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;
        process.stderr_behavior = .Pipe;
        
        try process.spawn();
        
        self.process = process;
        self.state = .shell_started;
    }
    
    pub fn executeCommand(self: *Self, command: []const u8) !void {
        if (self.state != .pty_allocated and self.state != .created) {
            return SessionError.ProcessSpawnFailed;
        }
        
        self.command = try self.allocator.dupe(u8, command);
        
        // Parse command into arguments
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (args.items) |arg| {
                self.allocator.free(arg);
            }
            args.deinit();
        }
        
        var tokenizer = std.mem.tokenizeScalar(u8, command, ' ');
        while (tokenizer.next()) |token| {
            try args.append(try self.allocator.dupe(u8, token));
        }
        
        if (args.items.len == 0) {
            return SessionError.ProcessSpawnFailed;
        }
        
        var process = std.process.Child.init(args.items, self.allocator);
        
        // Configure stdio
        process.stdin_behavior = .Pipe;
        process.stdout_behavior = .Pipe;
        process.stderr_behavior = .Pipe;
        
        try process.spawn();
        
        self.process = process;
        self.state = .exec_running;
    }
    
    pub fn writeToProcess(self: *Self, data: []const u8) !void {
        if (self.process == null) {
            return SessionError.SessionClosed;
        }
        
        if (self.process.?.stdin) |stdin| {
            _ = try stdin.writeAll(data);
        }
    }
    
    pub fn readFromProcess(self: *Self, buffer: []u8) !usize {
        if (self.process == null) {
            return SessionError.SessionClosed;
        }
        
        if (self.process.?.stdout) |stdout| {
            return try stdout.read(buffer);
        }
        
        return 0;
    }
    
    pub fn readFromProcessStderr(self: *Self, buffer: []u8) !usize {
        if (self.process == null) {
            return SessionError.SessionClosed;
        }
        
        if (self.process.?.stderr) |stderr| {
            return try stderr.read(buffer);
        }
        
        return 0;
    }
    
    pub fn setEnvironmentVariable(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.environment.put(self.allocator, owned_name, owned_value);
    }
    
    pub fn resizePty(self: *Self, width: u32, height: u32) !void {
        if (self.pty_info == null) {
            return SessionError.PtyAllocationFailed;
        }
        
        self.pty_info.?.width_chars = width;
        self.pty_info.?.height_rows = height;
        
        // In a real implementation, this would send a SIGWINCH signal to the process
        // and update the terminal size through system calls
    }
    
    pub fn waitForExit(self: *Self) !u32 {
        if (self.process == null) {
            return self.exit_code orelse 0;
        }
        
        const term = try self.process.?.wait();
        self.exit_code = switch (term) {
            .Exited => |code| code,
            .Signal => |_| 128, // Convention: 128 + signal number, simplified here
            .Stopped => |_| 128,
            .Unknown => |code| code,
        };
        
        self.state = .closed;
        return self.exit_code.?;
    }
    
    pub fn isActive(self: *const Self) bool {
        return self.state == .shell_started or self.state == .exec_running;
    }
    
    pub fn close(self: *Self) void {
        if (self.process) |*process| {
            _ = process.kill() catch {};
        }
        self.state = .closed;
    }
};

pub const SessionManager = struct {
    allocator: Allocator,
    sessions: std.HashMapUnmanaged(u32, *Session, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage),
    max_sessions: u32,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, max_sessions: u32) Self {
        return Self{
            .allocator = allocator,
            .sessions = std.HashMapUnmanaged(u32, *Session, std.hash_map.AutoContext(u32), std.hash_map.default_max_load_percentage){},
            .max_sessions = max_sessions,
        };
    }
    
    pub fn deinit(self: *Self) void {
        var iterator = self.sessions.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sessions.deinit(self.allocator);
    }
    
    pub fn createSession(self: *Self, channel_id: u32) !*Session {
        if (self.sessions.count() >= self.max_sessions) {
            return SessionError.ProcessSpawnFailed;
        }
        
        const session = try self.allocator.create(Session);
        session.* = Session.init(self.allocator, channel_id);
        
        try self.sessions.put(self.allocator, channel_id, session);
        return session;
    }
    
    pub fn getSession(self: *Self, channel_id: u32) ?*Session {
        return self.sessions.get(channel_id);
    }
    
    pub fn removeSession(self: *Self, channel_id: u32) void {
        if (self.sessions.fetchRemove(channel_id)) |entry| {
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        }
    }
    
    pub fn getSessionCount(self: *const Self) u32 {
        return @intCast(self.sessions.count());
    }
};

test "Session creation and lifecycle" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var session = Session.init(allocator, 123);
    defer session.deinit();
    
    try testing.expectEqual(@as(u32, 123), session.channel_id);
    try testing.expectEqual(SessionState.created, session.state);
    try testing.expect(session.pty_info == null);
    
    try session.setEnvironmentVariable("TEST_VAR", "test_value");
    const env_value = session.environment.get("TEST_VAR");
    try testing.expect(env_value != null);
    try testing.expectEqualStrings("test_value", env_value.?);
}

test "PTY allocation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var session = Session.init(allocator, 456);
    defer session.deinit();
    
    const modes_data = [_]u8{ @intFromEnum(TerminalMode.ECHO), 0, 0, 0, 1, @intFromEnum(TerminalMode.TTY_OP_END) };
    
    try session.allocatePty("xterm-256color", 80, 24, &modes_data);
    
    try testing.expectEqual(SessionState.pty_allocated, session.state);
    try testing.expect(session.pty_info != null);
    try testing.expectEqualStrings("xterm-256color", session.pty_info.?.term);
    try testing.expectEqual(@as(u32, 80), session.pty_info.?.width_chars);
    try testing.expectEqual(@as(u32, 24), session.pty_info.?.height_rows);
    
    const echo_mode = session.pty_info.?.getMode(.ECHO);
    try testing.expect(echo_mode != null);
    try testing.expectEqual(@as(u32, 1), echo_mode.?);
}

test "Session manager" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var manager = SessionManager.init(allocator, 5);
    defer manager.deinit();
    
    const session = try manager.createSession(789);
    try testing.expectEqual(@as(u32, 789), session.channel_id);
    try testing.expectEqual(@as(u32, 1), manager.getSessionCount());
    
    const retrieved = manager.getSession(789);
    try testing.expect(retrieved != null);
    try testing.expectEqual(session, retrieved.?);
    
    manager.removeSession(789);
    try testing.expectEqual(@as(u32, 0), manager.getSessionCount());
    try testing.expect(manager.getSession(789) == null);
}