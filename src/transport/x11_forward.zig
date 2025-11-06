//! X11 Forwarding Support
//!
//! Implements SSH X11 forwarding for running graphical applications remotely.
//! Supports both X11 forwarding and X11 security extensions (MIT-MAGIC-COOKIE).
//!
//! Features:
//! - Automatic X11 authentication cookie management
//! - X11 display detection and configuration
//! - Xauthority file handling
//! - MIT-MAGIC-COOKIE-1 authentication
//! - Secure channel forwarding

const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;

pub const X11Error = error{
    DisplayNotFound,
    AuthCookieError,
    ChannelCreationFailed,
    ForwardingFailed,
    XAuthorityError,
} || Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;

/// X11 display information
pub const X11Display = struct {
    display_number: u16,
    screen: u16 = 0,
    hostname: ?[]const u8 = null,

    pub fn parse(allocator: Allocator, display_str: []const u8) !X11Display {
        // Parse DISPLAY format: [hostname]:display[.screen]
        var display = X11Display{
            .display_number = 0,
            .screen = 0,
            .hostname = null,
        };

        // Find colon
        const colon_pos = std.mem.indexOf(u8, display_str, ":") orelse return error.DisplayNotFound;

        // Parse hostname (if present)
        if (colon_pos > 0) {
            display.hostname = try allocator.dupe(u8, display_str[0..colon_pos]);
        }

        // Parse display number and screen
        const rest = display_str[colon_pos + 1 ..];
        if (std.mem.indexOf(u8, rest, ".")) |dot_pos| {
            display.display_number = try std.fmt.parseInt(u16, rest[0..dot_pos], 10);
            display.screen = try std.fmt.parseInt(u16, rest[dot_pos + 1 ..], 10);
        } else {
            display.display_number = try std.fmt.parseInt(u16, rest, 10);
        }

        return display;
    }

    pub fn deinit(self: *X11Display, allocator: Allocator) void {
        if (self.hostname) |h| {
            allocator.free(h);
        }
    }

    pub fn format(self: X11Display) ![]u8 {
        // Format as hostname:display.screen
        // TODO: Implement proper formatting
        _ = self;
        return error.DisplayNotFound;
    }
};

/// X11 authentication cookie
pub const X11AuthCookie = struct {
    proto: []const u8,
    data: []const u8,

    pub fn deinit(self: *X11AuthCookie, allocator: Allocator) void {
        allocator.free(self.proto);
        allocator.free(self.data);
    }
};

/// X11 forwarding configuration
pub const X11Config = struct {
    enabled: bool = false,
    display: ?X11Display = null,
    auth_cookie: ?X11AuthCookie = null,
    trusted: bool = false,  // Use ForwardX11Trusted
    single_connection: bool = false,
    timeout_seconds: u32 = 1200,  // 20 minutes

    pub fn deinit(self: *X11Config, allocator: Allocator) void {
        if (self.display) |*d| {
            d.deinit(allocator);
        }
        if (self.auth_cookie) |*c| {
            c.deinit(allocator);
        }
    }
};

/// X11 forwarding handler
pub const X11Forward = struct {
    allocator: Allocator,
    config: X11Config,
    display: ?X11Display,
    auth_cookie: ?X11AuthCookie,
    channels: std.ArrayList(*X11Channel),

    const Self = @This();

    pub fn init(allocator: Allocator, config: X11Config) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .display = null,
            .auth_cookie = null,
            .channels = std.ArrayList(*X11Channel).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.display) |*d| {
            d.deinit(self.allocator);
        }
        if (self.auth_cookie) |*c| {
            c.deinit(self.allocator);
        }

        for (self.channels.items) |chan| {
            chan.deinit();
            self.allocator.destroy(chan);
        }
        self.channels.deinit();
    }

    /// Setup X11 forwarding by reading DISPLAY and generating auth cookie
    pub fn setup(self: *Self) !void {
        // Get DISPLAY environment variable
        const display_str = std.posix.getenv("DISPLAY") orelse return error.DisplayNotFound;

        self.display = try X11Display.parse(self.allocator, display_str);

        // Generate or read auth cookie
        self.auth_cookie = try self.getAuthCookie();
    }

    /// Get X11 authentication cookie from xauth
    fn getAuthCookie(self: *Self) !X11AuthCookie {
        // Try to read from .Xauthority file
        const home = std.posix.getenv("HOME") orelse return error.XAuthorityError;

        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const xauth_path = try std.fmt.bufPrint(&path_buf, "{s}/.Xauthority", .{home});

        const file = std.fs.cwd().openFile(xauth_path, .{}) catch {
            // If .Xauthority doesn't exist, generate a random cookie
            return try self.generateAuthCookie();
        };
        defer file.close();

        // TODO: Parse .Xauthority file format
        // For now, generate a random cookie
        return try self.generateAuthCookie();
    }

    /// Generate a random MIT-MAGIC-COOKIE-1
    fn generateAuthCookie(self: *Self) !X11AuthCookie {
        const proto = try self.allocator.dupe(u8, "MIT-MAGIC-COOKIE-1");
        errdefer self.allocator.free(proto);

        // Generate 16 random bytes for cookie
        var cookie_data: [16]u8 = undefined;
        std.crypto.random.bytes(&cookie_data);

        // Convert to hex string
        const hex_data = try self.allocator.alloc(u8, 32);
        errdefer self.allocator.free(hex_data);

        _ = try std.fmt.bufPrint(hex_data, "{x}", .{std.fmt.fmtSliceHexLower(&cookie_data)});

        return X11AuthCookie{
            .proto = proto,
            .data = hex_data,
        };
    }

    /// Request X11 forwarding from SSH server
    pub fn requestForwarding(self: *Self, ssh_channel: anytype) !void {
        _ = ssh_channel;

        if (self.display == null) {
            try self.setup();
        }

        // TODO: Send SSH_MSG_CHANNEL_REQUEST with "x11-req"
        // This would include:
        // - single_connection flag
        // - x11_authentication_protocol (e.g., "MIT-MAGIC-COOKIE-1")
        // - x11_authentication_cookie (hex encoded)
        // - x11_screen_number
    }

    /// Handle incoming X11 connection from server
    pub fn handleConnection(self: *Self, remote_channel_id: u32) !*X11Channel {
        const channel = try self.allocator.create(X11Channel);
        errdefer self.allocator.destroy(channel);

        channel.* = try X11Channel.init(self.allocator, remote_channel_id, self.display.?);

        try self.channels.append(channel);

        return channel;
    }

    /// Connect to local X11 server
    pub fn connectToX11Server(self: *Self) !net.Stream {
        const display = self.display orelse return error.DisplayNotFound;

        // X11 Unix domain socket path
        var socket_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const socket_path = try std.fmt.bufPrint(&socket_buf, "/tmp/.X11-unix/X{d}", .{display.display_number});

        return try net.connectUnixSocket(socket_path);
    }
};

/// Individual X11 forwarding channel
pub const X11Channel = struct {
    allocator: Allocator,
    remote_channel_id: u32,
    local_stream: ?net.Stream,
    display: X11Display,
    active: bool,

    pub fn init(allocator: Allocator, remote_channel_id: u32, display: X11Display) !X11Channel {
        return .{
            .allocator = allocator,
            .remote_channel_id = remote_channel_id,
            .local_stream = null,
            .display = display,
            .active = false,
        };
    }

    pub fn deinit(self: *X11Channel) void {
        if (self.local_stream) |stream| {
            stream.close();
        }
    }

    /// Connect to local X11 server
    pub fn connect(self: *X11Channel) !void {
        var socket_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const socket_path = try std.fmt.bufPrint(&socket_buf, "/tmp/.X11-unix/X{d}", .{self.display.display_number});

        self.local_stream = try net.connectUnixSocket(socket_path);
        self.active = true;
    }

    /// Forward data from SSH to X11 server
    pub fn forwardToX11(self: *X11Channel, data: []const u8) !void {
        if (self.local_stream) |stream| {
            try stream.writeAll(data);
        }
    }

    /// Read data from X11 server
    pub fn readFromX11(self: *X11Channel, buffer: []u8) !usize {
        if (self.local_stream) |stream| {
            return try stream.read(buffer);
        }
        return 0;
    }
};

/// Helper to set DISPLAY environment variable for SSH session
pub fn setRemoteDisplay(allocator: Allocator, display_number: u16) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "localhost:{d}.0", .{display_number});
}

// Tests

test "X11 display parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test :0
    var display1 = try X11Display.parse(allocator, ":0");
    defer display1.deinit(allocator);
    try testing.expectEqual(@as(u16, 0), display1.display_number);
    try testing.expectEqual(@as(u16, 0), display1.screen);
    try testing.expect(display1.hostname == null);

    // Test :0.1
    var display2 = try X11Display.parse(allocator, ":0.1");
    defer display2.deinit(allocator);
    try testing.expectEqual(@as(u16, 0), display2.display_number);
    try testing.expectEqual(@as(u16, 1), display2.screen);

    // Test hostname:10
    var display3 = try X11Display.parse(allocator, "localhost:10");
    defer display3.deinit(allocator);
    try testing.expectEqual(@as(u16, 10), display3.display_number);
    try testing.expectEqualStrings("localhost", display3.hostname.?);
}

test "X11 auth cookie generation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = X11Config{};
    var x11 = try X11Forward.init(allocator, config);
    defer x11.deinit();

    const cookie = try x11.generateAuthCookie();
    defer {
        allocator.free(cookie.proto);
        allocator.free(cookie.data);
    }

    try testing.expectEqualStrings("MIT-MAGIC-COOKIE-1", cookie.proto);
    try testing.expectEqual(@as(usize, 32), cookie.data.len); // 16 bytes as hex = 32 chars
}
