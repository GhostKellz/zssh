const std = @import("std");
const zssh = @import("zssh");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    std.debug.print("SSH - Zig SSH 2.0 Library v{s}\n", .{zssh.SSH_VERSION});

    // Collect args into a slice
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch |err| {
        std.debug.print("Failed to get args: {}\n", .{err});
        return;
    };

    if (args.len < 2) {
        try printUsage();
        return;
    }

    if (std.mem.eql(u8, args[1], "server")) {
        try runServer(allocator);
    } else if (std.mem.eql(u8, args[1], "client")) {
        if (args.len < 3) {
            std.debug.print("Usage: ssh client <hostname>\n", .{});
            return;
        }
        try runClient(allocator, args[2]);
    } else {
        try printUsage();
    }
}

fn printUsage() !void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  ssh server    - Start SSH server on port 2222\n", .{});
    std.debug.print("  ssh client <host> - Connect to SSH server\n", .{});
}

fn runServer(allocator: std.mem.Allocator) !void {
    std.debug.print("Starting SSH server...\n", .{});

    const config = zssh.server.ServerConfig{
        .host = "127.0.0.1",
        .port = 2222,
        .max_connections = 10,
    };

    var server = try zssh.Server.init(allocator, config);
    defer server.deinit();

    try server.listen();

    std.debug.print("Server ready. Press Ctrl+C to stop.\n", .{});

    while (server.isRunning()) {
        server.accept() catch |err| {
            std.debug.print("Accept error: {}\n", .{err});
        };
    }
}

fn runClient(allocator: std.mem.Allocator, hostname: []const u8) !void {
    std.debug.print("Connecting to {s}:2222...\n", .{hostname});

    const config = zssh.client.ClientConfig{
        .username = "testuser",
        .host = hostname,
        .port = 2222,
    };

    var client = try zssh.Client.init(allocator, config);
    defer client.deinit();

    client.connect() catch |err| {
        std.debug.print("Connection failed: {}\n", .{err});
        return;
    };

    std.debug.print("Connected! Attempting authentication...\n", .{});

    const credentials = zssh.auth.Credentials{ .password = "testpass" };
    client.authenticate(credentials) catch |err| {
        std.debug.print("Authentication failed: {}\n", .{err});
        return;
    };

    std.debug.print("Authentication successful!\n", .{});

    client.disconnect();
}

test "main module imports" {
    _ = zssh;
}
