//! Basic SSH Client Example
//!
//! Demonstrates how to create a simple SSH client connection
//! using zssh with password authentication.

const std = @import("std");
const zssh = @import("zssh");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <host> <username> <password>\n", .{args[0]});
        std.process.exit(1);
    }

    const host = args[1];
    const username = args[2];
    const password = args[3];

    std.debug.print("Connecting to {s} as {s}...\n", .{ host, username });

    // Create SSH client
    var client = try zssh.Client.init(allocator, .{
        .host = host,
        .port = 22,
        .username = username,
        .authentication = .{ .password = password },
        .host_key_verification = .none, // For demo purposes
    });
    defer client.deinit();

    // Connect to the server
    try client.connect();
    std.debug.print("Connected successfully!\n");

    // Execute a simple command
    const result = try client.execute("echo 'Hello from zssh!'");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.debug.print("Command output: {s}\n", .{result.stdout});

    if (result.exit_code != 0) {
        std.debug.print("Command failed with exit code: {d}\n", .{result.exit_code});
        std.debug.print("Error: {s}\n", .{result.stderr});
    }

    // Open an interactive shell
    std.debug.print("\nStarting interactive shell (type 'exit' to quit):\n");

    var session = try client.createSession();
    defer session.deinit();

    try session.requestPty(.{
        .term = "xterm-256color",
        .width = 80,
        .height = 24,
    });

    try session.shell();

    // Simple interactive loop
    const stdin = std.io.getStdIn().reader();
    var input_buffer: [1024]u8 = undefined;

    while (true) {
        std.debug.print("$ ");

        if (try stdin.readUntilDelimiterOrEof(input_buffer[0..], '\n')) |input| {
            const command = std.mem.trim(u8, input, " \t\r\n");

            if (std.mem.eql(u8, command, "exit")) {
                break;
            }

            try session.write(command);
            try session.write("\n");

            // Read response (simplified)
            var output_buffer: [4096]u8 = undefined;
            const bytes_read = try session.read(output_buffer[0..]);
            std.debug.print("{s}", .{output_buffer[0..bytes_read]});
        } else {
            break;
        }
    }

    std.debug.print("Disconnecting...\n");
}