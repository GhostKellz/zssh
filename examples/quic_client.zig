//! QUIC SSH Client Example
//!
//! Demonstrates how to use QUIC transport for SSH connections
//! with multiplexing and enhanced performance.

const std = @import("std");
const zssh = @import("zssh");
const quic_transport = @import("zssh").transport.quic_transport;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        std.debug.print("Usage: {s} <host> <username>\n", .{args[0]});
        std.process.exit(1);
    }

    const host = args[1];
    const username = args[2];

    std.debug.print("Connecting to {s} using QUIC transport...\n", .{host});

    // Create QUIC transport
    var transport = quic_transport.QuicTransport.init(allocator);
    defer transport.deinit();

    // Connect using QUIC
    const address = try std.Io.net.IpAddress.parse(host, 22);
    try transport.connect(address, host);

    std.debug.print("QUIC connection established!\n");

    // Create SSH client with QUIC transport
    var client = try zssh.Client.initWithTransport(allocator, &transport, .{
        .username = username,
        .authentication = .{ .public_key = "/home/user/.ssh/id_ed25519" },
        .enable_multiplexing = true,
        .enable_0rtt = true,
    });
    defer client.deinit();

    try client.authenticate();
    std.debug.print("Authenticated successfully!\n");

    // Demonstrate multiplexing - create multiple concurrent sessions
    var sessions: [3]*zssh.Session = undefined;

    for (sessions, 0..) |*session, i| {
        session.* = try client.createSession();
        std.debug.print("Created session {d}\n", .{i + 1});

        // Run a different command on each session concurrently
        const commands = [_][]const u8{
            "echo 'Session 1: Getting system info' && uname -a",
            "echo 'Session 2: Checking disk space' && df -h",
            "echo 'Session 3: Listing processes' && ps aux | head -10",
        };

        // Execute commands concurrently
        const result = try session.*.execute(commands[i]);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        std.debug.print("\n=== Session {d} Output ===\n", .{i + 1});
        std.debug.print("{s}\n", .{result.stdout});
    }

    // Clean up sessions
    for (sessions) |session| {
        session.deinit();
    }

    // Demonstrate QUIC-specific features
    const stats = transport.getConnectionStats();
    std.debug.print("\n=== QUIC Connection Statistics ===\n");
    std.debug.print("Bytes sent: {d}\n", .{stats.bytes_sent});
    std.debug.print("Bytes received: {d}\n", .{stats.bytes_received});
    std.debug.print("Round-trip time: {d}ms\n", .{stats.rtt_ms});
    std.debug.print("Active streams: {d}\n", .{stats.active_streams});

    // Test 0-RTT if supported
    if (transport.supportsEarlyData()) {
        std.debug.print("\n0-RTT supported! Sending early data...\n");
        try transport.send0RTTData("SSH-2.0-zssh_1.0");
    }

    // Set bandwidth shaping
    try transport.setTrafficShaping(10 * 1024 * 1024); // 10 MB/s limit
    std.debug.print("Bandwidth limit set to 10 MB/s\n");

    std.debug.print("\nQUIC SSH session completed!\n");
}