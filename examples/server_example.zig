//! SSH Server Example
//!
//! Demonstrates how to create an SSH server with zssh including
//! authentication, session management, and SFTP support.

const std = @import("std");
const zssh = @import("zssh");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const port: u16 = if (args.len > 1)
        std.fmt.parseInt(u16, args[1], 10) catch 2222
    else
        2222;

    std.debug.print("Starting SSH server on port {d}...\n", .{port});

    // Configure server
    var server = try zssh.Server.init(allocator, .{
        .host = "0.0.0.0",
        .port = port,
        .host_key_file = "/etc/ssh/ssh_host_ed25519_key",
        .max_connections = 100,
        .authentication_methods = &[_]zssh.AuthMethod{
            .password,
            .public_key,
            .oidc,
        },
        .subsystems = &[_]zssh.Subsystem{
            .sftp,
            .netconf,
        },
        .enable_compression = true,
        .enable_multiplexing = true,
    });
    defer server.deinit();

    // Set up authentication handlers
    try server.setPasswordAuthHandler(passwordAuthHandler);
    try server.setPublicKeyAuthHandler(publicKeyAuthHandler);
    try server.setOIDCAuthHandler(oidcAuthHandler);

    // Set up session handlers
    try server.setShellHandler(shellHandler);
    try server.setExecHandler(execHandler);
    try server.setSftpHandler(sftpHandler);

    // Set up connection event handlers
    try server.setConnectionHandler(connectionHandler);
    try server.setDisconnectionHandler(disconnectionHandler);

    std.debug.print("SSH server configured\n");
    std.debug.print("Listening on 0.0.0.0:{d}\n", .{port});
    std.debug.print("Host key: /etc/ssh/ssh_host_ed25519_key\n");
    std.debug.print("Authentication methods: password, public_key, oidc\n");
    std.debug.print("Supported subsystems: sftp, netconf\n");

    // Start server
    try server.listen();

    std.debug.print("Server started. Press Ctrl+C to stop.\n");

    // Handle signals for graceful shutdown
    const signal_handler = struct {
        var should_stop: bool = false;

        fn handleSignal(sig: i32) callconv(.C) void {
            _ = sig;
            should_stop = true;
        }
    };

    _ = std.c.signal(std.c.SIGINT, signal_handler.handleSignal);
    _ = std.c.signal(std.c.SIGTERM, signal_handler.handleSignal);

    // Main server loop
    while (!signal_handler.should_stop) {
        try server.processEvents();
        std.time.sleep(10 * std.time.ns_per_ms); // 10ms
    }

    std.debug.print("\nShutting down server...\n");
}

// Authentication handlers
fn passwordAuthHandler(username: []const u8, password: []const u8) !bool {
    std.debug.print("Password auth attempt: user={s}\n", .{username});

    // Simple demo authentication - in production, use proper password verification
    const valid_users = std.ComptimeStringMap([]const u8, .{
        .{ "demo", "password123" },
        .{ "test", "test123" },
        .{ "admin", "admin456" },
    });

    if (valid_users.get(username)) |expected_password| {
        return std.mem.eql(u8, password, expected_password);
    }

    return false;
}

fn publicKeyAuthHandler(username: []const u8, public_key: []const u8) !bool {
    std.debug.print("Public key auth attempt: user={s}\n", .{username});

    // In production, verify against authorized_keys
    // For demo, accept any public key for specific users
    const allowed_users = [_][]const u8{ "demo", "test", "admin" };

    for (allowed_users) |user| {
        if (std.mem.eql(u8, username, user)) {
            return true;
        }
    }

    return false;
}

fn oidcAuthHandler(username: []const u8, access_token: []const u8, user_info: zssh.auth.oidc_auth.UserInfo) !bool {
    std.debug.print("OIDC auth attempt: user={s}, sub={s}\n", .{ username, user_info.sub });

    // Verify OIDC token and user information
    // In production, validate token with identity provider

    // For demo, accept any valid-looking token
    if (access_token.len > 10 and user_info.sub.len > 0) {
        return true;
    }

    return false;
}

// Session handlers
fn shellHandler(session: *zssh.Session) !void {
    std.debug.print("Shell session started for user: {s}\n", .{session.getUsername()});

    // Set up PTY
    try session.allocatePty(.{
        .term = "xterm-256color",
        .width = 80,
        .height = 24,
    });

    // Start shell process
    const shell_path = "/bin/bash";
    var shell_process = std.ChildProcess.init(&[_][]const u8{shell_path}, std.heap.page_allocator);
    shell_process.stdin_behavior = .Pipe;
    shell_process.stdout_behavior = .Pipe;
    shell_process.stderr_behavior = .Pipe;

    try shell_process.spawn();
    defer _ = shell_process.kill() catch {};

    std.debug.print("Shell process started (PID: {d})\n", .{shell_process.id});

    // I/O forwarding loop (simplified)
    var buffer: [4096]u8 = undefined;

    while (true) {
        // Forward data from SSH session to shell
        const ssh_data = session.read(buffer[0..]) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };

        if (ssh_data.len > 0) {
            _ = try shell_process.stdin.?.writeAll(ssh_data);
        }

        // Forward data from shell to SSH session
        const shell_data = shell_process.stdout.?.read(buffer[0..]) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        if (shell_data.len > 0) {
            try session.write(shell_data);
        }

        std.time.sleep(1 * std.time.ns_per_ms); // 1ms
    }

    std.debug.print("Shell session ended for user: {s}\n", .{session.getUsername()});
}

fn execHandler(session: *zssh.Session, command: []const u8) !void {
    std.debug.print("Exec request from user {s}: {s}\n", .{ session.getUsername(), command });

    // Execute command
    var process = std.ChildProcess.init(&[_][]const u8{ "/bin/sh", "-c", command }, std.heap.page_allocator);
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;

    try process.spawn();
    const result = try process.wait();

    // Send output back to client
    if (process.stdout) |stdout| {
        var buffer: [4096]u8 = undefined;
        const bytes_read = try stdout.readAll(buffer[0..]);
        try session.write(buffer[0..bytes_read]);
    }

    if (process.stderr) |stderr| {
        var buffer: [4096]u8 = undefined;
        const bytes_read = try stderr.readAll(buffer[0..]);
        try session.writeStderr(buffer[0..bytes_read]);
    }

    // Send exit status
    try session.sendExitStatus(@intCast(result.Exited));

    std.debug.print("Command completed with exit code: {d}\n", .{result.Exited});
}

fn sftpHandler(session: *zssh.Session) !void {
    std.debug.print("SFTP subsystem started for user: {s}\n", .{session.getUsername()});

    // Initialize SFTP server
    var sftp_server = try zssh.SftpServer.init(session.allocator, session);
    defer sftp_server.deinit();

    // Configure SFTP permissions
    try sftp_server.setRootDirectory("/home/" ++ session.getUsername());
    try sftp_server.setPermissions(.{
        .read = true,
        .write = true,
        .delete = true,
        .create_directories = true,
    });

    // Process SFTP requests
    try sftp_server.serve();

    std.debug.print("SFTP subsystem ended for user: {s}\n", .{session.getUsername()});
}

// Connection event handlers
fn connectionHandler(connection: *zssh.Connection) !void {
    const client_addr = connection.getClientAddress();
    std.debug.print("New connection from: {}\n", .{client_addr});

    // Log connection details
    std.debug.print("Client version: {s}\n", .{connection.getClientVersion()});
    std.debug.print("Encryption: {s}\n", .{connection.getEncryptionAlgorithm()});
    std.debug.print("MAC: {s}\n", .{connection.getMacAlgorithm()});
}

fn disconnectionHandler(connection: *zssh.Connection, reason: zssh.DisconnectReason) !void {
    const client_addr = connection.getClientAddress();
    std.debug.print("Client disconnected: {} (reason: {})\n", .{ client_addr, reason });

    // Log session statistics
    const stats = connection.getStatistics();
    std.debug.print("Session stats - Bytes sent: {d}, Bytes received: {d}, Duration: {d}s\n", .{
        stats.bytes_sent,
        stats.bytes_received,
        stats.duration_seconds,
    });
}