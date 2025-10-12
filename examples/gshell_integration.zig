//! GShell SSH Integration Example
//!
//! This file demonstrates how GShell (GSH) would integrate zssh for native SSH support.
//! It shows all the key use cases from the GSHELL_GSH_WISHLIST.md:
//!
//! 1. Simple SSH connection with auto-loaded credentials
//! 2. Remote command execution with output capture
//! 3. Interactive shell sessions
//! 4. Port forwarding (local and remote)
//! 5. Connection reuse for fast subsequent commands
//! 6. Jump host / bastion support
//!
//! Build and run: zig build run-gshell-example

const std = @import("std");
const zssh = @import("zssh");

// Simulated GVault credential structure
const GVaultCredential = struct {
    hostname: []const u8,
    username: []const u8,
    private_key_path: []const u8,
    port: u16,
};

// Simulated GVault lookup
fn gvaultLookup(allocator: std.mem.Allocator, alias: []const u8) !GVaultCredential {
    _ = allocator;

    // In real GShell, this would query GVault's credential database
    if (std.mem.eql(u8, alias, "prod-db")) {
        return GVaultCredential{
            .hostname = "prod-db.example.com",
            .username = "chris",
            .private_key_path = "/home/chris/.ssh/id_ed25519",
            .port = 22,
        };
    }

    return error.CredentialNotFound;
}

/// Example 1: Simple SSH connection from GShell builtin
/// Usage in GShell: `ssh prod-db`
fn sshBuiltin(allocator: std.mem.Allocator, args: []const []const u8) !i32 {
    if (args.len < 2) {
        std.debug.print("Usage: ssh <host>\n", .{});
        return 1;
    }

    const hostname = args[1];

    std.debug.print("Looking up credentials for '{s}' in GVault...\n", .{hostname});

    // Get credential from GVault
    const cred = gvaultLookup(allocator, hostname) catch |err| {
        std.debug.print("Error: Could not find credentials for '{s}': {any}\n", .{ hostname, err });
        return 1;
    };

    std.debug.print("Connecting to {s}@{s}:{d}...\n", .{ cred.username, cred.hostname, cred.port });

    // Connect using zssh easy client
    var session = zssh.connect(allocator, .{
        .host = cred.hostname,
        .port = cred.port,
        .user = cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = cred.private_key_path,
            .passphrase = null,
        } },
    }) catch |err| {
        std.debug.print("Connection failed: {any}\n", .{err});
        return 1;
    };
    defer session.close();

    std.debug.print("✅ Connected to {s}\n", .{hostname});

    // Start interactive shell
    session.interactive() catch |err| {
        std.debug.print("Interactive session failed: {any}\n", .{err});
        return 1;
    };

    return 0;
}

/// Example 2: Remote command execution
/// Usage in GShell: `ssh prod-db "uptime"`
fn sshExecBuiltin(allocator: std.mem.Allocator, args: []const []const u8) !i32 {
    if (args.len < 3) {
        std.debug.print("Usage: ssh <host> <command>\n", .{});
        return 1;
    }

    const hostname = args[1];
    const command = args[2];

    // Get credential from GVault
    const cred = try gvaultLookup(allocator, hostname);

    std.debug.print("Connecting to {s}...\n", .{hostname});

    // Connect using zssh
    var session = try zssh.connect(allocator, .{
        .host = cred.hostname,
        .port = cred.port,
        .user = cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = cred.private_key_path,
            .passphrase = null,
        } },
    });
    defer session.close();

    // Execute command
    const result = try session.exec(command);
    defer result.deinit(allocator);

    // Print output
    if (result.stdout.len > 0) {
        std.debug.print("{s}", .{result.stdout});
    }
    if (result.stderr.len > 0) {
        std.debug.print("{s}", .{result.stderr});
    }

    return result.exit_code;
}

/// Example 3: Port forwarding
/// Usage in GShell: `ssh -L 8080:localhost:80 prod-db`
fn sshPortForwardBuiltin(allocator: std.mem.Allocator, local_port: u16, remote_host: []const u8, remote_port: u16, hostname: []const u8) !i32 {
    const cred = try gvaultLookup(allocator, hostname);

    std.debug.print("Connecting to {s}...\n", .{hostname});

    var session = try zssh.connect(allocator, .{
        .host = cred.hostname,
        .port = cred.port,
        .user = cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = cred.private_key_path,
            .passphrase = null,
        } },
    });
    defer session.close();

    // Set up port forwarding
    var fwd = try session.forwardLocal(local_port, remote_host, remote_port);
    defer fwd.close();

    std.debug.print("✅ Port forward: localhost:{d} -> {s}:{d}\n", .{ local_port, remote_host, remote_port });
    std.debug.print("Press Ctrl+C to stop...\n", .{});

    // Keep connection alive
    // In real implementation, this would be an event loop
    while (fwd.active) {
        std.time.sleep(1_000_000_000); // 1 second
    }

    return 0;
}

/// Example 4: Connection pooling for fast command execution
/// This demonstrates how GShell would reuse connections for multiple commands
fn connectionReuseExample(allocator: std.mem.Allocator) !void {
    const cred = try gvaultLookup(allocator, "prod-db");

    std.debug.print("\n=== Connection Reuse Example ===\n", .{});
    std.debug.print("First connection (slower, ~500ms)...\n", .{});

    var session = try zssh.connect(allocator, .{
        .host = cred.hostname,
        .port = cred.port,
        .user = cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = cred.private_key_path,
            .passphrase = null,
        } },
    });
    defer session.close();

    // Execute multiple commands on same connection
    const commands = [_][]const u8{ "uptime", "df -h", "free -h", "hostname" };

    for (commands) |cmd| {
        std.debug.print("\n$ {s}\n", .{cmd});
        const result = try session.exec(cmd);
        defer result.deinit(allocator);

        if (result.stdout.len > 0) {
            std.debug.print("{s}", .{result.stdout});
        }
    }

    std.debug.print("\n✅ All commands executed on single connection!\n", .{});
}

/// Example 5: Jump host / bastion support
/// Usage in GShell: `ssh prod-db` (automatically uses bastion if configured)
fn sshViaBastion(allocator: std.mem.Allocator, target_alias: []const u8) !i32 {
    // In GVault, prod-db is configured to require bastion
    const bastion_cred = try gvaultLookup(allocator, "bastion");
    const target_cred = try gvaultLookup(allocator, target_alias);

    std.debug.print("Connecting via bastion...\n", .{});

    // Connect with jump hosts
    var session = try zssh.connect(allocator, .{
        .host = target_cred.hostname,
        .port = target_cred.port,
        .user = target_cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = target_cred.private_key_path,
            .passphrase = null,
        } },
        .jump_hosts = &[_]zssh.JumpHost{
            .{
                .host = bastion_cred.hostname,
                .port = bastion_cred.port,
                .user = bastion_cred.username,
                .auth = .{ .public_key = .{
                    .private_key_path = bastion_cred.private_key_path,
                    .passphrase = null,
                } },
            },
        },
    });
    defer session.close();

    std.debug.print("✅ Connected to {s} via bastion\n", .{target_alias});

    // Start interactive session
    try session.interactive();

    return 0;
}

/// Example 6: Connection health check and auto-reconnect
fn connectionHealthExample(allocator: std.mem.Allocator) !void {
    const cred = try gvaultLookup(allocator, "prod-db");

    std.debug.print("\n=== Connection Health & Auto-Reconnect Example ===\n", .{});

    var session = try zssh.connect(allocator, .{
        .host = cred.hostname,
        .port = cred.port,
        .user = cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = cred.private_key_path,
            .passphrase = null,
        } },
    });
    defer session.close();

    // Simulate command execution with connection check
    var attempt: u32 = 0;
    while (attempt < 3) : (attempt += 1) {
        // Check connection health before command
        if (!session.checkConnection()) {
            std.debug.print("⚠️  Connection lost, reconnecting...\n", .{});
            try session.reconnect();
            std.debug.print("✅ Reconnected\n", .{});
        }

        const result = try session.exec("echo test");
        defer result.deinit(allocator);

        std.debug.print("Command {d}: {s}", .{ attempt + 1, result.stdout });
    }
}

/// Example 7: SSH with password authentication
fn sshPasswordExample(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== Password Authentication Example ===\n", .{});

    var session = try zssh.connect(allocator, .{
        .host = "localhost",
        .port = 22,
        .user = "testuser",
        .auth = .{ .password = "testpassword" },
    });
    defer session.close();

    const result = try session.exec("whoami");
    defer result.deinit(allocator);

    std.debug.print("Logged in as: {s}", .{result.stdout});
}

/// Main entry point - demonstrates all GShell integration examples
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== zssh + GShell Integration Examples ===\n\n", .{});

    // Example 1: Simple SSH connection
    std.debug.print("Example 1: Simple SSH Connection\n", .{});
    std.debug.print("In GShell: $ ssh prod-db\n\n", .{});

    // Simulate command line args
    const args1 = [_][]const u8{ "ssh", "prod-db" };
    const exit_code1 = sshBuiltin(allocator, &args1) catch |err| {
        std.debug.print("Example 1 failed: {any}\n\n", .{err});
        return;
    };
    std.debug.print("Exit code: {d}\n\n", .{exit_code1});

    // Example 2: Remote command execution
    std.debug.print("Example 2: Remote Command Execution\n", .{});
    std.debug.print("In GShell: $ ssh prod-db \"uptime\"\n\n", .{});

    const args2 = [_][]const u8{ "ssh", "prod-db", "uptime" };
    const exit_code2 = sshExecBuiltin(allocator, &args2) catch |err| {
        std.debug.print("Example 2 failed: {any}\n\n", .{err});
        return;
    };
    std.debug.print("Exit code: {d}\n\n", .{exit_code2});

    // Example 3: Connection reuse
    connectionReuseExample(allocator) catch |err| {
        std.debug.print("Connection reuse example failed: {any}\n\n", .{err});
    };

    // Example 4: Port forwarding
    std.debug.print("\nExample 4: Port Forwarding\n", .{});
    std.debug.print("In GShell: $ ssh -L 8080:localhost:80 prod-db\n", .{});
    std.debug.print("(Skipped in demo - would run indefinitely)\n\n", .{});

    // Example 5: Jump host
    std.debug.print("Example 5: Jump Host / Bastion\n", .{});
    std.debug.print("In GShell: $ ssh prod-db (via bastion)\n", .{});
    std.debug.print("(Skipped in demo - requires bastion setup)\n\n", .{});

    // Example 6: Connection health
    connectionHealthExample(allocator) catch |err| {
        std.debug.print("Connection health example failed: {any}\n\n", .{err});
    };

    // Example 7: Password authentication
    passwordAuthExample(allocator) catch |err| {
        std.debug.print("Password auth example failed: {any}\n\n", .{err});
    };

    std.debug.print("=== All Examples Complete ===\n", .{});
}

// Add standalone test
test "GShell integration API availability" {
    const testing = std.testing;

    // Verify all required types are available
    _ = zssh.connect;
    _ = zssh.ConnectOptions;
    _ = zssh.EasyAuthMethod;
    _ = zssh.SshSession;
    _ = zssh.ExecResult;
    _ = zssh.JumpHost;
    _ = zssh.PortForward;

    // Test ConnectOptions structure
    const options = zssh.ConnectOptions{
        .host = "test.example.com",
        .user = "testuser",
        .auth = .{ .password = "test123" },
    };

    try testing.expectEqualStrings("test.example.com", options.host);
    try testing.expectEqualStrings("testuser", options.user);
}
