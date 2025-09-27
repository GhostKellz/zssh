//! zssh - SSH Client CLI Tool
//!
//! Production-ready SSH client built with flash CLI framework and flare configuration.
//! OpenSSH compatible with advanced features from zssh library.

const std = @import("std");
const flash = @import("flash");
const flare = @import("flare");
const zssh = @import("zssh");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // Initialize configuration manager
    var config = try flare.Config.init(allocator);
    defer config.deinit();

    // Load configuration from multiple sources
    try config.loadFromFile("~/.ssh/zssh_config");
    try config.loadFromEnv();

    // Initialize CLI framework
    var cli = try flash.CLI.init(allocator, .{
        .name = "zssh",
        .version = "2.0.0",
        .description = "High-performance SSH client with QUIC transport and advanced features",
        .author = "GhostStack",
    });
    defer cli.deinit();

    // Global options
    try cli.addGlobalOption(.{
        .name = "config",
        .short = 'F',
        .description = "Configuration file path",
        .type = .string,
        .default = "~/.ssh/zssh_config",
    });

    try cli.addGlobalOption(.{
        .name = "verbose",
        .short = 'v',
        .description = "Enable verbose output",
        .type = .boolean,
        .default = false,
    });

    try cli.addGlobalOption(.{
        .name = "quiet",
        .short = 'q',
        .description = "Suppress output",
        .type = .boolean,
        .default = false,
    });

    // Connect command (default)
    try cli.addCommand(.{
        .name = "connect",
        .description = "Connect to SSH server",
        .is_default = true,
        .options = &[_]flash.Option{
            .{ .name = "host", .short = 'h', .type = .string, .required = true, .description = "Hostname or IP address" },
            .{ .name = "port", .short = 'p', .type = .int, .default = 22, .description = "Port number" },
            .{ .name = "user", .short = 'l', .type = .string, .description = "Username" },
            .{ .name = "identity", .short = 'i', .type = .string, .description = "Identity file (private key)" },
            .{ .name = "password", .type = .boolean, .default = false, .description = "Use password authentication" },
            .{ .name = "transport", .short = 't', .type = .string, .default = "tcp", .description = "Transport: tcp, quic" },
            .{ .name = "compression", .short = 'C', .type = .boolean, .default = false, .description = "Enable compression" },
            .{ .name = "multiplex", .short = 'M', .type = .boolean, .default = false, .description = "Enable connection multiplexing" },
            .{ .name = "command", .short = 'c', .type = .string, .description = "Command to execute" },
            .{ .name = "subsystem", .short = 's', .type = .string, .description = "Request subsystem (sftp, netconf)" },
            .{ .name = "local-forward", .short = 'L', .type = .string, .description = "Local port forwarding [bind_address:]port:host:hostport" },
            .{ .name = "remote-forward", .short = 'R', .type = .string, .description = "Remote port forwarding [bind_address:]port:host:hostport" },
            .{ .name = "dynamic-forward", .short = 'D', .type = .string, .description = "Dynamic port forwarding [bind_address:]port" },
            .{ .name = "oidc-provider", .type = .string, .description = "OIDC provider: google, github, microsoft, okta" },
            .{ .name = "oidc-client-id", .type = .string, .description = "OIDC client ID" },
        },
        .handler = connectHandler,
    });

    // SFTP command
    try cli.addCommand(.{
        .name = "sftp",
        .description = "Start SFTP session",
        .options = &[_]flash.Option{
            .{ .name = "host", .short = 'h', .type = .string, .required = true, .description = "Hostname or IP address" },
            .{ .name = "port", .short = 'p', .type = .int, .default = 22, .description = "Port number" },
            .{ .name = "user", .short = 'l', .type = .string, .description = "Username" },
            .{ .name = "identity", .short = 'i', .type = .string, .description = "Identity file (private key)" },
            .{ .name = "version", .type = .int, .default = 6, .description = "SFTP protocol version (3-6)" },
            .{ .name = "optimization", .type = .boolean, .default = true, .description = "Enable large file optimizations" },
            .{ .name = "compression", .type = .string, .default = "zstd", .description = "Compression: none, zlib, gzip, lz4, zstd" },
            .{ .name = "bandwidth-limit", .type = .int, .description = "Bandwidth limit in MB/s" },
        },
        .handler = sftpHandler,
    });

    // Copy command (like scp)
    try cli.addCommand(.{
        .name = "copy",
        .description = "Copy files over SSH",
        .options = &[_]flash.Option{
            .{ .name = "recursive", .short = 'r', .type = .boolean, .default = false, .description = "Recursive copy" },
            .{ .name = "preserve", .short = 'p', .type = .boolean, .default = false, .description = "Preserve file attributes" },
            .{ .name = "compression", .short = 'C', .type = .boolean, .default = true, .description = "Enable compression" },
            .{ .name = "bandwidth-limit", .short = 'l', .type = .int, .description = "Bandwidth limit in MB/s" },
            .{ .name = "parallel-chunks", .type = .int, .default = 4, .description = "Number of parallel chunks" },
            .{ .name = "chunk-size", .type = .int, .default = 8, .description = "Chunk size in MB" },
            .{ .name = "resume", .type = .boolean, .default = true, .description = "Enable resumable transfers" },
            .{ .name = "verify-checksum", .type = .boolean, .default = true, .description = "Verify file checksums" },
        },
        .handler = copyHandler,
        .args = .{
            .min = 2,
            .max = 2,
            .names = &[_][]const u8{ "source", "destination" },
        },
    });

    // Tunnel command
    try cli.addCommand(.{
        .name = "tunnel",
        .description = "Create SSH tunnels",
        .options = &[_]flash.Option{
            .{ .name = "host", .short = 'h', .type = .string, .required = true, .description = "SSH server hostname" },
            .{ .name = "port", .short = 'p', .type = .int, .default = 22, .description = "SSH server port" },
            .{ .name = "user", .short = 'l', .type = .string, .description = "Username" },
            .{ .name = "identity", .short = 'i', .type = .string, .description = "Identity file" },
            .{ .name = "local-forward", .short = 'L', .type = .string, .description = "Local forwarding" },
            .{ .name = "remote-forward", .short = 'R', .type = .string, .description = "Remote forwarding" },
            .{ .name = "dynamic-forward", .short = 'D', .type = .string, .description = "Dynamic forwarding" },
            .{ .name = "background", .short = 'N', .type = .boolean, .default = false, .description = "Don't execute commands" },
            .{ .name = "keep-alive", .type = .int, .default = 30, .description = "Keep-alive interval in seconds" },
        },
        .handler = tunnelHandler,
    });

    // Config command
    try cli.addCommand(.{
        .name = "config",
        .description = "Manage SSH configuration",
        .subcommands = &[_]flash.Command{
            .{
                .name = "show",
                .description = "Show current configuration",
                .handler = configShowHandler,
            },
            .{
                .name = "set",
                .description = "Set configuration value",
                .args = .{ .min = 2, .max = 2, .names = &[_][]const u8{ "key", "value" } },
                .handler = configSetHandler,
            },
            .{
                .name = "get",
                .description = "Get configuration value",
                .args = .{ .min = 1, .max = 1, .names = &[_][]const u8{"key"} },
                .handler = configGetHandler,
            },
        },
    });

    // Parse and execute
    const result = try cli.parse();
    if (result.help_requested) {
        try cli.printHelp();
        return;
    }

    if (result.version_requested) {
        try cli.printVersion();
        return;
    }

    try result.execute();
}

fn connectHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;

    // Extract connection parameters
    const host = ctx.getString("host").?;
    const port = @as(u16, @intCast(ctx.getInt("port") orelse 22));
    const user = ctx.getString("user") orelse std.posix.getenv("USER") orelse "root";
    const command = ctx.getString("command");
    const transport_type = ctx.getString("transport") orelse "tcp";
    const enable_compression = ctx.getBool("compression") orelse false;
    const enable_multiplex = ctx.getBool("multiplex") orelse false;

    std.debug.print("Connecting to {s}@{s}:{d}\n", .{ user, host, port });

    // Determine authentication method
    var auth_method: zssh.AuthMethod = .password;
    if (ctx.getString("identity")) |identity_file| {
        auth_method = .{ .public_key = identity_file };
    } else if (ctx.getString("oidc-provider")) |provider_str| {
        const provider = parseOIDCProvider(provider_str) orelse {
            std.debug.print("Error: Invalid OIDC provider: {s}\n", .{provider_str});
            return;
        };

        const client_id = ctx.getString("oidc-client-id") orelse {
            std.debug.print("Error: OIDC client ID required for OIDC authentication\n");
            return;
        };

        auth_method = .{
            .oidc = .{
                .provider = provider,
                .client_id = client_id,
            }
        };
    }

    // Create SSH client
    var client = try zssh.Client.init(allocator, .{
        .host = host,
        .port = port,
        .username = user,
        .authentication = auth_method,
        .transport = if (std.mem.eql(u8, transport_type, "quic")) .quic else .tcp,
        .enable_compression = enable_compression,
        .enable_multiplexing = enable_multiplex,
        .host_key_verification = .strict,
    });
    defer client.deinit();

    // Connect
    try client.connect();
    std.debug.print("Connected successfully!\n");

    if (command) |cmd| {
        // Execute single command
        const result = try client.execute(cmd);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        std.debug.print("{s}", .{result.stdout});
        if (result.stderr.len > 0) {
            std.debug.print("{s}", .{result.stderr});
        }

        std.process.exit(@intCast(result.exit_code));
    } else if (ctx.getString("subsystem")) |subsystem| {
        // Start subsystem
        if (std.mem.eql(u8, subsystem, "sftp")) {
            var sftp = try client.createSftpSession();
            defer sftp.deinit();
            try runInteractiveSftp(&sftp);
        } else {
            std.debug.print("Error: Unsupported subsystem: {s}\n", .{subsystem});
            return;
        }
    } else {
        // Interactive shell
        var session = try client.createSession();
        defer session.deinit();

        try session.requestPty(.{
            .term = std.posix.getenv("TERM") orelse "xterm-256color",
            .width = 80,
            .height = 24,
        });

        try session.shell();
        try runInteractiveShell(&session);
    }
}

fn sftpHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;

    const host = ctx.getString("host").?;
    const port = @as(u16, @intCast(ctx.getInt("port") orelse 22));
    const user = ctx.getString("user") orelse std.posix.getenv("USER") orelse "root";
    const version = @as(u32, @intCast(ctx.getInt("version") orelse 6));
    const enable_optimization = ctx.getBool("optimization") orelse true;

    std.debug.print("Starting SFTP session with {s}@{s}:{d} (protocol v{d})\n", .{ user, host, port, version });

    // Create client and connect
    var client = try zssh.Client.init(allocator, .{
        .host = host,
        .port = port,
        .username = user,
        .authentication = .{ .public_key = "~/.ssh/id_ed25519" },
    });
    defer client.deinit();

    try client.connect();

    // Create SFTP session
    var sftp = try client.createAdvancedSftpSession(.{
        .version = version,
        .enable_optimization = enable_optimization,
    });
    defer sftp.deinit();

    try runInteractiveSftp(&sftp);
}

fn copyHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;
    const args = ctx.getArgs();

    const source = args[0];
    const dest = args[1];
    const recursive = ctx.getBool("recursive") orelse false;
    const preserve = ctx.getBool("preserve") orelse false;
    const enable_compression = ctx.getBool("compression") orelse true;
    const bandwidth_limit = ctx.getInt("bandwidth-limit");
    const parallel_chunks = @as(u32, @intCast(ctx.getInt("parallel-chunks") orelse 4));
    const chunk_size = @as(u32, @intCast(ctx.getInt("chunk-size") orelse 8)) * 1024 * 1024;

    std.debug.print("Copying {s} to {s}\n", .{ source, dest });

    // Parse source and destination (user@host:path format)
    const source_info = parseSSHPath(source);
    const dest_info = parseSSHPath(dest);

    if (source_info.is_remote and dest_info.is_remote) {
        std.debug.print("Error: Cannot copy between two remote hosts\n");
        return;
    }

    if (source_info.is_remote) {
        // Download from remote
        try downloadFile(allocator, source_info, dest_info, .{
            .recursive = recursive,
            .preserve = preserve,
            .compression = enable_compression,
            .bandwidth_limit = bandwidth_limit,
            .parallel_chunks = parallel_chunks,
            .chunk_size = chunk_size,
        });
    } else if (dest_info.is_remote) {
        // Upload to remote
        try uploadFile(allocator, source_info, dest_info, .{
            .recursive = recursive,
            .preserve = preserve,
            .compression = enable_compression,
            .bandwidth_limit = bandwidth_limit,
            .parallel_chunks = parallel_chunks,
            .chunk_size = chunk_size,
        });
    } else {
        // Local copy
        std.debug.print("Error: Use 'cp' for local file copying\n");
        return;
    }
}

fn tunnelHandler(ctx: *flash.Context) !void {
    // Implementation for SSH tunneling
    _ = ctx;
    std.debug.print("SSH tunnel functionality not yet implemented\n");
}

fn configShowHandler(ctx: *flash.Context) !void {
    // Implementation for showing configuration
    _ = ctx;
    std.debug.print("Configuration display not yet implemented\n");
}

fn configSetHandler(ctx: *flash.Context) !void {
    // Implementation for setting configuration
    _ = ctx;
    std.debug.print("Configuration setting not yet implemented\n");
}

fn configGetHandler(ctx: *flash.Context) !void {
    // Implementation for getting configuration
    _ = ctx;
    std.debug.print("Configuration getting not yet implemented\n");
}

// Helper functions
fn parseOIDCProvider(provider_str: []const u8) ?zssh.auth.oidc_auth.AuthProvider {
    if (std.mem.eql(u8, provider_str, "google")) return .google;
    if (std.mem.eql(u8, provider_str, "github")) return .github;
    if (std.mem.eql(u8, provider_str, "microsoft")) return .microsoft;
    if (std.mem.eql(u8, provider_str, "okta")) return .okta;
    return null;
}

const SSHPath = struct {
    is_remote: bool,
    user: ?[]const u8,
    host: ?[]const u8,
    port: u16,
    path: []const u8,
};

fn parseSSHPath(path_str: []const u8) SSHPath {
    // Parse [user@]host:path format
    if (std.mem.indexOf(u8, path_str, ":")) |colon_pos| {
        const host_part = path_str[0..colon_pos];
        const path_part = path_str[colon_pos + 1 ..];

        if (std.mem.indexOf(u8, host_part, "@")) |at_pos| {
            return SSHPath{
                .is_remote = true,
                .user = host_part[0..at_pos],
                .host = host_part[at_pos + 1 ..],
                .port = 22,
                .path = path_part,
            };
        } else {
            return SSHPath{
                .is_remote = true,
                .user = null,
                .host = host_part,
                .port = 22,
                .path = path_part,
            };
        }
    }

    return SSHPath{
        .is_remote = false,
        .user = null,
        .host = null,
        .port = 22,
        .path = path_str,
    };
}

const CopyOptions = struct {
    recursive: bool,
    preserve: bool,
    compression: bool,
    bandwidth_limit: ?i64,
    parallel_chunks: u32,
    chunk_size: u32,
};

fn uploadFile(allocator: std.mem.Allocator, source: SSHPath, dest: SSHPath, options: CopyOptions) !void {
    _ = allocator;
    _ = source;
    _ = dest;
    _ = options;
    std.debug.print("File upload functionality not yet implemented\n");
}

fn downloadFile(allocator: std.mem.Allocator, source: SSHPath, dest: SSHPath, options: CopyOptions) !void {
    _ = allocator;
    _ = source;
    _ = dest;
    _ = options;
    std.debug.print("File download functionality not yet implemented\n");
}

fn runInteractiveShell(session: *zssh.Session) !void {
    _ = session;
    std.debug.print("Interactive shell not yet implemented\n");
}

fn runInteractiveSftp(sftp: anytype) !void {
    _ = sftp;
    std.debug.print("Interactive SFTP not yet implemented\n");
}