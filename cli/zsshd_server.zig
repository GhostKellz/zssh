//! zsshd - SSH Server Daemon
//!
//! Production-ready SSH server daemon with advanced features

const std = @import("std");
const flash = @import("flash");
const flare = @import("flare");
const zssh = @import("zssh");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var cli = try flash.CLI.init(allocator, .{
        .name = "zsshd",
        .version = "2.0.0",
        .description = "High-performance SSH server daemon",
        .author = "GhostStack",
    });
    defer cli.deinit();

    try cli.addGlobalOption(.{
        .name = "config",
        .short = 'f',
        .description = "Configuration file path",
        .type = .string,
        .default = "/etc/zssh/zsshd_config",
    });

    try cli.addGlobalOption(.{
        .name = "debug",
        .short = 'd',
        .description = "Debug mode",
        .type = .boolean,
        .default = false,
    });

    try cli.addGlobalOption(.{
        .name = "test",
        .short = 't',
        .description = "Test configuration and exit",
        .type = .boolean,
        .default = false,
    });

    try cli.addCommand(.{
        .name = "start",
        .description = "Start SSH server daemon",
        .is_default = true,
        .options = &[_]flash.Option{
            .{ .name = "port", .short = 'p', .type = .int, .default = 22, .description = "Listen port" },
            .{ .name = "host", .short = 'h', .type = .string, .default = "0.0.0.0", .description = "Listen address" },
            .{ .name = "host-key", .short = 'k', .type = .string, .default = "/etc/ssh/ssh_host_ed25519_key", .description = "Host key file" },
            .{ .name = "max-connections", .type = .int, .default = 100, .description = "Maximum concurrent connections" },
            .{ .name = "daemon", .short = 'D', .type = .boolean, .default = false, .description = "Run as daemon" },
            .{ .name = "pid-file", .type = .string, .default = "/var/run/zsshd.pid", .description = "PID file path" },
            .{ .name = "log-level", .type = .string, .default = "info", .description = "Log level: debug, info, warn, error" },
            .{ .name = "enable-quic", .type = .boolean, .default = false, .description = "Enable QUIC transport" },
            .{ .name = "enable-compression", .type = .boolean, .default = true, .description = "Enable compression" },
            .{ .name = "enable-multiplexing", .type = .boolean, .default = true, .description = "Enable connection multiplexing" },
        },
        .handler = startHandler,
    });

    const result = try cli.parse();
    if (result.help_requested) {
        try cli.printHelp();
        return;
    }

    try result.execute();
}

fn startHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;

    const port = @as(u16, @intCast(ctx.getInt("port") orelse 22));
    const host = ctx.getString("host") orelse "0.0.0.0";
    const host_key_file = ctx.getString("host-key") orelse "/etc/ssh/ssh_host_ed25519_key";
    const max_connections = @as(u32, @intCast(ctx.getInt("max-connections") orelse 100));
    const daemon_mode = ctx.getBool("daemon") orelse false;
    const enable_quic = ctx.getBool("enable-quic") orelse false;

    std.debug.print("Starting zsshd on {s}:{d}\n", .{ host, port });

    if (daemon_mode) {
        try daemonize();
    }

    var server = try zssh.Server.init(allocator, .{
        .host = host,
        .port = port,
        .host_key_file = host_key_file,
        .max_connections = max_connections,
        .enable_quic_transport = enable_quic,
        .authentication_methods = &[_]zssh.AuthMethod{
            .password,
            .public_key,
            .oidc,
        },
        .subsystems = &[_]zssh.Subsystem{
            .sftp,
            .netconf,
        },
    });
    defer server.deinit();

    try server.listen();

    // Signal handling
    const SignalHandler = struct {
        var should_stop: bool = false;
        fn handleSignal(sig: i32) callconv(.C) void {
            _ = sig;
            should_stop = true;
        }
    };

    _ = std.c.signal(std.c.SIGINT, SignalHandler.handleSignal);
    _ = std.c.signal(std.c.SIGTERM, SignalHandler.handleSignal);

    std.debug.print("zsshd started successfully\n");

    while (!SignalHandler.should_stop) {
        try server.processEvents();
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    std.debug.print("Shutting down zsshd...\n");
}

fn daemonize() !void {
    // Fork process to background
    const pid = std.c.fork();
    if (pid < 0) {
        return error.ForkFailed;
    }
    if (pid > 0) {
        // Parent process exits
        std.process.exit(0);
    }

    // Child process continues as daemon
    _ = std.c.setsid();
    _ = std.c.umask(0);
}