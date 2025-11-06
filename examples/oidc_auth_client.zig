//! OIDC Authentication SSH Client Example
//!
//! Demonstrates SSH client with OpenID Connect authentication
//! using OAuth2 flows for enterprise SSO integration.

const std = @import("std");
const zssh = @import("zssh");
const oidc_auth = @import("zssh").auth.oidc_auth;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 5) {
        std.debug.print("Usage: {s} <host> <client_id> <client_secret> <provider>\n", .{args[0]});
        std.debug.print("Providers: google, github, microsoft, okta\n");
        std.process.exit(1);
    }

    const host = args[1];
    const client_id = args[2];
    const client_secret = args[3];
    const provider_str = args[4];

    // Parse provider
    const provider: oidc_auth.AuthProvider = if (std.mem.eql(u8, provider_str, "google"))
        .google
    else if (std.mem.eql(u8, provider_str, "github"))
        .github
    else if (std.mem.eql(u8, provider_str, "microsoft"))
        .microsoft
    else if (std.mem.eql(u8, provider_str, "okta"))
        .okta
    else {
        std.debug.print("Unsupported provider: {s}\n", .{provider_str});
        std.process.exit(1);
    };

    std.debug.print("Setting up OIDC authentication with {s}...\n", .{provider_str});

    // Configure OIDC
    const oidc_config = switch (provider) {
        .google => oidc_auth.OIDCConfig.initGoogle(
            client_id,
            client_secret,
            "http://localhost:8080/callback"
        ),
        .github => oidc_auth.OIDCConfig.initGitHub(
            client_id,
            client_secret,
            "http://localhost:8080/callback"
        ),
        else => {
            std.debug.print("Provider configuration not implemented\n");
            std.process.exit(1);
        },
    };

    // Initialize OIDC authenticator
    var authenticator = try oidc_auth.OIDCAuthenticator.init(allocator, oidc_config);
    defer authenticator.deinit();

    // Generate authorization URL
    const state = "random_state_string_123";
    const auth_url = try authenticator.generateAuthorizationUrl(state);
    defer allocator.free(auth_url);

    std.debug.print("\n=== OAuth2 Authorization ===\n");
    std.debug.print("Please visit this URL to authorize the application:\n");
    std.debug.print("{s}\n", .{auth_url});
    std.debug.print("\nAfter authorization, you'll be redirected to localhost:8080/callback\n");
    std.debug.print("Please copy the 'code' parameter from the callback URL.\n");

    // Simple HTTP server to handle callback (in real app, this would be more robust)
    const callback_server = try startCallbackServer(allocator);
    defer callback_server.deinit();

    std.debug.print("Listening for OAuth callback on http://localhost:8080/callback...\n");

    // Wait for authorization code
    const authorization_code = try waitForAuthorizationCode(callback_server);
    defer allocator.free(authorization_code);

    std.debug.print("Received authorization code, exchanging for tokens...\n");

    // Exchange authorization code for tokens
    var auth_result = try authenticator.exchangeCodeForTokens(authorization_code);
    defer auth_result.deinit(allocator);

    if (!auth_result.success) {
        std.debug.print("Authentication failed: {s}\n", .{auth_result.error_message.?});
        std.process.exit(1);
    }

    std.debug.print("Authentication successful!\n");

    // Display user information
    if (auth_result.user_info) |user_info| {
        std.debug.print("\n=== User Information ===\n");
        std.debug.print("User ID: {s}\n", .{user_info.sub});
        if (user_info.email) |email| std.debug.print("Email: {s}\n", .{email});
        if (user_info.name) |name| std.debug.print("Name: {s}\n", .{name});
        if (user_info.username) |username| std.debug.print("Username: {s}\n", .{username});

        if (user_info.ssh_public_keys) |keys| {
            std.debug.print("\nSSH Public Keys:\n");
            for (keys) |key| {
                std.debug.print("  {s}\n", .{key});
            }
        }
    }

    // Create SSH client with OIDC authentication
    std.debug.print("\n=== SSH Connection ===\n");
    std.debug.print("Connecting to {s} with OIDC credentials...\n", .{host});

    var client = try zssh.Client.init(allocator, .{
        .host = host,
        .port = 22,
        .authentication = .{
            .oidc = .{
                .access_token = auth_result.access_token.?,
                .id_token = auth_result.id_token,
                .user_info = auth_result.user_info.?,
            }
        },
        .host_key_verification = .strict,
    });
    defer client.deinit();

    try client.connect();
    std.debug.print("SSH connection established!\n");

    // Execute commands with OIDC-based authorization
    const commands = [_][]const u8{
        "whoami",
        "echo 'Authenticated via OIDC'",
        "id",
    };

    for (commands) |command| {
        std.debug.print("\nExecuting: {s}\n", .{command});
        const result = try client.execute(command);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        std.debug.print("Output: {s}", .{result.stdout});
        if (result.stderr.len > 0) {
            std.debug.print("Error: {s}", .{result.stderr});
        }
    }

    // Test token refresh if we have a refresh token
    if (auth_result.refresh_token) |refresh_token| {
        std.debug.print("\n=== Token Refresh ===\n");
        var refreshed_result = try authenticator.refreshAccessToken(refresh_token);
        defer refreshed_result.deinit(allocator);

        if (refreshed_result.success) {
            std.debug.print("Token refreshed successfully!\n");
            // Update client with new token
            try client.updateAccessToken(refreshed_result.access_token.?);
        }
    }

    std.debug.print("\nOIDC SSH session completed!\n");
}

// Simple HTTP server for OAuth callback
const CallbackServer = struct {
    allocator: Allocator,
    server: std.Io.net.Server,

    pub fn deinit(self: *CallbackServer) void {
        self.server.deinit();
    }
};

fn startCallbackServer(allocator: Allocator) !*CallbackServer {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 8080);
    var server = try address.listen(.{});

    const callback_server = try allocator.create(CallbackServer);
    callback_server.* = CallbackServer{
        .allocator = allocator,
        .server = server,
    };

    return callback_server;
}

fn waitForAuthorizationCode(server: *CallbackServer) ![]u8 {
    // Simplified implementation - in practice would parse HTTP request
    // For demo purposes, asking user to input manually
    const stdin = std.io.getStdIn().reader();
    var input_buffer: [1024]u8 = undefined;

    std.debug.print("\nPlease paste the authorization code: ");
    if (try stdin.readUntilDelimiterOrEof(input_buffer[0..], '\n')) |input| {
        const code = std.mem.trim(u8, input, " \t\r\n");
        return try server.allocator.dupe(u8, code);
    }

    return error.NoInput;
}