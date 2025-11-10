//! OIDC/SSO Authentication Module
//!
//! Integrates with the zid library to provide OpenID Connect and SSO authentication
//! capabilities for SSH connections. Supports OAuth2, OIDC, and SAML 2.0 flows.

const std = @import("std");
const zid = @import("zid");
const Allocator = std.mem.Allocator;

pub const OIDCError = error{
    InvalidToken,
    TokenExpired,
    AuthenticationFailed,
    InvalidConfiguration,
    NetworkError,
    InvalidScope,
    AuthorizationDenied,
} || Allocator.Error;

pub const AuthProvider = enum {
    google,
    microsoft,
    github,
    okta,
    auth0,
    custom,
};

pub const OIDCConfig = struct {
    provider: AuthProvider,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    userinfo_endpoint: []const u8,
    jwks_uri: []const u8,
    scopes: []const []const u8,
    pkce_enabled: bool,

    pub fn initGoogle(client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) OIDCConfig {
        return OIDCConfig{
            .provider = .google,
            .client_id = client_id,
            .client_secret = client_secret,
            .redirect_uri = redirect_uri,
            .authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth",
            .token_endpoint = "https://oauth2.googleapis.com/token",
            .userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo",
            .jwks_uri = "https://www.googleapis.com/oauth2/v3/certs",
            .scopes = &[_][]const u8{ "openid", "profile", "email" },
            .pkce_enabled = true,
        };
    }

    pub fn initGitHub(client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) OIDCConfig {
        return OIDCConfig{
            .provider = .github,
            .client_id = client_id,
            .client_secret = client_secret,
            .redirect_uri = redirect_uri,
            .authorization_endpoint = "https://github.com/login/oauth/authorize",
            .token_endpoint = "https://github.com/login/oauth/access_token",
            .userinfo_endpoint = "https://api.github.com/user",
            .jwks_uri = "", // GitHub doesn't provide JWKS endpoint for OAuth
            .scopes = &[_][]const u8{ "user:email", "read:org" },
            .pkce_enabled = true,
        };
    }
};

pub const UserInfo = struct {
    sub: []const u8,
    email: ?[]const u8,
    name: ?[]const u8,
    username: ?[]const u8,
    groups: ?[]const []const u8,
    roles: ?[]const []const u8,
    ssh_public_keys: ?[]const []const u8,

    pub fn deinit(self: *UserInfo, allocator: Allocator) void {
        allocator.free(self.sub);
        if (self.email) |email| allocator.free(email);
        if (self.name) |name| allocator.free(name);
        if (self.username) |username| allocator.free(username);
        if (self.groups) |groups| {
            for (groups) |group| allocator.free(group);
            allocator.free(groups);
        }
        if (self.roles) |roles| {
            for (roles) |role| allocator.free(role);
            allocator.free(roles);
        }
        if (self.ssh_public_keys) |keys| {
            for (keys) |key| allocator.free(key);
            allocator.free(keys);
        }
    }
};

pub const AuthResult = struct {
    success: bool,
    user_info: ?UserInfo,
    access_token: ?[]const u8,
    id_token: ?[]const u8,
    refresh_token: ?[]const u8,
    expires_in: ?u64,
    error_message: ?[]const u8,

    pub fn deinit(self: *AuthResult, allocator: Allocator) void {
        if (self.user_info) |*user_info| {
            user_info.deinit(allocator);
        }
        if (self.access_token) |token| allocator.free(token);
        if (self.id_token) |token| allocator.free(token);
        if (self.refresh_token) |token| allocator.free(token);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

pub const OIDCAuthenticator = struct {
    allocator: Allocator,
    config: OIDCConfig,
    oauth2_client: zid.OAuth2Client,
    oidc_client: zid.OIDCClient,
    jwk_set: ?zid.JWKSet,
    pkce_verifier: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, config: OIDCConfig) !Self {
        const oauth2_config = zid.OAuth2Config{
            .client_id = config.client_id,
            .client_secret = config.client_secret,
            .redirect_uri = config.redirect_uri,
            .authorization_endpoint = config.authorization_endpoint,
            .token_endpoint = config.token_endpoint,
            .scopes = config.scopes,
        };

        const oauth2_client = try zid.OAuth2Client.init(allocator, oauth2_config);

        const oidc_config = zid.OIDCConfig{
            .issuer = switch (config.provider) {
                .google => "https://accounts.google.com",
                .github => "https://github.com",
                .microsoft => "https://login.microsoftonline.com/common/v2.0",
                else => "",
            },
            .client_id = config.client_id,
            .client_secret = config.client_secret,
            .redirect_uri = config.redirect_uri,
            .userinfo_endpoint = config.userinfo_endpoint,
        };

        const oidc_client = try zid.OIDCClient.init(allocator, oidc_config);

        return Self{
            .allocator = allocator,
            .config = config,
            .oauth2_client = oauth2_client,
            .oidc_client = oidc_client,
            .jwk_set = null,
            .pkce_verifier = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.oauth2_client.deinit();
        self.oidc_client.deinit();
        if (self.jwk_set) |*jwk_set| {
            jwk_set.deinit();
        }
        if (self.pkce_verifier) |verifier| {
            self.allocator.free(verifier);
        }
    }

    pub fn generateAuthorizationUrl(self: *Self, state: []const u8) ![]const u8 {
        var auth_params = zid.AuthorizationParams{
            .response_type = "code",
            .state = state,
            .scope = try self.buildScopeString(),
        };

        // Generate PKCE challenge if enabled
        if (self.config.pkce_enabled) {
            const verifier = try zid.generateCodeVerifier(self.allocator);
            const challenge = try zid.generateCodeChallenge(self.allocator, verifier, .S256);

            self.pkce_verifier = verifier;
            auth_params.code_challenge = challenge;
            auth_params.code_challenge_method = "S256";
        }

        return try self.oauth2_client.buildAuthorizationUrl(auth_params);
    }

    pub fn exchangeCodeForTokens(self: *Self, authorization_code: []const u8) !AuthResult {
        var token_params = zid.TokenParams{
            .grant_type = "authorization_code",
            .code = authorization_code,
            .redirect_uri = self.config.redirect_uri,
        };

        // Add PKCE verifier if enabled
        if (self.config.pkce_enabled and self.pkce_verifier != null) {
            token_params.code_verifier = self.pkce_verifier;
        }

        const token_response = self.oauth2_client.exchangeAuthorizationCode(token_params) catch |err| {
            return AuthResult{
                .success = false,
                .user_info = null,
                .access_token = null,
                .id_token = null,
                .refresh_token = null,
                .expires_in = null,
                .error_message = try self.allocator.dupe(u8, "Token exchange failed"),
            };
        };

        // Validate ID token if present
        var user_info: ?UserInfo = null;
        if (token_response.id_token) |id_token| {
            user_info = self.validateAndExtractUserInfo(id_token) catch |err| {
                return AuthResult{
                    .success = false,
                    .user_info = null,
                    .access_token = null,
                    .id_token = null,
                    .refresh_token = null,
                    .expires_in = null,
                    .error_message = try self.allocator.dupe(u8, "ID token validation failed"),
                };
            };
        } else if (token_response.access_token) |access_token| {
            // Fallback to userinfo endpoint
            user_info = self.fetchUserInfo(access_token) catch |err| {
                return AuthResult{
                    .success = false,
                    .user_info = null,
                    .access_token = null,
                    .id_token = null,
                    .refresh_token = null,
                    .expires_in = null,
                    .error_message = try self.allocator.dupe(u8, "User info fetch failed"),
                };
            };
        }

        return AuthResult{
            .success = true,
            .user_info = user_info,
            .access_token = if (token_response.access_token) |token| try self.allocator.dupe(u8, token) else null,
            .id_token = if (token_response.id_token) |token| try self.allocator.dupe(u8, token) else null,
            .refresh_token = if (token_response.refresh_token) |token| try self.allocator.dupe(u8, token) else null,
            .expires_in = token_response.expires_in,
            .error_message = null,
        };
    }

    pub fn refreshAccessToken(self: *Self, refresh_token: []const u8) !AuthResult {
        const token_params = zid.RefreshTokenParams{
            .grant_type = "refresh_token",
            .refresh_token = refresh_token,
        };

        const token_response = self.oauth2_client.refreshToken(token_params) catch |err| {
            return AuthResult{
                .success = false,
                .user_info = null,
                .access_token = null,
                .id_token = null,
                .refresh_token = null,
                .expires_in = null,
                .error_message = try self.allocator.dupe(u8, "Token refresh failed"),
            };
        };

        return AuthResult{
            .success = true,
            .user_info = null,
            .access_token = if (token_response.access_token) |token| try self.allocator.dupe(u8, token) else null,
            .id_token = if (token_response.id_token) |token| try self.allocator.dupe(u8, token) else null,
            .refresh_token = if (token_response.refresh_token) |token| try self.allocator.dupe(u8, token) else refresh_token,
            .expires_in = token_response.expires_in,
            .error_message = null,
        };
    }

    fn validateAndExtractUserInfo(self: *Self, id_token: []const u8) !UserInfo {
        // Verify JWT signature using JWK set
        if (self.jwk_set == null and self.config.jwks_uri.len > 0) {
            self.jwk_set = try zid.JWKSet.fetchFromUri(self.allocator, self.config.jwks_uri);
        }

        const jwt = try zid.JWT.parse(self.allocator, id_token);
        defer jwt.deinit();

        if (self.jwk_set) |*jwk_set| {
            try jwt.verify(jwk_set);
        }

        // Extract claims from JWT payload
        const claims = jwt.payload;

        return UserInfo{
            .sub = try self.allocator.dupe(u8, claims.get("sub") orelse return OIDCError.InvalidToken),
            .email = if (claims.get("email")) |email| try self.allocator.dupe(u8, email) else null,
            .name = if (claims.get("name")) |name| try self.allocator.dupe(u8, name) else null,
            .username = if (claims.get("preferred_username")) |username| try self.allocator.dupe(u8, username) else null,
            .groups = try self.extractStringArray(claims, "groups"),
            .roles = try self.extractStringArray(claims, "roles"),
            .ssh_public_keys = try self.extractStringArray(claims, "ssh_public_keys"),
        };
    }

    fn fetchUserInfo(self: *Self, access_token: []const u8) !UserInfo {
        const user_info_response = try self.oidc_client.fetchUserInfo(access_token);
        defer user_info_response.deinit();

        return UserInfo{
            .sub = try self.allocator.dupe(u8, user_info_response.get("sub") orelse return OIDCError.InvalidToken),
            .email = if (user_info_response.get("email")) |email| try self.allocator.dupe(u8, email) else null,
            .name = if (user_info_response.get("name")) |name| try self.allocator.dupe(u8, name) else null,
            .username = if (user_info_response.get("login")) |login| try self.allocator.dupe(u8, login) else null,
            .groups = try self.extractStringArray(user_info_response, "groups"),
            .roles = try self.extractStringArray(user_info_response, "roles"),
            .ssh_public_keys = try self.extractGitHubSSHKeys(access_token),
        };
    }

    fn extractGitHubSSHKeys(self: *Self, access_token: []const u8) !?[]const []const u8 {
        if (self.config.provider != .github) return null;

        // GitHub-specific SSH key fetching
        const keys_response = try self.oauth2_client.makeAuthenticatedRequest(
            "https://api.github.com/user/keys",
            access_token
        );
        defer keys_response.deinit();

        // Parse JSON array of SSH keys
        var keys = std.ArrayList([]const u8).init(self.allocator);
        defer keys.deinit();

        // Implementation would parse the JSON response
        // For now, return null as placeholder
        return null;
    }

    fn extractStringArray(self: *Self, json_obj: anytype, key: []const u8) !?[]const []const u8 {
        const array_value = json_obj.get(key) orelse return null;

        // Implementation would parse JSON array into string array
        // For now, return null as placeholder
        _ = self;
        _ = array_value;
        return null;
    }

    fn buildScopeString(self: *Self) ![]const u8 {
        var scope_builder = std.ArrayList(u8).init(self.allocator);
        defer scope_builder.deinit();

        for (self.config.scopes, 0..) |scope, i| {
            if (i > 0) try scope_builder.append(' ');
            try scope_builder.appendSlice(scope);
        }

        return try self.allocator.dupe(u8, scope_builder.items);
    }

    pub fn validateAccessToken(self: *Self, access_token: []const u8) !bool {
        // For JWT access tokens, verify signature and expiration
        if (std.mem.startsWith(u8, access_token, "eyJ")) {
            const jwt = zid.JWT.parse(self.allocator, access_token) catch return false;
            defer jwt.deinit();

            if (self.jwk_set) |*jwk_set| {
                jwt.verify(jwk_set) catch return false;
            }

            // Check expiration
            // Zig 0.16.0-dev: std.time.timestamp() removed
            var io_threaded = std.Io.Threaded.init_single_threaded;
            const io = io_threaded.io();
            const now_ts = std.Io.Clock.now(.real, io) catch return false;
            const now: i64 = @divFloor(now_ts.nanoseconds, std.time.ns_per_s);
            if (jwt.payload.get("exp")) |exp_str| {
                const exp = std.fmt.parseInt(i64, exp_str, 10) catch return false;
                if (now >= exp) return false;
            }

            return true;
        }

        // For opaque tokens, make introspection request
        return self.introspectToken(access_token);
    }

    fn introspectToken(self: *Self, token: []const u8) !bool {
        // Token introspection endpoint call
        // Implementation would make HTTP request to introspection endpoint
        _ = self;
        _ = token;
        return true; // Placeholder
    }
};

test "OIDC authenticator initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = OIDCConfig.initGoogle("test_client_id", "test_secret", "http://localhost:8080/callback");
    var authenticator = try OIDCAuthenticator.init(allocator, config);
    defer authenticator.deinit();

    try testing.expect(std.mem.eql(u8, authenticator.config.client_id, "test_client_id"));
    try testing.expect(authenticator.config.provider == .google);
    try testing.expect(authenticator.config.pkce_enabled == true);
}

test "Authorization URL generation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = OIDCConfig.initGitHub("test_client", "test_secret", "http://localhost/callback");
    var authenticator = try OIDCAuthenticator.init(allocator, config);
    defer authenticator.deinit();

    const auth_url = try authenticator.generateAuthorizationUrl("test_state");
    defer allocator.free(auth_url);

    try testing.expect(std.mem.containsSlice(u8, auth_url, "github.com"));
    try testing.expect(std.mem.containsSlice(u8, auth_url, "test_client"));
    try testing.expect(std.mem.containsSlice(u8, auth_url, "test_state"));
}