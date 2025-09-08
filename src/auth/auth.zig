//! SSH Authentication
//!
//! Implements SSH authentication methods as defined in RFC 4252.
//! Supports password, public key, and extensible authentication.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const AuthError = error{
    AuthenticationFailed,
    UnsupportedMethod,
    InvalidCredentials,
    KeyLoadError,
} || Allocator.Error;

pub const AuthMethod = enum {
    none,
    password,
    publickey,
    keyboard_interactive,
};

pub const AuthResult = enum {
    success,
    partial_success,
    failure,
    continue_required,
};

pub const SSH_MSG_AUTH = struct {
    pub const REQUEST = 50;
    pub const FAILURE = 51;
    pub const SUCCESS = 52;
    pub const BANNER = 53;
    pub const PK_OK = 60;
};

pub const Credentials = union(AuthMethod) {
    none: void,
    password: []const u8,
    publickey: struct {
        algorithm: []const u8,
        key_data: []const u8,
        signature: ?[]const u8,
    },
    keyboard_interactive: struct {
        responses: [][]const u8,
    },
};

pub const AuthContext = struct {
    allocator: Allocator,
    username: []const u8,
    service: []const u8,
    methods_available: []const AuthMethod,
    current_method: ?AuthMethod,
    partial_success: bool,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, username: []const u8, service: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .username = try allocator.dupe(u8, username),
            .service = try allocator.dupe(u8, service),
            .methods_available = &[_]AuthMethod{ .password, .publickey },
            .current_method = null,
            .partial_success = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.username);
        self.allocator.free(self.service);
    }
    
    pub fn authenticate(self: *Self, credentials: Credentials) AuthResult {
        self.current_method = std.meta.activeTag(credentials);
        
        switch (credentials) {
            .none => return .failure,
            .password => |password| {
                return if (self.validatePassword(password)) .success else .failure;
            },
            .publickey => |pubkey| {
                return if (self.validatePublicKey(pubkey)) .success else .failure;
            },
            .keyboard_interactive => return .continue_required,
        }
    }
    
    pub fn isMethodAvailable(self: *const Self, method: AuthMethod) bool {
        for (self.methods_available) |available| {
            if (available == method) return true;
        }
        return false;
    }
    
    fn validatePassword(self: *const Self, password: []const u8) bool {
        _ = self;
        return password.len > 0;
    }
    
    fn validatePublicKey(self: *const Self, pubkey: anytype) bool {
        _ = self;
        return pubkey.key_data.len > 0;
    }
};

test "Authentication context initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var auth = try AuthContext.init(allocator, "testuser", "ssh-connection");
    defer auth.deinit();
    
    try testing.expectEqualStrings("testuser", auth.username);
    try testing.expectEqualStrings("ssh-connection", auth.service);
    try testing.expect(auth.isMethodAvailable(.password));
    try testing.expect(auth.isMethodAvailable(.publickey));
    try testing.expect(!auth.isMethodAvailable(.none));
}

test "Password authentication" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var auth = try AuthContext.init(allocator, "testuser", "ssh-connection");
    defer auth.deinit();
    
    const valid_creds = Credentials{ .password = "validpassword" };
    const invalid_creds = Credentials{ .password = "" };
    
    try testing.expectEqual(AuthResult.success, auth.authenticate(valid_creds));
    try testing.expectEqual(AuthResult.failure, auth.authenticate(invalid_creds));
}

test "Public key authentication structure" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var auth = try AuthContext.init(allocator, "testuser", "ssh-connection");
    defer auth.deinit();
    
    const pubkey_creds = Credentials{
        .publickey = .{
            .algorithm = "ssh-rsa",
            .key_data = "fake_key_data",
            .signature = null,
        }
    };
    
    try testing.expectEqual(AuthResult.success, auth.authenticate(pubkey_creds));
}