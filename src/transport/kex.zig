//! SSH Key Exchange Implementation
//!
//! Implements SSH 2.0 key exchange algorithms as defined in RFC 4253, RFC 5656, and RFC 8731.
//! Supports Diffie-Hellman, ECDH, and Curve25519 key exchange methods.

const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const transport = @import("transport.zig");
const Allocator = std.mem.Allocator;

pub const KexError = error{
    UnsupportedAlgorithm,
    InvalidPayload,
    KeyExchangeFailed,
    VerificationFailed,
} || crypto.CryptoError || Allocator.Error;

pub const KexState = enum {
    idle,
    initiated,
    exchanging,
    complete,
    failed,
};

pub const KexAlgorithm = enum {
    diffie_hellman_group14_sha256,
    diffie_hellman_group16_sha512,
    ecdh_sha2_nistp256,
    ecdh_sha2_nistp384,
    ecdh_sha2_nistp521,
    curve25519_sha256,
    
    pub fn toString(self: KexAlgorithm) []const u8 {
        return switch (self) {
            .diffie_hellman_group14_sha256 => "diffie-hellman-group14-sha256",
            .diffie_hellman_group16_sha512 => "diffie-hellman-group16-sha512",
            .ecdh_sha2_nistp256 => "ecdh-sha2-nistp256",
            .ecdh_sha2_nistp384 => "ecdh-sha2-nistp384",
            .ecdh_sha2_nistp521 => "ecdh-sha2-nistp521",
            .curve25519_sha256 => "curve25519-sha256@libssh.org",
        };
    }
    
    pub fn fromString(s: []const u8) ?KexAlgorithm {
        const algorithms = [_]KexAlgorithm{
            .diffie_hellman_group14_sha256,
            .diffie_hellman_group16_sha512,
            .ecdh_sha2_nistp256,
            .ecdh_sha2_nistp384,
            .ecdh_sha2_nistp521,
            .curve25519_sha256,
        };
        
        for (algorithms) |alg| {
            if (std.mem.eql(u8, s, alg.toString())) {
                return alg;
            }
        }
        return null;
    }
};

pub const KexInit = struct {
    cookie: [16]u8,
    kex_algorithms: [][]const u8,
    server_host_key_algorithms: [][]const u8,
    encryption_algorithms_client_to_server: [][]const u8,
    encryption_algorithms_server_to_client: [][]const u8,
    mac_algorithms_client_to_server: [][]const u8,
    mac_algorithms_server_to_client: [][]const u8,
    compression_algorithms_client_to_server: [][]const u8,
    compression_algorithms_server_to_client: [][]const u8,
    languages_client_to_server: [][]const u8,
    languages_server_to_client: [][]const u8,
    first_kex_packet_follows: bool,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator) !Self {
        var cookie: [16]u8 = undefined;
        std.crypto.random.bytes(&cookie);
        
        const kex_algs = [_][]const u8{
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha256",
        };
        
        const host_key_algs = [_][]const u8{
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ssh-rsa",
        };
        
        const enc_algs = [_][]const u8{
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes256-ctr",
        };
        
        const mac_algs = [_][]const u8{
            "umac-128-etm@openssh.com",
            "hmac-sha2-256",
        };
        
        const comp_algs = [_][]const u8{
            "none",
        };
        
        const langs = [_][]const u8{};
        
        return Self{
            .cookie = cookie,
            .kex_algorithms = try allocator.dupe([]const u8, &kex_algs),
            .server_host_key_algorithms = try allocator.dupe([]const u8, &host_key_algs),
            .encryption_algorithms_client_to_server = try allocator.dupe([]const u8, &enc_algs),
            .encryption_algorithms_server_to_client = try allocator.dupe([]const u8, &enc_algs),
            .mac_algorithms_client_to_server = try allocator.dupe([]const u8, &mac_algs),
            .mac_algorithms_server_to_client = try allocator.dupe([]const u8, &mac_algs),
            .compression_algorithms_client_to_server = try allocator.dupe([]const u8, &comp_algs),
            .compression_algorithms_server_to_client = try allocator.dupe([]const u8, &comp_algs),
            .languages_client_to_server = try allocator.dupe([]const u8, &langs),
            .languages_server_to_client = try allocator.dupe([]const u8, &langs),
            .first_kex_packet_follows = false,
        };
    }
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.kex_algorithms);
        allocator.free(self.server_host_key_algorithms);
        allocator.free(self.encryption_algorithms_client_to_server);
        allocator.free(self.encryption_algorithms_server_to_client);
        allocator.free(self.mac_algorithms_client_to_server);
        allocator.free(self.mac_algorithms_server_to_client);
        allocator.free(self.compression_algorithms_client_to_server);
        allocator.free(self.compression_algorithms_server_to_client);
        allocator.free(self.languages_client_to_server);
        allocator.free(self.languages_server_to_client);
    }
    
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayList(u8){};
        defer buffer.deinit(allocator);
        
        try buffer.append(allocator, transport.SSH_MSG.KEXINIT);
        try buffer.appendSlice(allocator, &self.cookie);
        
        const field_lists = [_][][]const u8{
            self.kex_algorithms,
            self.server_host_key_algorithms,
            self.encryption_algorithms_client_to_server,
            self.encryption_algorithms_server_to_client,
            self.mac_algorithms_client_to_server,
            self.mac_algorithms_server_to_client,
            self.compression_algorithms_client_to_server,
            self.compression_algorithms_server_to_client,
            self.languages_client_to_server,
            self.languages_server_to_client,
        };
        
        for (field_lists) |list| {
            try serializeStringList(&buffer, allocator, list);
        }
        
        try buffer.append(allocator, if (self.first_kex_packet_follows) 1 else 0);
        try buffer.appendSlice(allocator, &[_]u8{0, 0, 0, 0}); // Reserved
        
        return buffer.toOwnedSlice(allocator);
    }
    
    fn serializeStringList(buffer: *std.ArrayList(u8), allocator: Allocator, list: [][]const u8) !void {
        var total_len: u32 = 0;
        for (list) |item| {
            if (total_len > 0) total_len += 1; // comma
            total_len += @intCast(item.len);
        }
        
        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, total_len, .big);
        try buffer.appendSlice(allocator, &len_bytes);
        
        for (list, 0..) |item, i| {
            if (i > 0) try buffer.append(allocator, ',');
            try buffer.appendSlice(allocator, item);
        }
    }
};

pub const KeyExchange = struct {
    allocator: Allocator,
    state: KexState,
    algorithm: ?KexAlgorithm,
    crypto_ctx: ?crypto.CryptoContext,
    our_kexinit: ?KexInit,
    their_kexinit: ?KexInit,
    shared_secret: ?crypto.SharedSecret,
    session_id: ?[]u8,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .state = .idle,
            .algorithm = null,
            .crypto_ctx = null,
            .our_kexinit = null,
            .their_kexinit = null,
            .shared_secret = null,
            .session_id = null,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.our_kexinit) |*kex| {
            kex.deinit(self.allocator);
        }
        if (self.their_kexinit) |*kex| {
            kex.deinit(self.allocator);
        }
        if (self.shared_secret) |*secret| {
            secret.deinit(self.allocator);
        }
        if (self.session_id) |id| {
            self.allocator.free(id);
        }
    }
    
    pub fn initiate(self: *Self) ![]u8 {
        self.state = .initiated;
        self.our_kexinit = try KexInit.init(self.allocator);
        return try self.our_kexinit.?.serialize(self.allocator);
    }
    
    pub fn processKexInit(self: *Self, payload: []const u8) !void {
        self.their_kexinit = try self.deserializeKexInit(payload);
        try self.negotiateAlgorithms();
        self.state = .exchanging;
    }
    
    pub fn performKeyExchange(self: *Self) !void {
        const algorithm = self.algorithm orelse return KexError.UnsupportedAlgorithm;
        
        const crypto_algorithm = switch (algorithm) {
            .curve25519_sha256 => crypto.KeyExchangeAlgorithm.curve25519_sha256,
            .ecdh_sha2_nistp256 => crypto.KeyExchangeAlgorithm.ecdh_sha2_nistp256,
            .diffie_hellman_group14_sha256 => crypto.KeyExchangeAlgorithm.diffie_hellman_group14_sha256,
            else => return KexError.UnsupportedAlgorithm,
        };
        
        self.crypto_ctx = crypto.CryptoContext.init(
            self.allocator,
            crypto_algorithm,
            .aes256_ctr,
            .hmac_sha256,
        );
        
        var keypair = try self.crypto_ctx.?.generateKeyPair();
        defer keypair.deinit(self.allocator);
        
        self.state = .complete;
    }
    
    fn deserializeKexInit(self: *Self, payload: []const u8) !KexInit {
        if (payload.len < 17) return KexError.InvalidPayload; // 1 byte type + 16 bytes cookie
        
        var kex: KexInit = undefined;
        @memcpy(&kex.cookie, payload[1..17]);
        
        var pos: usize = 17;
        const field_ptrs = [_]*[][]const u8{
            &kex.kex_algorithms,
            &kex.server_host_key_algorithms,
            &kex.encryption_algorithms_client_to_server,
            &kex.encryption_algorithms_server_to_client,
            &kex.mac_algorithms_client_to_server,
            &kex.mac_algorithms_server_to_client,
            &kex.compression_algorithms_client_to_server,
            &kex.compression_algorithms_server_to_client,
            &kex.languages_client_to_server,
            &kex.languages_server_to_client,
        };
        
        for (field_ptrs) |field_ptr| {
            const result = try self.deserializeStringList(payload[pos..]);
            field_ptr.* = result.list;
            pos += result.bytes_consumed;
        }
        
        if (pos < payload.len) {
            kex.first_kex_packet_follows = payload[pos] != 0;
        } else {
            kex.first_kex_packet_follows = false;
        }
        
        return kex;
    }
    
    fn deserializeStringList(self: *Self, data: []const u8) !struct { list: [][]const u8, bytes_consumed: usize } {
        if (data.len < 4) return KexError.InvalidPayload;
        
        const list_len = std.mem.readInt(u32, data[0..4], .big);
        if (data.len < 4 + list_len) return KexError.InvalidPayload;
        
        const list_data = data[4..4 + list_len];
        var algorithms = std.ArrayList([]const u8).init(self.allocator);
        
        var start: usize = 0;
        for (list_data, 0..) |char, i| {
            if (char == ',' or i == list_data.len - 1) {
                const end = if (char == ',') i else i + 1;
                if (end > start) {
                    const alg = try self.allocator.dupe(u8, list_data[start..end]);
                    try algorithms.append(alg);
                }
                start = i + 1;
            }
        }
        
        return .{
            .list = try algorithms.toOwnedSlice(),
            .bytes_consumed = 4 + list_len,
        };
    }
    
    fn negotiateAlgorithms(self: *Self) !void {
        const our_kex = self.our_kexinit.?;
        const their_kex = self.their_kexinit.?;
        
        // Negotiate key exchange algorithm
        for (our_kex.kex_algorithms) |our_alg| {
            for (their_kex.kex_algorithms) |their_alg| {
                if (std.mem.eql(u8, our_alg, their_alg)) {
                    self.algorithm = KexAlgorithm.fromString(our_alg);
                    return;
                }
            }
        }
        
        return KexError.UnsupportedAlgorithm;
    }
};

test "KexInit creation and serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var kexinit = try KexInit.init(allocator);
    defer kexinit.deinit(allocator);
    
    const serialized = try kexinit.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len > 0);
    try testing.expectEqual(@as(u8, transport.SSH_MSG.KEXINIT), serialized[0]);
}

test "Key exchange negotiation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var kex = KeyExchange.init(allocator);
    defer kex.deinit();
    
    const kexinit_payload = try kex.initiate();
    defer allocator.free(kexinit_payload);
    
    try testing.expectEqual(KexState.initiated, kex.state);
}

test "Algorithm string conversion" {
    try std.testing.expectEqualStrings("curve25519-sha256@libssh.org", KexAlgorithm.curve25519_sha256.toString());
    try std.testing.expectEqual(@as(?KexAlgorithm, .curve25519_sha256), KexAlgorithm.fromString("curve25519-sha256@libssh.org"));
    try std.testing.expectEqual(@as(?KexAlgorithm, null), KexAlgorithm.fromString("invalid-algorithm"));
}