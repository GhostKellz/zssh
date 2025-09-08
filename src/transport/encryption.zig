//! SSH Encryption and MAC Implementation
//!
//! Provides encryption, decryption, and message authentication for SSH transport.
//! Supports multiple cipher and MAC algorithms as defined in SSH RFCs.

const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const Allocator = std.mem.Allocator;

pub const EncryptionError = error{
    InvalidCipher,
    InvalidMac,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    MacVerificationFailed,
} || crypto.CryptoError || Allocator.Error;

pub const CipherSpec = struct {
    name: []const u8,
    key_length: u32,
    iv_length: u32,
    block_size: u32,
    auth_tag_length: u32, // For AEAD ciphers
};

pub const MacSpec = struct {
    name: []const u8,
    key_length: u32,
    digest_length: u32,
};

pub const CIPHERS = struct {
    pub const AES128_CTR = CipherSpec{
        .name = "aes128-ctr",
        .key_length = 16,
        .iv_length = 16,
        .block_size = 16,
        .auth_tag_length = 0,
    };
    
    pub const AES256_CTR = CipherSpec{
        .name = "aes256-ctr",
        .key_length = 32,
        .iv_length = 16,
        .block_size = 16,
        .auth_tag_length = 0,
    };
    
    pub const AES256_GCM = CipherSpec{
        .name = "aes256-gcm@openssh.com",
        .key_length = 32,
        .iv_length = 12,
        .block_size = 16,
        .auth_tag_length = 16,
    };
    
    pub const CHACHA20_POLY1305 = CipherSpec{
        .name = "chacha20-poly1305@openssh.com",
        .key_length = 32,
        .iv_length = 12,
        .block_size = 8,
        .auth_tag_length = 16,
    };
    
    pub const NONE = CipherSpec{
        .name = "none",
        .key_length = 0,
        .iv_length = 0,
        .block_size = 8,
        .auth_tag_length = 0,
    };
};

pub const MACS = struct {
    pub const HMAC_SHA256 = MacSpec{
        .name = "hmac-sha2-256",
        .key_length = 32,
        .digest_length = 32,
    };
    
    pub const HMAC_SHA512 = MacSpec{
        .name = "hmac-sha2-512",
        .key_length = 64,
        .digest_length = 64,
    };
    
    pub const NONE = MacSpec{
        .name = "none",
        .key_length = 0,
        .digest_length = 0,
    };
};

pub const EncryptionKeys = struct {
    cipher_key_c2s: []u8,
    cipher_key_s2c: []u8,
    cipher_iv_c2s: []u8,
    cipher_iv_s2c: []u8,
    mac_key_c2s: []u8,
    mac_key_s2c: []u8,
    
    const Self = @This();
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        // Zero out sensitive key material
        std.crypto.utils.secureZero(u8, self.cipher_key_c2s);
        std.crypto.utils.secureZero(u8, self.cipher_key_s2c);
        std.crypto.utils.secureZero(u8, self.cipher_iv_c2s);
        std.crypto.utils.secureZero(u8, self.cipher_iv_s2c);
        std.crypto.utils.secureZero(u8, self.mac_key_c2s);
        std.crypto.utils.secureZero(u8, self.mac_key_s2c);
        
        allocator.free(self.cipher_key_c2s);
        allocator.free(self.cipher_key_s2c);
        allocator.free(self.cipher_iv_c2s);
        allocator.free(self.cipher_iv_s2c);
        allocator.free(self.mac_key_c2s);
        allocator.free(self.mac_key_s2c);
    }
};

pub const CipherContext = struct {
    allocator: Allocator,
    cipher_spec: CipherSpec,
    mac_spec: MacSpec,
    keys: EncryptionKeys,
    sequence_number_send: u32,
    sequence_number_recv: u32,
    
    const Self = @This();
    
    pub fn init(
        allocator: Allocator,
        cipher_name: []const u8,
        mac_name: []const u8,
        shared_secret: []const u8,
        session_id: []const u8,
    ) !Self {
        const cipher_spec = getCipherSpec(cipher_name) orelse return EncryptionError.InvalidCipher;
        const mac_spec = getMacSpec(mac_name) orelse return EncryptionError.InvalidMac;
        
        const keys = try deriveKeys(allocator, cipher_spec, mac_spec, shared_secret, session_id);
        
        return Self{
            .allocator = allocator,
            .cipher_spec = cipher_spec,
            .mac_spec = mac_spec,
            .keys = keys,
            .sequence_number_send = 0,
            .sequence_number_recv = 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.keys.deinit(self.allocator);
    }
    
    pub fn encryptPacket(self: *Self, packet_data: []const u8) ![]u8 {
        if (std.mem.eql(u8, self.cipher_spec.name, "none")) {
            return try self.allocator.dupe(u8, packet_data);
        }
        
        var crypto_ctx = crypto.CryptoContext.init(
            self.allocator,
            .curve25519_sha256, // This doesn't matter for encryption
            if (std.mem.eql(u8, self.cipher_spec.name, "chacha20-poly1305@openssh.com"))
                .chacha20_poly1305
            else
                .aes256_ctr,
            if (std.mem.eql(u8, self.mac_spec.name, "hmac-sha2-256"))
                .hmac_sha256
            else
                .hmac_sha512,
        );
        
        const nonce = try self.generateNonce();
        defer self.allocator.free(nonce);
        
        const encrypted = try crypto_ctx.encrypt(packet_data, self.keys.cipher_key_c2s, nonce);
        
        // Add MAC if not AEAD
        if (self.cipher_spec.auth_tag_length == 0 and self.mac_spec.digest_length > 0) {
            const mac_input = try self.prepareMacInput(packet_data);
            defer self.allocator.free(mac_input);
            
            const mac = try crypto_ctx.computeHmac(mac_input, self.keys.mac_key_c2s);
            defer self.allocator.free(mac);
            
            var result = try self.allocator.alloc(u8, encrypted.len + mac.len);
            @memcpy(result[0..encrypted.len], encrypted);
            @memcpy(result[encrypted.len..], mac);
            
            self.allocator.free(encrypted);
            return result;
        }
        
        self.sequence_number_send += 1;
        return encrypted;
    }
    
    pub fn decryptPacket(self: *Self, encrypted_data: []const u8) ![]u8 {
        if (std.mem.eql(u8, self.cipher_spec.name, "none")) {
            return try self.allocator.dupe(u8, encrypted_data);
        }
        
        var crypto_ctx = crypto.CryptoContext.init(
            self.allocator,
            .curve25519_sha256,
            if (std.mem.eql(u8, self.cipher_spec.name, "chacha20-poly1305@openssh.com"))
                .chacha20_poly1305
            else
                .aes256_ctr,
            if (std.mem.eql(u8, self.mac_spec.name, "hmac-sha2-256"))
                .hmac_sha256
            else
                .hmac_sha512,
        );
        
        var ciphertext = encrypted_data;
        
        // Handle MAC verification for non-AEAD ciphers
        if (self.cipher_spec.auth_tag_length == 0 and self.mac_spec.digest_length > 0) {
            if (encrypted_data.len < self.mac_spec.digest_length) {
                return EncryptionError.DecryptionFailed;
            }
            
            const mac_start = encrypted_data.len - self.mac_spec.digest_length;
            ciphertext = encrypted_data[0..mac_start];
            const received_mac = encrypted_data[mac_start..];
            
            const mac_input = try self.prepareMacInput(ciphertext);
            defer self.allocator.free(mac_input);
            
            const is_valid = try crypto_ctx.verifyHmac(mac_input, self.keys.mac_key_s2c, received_mac);
            if (!is_valid) {
                return EncryptionError.MacVerificationFailed;
            }
        }
        
        const nonce = try self.generateNonce();
        defer self.allocator.free(nonce);
        
        const decrypted = try crypto_ctx.decrypt(ciphertext, self.keys.cipher_key_s2c, nonce);
        
        self.sequence_number_recv += 1;
        return decrypted;
    }
    
    fn generateNonce(self: *Self) ![]u8 {
        var nonce = try self.allocator.alloc(u8, self.cipher_spec.iv_length);
        
        if (self.cipher_spec.iv_length == 16) {
            // For CTR mode, use sequence number as part of IV
            std.mem.writeInt(u32, nonce[12..16], self.sequence_number_send, .big);
            @memcpy(nonce[0..12], self.keys.cipher_iv_c2s[0..12]);
        } else if (self.cipher_spec.iv_length == 12) {
            // For GCM/ChaCha20, use sequence number directly
            std.mem.writeInt(u32, nonce[8..12], self.sequence_number_send, .big);
            @memcpy(nonce[0..8], self.keys.cipher_iv_c2s[0..8]);
        }
        
        return nonce;
    }
    
    fn prepareMacInput(self: *Self, packet_data: []const u8) ![]u8 {
        var mac_input = try self.allocator.alloc(u8, 4 + packet_data.len);
        std.mem.writeInt(u32, mac_input[0..4], self.sequence_number_send, .big);
        @memcpy(mac_input[4..], packet_data);
        return mac_input;
    }
};

fn getCipherSpec(name: []const u8) ?CipherSpec {
    const ciphers = [_]CipherSpec{
        CIPHERS.AES128_CTR,
        CIPHERS.AES256_CTR,
        CIPHERS.AES256_GCM,
        CIPHERS.CHACHA20_POLY1305,
        CIPHERS.NONE,
    };
    
    for (ciphers) |cipher| {
        if (std.mem.eql(u8, cipher.name, name)) {
            return cipher;
        }
    }
    return null;
}

fn getMacSpec(name: []const u8) ?MacSpec {
    const macs = [_]MacSpec{
        MACS.HMAC_SHA256,
        MACS.HMAC_SHA512,
        MACS.NONE,
    };
    
    for (macs) |mac| {
        if (std.mem.eql(u8, mac.name, name)) {
            return mac;
        }
    }
    return null;
}

fn deriveKeys(
    allocator: Allocator,
    cipher_spec: CipherSpec,
    mac_spec: MacSpec,
    shared_secret: []const u8,
    session_id: []const u8,
) !EncryptionKeys {
    // Simplified key derivation - in a real implementation, this would use
    // the SSH key derivation function (KDF) as specified in RFC 4253
    
    const total_key_material = 2 * (cipher_spec.key_length + cipher_spec.iv_length + mac_spec.key_length);
    var key_material = try allocator.alloc(u8, total_key_material);
    defer allocator.free(key_material);
    
    // Generate key material using HKDF-like expansion
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(shared_secret);
    hasher.update(session_id);
    
    var i: u32 = 0;
    var pos: usize = 0;
    while (pos < total_key_material) {
        var round_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        round_hasher.update(shared_secret);
        round_hasher.update(session_id);
        round_hasher.update(&std.mem.toBytes(i));
        
        var digest: [32]u8 = undefined;
        round_hasher.final(&digest);
        
        const to_copy = @min(digest.len, total_key_material - pos);
        @memcpy(key_material[pos..pos + to_copy], digest[0..to_copy]);
        pos += to_copy;
        i += 1;
    }
    
    // Extract keys from derived material
    var offset: usize = 0;
    
    const cipher_key_c2s = try allocator.dupe(u8, key_material[offset..offset + cipher_spec.key_length]);
    offset += cipher_spec.key_length;
    
    const cipher_key_s2c = try allocator.dupe(u8, key_material[offset..offset + cipher_spec.key_length]);
    offset += cipher_spec.key_length;
    
    const cipher_iv_c2s = try allocator.dupe(u8, key_material[offset..offset + cipher_spec.iv_length]);
    offset += cipher_spec.iv_length;
    
    const cipher_iv_s2c = try allocator.dupe(u8, key_material[offset..offset + cipher_spec.iv_length]);
    offset += cipher_spec.iv_length;
    
    const mac_key_c2s = try allocator.dupe(u8, key_material[offset..offset + mac_spec.key_length]);
    offset += mac_spec.key_length;
    
    const mac_key_s2c = try allocator.dupe(u8, key_material[offset..offset + mac_spec.key_length]);
    
    return EncryptionKeys{
        .cipher_key_c2s = cipher_key_c2s,
        .cipher_key_s2c = cipher_key_s2c,
        .cipher_iv_c2s = cipher_iv_c2s,
        .cipher_iv_s2c = cipher_iv_s2c,
        .mac_key_c2s = mac_key_c2s,
        .mac_key_s2c = mac_key_s2c,
    };
}

test "Cipher spec lookup" {
    const aes256 = getCipherSpec("aes256-ctr");
    try std.testing.expect(aes256 != null);
    try std.testing.expectEqual(@as(u32, 32), aes256.?.key_length);
    
    const invalid = getCipherSpec("invalid-cipher");
    try std.testing.expect(invalid == null);
}

test "MAC spec lookup" {
    const hmac_sha256 = getMacSpec("hmac-sha2-256");
    try std.testing.expect(hmac_sha256 != null);
    try std.testing.expectEqual(@as(u32, 32), hmac_sha256.?.digest_length);
    
    const invalid = getMacSpec("invalid-mac");
    try std.testing.expect(invalid == null);
}

test "Key derivation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const shared_secret = "shared_secret";
    const session_id = "session_id";
    
    var keys = try deriveKeys(allocator, CIPHERS.AES256_CTR, MACS.HMAC_SHA256, shared_secret, session_id);
    defer keys.deinit(allocator);
    
    try testing.expectEqual(@as(usize, 32), keys.cipher_key_c2s.len);
    try testing.expectEqual(@as(usize, 32), keys.cipher_key_s2c.len);
    try testing.expectEqual(@as(usize, 16), keys.cipher_iv_c2s.len);
    try testing.expectEqual(@as(usize, 16), keys.cipher_iv_s2c.len);
}