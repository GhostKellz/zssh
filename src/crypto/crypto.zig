//! SSH Cryptographic Operations
//!
//! Provides cryptographic functions for SSH including key exchange,
//! encryption, MAC, and digital signatures using zcrypto.

const std = @import("std");
const zcrypto = @import("zcrypto");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

pub const CryptoError = error{
    InvalidKeySize,
    EncryptionFailed,
    DecryptionFailed,
    SignatureFailed,
    VerificationFailed,
    KeyGenerationFailed,
} || Allocator.Error;

pub const KeyExchangeAlgorithm = enum {
    diffie_hellman_group14_sha256,
    diffie_hellman_group16_sha512,
    ecdh_sha2_nistp256,
    ecdh_sha2_nistp384,
    ecdh_sha2_nistp521,
    curve25519_sha256,
};

pub const EncryptionAlgorithm = enum {
    aes128_ctr,
    aes192_ctr,
    aes256_ctr,
    aes128_gcm,
    aes256_gcm,
    chacha20_poly1305,
};

pub const MacAlgorithm = enum {
    hmac_sha1,
    hmac_sha256,
    hmac_sha512,
    none, // For authenticated encryption like GCM
};

pub const KeyPair = struct {
    public_key: []u8,
    private_key: []u8,
    algorithm: KeyExchangeAlgorithm,
    
    pub fn deinit(self: *KeyPair, allocator: Allocator) void {
        allocator.free(self.public_key);
        allocator.free(self.private_key);
    }
};

pub const SharedSecret = struct {
    data: []u8,
    
    pub fn deinit(self: *SharedSecret, allocator: Allocator) void {
        // Zero out sensitive data
        std.crypto.utils.secureZero(u8, self.data);
        allocator.free(self.data);
    }
};

pub const CryptoContext = struct {
    allocator: Allocator,
    kex_algorithm: KeyExchangeAlgorithm,
    enc_algorithm: EncryptionAlgorithm,
    mac_algorithm: MacAlgorithm,
    
    const Self = @This();
    
    pub fn init(
        allocator: Allocator,
        kex: KeyExchangeAlgorithm,
        enc: EncryptionAlgorithm,
        mac: MacAlgorithm,
    ) Self {
        return Self{
            .allocator = allocator,
            .kex_algorithm = kex,
            .enc_algorithm = enc,
            .mac_algorithm = mac,
        };
    }
    
    pub fn generateKeyPair(self: *Self) !KeyPair {
        switch (self.kex_algorithm) {
            .curve25519_sha256 => {
                var private_key: [crypto.dh.X25519.secret_length]u8 = undefined;
                var public_key: [crypto.dh.X25519.public_length]u8 = undefined;
                
                crypto.random.bytes(&private_key);
                const public_key_result = crypto.dh.X25519.recoverPublicKey(private_key[0..32].*);
                @memcpy(public_key[0..], &public_key_result);
                
                return KeyPair{
                    .public_key = try self.allocator.dupe(u8, &public_key),
                    .private_key = try self.allocator.dupe(u8, &private_key),
                    .algorithm = .curve25519_sha256,
                };
            },
            .ecdh_sha2_nistp256 => {
                const keypair = crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.create(null) catch {
                    return CryptoError.KeyGenerationFailed;
                };
                
                return KeyPair{
                    .public_key = try self.allocator.dupe(u8, &keypair.public_key.toUncompressedSec1()),
                    .private_key = try self.allocator.dupe(u8, &keypair.secret_key.toBytes()),
                    .algorithm = .ecdh_sha2_nistp256,
                };
            },
            else => return CryptoError.KeyGenerationFailed,
        }
    }
    
    pub fn computeSharedSecret(
        self: *Self,
        private_key: []const u8,
        peer_public_key: []const u8,
    ) !SharedSecret {
        switch (self.kex_algorithm) {
            .curve25519_sha256 => {
                if (private_key.len != crypto.dh.X25519.secret_length or
                    peer_public_key.len != crypto.dh.X25519.public_length) {
                    return CryptoError.InvalidKeySize;
                }
                
                var shared_key: [crypto.dh.X25519.shared_length]u8 = undefined;
                _ = crypto.dh.X25519.create(shared_key[0..], private_key[0..32].*, peer_public_key[0..32].*) catch {
                    return CryptoError.KeyGenerationFailed;
                };
                
                return SharedSecret{
                    .data = try self.allocator.dupe(u8, &shared_key),
                };
            },
            else => return CryptoError.KeyGenerationFailed,
        }
    }
    
    pub fn encrypt(
        self: *Self,
        plaintext: []const u8,
        key: []const u8,
        nonce: []const u8,
    ) ![]u8 {
        switch (self.enc_algorithm) {
            .aes256_ctr => {
                if (key.len != 32) return CryptoError.InvalidKeySize;
                
                const ciphertext = try self.allocator.alloc(u8, plaintext.len);
                const ctx = crypto.core.aes.Aes256.initEnc(key[0..32].*);
                crypto.core.modes.ctr(crypto.core.aes.Aes256, ctx, ciphertext, plaintext, nonce[0..16].*, .big);
                
                return ciphertext;
            },
            .chacha20_poly1305 => {
                if (key.len != 32 or nonce.len != 12) return CryptoError.InvalidKeySize;
                
                var ciphertext = try self.allocator.alloc(u8, plaintext.len + crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length);
                var tag: [crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length]u8 = undefined;
                
                crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                    ciphertext[0..plaintext.len],
                    &tag,
                    plaintext,
                    &[_]u8{},
                    nonce[0..12].*,
                    key[0..32].*,
                );
                
                @memcpy(ciphertext[plaintext.len..], &tag);
                return ciphertext;
            },
            else => return CryptoError.EncryptionFailed,
        }
    }
    
    pub fn decrypt(
        self: *Self,
        ciphertext: []const u8,
        key: []const u8,
        nonce: []const u8,
    ) ![]u8 {
        switch (self.enc_algorithm) {
            .aes256_ctr => {
                if (key.len != 32) return CryptoError.InvalidKeySize;
                
                const plaintext = try self.allocator.alloc(u8, ciphertext.len);
                const ctx = crypto.core.aes.Aes256.initEnc(key[0..32].*);
                crypto.core.modes.ctr(crypto.core.aes.Aes256, ctx, plaintext, ciphertext, nonce[0..16].*, .big);
                
                return plaintext;
            },
            .chacha20_poly1305 => {
                if (key.len != 32 or nonce.len != 12) return CryptoError.InvalidKeySize;
                if (ciphertext.len < crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length) {
                    return CryptoError.DecryptionFailed;
                }
                
                const plaintext_len = ciphertext.len - crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length;
                const plaintext = try self.allocator.alloc(u8, plaintext_len);
                
                crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                    plaintext,
                    ciphertext[0..plaintext_len],
                    ciphertext[plaintext_len..][0..crypto.aead.chacha_poly.ChaCha20Poly1305.tag_length].*,
                    &[_]u8{},
                    nonce[0..12].*,
                    key[0..32].*,
                ) catch {
                    self.allocator.free(plaintext);
                    return CryptoError.DecryptionFailed;
                };
                
                return plaintext;
            },
            else => return CryptoError.DecryptionFailed,
        }
    }
    
    pub fn computeHmac(
        self: *Self,
        data: []const u8,
        key: []const u8,
    ) ![]u8 {
        switch (self.mac_algorithm) {
            .hmac_sha256 => {
                var out: [crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
                crypto.auth.hmac.sha2.HmacSha256.create(&out, data, key);
                return try self.allocator.dupe(u8, &out);
            },
            .hmac_sha512 => {
                var out: [crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
                crypto.auth.hmac.sha2.HmacSha512.create(&out, data, key);
                return try self.allocator.dupe(u8, &out);
            },
            .none => {
                return try self.allocator.alloc(u8, 0);
            },
            else => return CryptoError.SignatureFailed,
        }
    }
    
    pub fn verifyHmac(
        self: *Self,
        data: []const u8,
        key: []const u8,
        expected_mac: []const u8,
    ) !bool {
        const computed_mac = try self.computeHmac(data, key);
        defer self.allocator.free(computed_mac);
        
        return std.crypto.utils.timingSafeEql([*]const u8, computed_mac.ptr, expected_mac.ptr, expected_mac.len);
    }
};

test "Key generation and shared secret" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var ctx = CryptoContext.init(allocator, .curve25519_sha256, .aes256_ctr, .hmac_sha256);
    
    var alice_keys = try ctx.generateKeyPair();
    defer alice_keys.deinit(allocator);
    
    var bob_keys = try ctx.generateKeyPair();
    defer bob_keys.deinit(allocator);
    
    var alice_shared = try ctx.computeSharedSecret(alice_keys.private_key, bob_keys.public_key);
    defer alice_shared.deinit(allocator);
    
    var bob_shared = try ctx.computeSharedSecret(bob_keys.private_key, alice_keys.public_key);
    defer bob_shared.deinit(allocator);
    
    try testing.expectEqualSlices(u8, alice_shared.data, bob_shared.data);
}

test "Encryption and decryption" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var ctx = CryptoContext.init(allocator, .curve25519_sha256, .aes256_ctr, .hmac_sha256);
    
    const plaintext = "Hello, SSH World!";
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{1} ** 16;
    
    const ciphertext = try ctx.encrypt(plaintext, &key, &nonce);
    defer allocator.free(ciphertext);
    
    const decrypted = try ctx.decrypt(ciphertext, &key, &nonce);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(plaintext, decrypted);
}

test "HMAC computation and verification" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var ctx = CryptoContext.init(allocator, .curve25519_sha256, .aes256_ctr, .hmac_sha256);
    
    const data = "test data";
    const key = "secret key";
    
    const mac = try ctx.computeHmac(data, key);
    defer allocator.free(mac);
    
    const is_valid = try ctx.verifyHmac(data, key, mac);
    try testing.expect(is_valid);
    
    const is_invalid = try ctx.verifyHmac("wrong data", key, mac);
    try testing.expect(!is_invalid);
}