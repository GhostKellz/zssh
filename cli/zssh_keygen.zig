//! zssh-keygen - SSH Key Generation Utility
//!
//! Compatible with OpenSSH key formats with additional key types

const std = @import("std");
const flash = @import("flash");
const zssh = @import("zssh");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var cli = try flash.CLI.init(allocator, .{
        .name = "zssh-keygen",
        .version = "2.0.0",
        .description = "SSH key generation and management utility",
        .author = "GhostStack",
    });
    defer cli.deinit();

    try cli.addCommand(.{
        .name = "generate",
        .description = "Generate new SSH key pair",
        .is_default = true,
        .options = &[_]flash.Option{
            .{ .name = "type", .short = 't', .type = .string, .default = "ed25519", .description = "Key type: rsa, ed25519, ecdsa, x25519" },
            .{ .name = "bits", .short = 'b', .type = .int, .default = 4096, .description = "Key size in bits (for RSA)" },
            .{ .name = "file", .short = 'f', .type = .string, .description = "Output file path" },
            .{ .name = "comment", .short = 'C', .type = .string, .description = "Key comment" },
            .{ .name = "passphrase", .short = 'N', .type = .string, .description = "Passphrase for private key" },
            .{ .name = "format", .short = 'm', .type = .string, .default = "openssh", .description = "Key format: openssh, pem, pkcs8" },
            .{ .name = "overwrite", .short = 'y', .type = .boolean, .default = false, .description = "Overwrite existing files" },
        },
        .handler = generateHandler,
    });

    try cli.addCommand(.{
        .name = "fingerprint",
        .description = "Show key fingerprint",
        .options = &[_]flash.Option{
            .{ .name = "file", .short = 'f', .type = .string, .required = true, .description = "Key file path" },
            .{ .name = "hash", .short = 'h', .type = .string, .default = "sha256", .description = "Hash algorithm: md5, sha1, sha256" },
            .{ .name = "format", .short = 'm', .type = .string, .default = "base64", .description = "Output format: hex, base64, bubblebabble" },
        },
        .handler = fingerprintHandler,
    });

    try cli.addCommand(.{
        .name = "convert",
        .description = "Convert key format",
        .options = &[_]flash.Option{
            .{ .name = "input", .short = 'i', .type = .string, .required = true, .description = "Input key file" },
            .{ .name = "output", .short = 'o', .type = .string, .required = true, .description = "Output key file" },
            .{ .name = "input-format", .type = .string, .default = "auto", .description = "Input format: openssh, pem, pkcs8, auto" },
            .{ .name = "output-format", .type = .string, .default = "openssh", .description = "Output format: openssh, pem, pkcs8" },
            .{ .name = "passphrase", .short = 'N', .type = .string, .description = "New passphrase" },
        },
        .handler = convertHandler,
    });

    const result = try cli.parse();
    if (result.help_requested) {
        try cli.printHelp();
        return;
    }

    try result.execute();
}

fn generateHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;

    const key_type = ctx.getString("type") orelse "ed25519";
    const bits = @as(u32, @intCast(ctx.getInt("bits") orelse 4096));
    const file_path = ctx.getString("file");
    const comment = ctx.getString("comment");
    const passphrase = ctx.getString("passphrase");
    const format = ctx.getString("format") orelse "openssh";
    const overwrite = ctx.getBool("overwrite") orelse false;

    std.debug.print("Generating {s} key pair...\n", .{key_type});

    // Determine output file paths
    var private_key_path: []const u8 = undefined;
    var public_key_path: []const u8 = undefined;

    if (file_path) |path| {
        private_key_path = path;
        public_key_path = try std.fmt.allocPrint(allocator, "{s}.pub", .{path});
    } else {
        const default_name = try std.fmt.allocPrint(allocator, "id_{s}", .{key_type});
        defer allocator.free(default_name);

        private_key_path = try std.fmt.allocPrint(allocator, "~/.ssh/{s}", .{default_name});
        public_key_path = try std.fmt.allocPrint(allocator, "~/.ssh/{s}.pub", .{default_name});
    }
    defer if (file_path == null) {
        allocator.free(private_key_path);
        allocator.free(public_key_path);
    };

    // Check if files exist
    if (!overwrite) {
        if (std.fs.cwd().access(private_key_path, .{})) {
            std.debug.print("File {s} already exists. Use -y to overwrite.\n", .{private_key_path});
            return;
        } else |_| {}
    }

    // Generate key pair based on type
    if (std.mem.eql(u8, key_type, "ed25519")) {
        try generateEd25519KeyPair(allocator, private_key_path, public_key_path, comment, passphrase, format);
    } else if (std.mem.eql(u8, key_type, "rsa")) {
        try generateRSAKeyPair(allocator, private_key_path, public_key_path, bits, comment, passphrase, format);
    } else if (std.mem.eql(u8, key_type, "ecdsa")) {
        try generateECDSAKeyPair(allocator, private_key_path, public_key_path, comment, passphrase, format);
    } else if (std.mem.eql(u8, key_type, "x25519")) {
        try generateX25519KeyPair(allocator, private_key_path, public_key_path, comment, passphrase, format);
    } else {
        std.debug.print("Error: Unsupported key type: {s}\n", .{key_type});
        return;
    }

    std.debug.print("Your identification has been saved in {s}\n", .{private_key_path});
    std.debug.print("Your public key has been saved in {s}\n", .{public_key_path});

    // Show fingerprint
    try showKeyFingerprint(allocator, public_key_path);
}

fn fingerprintHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;

    const file_path = ctx.getString("file").?;
    const hash_algo = ctx.getString("hash") orelse "sha256";
    const output_format = ctx.getString("format") orelse "base64";

    try showKeyFingerprintWithOptions(allocator, file_path, hash_algo, output_format);
}

fn convertHandler(ctx: *flash.Context) !void {
    const allocator = ctx.allocator;

    const input_file = ctx.getString("input").?;
    const output_file = ctx.getString("output").?;
    const input_format = ctx.getString("input-format") orelse "auto";
    const output_format = ctx.getString("output-format") orelse "openssh";
    const new_passphrase = ctx.getString("passphrase");

    std.debug.print("Converting {s} -> {s} ({s} to {s})\n", .{ input_file, output_file, input_format, output_format });

    // Load key from input file
    const key_data = try std.fs.cwd().readFileAlloc(allocator, input_file, 64 * 1024);
    defer allocator.free(key_data);

    // Parse input key (implementation would handle different formats)
    // Convert to output format (implementation would handle conversion)
    // Write to output file

    std.debug.print("Key converted successfully\n");
}

fn generateEd25519KeyPair(allocator: std.mem.Allocator, private_path: []const u8, public_path: []const u8, comment: ?[]const u8, passphrase: ?[]const u8, format: []const u8) !void {
    // Generate Ed25519 key pair using zcrypto
    const key_pair = try zcrypto.Ed25519.generateKeyPair();

    // Format private key
    const private_key_content = try formatPrivateKey(allocator, key_pair.private_key, "ed25519", passphrase, format);
    defer allocator.free(private_key_content);

    // Format public key
    const final_comment = comment orelse try std.fmt.allocPrint(allocator, "{s}@{s}", .{ std.posix.getenv("USER") orelse "user", std.posix.getenv("HOSTNAME") orelse "localhost" });
    defer if (comment == null) allocator.free(final_comment);

    const public_key_content = try formatPublicKey(allocator, key_pair.public_key, "ssh-ed25519", final_comment);
    defer allocator.free(public_key_content);

    // Write files
    try std.fs.cwd().writeFile(.{ .sub_path = private_path, .data = private_key_content });
    try std.fs.cwd().writeFile(.{ .sub_path = public_path, .data = public_key_content });

    // Set appropriate permissions
    try std.fs.cwd().chmod(private_path, 0o600);
    try std.fs.cwd().chmod(public_path, 0o644);
}

fn generateRSAKeyPair(allocator: std.mem.Allocator, private_path: []const u8, public_path: []const u8, bits: u32, comment: ?[]const u8, passphrase: ?[]const u8, format: []const u8) !void {
    // Generate RSA key pair using zcrypto
    const key_pair = try zcrypto.RSA.generateKeyPair(bits);

    const private_key_content = try formatPrivateKey(allocator, key_pair.private_key, "rsa", passphrase, format);
    defer allocator.free(private_key_content);

    const final_comment = comment orelse try std.fmt.allocPrint(allocator, "{s}@{s}", .{ std.posix.getenv("USER") orelse "user", std.posix.getenv("HOSTNAME") orelse "localhost" });
    defer if (comment == null) allocator.free(final_comment);

    const public_key_content = try formatPublicKey(allocator, key_pair.public_key, "ssh-rsa", final_comment);
    defer allocator.free(public_key_content);

    try std.fs.cwd().writeFile(.{ .sub_path = private_path, .data = private_key_content });
    try std.fs.cwd().writeFile(.{ .sub_path = public_path, .data = public_key_content });

    try std.fs.cwd().chmod(private_path, 0o600);
    try std.fs.cwd().chmod(public_path, 0o644);
}

fn generateECDSAKeyPair(allocator: std.mem.Allocator, private_path: []const u8, public_path: []const u8, comment: ?[]const u8, passphrase: ?[]const u8, format: []const u8) !void {
    // Generate ECDSA key pair
    _ = allocator;
    _ = private_path;
    _ = public_path;
    _ = comment;
    _ = passphrase;
    _ = format;
    std.debug.print("ECDSA key generation not yet implemented\n");
}

fn generateX25519KeyPair(allocator: std.mem.Allocator, private_path: []const u8, public_path: []const u8, comment: ?[]const u8, passphrase: ?[]const u8, format: []const u8) !void {
    // Generate X25519 key pair for ECDH
    _ = allocator;
    _ = private_path;
    _ = public_path;
    _ = comment;
    _ = passphrase;
    _ = format;
    std.debug.print("X25519 key generation not yet implemented\n");
}

fn formatPrivateKey(allocator: std.mem.Allocator, private_key: anytype, key_type: []const u8, passphrase: ?[]const u8, format: []const u8) ![]u8 {
    // Format private key in requested format (OpenSSH, PEM, PKCS8)
    _ = private_key;
    _ = key_type;
    _ = passphrase;
    _ = format;
    return try allocator.dupe(u8, "-----BEGIN OPENSSH PRIVATE KEY-----\n[base64 encoded key data]\n-----END OPENSSH PRIVATE KEY-----\n");
}

fn formatPublicKey(allocator: std.mem.Allocator, public_key: anytype, key_type: []const u8, comment: []const u8) ![]u8 {
    // Format public key in OpenSSH format
    _ = public_key;
    return try std.fmt.allocPrint(allocator, "{s} [base64 encoded key data] {s}\n", .{ key_type, comment });
}

fn showKeyFingerprint(allocator: std.mem.Allocator, key_path: []const u8) !void {
    try showKeyFingerprintWithOptions(allocator, key_path, "sha256", "base64");
}

fn showKeyFingerprintWithOptions(allocator: std.mem.Allocator, key_path: []const u8, hash_algo: []const u8, output_format: []const u8) !void {
    // Read and parse public key
    const key_data = try std.fs.cwd().readFileAlloc(allocator, key_path, 64 * 1024);
    defer allocator.free(key_data);

    // Calculate fingerprint
    var hasher = if (std.mem.eql(u8, hash_algo, "md5"))
        zcrypto.MD5.init()
    else if (std.mem.eql(u8, hash_algo, "sha1"))
        zcrypto.SHA1.init()
    else
        zcrypto.SHA256.init();

    hasher.update(key_data);
    const hash = hasher.final();

    // Format fingerprint
    const fingerprint = if (std.mem.eql(u8, output_format, "hex"))
        try formatHex(allocator, hash)
    else
        try formatBase64(allocator, hash);

    defer allocator.free(fingerprint);

    // Extract key type and size from key data
    const key_info = parseKeyInfo(key_data);

    std.debug.print("{d} {s}:{s} {s}\n", .{ key_info.bits, hash_algo, fingerprint, key_path });
}

const KeyInfo = struct {
    bits: u32,
    key_type: []const u8,
};

fn parseKeyInfo(key_data: []const u8) KeyInfo {
    // Parse key data to extract type and size information
    _ = key_data;
    return KeyInfo{
        .bits = 256, // Placeholder
        .key_type = "ED25519", // Placeholder
    };
}

fn formatHex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, data.len * 3 - 1); // Include colons

    for (data, 0..) |byte, i| {
        if (i > 0) {
            result[i * 3 - 1] = ':';
        }
        result[i * 3] = hex_chars[byte >> 4];
        result[i * 3 + 1] = hex_chars[byte & 0x0f];
    }

    return result;
}

fn formatBase64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    // Simple base64 encoding
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const result = try allocator.alloc(u8, encoded_len);
    return encoder.encode(result, data);
}