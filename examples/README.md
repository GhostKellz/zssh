# zssh Examples

This directory contains comprehensive examples demonstrating the advanced features of zssh.

## Examples Overview

### 1. Basic Client (`basic_client.zig`)
- Simple SSH client connection
- Password authentication
- Command execution
- Interactive shell session

**Usage:**
```bash
zig run examples/basic_client.zig -- <host> <username> <password>
```

### 2. QUIC Client (`quic_client.zig`)
- QUIC-based SSH transport
- Connection multiplexing
- 0-RTT support
- Performance monitoring

**Usage:**
```bash
zig run examples/quic_client.zig -- <host> <username>
```

### 3. OIDC Authentication (`oidc_auth_client.zig`)
- OpenID Connect authentication
- OAuth2 flows
- Enterprise SSO integration
- Token management

**Usage:**
```bash
zig run examples/oidc_auth_client.zig -- <host> <client_id> <client_secret> <provider>
```

Supported providers: `google`, `github`, `microsoft`, `okta`

### 4. Large File Transfer (`large_file_transfer.zig`)
- Optimized large file transfers
- Progress tracking and ETA
- Resumable transfers
- Compression support
- Bandwidth throttling

**Usage:**
```bash
# Upload
zig run examples/large_file_transfer.zig -- <host> <username> <local_file> <remote_file> upload

# Download
zig run examples/large_file_transfer.zig -- <host> <username> <local_file> <remote_file> download

# Resume
zig run examples/large_file_transfer.zig -- <host> <username> <local_file> <remote_file> resume
```

### 5. SSH Server (`server_example.zig`)
- Full SSH server implementation
- Multiple authentication methods
- Session management
- SFTP subsystem support

**Usage:**
```bash
zig run examples/server_example.zig -- [port]
```

Default port: 2222

## Features Demonstrated

### Transport Layer
- ✅ Traditional TCP transport
- ✅ QUIC transport with multiplexing
- ✅ Connection keep-alive and heartbeat
- ✅ Encryption and integrity verification

### Authentication
- ✅ Password authentication
- ✅ Public key authentication
- ✅ OpenID Connect (OIDC) authentication
- ✅ Multi-factor authentication support

### Advanced Features
- ✅ Connection multiplexing
- ✅ Large file transfer optimization
- ✅ Resumable transfers
- ✅ Compression (zlib, gzip, lz4, zstd)
- ✅ Bandwidth throttling
- ✅ Progress tracking and ETA
- ✅ SFTP v4-v6 protocol support

### Performance & Reliability
- ✅ Parallel chunk transfers
- ✅ Zero-copy buffer management
- ✅ Memory pool allocation
- ✅ Error recovery and reconnection
- ✅ Async I/O optimization

## Building Examples

To build and run the examples:

```bash
# Build specific example
zig build-exe examples/basic_client.zig --deps zssh

# Or use the project's build system
zig build examples
```

## Configuration

### SSH Client Configuration
Examples support various configuration options:

```zig
const config = zssh.ClientConfig{
    .host = "example.com",
    .port = 22,
    .username = "user",
    .authentication = .{ .public_key = "~/.ssh/id_ed25519" },
    .host_key_verification = .strict,
    .enable_compression = true,
    .enable_multiplexing = true,
    .connection_timeout_ms = 30000,
    .keepalive_interval_ms = 30000,
};
```

### Transfer Optimization
Large file transfers can be configured for optimal performance:

```zig
const transfer_config = TransferConfig{
    .strategy = .adaptive_chunking,
    .max_chunk_size = 16 * 1024 * 1024, // 16MB
    .max_parallel_chunks = 8,
    .compression = .zstd,
    .bandwidth_limit = 100 * 1024 * 1024, // 100 MB/s
    .enable_resume = true,
    .verify_checksums = true,
};
```

### OIDC Configuration
Enterprise authentication setup:

```zig
const oidc_config = OIDCConfig{
    .provider = .google,
    .client_id = "your-client-id",
    .client_secret = "your-client-secret",
    .redirect_uri = "http://localhost:8080/callback",
    .scopes = &[_][]const u8{ "openid", "profile", "email" },
    .pkce_enabled = true,
};
```

## Security Considerations

### Host Key Verification
Always verify host keys in production:

```zig
.host_key_verification = .{
    .mode = .strict,
    .known_hosts_file = "~/.ssh/known_hosts",
}
```

### Authentication Best Practices
- Use public key authentication when possible
- Enable multi-factor authentication for sensitive systems
- Implement proper token validation for OIDC flows
- Use strong passwords and rotate credentials regularly

### Network Security
- Always use encrypted connections
- Implement proper firewall rules
- Monitor connection logs for suspicious activity
- Use connection limits to prevent DoS attacks

## Performance Tips

### Large File Transfers
- Use adaptive chunking for best performance
- Enable compression for text/code files
- Set appropriate bandwidth limits
- Use parallel transfers for multiple files

### QUIC Transport
- Enable 0-RTT for repeated connections
- Use connection migration for mobile clients
- Monitor RTT and adjust chunk sizes accordingly

### Memory Management
- Use memory pools for high-frequency operations
- Enable zero-copy operations where possible
- Monitor memory usage for long-running transfers

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Check firewall settings
   - Verify host and port
   - Increase timeout values

2. **Authentication Failures**
   - Verify credentials
   - Check key file permissions
   - Validate OIDC configuration

3. **Transfer Failures**
   - Check disk space
   - Verify file permissions
   - Enable transfer resume

4. **Performance Issues**
   - Adjust chunk sizes
   - Enable compression
   - Use QUIC transport
   - Check network conditions

### Debug Logging
Enable debug logging for troubleshooting:

```zig
client.setLogLevel(.debug);
```

## Contributing

To add new examples:

1. Create a new `.zig` file in the `examples/` directory
2. Follow the existing example structure
3. Add documentation to this README
4. Test thoroughly with different configurations
5. Submit a pull request

## License

These examples are part of the zssh project and follow the same license terms.