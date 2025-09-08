## zssh (Zig SSH 2.0)

### Phase 1 – Transport
- [ ] Implement SSH 2.0 transport layer
- [ ] Key exchange (Diffie-Hellman, Ed25519, Curve25519)
- [ ] Encryption and MAC (AES, ChaCha20, Poly1305 via `zcrypto`)
- [ ] Async event loop integration (`zsync`)

### Phase 2 – Authentication
- [ ] Password-based authentication
- [ ] Public key authentication
- [ ] Integration with `zauth` for OIDC/SSO logins
- [ ] Configurable auth backends

### Phase 3 – Subsystems
- [ ] Terminal/PTY sessions
- [ ] Port forwarding / tunneling
- [ ] SFTP subsystem
- [ ] Multiplexed channels over QUIC (`zquic`)

### Phase 4 – Extras
- [ ] Client utility API (`zssh.Client`)
- [ ] Server daemon API (`zssh.Server`)
- [ ] Example CLI tools (zssh client & server)
- [ ] Benchmarks and interoperability tests

---

## Shared Tasks
- [ ] Unified documentation style across all GhostStack libraries
- [ ] Integration tests with other zig projects - zcrypto etc. 
