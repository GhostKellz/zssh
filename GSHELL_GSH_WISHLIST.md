# 🔐 zssh Wishlist for GShell Integration

<div align="center">
  <strong>What GShell needs from zssh for native SSH support</strong>
</div>

---

## 📋 Current Status

⏳ **Experimental Library:**
- SSH 2.0 protocol architecture designed
- Async support with zsync planned
- Strong crypto with zcrypto planned
- Multiple auth methods planned (password, pubkey, OIDC)
- Tunneling and port forwarding planned

❌ **Not Yet Implemented:**
- Core SSH 2.0 transport
- Terminal session support (PTY, channels)
- Authentication backends
- SFTP subsystem
- QUIC multiplexing

---

## 🎯 What GShell Needs

### **P0: Critical Path** (Needed for GShell v0.3.0 - 4-8 weeks)

#### 1. **Easy SSH Client API** (`easy_client.zig`)

GShell needs a simple, synchronous API for SSH connections:

```zig
const zssh = @import("zssh");

// Simple connection
pub fn connect(allocator: std.mem.Allocator, options: ConnectOptions) !SshSession {
    // Connect to SSH server
    // Authenticate
    // Return session handle
}

pub const ConnectOptions = struct {
    host: []const u8,
    port: u16 = 22,
    user: []const u8,
    auth: AuthMethod,
    timeout_ms: u64 = 10_000,
};

pub const AuthMethod = union(enum) {
    password: []const u8,
    public_key: struct {
        private_key_path: []const u8,
        passphrase: ?[]const u8 = null,
    },
    agent: void,  // Use SSH agent (from GVault)
};

pub const SshSession = struct {
    pub fn exec(self: *SshSession, command: []const u8) !ExecResult;
    pub fn interactive(self: *SshSession) !void;
    pub fn close(self: *SshSession) void;
};

pub const ExecResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    exit_code: i32,
};
```

**Use Case:**
```zig
// In GShell's SSH builtin (src/builtins/ssh.zig)
const zssh = @import("zssh");
const gvault = @import("gvault");

pub fn sshBuiltin(allocator: std.mem.Allocator, args: []const []const u8) !i32 {
    const hostname = args[1];  // ssh prod-db

    // Get credential from GVault
    const cred = try gvault.getCredentialForHost(allocator, hostname);

    // Connect using zssh
    var session = try zssh.connect(allocator, .{
        .host = cred.hostname,
        .user = cred.username,
        .auth = .{ .public_key = .{
            .private_key_path = cred.private_key_path,
            .passphrase = null,
        }},
    });
    defer session.close();

    // Start interactive shell
    try session.interactive();

    return 0;
}
```

**Command Line:**
```bash
$ ssh prod-db
# GShell:
#   1. Looks up 'prod-db' in GVault
#   2. Gets SSH key and hostname
#   3. Uses zssh to connect
#   4. Starts interactive session
# User sees:
#   Connecting to prod-db.example.com...
#   Last login: Mon Oct 11 12:34:56 2025 from 192.168.1.100
#   user@prod-db:~$
```

#### 2. **Non-interactive Command Execution**

Run commands on remote servers without interactive shell:

```zig
pub fn execRemote(
    allocator: std.mem.Allocator,
    session: *SshSession,
    command: []const u8,
) !ExecResult {
    // Execute command
    // Capture stdout/stderr
    // Wait for completion
    // Return result with exit code
}
```

**Use Case:**
```bash
$ ssh prod-db "df -h"
# GShell connects, runs command, shows output, disconnects
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   45G   50G  48% /

$ ssh prod-db "systemctl status nginx" | grep Active
Active: active (running) since Mon 2025-10-11 12:00:00 UTC; 2h 34min ago
```

#### 3. **Connection Pooling and Reuse**

GShell should reuse connections for multiple commands:

```zig
pub const SshConnectionPool = struct {
    pub fn init(allocator: std.mem.Allocator) !SshConnectionPool;
    pub fn deinit(self: *SshConnectionPool) void;

    pub fn getOrConnect(
        self: *SshConnectionPool,
        options: ConnectOptions,
    ) !*SshSession;

    pub fn closeAll(self: *SshConnectionPool) void;
};
```

**Use Case:**
```bash
$ ssh prod-db "uptime"
# First connection: ~500ms (establish connection)
 12:34:56 up 45 days, 3:21, 1 user, load average: 0.15, 0.20, 0.18

$ ssh prod-db "df -h"
# Reuses connection: ~50ms (no reconnect)
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   45G   50G  48% /

$ ssh prod-db "free -h"
# Reuses connection: ~50ms
              total        used        free
Mem:           32G         12G         20G
```

---

### **P1: Important** (Needed for GShell v0.4.0 - 8-12 weeks)

#### 4. **Connection Health Monitoring**

Detect and recover from broken connections:

```zig
pub fn checkConnection(session: *SshSession) bool {
    // Send keepalive packet
    // Return true if connection is alive
}

pub fn reconnect(session: *SshSession) !void {
    // Reconnect using same credentials
}
```

**Use Case:**
```bash
$ ssh prod-db "sleep 10 && echo done"
# Network glitch during command...
⚠️  Connection lost, reconnecting...
✅ Reconnected, resuming command...
done

$ ssh prod-db "echo test"
# Connection already broken, auto-reconnect
⚠️  Connection timeout, reconnecting...
✅ Connected
test
```

#### 5. **Jump Host / Bastion Support**

Connect through intermediate servers:

```zig
pub const JumpHost = struct {
    host: []const u8,
    user: []const u8,
    auth: AuthMethod,
};

pub const ConnectOptions = struct {
    // ... existing fields ...
    jump_hosts: []const JumpHost = &[_]JumpHost{},
};

pub fn connectViaJump(
    allocator: std.mem.Allocator,
    target: ConnectOptions,
    jumps: []const JumpHost,
) !SshSession {
    // Connect: local -> jump1 -> jump2 -> target
}
```

**Use Case:**
```bash
$ ssh prod-db  # prod-db requires bastion
# GVault knows: prod-db -> bastion.example.com -> prod-db.internal
# zssh automatically:
#   1. Connect to bastion.example.com
#   2. From bastion, connect to prod-db.internal
#   3. Start interactive session on prod-db.internal

Connecting via bastion.example.com...
✅ Connected to prod-db.internal
user@prod-db:~$
```

#### 6. **Port Forwarding**

Local and remote port forwarding:

```zig
pub fn forwardLocal(
    session: *SshSession,
    local_port: u16,
    remote_host: []const u8,
    remote_port: u16,
) !PortForward {
    // Forward local_port to remote_host:remote_port via SSH
}

pub fn forwardRemote(
    session: *SshSession,
    remote_port: u16,
    local_host: []const u8,
    local_port: u16,
) !PortForward {
    // Forward remote_port to local_host:local_port via SSH
}

pub const PortForward = struct {
    pub fn close(self: *PortForward) void;
};
```

**Use Case:**
```bash
$ ssh -L 8080:localhost:80 prod-db
# Forward local port 8080 to prod-db:80
✅ Port forward: localhost:8080 -> prod-db:80
# Now browse to http://localhost:8080

$ ssh -R 9000:localhost:3000 prod-db
# Forward prod-db:9000 to local:3000
✅ Reverse port forward: prod-db:9000 -> localhost:3000
# prod-db can now access localhost:3000 via :9000
```

#### 7. **SFTP / SCP Support**

File transfer commands:

```zig
pub const SftpSession = struct {
    pub fn init(ssh_session: *SshSession) !SftpSession;
    pub fn deinit(self: *SftpSession) void;

    pub fn upload(
        self: *SftpSession,
        local_path: []const u8,
        remote_path: []const u8,
    ) !void;

    pub fn download(
        self: *SftpSession,
        remote_path: []const u8,
        local_path: []const u8,
    ) !void;

    pub fn list(
        self: *SftpSession,
        remote_dir: []const u8,
    ) ![]FileInfo;
};
```

**Use Case:**
```bash
$ scp file.txt prod-db:/tmp/
Uploading file.txt to prod-db:/tmp/...
100% [====================] 1.2MB/s
✅ Uploaded 1.2MB in 2.3s

$ scp prod-db:/var/log/app.log ./
Downloading prod-db:/var/log/app.log...
100% [====================] 3.4MB/s
✅ Downloaded 10.5MB in 3.1s

$ sftp prod-db
Connected to prod-db
sftp> ls /tmp
file1.txt
file2.txt
sftp> get /tmp/file1.txt
✅ Downloaded file1.txt
```

---

### **P2: Nice to Have** (Needed for GShell v0.5.0+ - 12+ weeks)

#### 8. **Multiplexing (ControlMaster)**

Share connections between multiple shell sessions:

```zig
pub const MultiplexOptions = struct {
    socket_path: []const u8,  // Control socket path
    persist_minutes: u32 = 10,  // Keep connection open
};

pub fn enableMultiplexing(
    session: *SshSession,
    options: MultiplexOptions,
) !void {
    // Enable connection sharing
}
```

**Use Case:**
```bash
# Terminal 1
$ ssh prod-db
# Connection established (500ms)
user@prod-db:~$

# Terminal 2 (different GShell instance)
$ ssh prod-db "uptime"
# Reuses existing connection (50ms, no auth!)
 12:34:56 up 45 days, 3:21, 2 users, load average: 0.15
```

#### 9. **Connection Profiling**

Track connection performance:

```zig
pub const ConnectionStats = struct {
    connect_time_ms: u64,
    auth_time_ms: u64,
    bytes_sent: u64,
    bytes_received: u64,
    round_trip_time_ms: u64,
};

pub fn getStats(session: *SshSession) ConnectionStats {
    // Return connection statistics
}
```

**Use Case:**
```bash
$ ssh prod-db --profile
Connecting to prod-db.example.com...
  DNS lookup:     23ms
  TCP connect:    45ms
  SSH handshake:  120ms
  Auth:           67ms
  Total:          255ms
✅ Connected

$ ssh --stats
Active Connections:
  prod-db.example.com:22
    Uptime: 2h 34m
    Data sent: 1.2MB
    Data received: 4.5MB
    RTT: 23ms
```

#### 10. **Async Connection API**

For advanced use cases (multiplexing, concurrent connections):

```zig
pub fn connectAsync(
    allocator: std.mem.Allocator,
    options: ConnectOptions,
) !zsync.Task(*SshSession) {
    // Return async task that connects
}

pub fn execAsync(
    session: *SshSession,
    command: []const u8,
) !zsync.Task(ExecResult) {
    // Execute command asynchronously
}
```

**Use Case:**
```bash
# Connect to multiple servers concurrently
$ ssh prod-db-01 prod-db-02 prod-db-03 "uptime"
Connecting to 3 servers...
✅ prod-db-01 (234ms):  12:34:56 up 45 days
✅ prod-db-02 (198ms):  12:34:56 up 32 days
✅ prod-db-03 (267ms):  12:34:56 up 21 days
```

---

### **P3: Future Vision** (Nice to have, no timeline)

#### 11. **QUIC Multiplexing**

Use QUIC for faster, more reliable connections:

```zig
pub const QuicOptions = struct {
    enable_quic: bool = false,
    fallback_to_tcp: bool = true,
};
```

#### 12. **Session Recording**

Record SSH sessions for auditing:

```zig
pub fn recordSession(
    session: *SshSession,
    output_path: []const u8,
) !void {
    // Record session to file
}
```

---

## 🔧 API Design Preferences

### **What GShell Prefers:**

1. **Synchronous by Default**: Async is great, but GShell needs simple sync API
2. **Zero-allocation Hot Paths**: Reuse buffers where possible
3. **Clear Error Types**: SSH-specific errors (auth failed, timeout, etc.)
4. **Integration with GVault**: Accept SSH keys from GVault's key manager
5. **Minimal Dependencies**: Only zcrypto, zsync, no extra deps

### **Example Perfect API:**

```zig
// Simple, synchronous, allocator-based
var session = try zssh.connect(allocator, .{
    .host = "prod-db.example.com",
    .user = "chris",
    .auth = .{ .agent = {} },  // Use SSH agent (GVault)
});
defer session.close();

// Execute command
const result = try session.exec("uptime");
defer allocator.free(result.stdout);
std.debug.print("{s}", .{result.stdout});
```

---

## 📊 Integration Success Metrics

When zssh integration is complete, GShell users should be able to:

- ✅ `ssh prod-db` connects with auto-loaded credentials
- ✅ `ssh prod-db "command"` executes remote command
- ✅ Connection reuse for multiple commands (fast!)
- ✅ `ssh -L 8080:localhost:80 prod-db` port forwarding works
- ✅ `ssh bastion-host -> prod-db` jump hosts work transparently
- ✅ `scp file.txt prod-db:/tmp/` file transfers work
- ✅ <100ms for reused connections
- ✅ <500ms for new connections
- ✅ Auto-reconnect on connection loss

---

## 🤝 Collaboration

GShell is happy to:
- Test zssh features as they're built
- Provide real-world SSH use cases and feedback
- Contribute PRs for shell-specific APIs
- Write integration tests

zssh can prioritize:
- P0: Basic client + command execution (next 4-8 weeks)
- P1: Jump hosts + port forwarding (8-12 weeks)
- P2: Advanced features (12+ weeks)

**Let's build the best native SSH experience for a modern shell!** 🚀

---

## 📞 Contact

For questions or coordination:
- Open an issue in GShell repo: [ghostkellz/gshell](https://github.com/ghostkellz/gshell)
- Reference this wishlist in zssh issues/PRs
- Coordinate timelines in DRAFT_DISCOVERY.md

**Thank you for building zssh!** 🔐
