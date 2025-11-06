//! SSH Connection Pool for High-Performance Client Operations
//!
//! Manages a pool of SSH connections for efficient connection reuse,
//! automatic reconnection, and load balancing across multiple servers.

const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;
const Client = @import("client.zig").Client;

pub const PoolError = error{
    NoAvailableConnections,
    ConnectionFailed,
    PoolExhausted,
    InvalidConfiguration,
} || Allocator.Error;

pub const ConnectionState = enum {
    idle,
    active,
    connecting,
    failed,
    disconnected,
};

pub const PooledConnection = struct {
    client: Client,
    state: ConnectionState,
    last_used: i64,
    error_count: u32,
    connection_id: u32,

    const Self = @This();

    pub fn init(allocator: Allocator, config: Client.ClientConfig, connection_id: u32) !Self {
        return Self{
            .client = try Client.init(allocator, config),
            .state = .idle,
            .last_used = std.time.milliTimestamp(),
            .error_count = 0,
            .connection_id = connection_id,
        };
    }

    pub fn deinit(self: *Self) void {
        self.client.deinit();
    }

    pub fn isHealthy(self: *const Self) bool {
        return self.state != .failed and self.error_count < 3;
    }

    pub fn markUsed(self: *Self) void {
        self.last_used = std.time.milliTimestamp();
        self.state = .active;
    }

    pub fn markIdle(self: *Self) void {
        self.state = .idle;
    }

    pub fn markFailed(self: *Self) void {
        self.state = .failed;
        self.error_count += 1;
    }

    pub fn reset(self: *Self) void {
        self.error_count = 0;
        self.state = .idle;
    }
};

pub const PoolConfig = struct {
    min_connections: u32 = 1,
    max_connections: u32 = 10,
    connection_timeout_ms: u32 = 30000,
    idle_timeout_ms: u32 = 300000, // 5 minutes
    max_retries: u32 = 3,
    health_check_interval_ms: u32 = 60000, // 1 minute
};

pub const ConnectionPool = struct {
    allocator: Allocator,
    config: PoolConfig,
    client_config: Client.ClientConfig,
    connections: std.ArrayList(PooledConnection),
    next_connection_id: u32,
    last_health_check: i64,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: Allocator, client_config: Client.ClientConfig, pool_config: PoolConfig) !Self {
        if (pool_config.min_connections > pool_config.max_connections) {
            return PoolError.InvalidConfiguration;
        }

        var pool = Self{
            .allocator = allocator,
            .config = pool_config,
            .client_config = client_config,
            .connections = std.ArrayList(PooledConnection).init(allocator),
            .next_connection_id = 1,
            .last_health_check = std.time.milliTimestamp(),
            .mutex = std.Thread.Mutex{},
        };

        // Create minimum connections
        var i: u32 = 0;
        while (i < pool_config.min_connections) : (i += 1) {
            _ = try pool.createConnection();
        }

        return pool;
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |*conn| {
            conn.deinit();
        }
        self.connections.deinit();
    }

    pub fn acquire(self: *Self) !*PooledConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // First, try to find an idle healthy connection
        for (self.connections.items) |*conn| {
            if (conn.state == .idle and conn.isHealthy()) {
                conn.markUsed();
                return conn;
            }
        }

        // If no idle connection, try to create a new one
        if (self.connections.items.len < self.config.max_connections) {
            const conn = try self.createConnection();
            conn.markUsed();
            return conn;
        }

        // Pool is at capacity and no idle connections available
        return PoolError.NoAvailableConnections;
    }

    pub fn release(self: *Self, connection: *PooledConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        connection.markIdle();
    }

    pub fn healthCheck(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        if (now - self.last_health_check < self.config.health_check_interval_ms) {
            return; // Not time for health check yet
        }

        self.last_health_check = now;

        // Check for idle timeouts and failed connections
        var i: usize = 0;
        while (i < self.connections.items.len) {
            const conn = &self.connections.items[i];

            // Remove timed-out idle connections (but keep minimum)
            if (conn.state == .idle and
                self.connections.items.len > self.config.min_connections and
                now - conn.last_used > self.config.idle_timeout_ms) {

                var removed = self.connections.swapRemove(i);
                removed.deinit();
                continue;
            }

            // Try to recover failed connections
            if (conn.state == .failed) {
                // Attempt to reconnect
                conn.client.disconnect();
                if (conn.client.connect()) {
                    conn.reset();
                } else |_| {
                    // Still failed, check if we should remove it
                    if (conn.error_count >= self.config.max_retries and
                        self.connections.items.len > self.config.min_connections) {

                        var removed = self.connections.swapRemove(i);
                        removed.deinit();
                        continue;
                    }
                }
            }

            i += 1;
        }

        // Ensure we have minimum connections
        while (self.connections.items.len < self.config.min_connections) {
            _ = self.createConnection() catch break;
        }
    }

    pub fn getStats(self: *Self) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var stats = PoolStats{
            .total_connections = self.connections.items.len,
            .idle_connections = 0,
            .active_connections = 0,
            .failed_connections = 0,
        };

        for (self.connections.items) |*conn| {
            switch (conn.state) {
                .idle => stats.idle_connections += 1,
                .active => stats.active_connections += 1,
                .failed => stats.failed_connections += 1,
                else => {},
            }
        }

        return stats;
    }

    fn createConnection(self: *Self) !*PooledConnection {
        var pooled_conn = try PooledConnection.init(
            self.allocator,
            self.client_config,
            self.next_connection_id
        );
        self.next_connection_id += 1;

        // Attempt to connect
        pooled_conn.client.connect() catch |err| {
            pooled_conn.deinit();
            return err;
        };

        try self.connections.append(pooled_conn);
        return &self.connections.items[self.connections.items.len - 1];
    }
};

pub const PoolStats = struct {
    total_connections: usize,
    idle_connections: usize,
    active_connections: usize,
    failed_connections: usize,
};

/// RAII wrapper for pool connections
pub const PooledClient = struct {
    pool: *ConnectionPool,
    connection: *PooledConnection,

    const Self = @This();

    pub fn init(pool: *ConnectionPool) !Self {
        const connection = try pool.acquire();
        return Self{
            .pool = pool,
            .connection = connection,
        };
    }

    pub fn deinit(self: Self) void {
        self.pool.release(self.connection);
    }

    pub fn client(self: *const Self) *Client {
        return &self.connection.client;
    }
};

test "ConnectionPool creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const client_config = Client.ClientConfig{
        .username = "test",
        .host = "localhost",
        .port = 22,
    };

    const pool_config = PoolConfig{
        .min_connections = 1,
        .max_connections = 3,
    };

    var pool = try ConnectionPool.init(allocator, client_config, pool_config);
    defer pool.deinit();

    // Test stats
    const initial_stats = pool.getStats();
    try testing.expectEqual(@as(usize, 1), initial_stats.total_connections);
    try testing.expectEqual(@as(usize, 1), initial_stats.idle_connections);

    // Test acquire/release
    const conn1 = try pool.acquire();
    const stats_after_acquire = pool.getStats();
    try testing.expectEqual(@as(usize, 1), stats_after_acquire.active_connections);
    try testing.expectEqual(@as(usize, 0), stats_after_acquire.idle_connections);

    pool.release(conn1);
    const stats_after_release = pool.getStats();
    try testing.expectEqual(@as(usize, 0), stats_after_release.active_connections);
    try testing.expectEqual(@as(usize, 1), stats_after_release.idle_connections);
}

test "PooledClient RAII pattern" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const client_config = Client.ClientConfig{
        .username = "test",
        .host = "localhost",
        .port = 22,
    };

    const pool_config = PoolConfig{
        .min_connections = 1,
        .max_connections = 2,
    };

    var pool = try ConnectionPool.init(allocator, client_config, pool_config);
    defer pool.deinit();

    {
        const pooled_client = try PooledClient.init(&pool);
        defer pooled_client.deinit();

        const stats = pool.getStats();
        try testing.expectEqual(@as(usize, 1), stats.active_connections);
    }

    // Connection should be released automatically
    const final_stats = pool.getStats();
    try testing.expectEqual(@as(usize, 1), final_stats.idle_connections);
    try testing.expectEqual(@as(usize, 0), final_stats.active_connections);
}