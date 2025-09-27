//! Error Recovery and Connection Resilience
//!
//! Implements automatic retry logic, exponential backoff, circuit breaker
//! pattern, and connection recovery strategies for robust SSH operations.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const RecoveryError = error{
    MaxRetriesExceeded,
    CircuitBreakerOpen,
    BackoffTimedOut,
    RecoveryAborted,
} || Allocator.Error;

pub const RetryPolicy = struct {
    max_attempts: u32 = 3,
    initial_delay_ms: u32 = 1000,
    max_delay_ms: u32 = 30000,
    backoff_multiplier: f64 = 2.0,
    jitter_ms: u32 = 100,

    const Self = @This();

    pub fn getDelay(self: *const Self, attempt: u32) u32 {
        if (attempt == 0) return 0;

        const base_delay = self.initial_delay_ms * std.math.pow(f64, self.backoff_multiplier, @floatFromInt(attempt - 1));
        const clamped_delay = @min(base_delay, @floatFromInt(self.max_delay_ms));

        // Add jitter to prevent thundering herd
        const jitter = std.crypto.random.intRangeLessThan(u32, 0, self.jitter_ms);
        return @intFromFloat(clamped_delay) + jitter;
    }
};

pub const CircuitBreakerState = enum {
    closed,    // Normal operation
    open,      // Failing, rejecting requests
    half_open, // Testing if service recovered
};

pub const CircuitBreaker = struct {
    state: CircuitBreakerState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: i64,
    failure_threshold: u32,
    recovery_timeout_ms: u32,
    success_threshold: u32, // For half-open -> closed transition

    const Self = @This();

    pub fn init(failure_threshold: u32, recovery_timeout_ms: u32, success_threshold: u32) Self {
        return Self{
            .state = .closed,
            .failure_count = 0,
            .success_count = 0,
            .last_failure_time = 0,
            .failure_threshold = failure_threshold,
            .recovery_timeout_ms = recovery_timeout_ms,
            .success_threshold = success_threshold,
        };
    }

    pub fn canExecute(self: *Self) bool {
        const now = std.time.milliTimestamp();

        switch (self.state) {
            .closed => return true,
            .open => {
                if (now - self.last_failure_time >= self.recovery_timeout_ms) {
                    self.state = .half_open;
                    self.success_count = 0;
                    return true;
                }
                return false;
            },
            .half_open => return true,
        }
    }

    pub fn recordSuccess(self: *Self) void {
        self.failure_count = 0;

        switch (self.state) {
            .closed => {}, // Stay closed
            .open => {}, // Should not happen
            .half_open => {
                self.success_count += 1;
                if (self.success_count >= self.success_threshold) {
                    self.state = .closed;
                }
            },
        }
    }

    pub fn recordFailure(self: *Self) void {
        self.failure_count += 1;
        self.last_failure_time = std.time.milliTimestamp();

        switch (self.state) {
            .closed => {
                if (self.failure_count >= self.failure_threshold) {
                    self.state = .open;
                }
            },
            .open => {}, // Stay open
            .half_open => {
                self.state = .open; // Back to open on any failure
            },
        }
    }

    pub fn getState(self: *const Self) CircuitBreakerState {
        return self.state;
    }

    pub fn reset(self: *Self) void {
        self.state = .closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.last_failure_time = 0;
    }
};

pub const RecoveryContext = struct {
    retry_policy: RetryPolicy,
    circuit_breaker: CircuitBreaker,
    operation_timeout_ms: u32,

    const Self = @This();

    pub fn init(retry_policy: RetryPolicy, circuit_breaker: CircuitBreaker, operation_timeout_ms: u32) Self {
        return Self{
            .retry_policy = retry_policy,
            .circuit_breaker = circuit_breaker,
            .operation_timeout_ms = operation_timeout_ms,
        };
    }

    pub fn executeWithRetry(
        self: *Self,
        comptime T: type,
        operation: fn() anyerror!T,
    ) !T {
        var attempt: u32 = 0;
        const start_time = std.time.milliTimestamp();

        while (attempt < self.retry_policy.max_attempts) {
            // Check circuit breaker
            if (!self.circuit_breaker.canExecute()) {
                return RecoveryError.CircuitBreakerOpen;
            }

            // Check overall timeout
            const elapsed = std.time.milliTimestamp() - start_time;
            if (elapsed >= self.operation_timeout_ms) {
                return RecoveryError.BackoffTimedOut;
            }

            // Wait for backoff if not first attempt
            if (attempt > 0) {
                const delay = self.retry_policy.getDelay(attempt);
                std.time.sleep(delay * std.time.ns_per_ms);
            }

            // Execute operation
            if (operation()) |result| {
                self.circuit_breaker.recordSuccess();
                return result;
            } else |err| {
                self.circuit_breaker.recordFailure();

                // Check if we should retry this error
                if (!self.shouldRetry(err)) {
                    return err;
                }

                attempt += 1;
            }
        }

        return RecoveryError.MaxRetriesExceeded;
    }

    fn shouldRetry(self: *const Self, err: anyerror) bool {
        _ = self;

        // Define which errors are retryable
        return switch (err) {
            error.ConnectionRefused,
            error.NetworkUnreachable,
            error.ConnectionTimedOut,
            error.BrokenPipe,
            error.ConnectionResetByPeer,
            => true,

            // Non-retryable errors
            error.AccessDenied,
            error.AuthenticationFailed,
            error.InvalidCredentials,
            => false,

            else => false, // Conservative: don't retry unknown errors
        };
    }
};

/// Connection recovery manager
pub const ConnectionRecovery = struct {
    allocator: Allocator,
    recovery_context: RecoveryContext,
    health_check_interval_ms: u32,
    last_health_check: i64,

    const Self = @This();

    pub fn init(allocator: Allocator, recovery_context: RecoveryContext, health_check_interval_ms: u32) Self {
        return Self{
            .allocator = allocator,
            .recovery_context = recovery_context,
            .health_check_interval_ms = health_check_interval_ms,
            .last_health_check = std.time.milliTimestamp(),
        };
    }

    pub fn recoverConnection(self: *Self, reconnect_fn: fn() anyerror!void) !void {
        return self.recovery_context.executeWithRetry(void, reconnect_fn);
    }

    pub fn needsHealthCheck(self: *const Self) bool {
        const now = std.time.milliTimestamp();
        return (now - self.last_health_check) >= self.health_check_interval_ms;
    }

    pub fn performHealthCheck(self: *Self, health_check_fn: fn() anyerror!void) !void {
        self.last_health_check = std.time.milliTimestamp();

        if (health_check_fn()) |_| {
            self.recovery_context.circuit_breaker.recordSuccess();
        } else |err| {
            self.recovery_context.circuit_breaker.recordFailure();
            return err;
        }
    }

    pub fn isHealthy(self: *const Self) bool {
        return self.recovery_context.circuit_breaker.getState() != .open;
    }

    pub fn reset(self: *Self) void {
        self.recovery_context.circuit_breaker.reset();
    }
};

/// Utility function for retrying operations with default policies
pub fn retryOperation(
    comptime T: type,
    operation: fn() anyerror!T,
    max_attempts: u32,
) !T {
    const retry_policy = RetryPolicy{ .max_attempts = max_attempts };
    const circuit_breaker = CircuitBreaker.init(5, 30000, 2);
    var recovery_context = RecoveryContext.init(retry_policy, circuit_breaker, 120000);

    return recovery_context.executeWithRetry(T, operation);
}

test "RetryPolicy delay calculation" {
    const policy = RetryPolicy{
        .initial_delay_ms = 1000,
        .backoff_multiplier = 2.0,
        .max_delay_ms = 10000,
        .jitter_ms = 0, // No jitter for predictable testing
    };

    try std.testing.expectEqual(@as(u32, 0), policy.getDelay(0));
    try std.testing.expectEqual(@as(u32, 1000), policy.getDelay(1));
    try std.testing.expectEqual(@as(u32, 2000), policy.getDelay(2));
    try std.testing.expectEqual(@as(u32, 4000), policy.getDelay(3));
    try std.testing.expectEqual(@as(u32, 8000), policy.getDelay(4));
    try std.testing.expectEqual(@as(u32, 10000), policy.getDelay(5)); // Clamped to max
}

test "CircuitBreaker state transitions" {
    var cb = CircuitBreaker.init(3, 5000, 2);

    // Initially closed
    try std.testing.expect(cb.canExecute());
    try std.testing.expectEqual(CircuitBreakerState.closed, cb.getState());

    // Record failures to open circuit
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(CircuitBreakerState.open, cb.getState());
    try std.testing.expect(!cb.canExecute());

    // Wait and transition to half-open
    std.time.sleep(6 * std.time.ns_per_ms); // Simulate time passing
    cb.last_failure_time = std.time.milliTimestamp() - 6000; // Manually set for test
    try std.testing.expect(cb.canExecute());

    // Success in half-open should eventually close
    cb.recordSuccess();
    cb.recordSuccess();
    try std.testing.expectEqual(CircuitBreakerState.closed, cb.getState());
}

test "RecoveryContext retry logic" {
    const TestError = error{TemporaryFailure};

    var call_count: u32 = 0;
    const failing_operation = struct {
        fn call(count: *u32) anyerror!u32 {
            count.* += 1;
            if (count.* < 3) {
                return TestError.TemporaryFailure;
            }
            return 42;
        }
    }.call;

    const retry_policy = RetryPolicy{ .max_attempts = 5, .initial_delay_ms = 1 };
    const circuit_breaker = CircuitBreaker.init(10, 1000, 1);
    var recovery_context = RecoveryContext.init(retry_policy, circuit_breaker, 10000);

    const result = try recovery_context.executeWithRetry(u32, struct {
        fn op() anyerror!u32 {
            return failing_operation(&call_count);
        }
    }.op);

    try std.testing.expectEqual(@as(u32, 42), result);
    try std.testing.expectEqual(@as(u32, 3), call_count);
}