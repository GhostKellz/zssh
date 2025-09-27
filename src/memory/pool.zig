//! Memory Pool Allocator for High-Performance SSH Operations
//!
//! Provides specialized memory management for SSH packet handling,
//! crypto operations, and buffer management to reduce allocation overhead.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const PoolError = error{
    PoolExhausted,
    InvalidBlockSize,
    NotFromPool,
} || Allocator.Error;

/// Fixed-size memory pool for objects of a specific size
pub fn FixedPool(comptime T: type) type {
    return struct {
        const Self = @This();

        const Block = struct {
            data: T,
            next: ?*Block,
        };

        backing_allocator: Allocator,
        blocks: []Block,
        free_list: ?*Block,
        total_blocks: usize,
        free_blocks: usize,

        pub fn init(backing_allocator: Allocator, capacity: usize) !Self {
            const blocks = try backing_allocator.alloc(Block, capacity);

            // Initialize free list
            for (blocks, 0..) |*block, i| {
                block.next = if (i + 1 < blocks.len) &blocks[i + 1] else null;
            }

            return Self{
                .backing_allocator = backing_allocator,
                .blocks = blocks,
                .free_list = if (blocks.len > 0) &blocks[0] else null,
                .total_blocks = capacity,
                .free_blocks = capacity,
            };
        }

        pub fn deinit(self: *Self) void {
            self.backing_allocator.free(self.blocks);
        }

        pub fn acquire(self: *Self) ?*T {
            if (self.free_list) |block| {
                self.free_list = block.next;
                self.free_blocks -= 1;
                return &block.data;
            }
            return null;
        }

        pub fn release(self: *Self, obj: *T) void {
            // Find the block containing this object
            const block_ptr = @fieldParentPtr(Block, "data", obj);

            // Add back to free list
            block_ptr.next = self.free_list;
            self.free_list = block_ptr;
            self.free_blocks += 1;
        }

        pub fn getFreeCount(self: *const Self) usize {
            return self.free_blocks;
        }

        pub fn getUsedCount(self: *const Self) usize {
            return self.total_blocks - self.free_blocks;
        }

        pub fn isFromPool(self: *const Self, obj: *T) bool {
            const obj_addr = @intFromPtr(obj);
            const pool_start = @intFromPtr(self.blocks.ptr);
            const pool_end = pool_start + self.blocks.len * @sizeOf(Block);
            return obj_addr >= pool_start and obj_addr < pool_end;
        }
    };
}

/// Buffer pool for SSH packet buffers
pub const BufferPool = struct {
    const SMALL_BUFFER_SIZE = 1024;
    const MEDIUM_BUFFER_SIZE = 4096;
    const LARGE_BUFFER_SIZE = 16384;

    const SmallBuffer = [SMALL_BUFFER_SIZE]u8;
    const MediumBuffer = [MEDIUM_BUFFER_SIZE]u8;
    const LargeBuffer = [LARGE_BUFFER_SIZE]u8;

    small_pool: FixedPool(SmallBuffer),
    medium_pool: FixedPool(MediumBuffer),
    large_pool: FixedPool(LargeBuffer),

    const Self = @This();

    pub fn init(allocator: Allocator, small_count: usize, medium_count: usize, large_count: usize) !Self {
        return Self{
            .small_pool = try FixedPool(SmallBuffer).init(allocator, small_count),
            .medium_pool = try FixedPool(MediumBuffer).init(allocator, medium_count),
            .large_pool = try FixedPool(LargeBuffer).init(allocator, large_count),
        };
    }

    pub fn deinit(self: *Self) void {
        self.small_pool.deinit();
        self.medium_pool.deinit();
        self.large_pool.deinit();
    }

    pub fn acquireBuffer(self: *Self, size: usize) ?[]u8 {
        if (size <= SMALL_BUFFER_SIZE) {
            if (self.small_pool.acquire()) |buffer| {
                return buffer[0..size];
            }
        } else if (size <= MEDIUM_BUFFER_SIZE) {
            if (self.medium_pool.acquire()) |buffer| {
                return buffer[0..size];
            }
        } else if (size <= LARGE_BUFFER_SIZE) {
            if (self.large_pool.acquire()) |buffer| {
                return buffer[0..size];
            }
        }
        return null;
    }

    pub fn releaseBuffer(self: *Self, buffer: []u8) void {
        const ptr = buffer.ptr;

        if (self.small_pool.isFromPool(@ptrCast(ptr))) {
            self.small_pool.release(@ptrCast(ptr));
        } else if (self.medium_pool.isFromPool(@ptrCast(ptr))) {
            self.medium_pool.release(@ptrCast(ptr));
        } else if (self.large_pool.isFromPool(@ptrCast(ptr))) {
            self.large_pool.release(@ptrCast(ptr));
        }
    }

    pub fn getStats(self: *const Self) BufferStats {
        return BufferStats{
            .small_free = self.small_pool.getFreeCount(),
            .small_used = self.small_pool.getUsedCount(),
            .medium_free = self.medium_pool.getFreeCount(),
            .medium_used = self.medium_pool.getUsedCount(),
            .large_free = self.large_pool.getFreeCount(),
            .large_used = self.large_pool.getUsedCount(),
        };
    }
};

pub const BufferStats = struct {
    small_free: usize,
    small_used: usize,
    medium_free: usize,
    medium_used: usize,
    large_free: usize,
    large_used: usize,
};

/// Pool-aware allocator that falls back to backing allocator
pub const PoolAllocator = struct {
    backing_allocator: Allocator,
    buffer_pool: *BufferPool,

    const Self = @This();

    pub fn init(backing_allocator: Allocator, buffer_pool: *BufferPool) Self {
        return Self{
            .backing_allocator = backing_allocator,
            .buffer_pool = buffer_pool,
        };
    }

    pub fn allocator(self: *Self) Allocator {
        return Allocator{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, log2_ptr_align: u8, ret_addr: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));
        _ = log2_ptr_align;
        _ = ret_addr;

        // Try pool first for common buffer sizes
        if (self.buffer_pool.acquireBuffer(len)) |buffer| {
            return buffer.ptr;
        }

        // Fall back to backing allocator
        return self.backing_allocator.rawAlloc(len, log2_ptr_align, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, new_len: usize, ret_addr: usize) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        _ = log2_buf_align;
        _ = ret_addr;

        // Pool buffers can't be resized, fall back to backing allocator
        return self.backing_allocator.rawResize(buf, log2_buf_align, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, ret_addr: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        _ = log2_buf_align;
        _ = ret_addr;

        // Try to release back to pool
        self.buffer_pool.releaseBuffer(buf);

        // If not from pool, it was allocated by backing allocator
        // The buffer pool will ignore buffers not from the pool
    }
};

test "FixedPool basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const TestStruct = struct { value: u32 };
    var pool = try FixedPool(TestStruct).init(allocator, 3);
    defer pool.deinit();

    // Test acquisition
    const obj1 = pool.acquire().?;
    const obj2 = pool.acquire().?;
    const obj3 = pool.acquire().?;
    const obj4 = pool.acquire();

    try testing.expect(obj4 == null); // Pool exhausted

    // Test release
    pool.release(obj2);
    const obj5 = pool.acquire().?;
    try testing.expect(obj5 == obj2); // Should reuse released object

    // Test statistics
    try testing.expectEqual(@as(usize, 2), pool.getUsedCount());
    try testing.expectEqual(@as(usize, 1), pool.getFreeCount());
}

test "BufferPool operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var buffer_pool = try BufferPool.init(allocator, 2, 2, 1);
    defer buffer_pool.deinit();

    // Test small buffer acquisition
    const small1 = buffer_pool.acquireBuffer(512).?;
    const small2 = buffer_pool.acquireBuffer(1024).?;
    const small3 = buffer_pool.acquireBuffer(256);
    try testing.expect(small3 == null); // Small pool exhausted

    // Test medium buffer acquisition
    const medium1 = buffer_pool.acquireBuffer(2048).?;
    try testing.expectEqual(@as(usize, 2048), medium1.len);

    // Test release and reuse
    buffer_pool.releaseBuffer(small1);
    const small4 = buffer_pool.acquireBuffer(512).?;
    try testing.expect(small4.ptr == small1.ptr);

    // Test stats
    const stats = buffer_pool.getStats();
    try testing.expectEqual(@as(usize, 1), stats.small_free);
    try testing.expectEqual(@as(usize, 1), stats.small_used);
    try testing.expectEqual(@as(usize, 1), stats.medium_free);
    try testing.expectEqual(@as(usize, 1), stats.medium_used);
}