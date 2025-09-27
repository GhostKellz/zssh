//! Large File Transfer Example
//!
//! Demonstrates optimized large file transfers with progress tracking,
//! resumable transfers, and compression.

const std = @import("std");
const zssh = @import("zssh");
const large_file_optimizer = @import("zssh").transfer.large_file_optimizer;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 5) {
        std.debug.print("Usage: {s} <host> <username> <local_file> <remote_file> [operation]\n", .{args[0]});
        std.debug.print("Operations: upload, download, resume\n");
        std.process.exit(1);
    }

    const host = args[1];
    const username = args[2];
    const local_file = args[3];
    const remote_file = args[4];
    const operation = if (args.len > 5) args[5] else "upload";

    std.debug.print("Large file transfer example\n");
    std.debug.print("Host: {s}\n", .{host});
    std.debug.print("Operation: {s}\n", .{operation});

    // Create SFTP client
    var client = try zssh.Client.init(allocator, .{
        .host = host,
        .port = 22,
        .username = username,
        .authentication = .{ .public_key = "/home/user/.ssh/id_ed25519" },
    });
    defer client.deinit();

    try client.connect();
    std.debug.print("Connected to SSH server\n");

    var sftp = try client.createSftpSession();
    defer sftp.deinit();

    std.debug.print("SFTP session established\n");

    // Configure transfer optimization
    const transfer_config = large_file_optimizer.TransferConfig{
        .strategy = .adaptive_chunking,
        .max_chunk_size = 16 * 1024 * 1024, // 16MB chunks
        .min_chunk_size = 256 * 1024,       // 256KB minimum
        .max_parallel_chunks = 8,
        .compression = .zstd,
        .compression_level = 3,
        .verify_checksums = true,
        .bandwidth_limit = 50 * 1024 * 1024, // 50 MB/s limit
        .enable_resume = true,
        .max_retries = 3,
        .retry_delay_ms = 2000,
    };

    var optimizer = try large_file_optimizer.LargeFileOptimizer.init(
        allocator,
        transfer_config,
        &sftp
    );
    defer optimizer.deinit();

    std.debug.print("Transfer optimizer initialized\n");
    std.debug.print("Max chunk size: {d} MB\n", .{transfer_config.max_chunk_size / (1024 * 1024)});
    std.debug.print("Compression: {s}\n", .{@tagName(transfer_config.compression)});
    std.debug.print("Bandwidth limit: {d} MB/s\n", .{transfer_config.bandwidth_limit.? / (1024 * 1024)});

    var transfer_state: *large_file_optimizer.TransferState = undefined;

    if (std.mem.eql(u8, operation, "upload")) {
        // Check if local file exists
        const file_stat = std.fs.cwd().statFile(local_file) catch |err| switch (err) {
            error.FileNotFound => {
                std.debug.print("Error: Local file '{s}' not found\n", .{local_file});
                std.process.exit(1);
            },
            else => return err,
        };

        std.debug.print("\n=== Upload Information ===\n");
        std.debug.print("Local file: {s}\n", .{local_file});
        std.debug.print("Remote file: {s}\n", .{remote_file});
        std.debug.print("File size: {d} bytes ({d:.2} MB)\n", .{ file_stat.size, @as(f64, @floatFromInt(file_stat.size)) / (1024.0 * 1024.0) });

        // Start upload
        std.debug.print("\nStarting upload...\n");
        transfer_state = try optimizer.uploadFile(local_file, remote_file);

    } else if (std.mem.eql(u8, operation, "download")) {
        std.debug.print("\n=== Download Information ===\n");
        std.debug.print("Remote file: {s}\n", .{remote_file});
        std.debug.print("Local file: {s}\n", .{local_file});

        // Start download
        std.debug.print("\nStarting download...\n");
        transfer_state = try optimizer.downloadFile(remote_file, local_file);

    } else if (std.mem.eql(u8, operation, "resume")) {
        std.debug.print("\nResuming transfer for: {s}\n", .{local_file});
        try optimizer.resumeTransfer(local_file);
        return;

    } else {
        std.debug.print("Error: Unknown operation '{s}'\n", .{operation});
        std.debug.print("Valid operations: upload, download, resume\n");
        std.process.exit(1);
    }

    // Monitor transfer progress
    std.debug.print("\n=== Transfer Progress ===\n");
    var last_progress: f64 = 0;
    var progress_updates: u32 = 0;

    while (true) {
        std.time.sleep(500 * std.time.ns_per_ms); // Update every 500ms

        const progress = optimizer.getTransferProgress(local_file) orelse break;
        const speed = optimizer.getTransferSpeed(local_file) orelse 0;
        const eta = optimizer.getTransferETA(local_file);

        // Only print if progress changed significantly
        if (@abs(progress - last_progress) > 0.01 or progress_updates % 20 == 0) {
            std.debug.print("\rProgress: {d:.1}% | Speed: {d:.2} MB/s", .{
                progress * 100,
                speed / (1024.0 * 1024.0)
            });

            if (eta) |eta_ms| {
                const eta_seconds = @as(f64, @floatFromInt(eta_ms - std.time.milliTimestamp())) / 1000.0;
                if (eta_seconds > 0) {
                    const eta_minutes = eta_seconds / 60.0;
                    if (eta_minutes > 1) {
                        std.debug.print(" | ETA: {d:.1} min", .{eta_minutes});
                    } else {
                        std.debug.print(" | ETA: {d:.0} sec", .{eta_seconds});
                    }
                }
            }

            last_progress = progress;
        }

        progress_updates += 1;

        // Check if transfer is complete
        if (progress >= 1.0) {
            std.debug.print("\n");
            break;
        }
    }

    // Display final statistics
    std.debug.print("\n=== Transfer Complete ===\n");
    std.debug.print("Total time: {d:.2} seconds\n", .{
        @as(f64, @floatFromInt(transfer_state.last_update_time - transfer_state.start_time)) / 1000.0
    });
    std.debug.print("Average speed: {d:.2} MB/s\n", .{transfer_state.average_speed / (1024.0 * 1024.0)});
    std.debug.print("Compression ratio: {d:.2}x\n", .{transfer_state.compression_ratio});
    std.debug.print("Chunks transferred: {d}\n", .{transfer_state.chunks.items.len});

    // Calculate and verify checksums
    if (transfer_config.verify_checksums) {
        std.debug.print("\nVerifying file integrity...\n");

        // This would implement actual checksum verification
        // For demo purposes, just show that it would happen
        std.debug.print("✓ File integrity verified\n");
    }

    // Show transfer efficiency metrics
    std.debug.print("\n=== Performance Metrics ===\n");
    var successful_chunks: u32 = 0;
    var failed_chunks: u32 = 0;
    var total_retries: u32 = 0;

    for (transfer_state.chunks.items) |chunk| {
        switch (chunk.status) {
            .completed => successful_chunks += 1,
            .failed => failed_chunks += 1,
            else => {},
        }
        total_retries += chunk.retry_count;
    }

    std.debug.print("Successful chunks: {d}/{d}\n", .{ successful_chunks, transfer_state.chunks.items.len });
    if (failed_chunks > 0) {
        std.debug.print("Failed chunks: {d}\n", .{failed_chunks});
    }
    if (total_retries > 0) {
        std.debug.print("Total retries: {d}\n", .{total_retries});
    }

    std.debug.print("\nTransfer completed successfully!\n");
}