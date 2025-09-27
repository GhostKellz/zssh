pub const packages = struct {
    pub const @"zcrypto-0.9.0-rgQAI79uDQArK9xAs_3jE_fAhsLf46jUowo8aNguD1oy" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.9.0-rgQAI79uDQArK9xAs_3jE_fAhsLf46jUowo8aNguD1oy";
        pub const build_zig = @import("zcrypto-0.9.0-rgQAI79uDQArK9xAs_3jE_fAhsLf46jUowo8aNguD1oy");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.5.4-KAuheZ4THQAlN32uBKm76ezT7dPT6rvj4ll56NiA9z9M" },
        };
    };
    pub const @"zquic-0.9.0-2rPdsyexmxOTG6tHoQMyP9wrGNTx9H1SueA9zTfYKCY4" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zquic-0.9.0-2rPdsyexmxOTG6tHoQMyP9wrGNTx9H1SueA9zTfYKCY4";
        pub const build_zig = @import("zquic-0.9.0-2rPdsyexmxOTG6tHoQMyP9wrGNTx9H1SueA9zTfYKCY4");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zcrypto", "zcrypto-0.9.0-rgQAI79uDQArK9xAs_3jE_fAhsLf46jUowo8aNguD1oy" },
            .{ "zsync", "zsync-0.5.4-KAuheZ4THQAlN32uBKm76ezT7dPT6rvj4ll56NiA9z9M" },
        };
    };
    pub const @"zsync-0.5.4-KAuheZ4THQAlN32uBKm76ezT7dPT6rvj4ll56NiA9z9M" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zsync-0.5.4-KAuheZ4THQAlN32uBKm76ezT7dPT6rvj4ll56NiA9z9M";
        pub const build_zig = @import("zsync-0.5.4-KAuheZ4THQAlN32uBKm76ezT7dPT6rvj4ll56NiA9z9M");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zcrypto", "zcrypto-0.9.0-rgQAI79uDQArK9xAs_3jE_fAhsLf46jUowo8aNguD1oy" },
    .{ "zquic", "zquic-0.9.0-2rPdsyexmxOTG6tHoQMyP9wrGNTx9H1SueA9zTfYKCY4" },
};
