pub const wav = @import("wav.zig");
pub const ogg_vorbis = @import("ogg_vorbis.zig");
pub const Arena = @import("arena.zig");

test {
    std.testing.refAllDecls(@This());
}
// pub fn main() !void {
//     const ogg_data = try std.fs.cwd().readFileAlloc("assets/sounds/footstep00.ogg", std.testing.allocator, .unlimited);
//     defer std.testing.allocator.free(ogg_data);
//     const ogg_data_decoded = try ogg_vorbis.decode(std.testing.allocator, ogg_data);
//     defer std.testing.allocator.free(ogg_data_decoded);
// }

const std = @import("std");
