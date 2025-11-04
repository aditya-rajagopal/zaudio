const std = @import("std");
const assert = std.debug.assert;

pub const FourCC = packed struct(u32) {
    byte_1: u8,
    byte_2: u8,
    byte_3: u8,
    byte_4: u8,

    pub fn toInt(self: FourCC) u32 {
        return @bitCast(self);
    }
};
// NOTE:
//  1.  Each segment is prefixed with an 27 byte header
//  2. If header's Flags field has a bit 2, or TotalSegments field is a zero, this is the end of the audio file.
//  You start with reading the OGG header, figure out how many segments there are grab them and then move to the next
//  header and repeat. This will pick up all the vorbis data.
pub const OGG_MAGIC: FourCC = .{ .byte_1 = 'O', .byte_2 = 'g', .byte_3 = 'g', .byte_4 = 'S' };
pub const OggHeader = extern struct {
    magic: FourCC align(1),
    version: u8 align(1),
    header_type_flag: HeaderFlags align(1),
    granule_position: u64 align(1),
    bitstream_serial_number: u32 align(1),
    page_sequence_number: u32 align(1),
    crc_checksum: u32 align(1), // The generator polynomial is 0x04c11db7.
    number_page_segments: u8 align(1), // If this is 0 then the header is for the end of the stream.

    pub const HeaderFlags = packed struct(u8) {
        continued_packet: bool = false,
        bos: bool = false,
        eos: bool = false,
        _reserved: u5 = 0,
    };
};

// TODO: Use IO interface maybe?
pub fn decode(allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error![]u8 {
    assert(data.len >= @sizeOf(OggHeader));
}
