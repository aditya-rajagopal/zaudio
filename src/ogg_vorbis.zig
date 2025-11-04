const std = @import("std");
const assert = std.debug.assert;

const FourCC = packed struct(u32) {
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
//  NOTE: Packets are logically divided into multiple segments before encoding into a page. Packets are divided into segments
//  of 255 bytes, the first segment that has a size of less than 255 bytes is the last segment of the packet. If a packet
//  is exactly 255 bytes it is followed by a 0 value segment.
//  NOTE: A zero value zegment is not invalid;
//  NOTE: Packets are not restricted to beginning and ending within a page
//  although individual segments are, by definition, required to do so
const OGG_MAGIC: FourCC = .{ .byte_1 = 'O', .byte_2 = 'g', .byte_3 = 'g', .byte_4 = 'S' };
const OggHeader = extern struct {
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

pub const Error = error{
    InvalidOggSMagic,
    MalformedIncompleteData,
    MalformedNoBeginningOfStream,
    MalformedMissingContinuedPacket,
    MalformedPageSequenceOutOfOrder,
} || std.mem.Allocator.Error;

// TODO: Use errors instead of asserts?
// TODO: Use IO interface maybe?
// TODO: Is there any way to provide an arena to thsi function so that we dont ahve to worry about frees?
// TODO: Do we need to handle multiplexed streams? We can look at all BOS packets and the codec definition to figure out
// which serial number to use for which type of stream.
pub fn decode(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const start_state: DecoderState = .read_header;

    var read_head: []const u8 = data;

    // TODO: Is there any way to avoid this allocation?
    // PERF: Can we have a code path when the packets are contigous and not write to this buffer?
    // PERF: 4096 seems reasonable as a buffer for packets since we expect small packets when dealing with audio files.
    var packet_buffer = try std.ArrayList(u8).initCapacity(allocator, 4096);
    defer packet_buffer.deinit(allocator);
    var segments: []const u8 = undefined;
    var current_segment: usize = 0;
    var current_page: usize = 0;
    var continued_packet_flag: bool = false;
    var begin_of_stream_flag: bool = true;
    var end_of_stream_flag: bool = false;
    // TODO: Filter only the vorbis packets
    // var vorbis_serial_number: u32 = undefined;

    blk: switch (start_state) {
        .read_header => {
            if (end_of_stream_flag) {
                break :blk;
            }
            if (read_head.len < @sizeOf(OggHeader)) {
                return error.MalformedIncompleteData;
            }

            const ogg_header: *const OggHeader = @ptrCast(@alignCast(read_head[0..@sizeOf(OggHeader)].ptr));

            if (ogg_header.magic != OGG_MAGIC) {
                return error.InvalidOggSMagic;
            }
            if (begin_of_stream_flag and !ogg_header.header_type_flag.bos) {
                return error.MalformedNoBeginningOfStream;
            }
            begin_of_stream_flag = false;

            if (continued_packet_flag and !ogg_header.header_type_flag.continued_packet) {
                return error.MalformedMissingContinuedPacket;
            }
            continued_packet_flag = false;

            end_of_stream_flag = ogg_header.header_type_flag.eos;

            if (ogg_header.page_sequence_number != current_page) {
                return error.MalformedPageSequenceOutOfOrder;
            }

            read_head = read_head[@sizeOf(OggHeader)..];

            segments = read_head[0..ogg_header.number_page_segments];
            // std.log.err("Segments: {any}", .{segments});
            current_segment = 0;
            read_head = read_head[ogg_header.number_page_segments..];

            current_page += 1;
            continue :blk .read_next_packet;
        },
        .read_next_packet => {
            if (current_segment >= segments.len) {
                continue :blk .read_header;
            }
            var packet_size: usize = 0;
            for (current_segment..segments.len) |index| {
                packet_size += segments[index];
                if (segments[index] < 255) {
                    // std.log.err("packet size: {any}", .{packet_size});
                    current_segment = index + 1;
                    if (packet_buffer.items.len > 0) {
                        // NOTE: We have already collected some packets so we need to append to the buffer
                        try packet_buffer.appendSlice(allocator, read_head[0..packet_size]);
                        read_head = read_head[packet_size..];
                        continue :blk .{ .parse_packet = packet_buffer.items };
                    } else {
                        const packet = read_head[0..packet_size];
                        read_head = read_head[packet_size..];
                        // NOTE: Since this is a contigious packet we dont need to use the packet_buffer
                        continue :blk .{ .parse_packet = packet };
                    }
                }
            }
            // NOTE: We can only reach here if the last segment is 255 and we havent reached the end of the packet.
            // std.log.err("Continuation packet", .{});
            try packet_buffer.appendSlice(allocator, read_head[0..packet_size]);
            continued_packet_flag = true;
            read_head = read_head[packet_size..];
            continue :blk .read_header;
        },
        .parse_packet => |packet| {
            std.log.err("Packet parsed: len: {any}", .{packet.len});
            // NOTE: Once we are done parsing the packet we can reset the buffer even if we are not using the packet_buffer
            packet_buffer.shrinkRetainingCapacity(0);
            // @INCOMPLETE
            continue :blk .read_next_packet;
        },
    }

    const intermediate_buffer = try allocator.alloc(u8, 10);
    return intermediate_buffer;
}

// NOTE:
// 1. Read the header passing what is expected to be in that header
// 2. Store the vorbis serial number so we can skip pages that dont match the serial number
// 3. Store the segment table and read the packet
// 4. Start collecting different segments into a single buffer and once done send to parse packet
// 5. Once we are done parsing packet we go read the next packet. If there is no more segments left we go to step 1.
// 6. If there is a case where the last segment is 255 then we pause reading and go back to step 1 with expecting that
// the continue bit is set in the header. Once we read the header we continue collecitng the segments for the packet.

const ParserState = enum(u8) {
    read_next_packet,
    read_header,
    parse_packet,
};

const DecoderState = union(ParserState) {
    read_next_packet,
    read_header,
    parse_packet: []const u8,
};

test "ogg decode" {
    const ogg_data = try std.fs.cwd().readFileAlloc("assets/sounds/footstep00.ogg", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(ogg_data);
    const ogg_data_decoded = try decode(std.testing.allocator, ogg_data);
    defer std.testing.allocator.free(ogg_data_decoded);
}
