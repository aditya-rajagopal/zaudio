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
    InvalidVorbisIdentificationPacket,
    InvalidVorbisCommentPacket,
} || std.mem.Allocator.Error;

const VORBIS_IDENTIFICATION: u32 = 0;
const VORBIS_COMMENT: u32 = 1;
const VORBIS_CODEC_SETUP: u32 = 2;
const VORBIS_CODEC_SETUP_NO: u32 = 3;

// TODO: Use errors instead of asserts?
// TODO: Use IO interface maybe?
// TODO: Is there any way to provide an arena to thsi function so that we dont ahve to worry about frees?
// TODO: Do we need to handle multiplexed streams? We can look at all BOS packets and the codec definition to figure out
// which serial number to use for which type of stream.
pub fn decode(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const start_state: DecoderState = .read_header;

    var read_head: []const u8 = data;
    // TODO: Do we want to parse this?
    // var comment_buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
    // var vorbis_comment_packet: VorbisCommentPacket = undefined;

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
    var current_packet_serial_number: u32 = undefined;

    // TODO: Filter only the vorbis packets
    var vorbis_current_packet_number: u32 = 0;
    var vorbis_serial_identified: bool = false;
    var vorbis_serial_number: u32 = undefined;
    var vorbis_identification_packet: VorbisIDPacket = undefined;
    // var vorbis_codec_setup_packet: VorbisCodecSetupPacket = undefined;

    blk: switch (start_state) {
        .read_header => {
            if (end_of_stream_flag) {
                break :blk;
            }
            if (read_head.len < @sizeOf(OggHeader)) {
                return error.MalformedIncompleteData;
            }

            const ogg_header: *const OggHeader = @ptrCast(@alignCast(read_head[0..@sizeOf(OggHeader)].ptr));
            read_head = read_head[@sizeOf(OggHeader)..];

            if (ogg_header.magic != OGG_MAGIC) {
                return error.InvalidOggSMagic;
            }

            if (vorbis_serial_identified and ogg_header.bitstream_serial_number != vorbis_serial_number) {
                const logal_segments = read_head[0..ogg_header.number_page_segments];
                var page_size: usize = 0;
                for (logal_segments) |segment| {
                    page_size += segment;
                    // TODO: Can we have continuations here?
                }
                read_head = read_head[page_size + ogg_header.number_page_segments ..];
                continue :blk .read_header;
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
            current_packet_serial_number = ogg_header.bitstream_serial_number;
            // TODO: Verify checksum

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
            var packet_read_head: []const u8 = packet;
            // NOTE: Once we are done parsing the packet we can reset the buffer even if we are not using the packet_buffer
            defer packet_buffer.shrinkRetainingCapacity(0);
            switch (vorbis_current_packet_number) {
                VORBIS_IDENTIFICATION => {
                    // TODO: Check if this is a vorbis stream and if not check the next header for a BOS packet
                    if (packet_read_head.len == 0) {
                        return error.MalformedIncompleteData;
                    }
                    const packet_type: u8 = packet[0];
                    if (packet_type != 0x01) {
                        begin_of_stream_flag = true;
                        // TODO: Flush the remaining packets of the page
                        // continue :blk .read_header;
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (packet_read_head.len < 7) {
                        begin_of_stream_flag = true;
                        // TODO: Flush the remaining packets of the page
                        // continue :blk .read_header;
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (!std.mem.eql(u8, packet_read_head[1..7], "vorbis")) {
                        begin_of_stream_flag = true;
                        // TODO: Flush the remaining packets of the page
                        // continue :blk .read_header;
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    vorbis_serial_number = current_packet_serial_number;
                    vorbis_serial_identified = true;
                    packet_read_head = packet_read_head[7..];
                    if (packet_read_head.len != @sizeOf(VorbisIDPacket)) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    const vorbis_id_packet: *const VorbisIDPacket = @ptrCast(@alignCast(packet_read_head[0..@sizeOf(VorbisIDPacket)].ptr));

                    if (vorbis_id_packet.version != 0) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.audio_channels == 0) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.audio_sample_rate == 0) {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.block_size._0 > vorbis_id_packet.block_size._1 or
                        vorbis_id_packet.block_size._0 < 6 or vorbis_id_packet.block_size._0 > 13 or
                        vorbis_id_packet.block_size._1 < 6 or vorbis_id_packet.block_size._1 > 13)
                    {
                        return error.InvalidVorbisIdentificationPacket;
                    }
                    if (vorbis_id_packet.framing_flag != 1) {
                        return error.InvalidVorbisIdentificationPacket;
                    }

                    vorbis_identification_packet = vorbis_id_packet.*;
                    std.log.err("ID header: {any}", .{vorbis_identification_packet});
                },
                VORBIS_COMMENT => {
                    // TODO: Parse the vorbis comment header
                    if (packet_read_head.len == 0) {
                        return error.MalformedIncompleteData;
                    }
                    const packet_type: u8 = packet[0];
                    if (packet_type != 0x03) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    if (packet_read_head.len < 7) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    if (!std.mem.eql(u8, packet_read_head[1..7], "vorbis")) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    packet_read_head = packet_read_head[7..];
                    if (packet_read_head.len < 4) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    const vendor_string_length: u32 = @bitCast(packet_read_head[0..4].*);
                    packet_read_head = packet_read_head[4..];
                    if (packet_read_head.len < vendor_string_length) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    // try comment_buffer.appendSlice(allocator, packet_read_head[0..vendor_string_length]);
                    // std.log.err("Vendor string: {s}", .{packet_read_head[0..vendor_string_length]});
                    packet_read_head = packet_read_head[vendor_string_length..];

                    if (packet_read_head.len < 4) {
                        return error.InvalidVorbisCommentPacket;
                    }
                    const user_comment_list_length: u32 = @bitCast(packet_read_head[0..4].*);
                    packet_read_head = packet_read_head[4..];
                    for (0..user_comment_list_length) |_| {
                        if (packet_read_head.len < 4) {
                            return error.InvalidVorbisCommentPacket;
                        }
                        const user_comment_length: u32 = @bitCast(packet_read_head[0..4].*);
                        packet_read_head = packet_read_head[4..];
                        if (packet_read_head.len < user_comment_length) {
                            return error.InvalidVorbisCommentPacket;
                        }
                        // try comment_buffer.appendSlice(allocator, packet_read_head[0..user_comment_length]);
                        // std.log.err("User comment: {s}", .{packet_read_head[0..user_comment_length]});
                        packet_read_head = packet_read_head[user_comment_length..];
                    }
                },

                VORBIS_CODEC_SETUP => {
                    // TODO: Parse the vorbis codec setup header
                    // std.log.err("Vorbis codec setup header parsed", .{});
                },
                else => {
                    // std.log.err("Audio packet", .{});
                },
            }
            vorbis_current_packet_number += 1;
            continue :blk .read_next_packet;
        },
    }

    const intermediate_buffer = try allocator.alloc(u8, 10);
    return intermediate_buffer;
}

const VorbisIDPacket = extern struct {
    version: u32 align(1), // Must be 0
    audio_channels: u8 align(1), // Number of audio channels 1 for mono 2 for stereo
    audio_sample_rate: u32 align(1), // Audio sample rate in Hz
    bitrate_maximum: u32 align(1), // Hint for the maximum bitrate in bps
    bitrate_nominal: u32 align(1), // Hint for the nominal bitrate in bps
    bitrate_minimum: u32 align(1), // Hint for the minimum bitrate in bps
    block_size: packed struct(u8) { _0: u4, _1: u4 } align(1), // Block size in samples
    framing_flag: u8 align(1), // Flag indicating whether the stream is framed must be 1
};

const VorbisCommentPacket = extern struct {
    vendor_string_length: u32 align(1), // Length of the vendor string
    vendor_string: [*]const u8 align(1), // Vendor string
    user_comment_list_length: u32 align(1), // Length of the user comment list
    user_comment_list: [*]const UserComment align(1), // User comment list

    pub const UserComment = extern struct {
        length: u32 align(1), // Length of the user comment
        entry: [*]const u8 align(1), // User comment
    };
};

const VorbisCodecSetupPacket = extern struct {};

test "comment packet" {
    std.log.err("ID packet size: {any}", .{@sizeOf(VorbisIDPacket)});
    std.log.err("Comment packet size: {any}", .{@sizeOf(VorbisCommentPacket)});
}

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
