// btrfs2squashfs: convert a directory on a compressed btrfs filesystem into
// a squashfs v4 image WITHOUT recompressing file data.
//
// How: btrfs transparent compression stores each 128 KiB chunk of a file as
// an independent, standard zstd frame (or zlib stream). squashfs (with the
// default 128 KiB block size) stores each 128 KiB block the same way. So the
// compressed bytes can be copied verbatim from btrfs extents (read via
// BTRFS_IOC_ENCODED_READ) into squashfs data blocks.
//
// A squashfs image has a single compressor, so it is locked to the algorithm
// of the first extent copied verbatim (zstd -> zstd, zlib -> gzip); extents
// of the other algorithm are then stored raw. btrfs lzo cannot be copied at
// all: it is a segmented container format (per-page segments with length
// headers), not the plain lzo1x stream squashfs expects.
//
// Tail ends whose extents decompress to more than the tail itself (btrfs
// pads compression input to the sector size; inline extents decompress to a
// full sector) are copied verbatim as squashfs fragment blocks: the inode
// references only the first `tail` bytes of the fragment, so the padding is
// never read. One fragment block per tail - packing several compressed tails
// into one fragment block would require recompression, because a fragment
// block is a single compression unit.
//
// Blocks that still can't be copied verbatim (uncompressed extents,
// misaligned extents, foreign-compressor extents) are stored as raw
// uncompressed squashfs blocks - still no recompression. All-zero blocks
// become squashfs sparse blocks. Metadata tables are stored uncompressed.
//
// Duplicate files (including hard links) are stored once: candidates are
// found by hashing the per-sector checksums btrfs already keeps in its csum
// tree (read via BTRFS_IOC_TREE_SEARCH_V2 - no checksum is computed here),
// then confirmed by pread'ing the already-written copy back from the image
// and comparing bytes, so no data blocks are kept in memory.
//
// Limitations (POC): no xattrs, directory listings < 64 KiB.
//
// Usage: sudo btrfs2squashfs <source-dir> <output.squashfs>
// (BTRFS_IOC_ENCODED_READ requires CAP_SYS_ADMIN.)

const std = @import("std");
const linux = std.os.linux;
const Dedup = @import("dedup.zig").Dedup;

const block_size: u32 = 131072;
const block_log: u16 = 17;
const meta_size: usize = 8192;

// ---------------------------------------------------------------- btrfs side

const EncodedIoArgs = extern struct {
    iov: ?[*]const std.posix.iovec,
    iovcnt: u64,
    offset: i64,
    flags: u64,
    len: u64,
    unencoded_len: u64,
    unencoded_offset: u64,
    compression: u32,
    encryption: u32,
    reserved: [64]u8,
};

const BTRFS_IOC_ENCODED_READ = linux.IOCTL.IOR(0x94, 64, EncodedIoArgs);
const BTRFS_ENCODED_IO_COMPRESSION_ZLIB: u32 = 1;
const BTRFS_ENCODED_IO_COMPRESSION_ZSTD: u32 = 2;

const SQFS_COMP_GZIP: u16 = 1;
const SQFS_COMP_ZSTD: u16 = 6;

const EncodedExtent = struct {
    encoded_len: usize,
    len: u64,
    unencoded_len: u64,
    unencoded_offset: u64,
    compression: u32,
};

fn encodedRead(fd: std.posix.fd_t, offset: u64, buf: []u8) !EncodedExtent {
    var iov = [_]std.posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
    var ea = std.mem.zeroes(EncodedIoArgs);
    ea.iov = &iov;
    ea.iovcnt = 1;
    ea.offset = @intCast(offset);
    const rc = linux.ioctl(fd, BTRFS_IOC_ENCODED_READ, @intFromPtr(&ea));
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        return switch (@as(linux.E, @enumFromInt(-signed))) {
            .PERM, .ACCES => error.NeedCapSysAdmin,
            .NOTTY, .OPNOTSUPP, .INVAL => error.EncodedReadUnsupported,
            else => error.EncodedReadFailed,
        };
    }
    return .{
        .encoded_len = rc,
        .len = ea.len,
        .unencoded_len = ea.unencoded_len,
        .unencoded_offset = ea.unencoded_offset,
        .compression = ea.compression,
    };
}

const ZstdFrame = struct {
    size: usize, // compressed size of the frame on disk
    content_size: u64, // decompressed size declared in the frame header, 0 means unknown
};

// btrfs pads the encoded data to the filesystem sector size, but squashfs
// tools do one-shot decompression and reject trailing garbage, so locate the
// exact end of the zstd frame by walking its header and block headers. Also
// extract the declared content size: btrfs sometimes compresses sector-padded
// data (e.g. inline extents decompress to 4 KiB while unencoded_len reports
// the unpadded length), and such frames must not be copied verbatim.
fn zstdFrameParse(buf: []const u8) !ZstdFrame {
    if (buf.len < 6) return error.Truncated;
    if (std.mem.readInt(u32, buf[0..4], .little) != 0xFD2FB528) return error.BadMagic;
    var pos: usize = 4;
    const fhd = buf[pos];
    pos += 1;
    const single_segment = (fhd & 0x20) != 0;
    if (!single_segment) pos += 1; // window descriptor
    pos += @as(usize, 1) << @as(u2, @truncate(fhd)) >> 1; // dictionary id
    const fcs_len: usize = (@as(usize, 1) << @as(u2, @truncate(fhd >> 6))) & ~@as(usize, @intFromBool(!single_segment));
    if (pos + fcs_len > buf.len) return error.Truncated;
    const content_size: u64 = switch (fcs_len) {
        0 => 0,
        1 => buf[pos],
        2 => @as(u64, std.mem.readInt(u16, buf[pos..][0..2], .little)) + 256,
        4 => std.mem.readInt(u32, buf[pos..][0..4], .little),
        8 => std.mem.readInt(u64, buf[pos..][0..8], .little),
        else => unreachable,
    };
    pos += fcs_len;
    while (true) {
        if (pos + 3 > buf.len) return error.Truncated;
        const bh = @as(u32, buf[pos]) | @as(u32, buf[pos + 1]) << 8 | @as(u32, buf[pos + 2]) << 16;
        pos += 3;
        const last = bh & 1;
        const btype = (bh >> 1) & 3;
        const bsize = bh >> 3;
        pos += switch (btype) {
            0, 2 => bsize, // raw / compressed
            1 => 1, // RLE
            else => return error.ReservedBlock,
        };
        if (pos > buf.len) return error.Truncated;
        if (last == 1) break;
    }
    if (fhd & 0x04 != 0) pos += 4; // content checksum
    if (pos > buf.len) return error.Truncated;
    return .{ .size = pos, .content_size = content_size };
}

// ------------------------------------------------------------------ fs tree

const Kind = enum(u16) {
    dir = 1,
    file = 2,
    symlink = 3,
    blkdev = 4,
    chrdev = 5,
    fifo = 6,
    socket = 7,
};

const Node = struct {
    name: []const u8,
    kind: Kind,
    mode: u16,
    uid_idx: u16,
    gid_idx: u16,
    mtime: u32,
    size: u64 = 0,
    rdev: u32 = 0,
    ino: u64 = 0, // btrfs inode number, used for dedup key lookups
    inum: u32 = 0,
    children: std.ArrayListUnmanaged(*Node) = .{},
    // location of this node's inode in the inode table, filled during write
    ref_block: u32 = 0,
    ref_offset: u16 = 0,
};

fn squashfsRdev(st_rdev: u64) u32 {
    // glibc dev_t -> (major, minor) -> kernel new_encode_dev layout
    const major: u32 = @truncate(((st_rdev >> 8) & 0xfff) | ((st_rdev >> 32) & 0xfffff000));
    const minor: u32 = @truncate((st_rdev & 0xff) | ((st_rdev >> 12) & 0xffffff00));
    return (minor & 0xff) | (major << 8) | ((minor & 0xffffff00) << 12);
}

const Builder = struct {
    alloc: std.mem.Allocator,
    ids: std.AutoArrayHashMapUnmanaged(u32, void) = .{},
    inode_count: u32 = 0,

    fn idIndex(b: *Builder, id: u32) !u16 {
        const gop = try b.ids.getOrPut(b.alloc, id);
        return @intCast(gop.index);
    }

    fn nodeFromStat(b: *Builder, name: []const u8, st: linux.Stat) !*Node {
        const m = st.mode;
        const kind: Kind = switch (m & linux.S.IFMT) {
            linux.S.IFDIR => .dir,
            linux.S.IFREG => .file,
            linux.S.IFLNK => .symlink,
            linux.S.IFBLK => .blkdev,
            linux.S.IFCHR => .chrdev,
            linux.S.IFIFO => .fifo,
            linux.S.IFSOCK => .socket,
            else => return error.UnsupportedFileType,
        };
        const node = try b.alloc.create(Node);
        node.* = .{
            .name = try b.alloc.dupe(u8, name),
            .kind = kind,
            .mode = @truncate(m & 0o7777),
            .uid_idx = try b.idIndex(st.uid),
            .gid_idx = try b.idIndex(st.gid),
            .mtime = std.math.lossyCast(u32, st.mtim.sec),
            .size = @intCast(st.size),
            .rdev = squashfsRdev(st.rdev),
            .ino = st.ino,
        };
        return node;
    }

    fn scan(b: *Builder, dir: std.fs.Dir, node: *Node) !void {
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.name.len > 256) return error.NameTooLong;
            const st = try std.posix.fstatat(dir.fd, entry.name, linux.AT.SYMLINK_NOFOLLOW);
            const child = try b.nodeFromStat(entry.name, st);
            try node.children.append(b.alloc, child);
            if (child.kind == .dir) {
                var sub = try dir.openDir(entry.name, .{ .iterate = true });
                defer sub.close();
                try b.scan(sub, child);
            }
        }
        std.mem.sortUnstable(*Node, node.children.items, {}, struct {
            fn lt(_: void, a: *Node, c: *Node) bool {
                return std.mem.order(u8, a.name, c.name) == .lt;
            }
        }.lt);
    }

    fn number(b: *Builder, node: *Node) void {
        for (node.children.items) |child| b.number(child);
        b.inode_count += 1;
        node.inum = b.inode_count;
    }
};

// ------------------------------------------------------------ squashfs side

fn metaBlockOf(pos: usize) u32 {
    return @intCast((pos / meta_size) * (meta_size + 2));
}
fn metaOffsetOf(pos: usize) u16 {
    return @intCast(pos % meta_size);
}

const FragEntry = struct {
    start: u64,
    size: u32,
};

// Everything needed to point a later identical file at the already-written
// copy of the same data, and to verify the two really match.
const FileRecord = struct {
    size: u64,
    start: u64, // block-data start (after the tail fragment, if any)
    range_begin: u64, // first byte this file wrote to the image
    range_end: u64,
    frag_idx: u32,
    frag_size: u32,
    sizes: []const u32, // block-list entries
};

fn preadFull(f: std.fs.File, buf: []u8, off: u64) !void {
    if (try f.preadAll(buf, off) != buf.len) return error.UnexpectedEof;
}

const Writer = struct {
    alloc: std.mem.Allocator,
    out: std.fs.File,
    pos: u64 = 0,
    inode_tab: std.ArrayListUnmanaged(u8) = .{},
    dir_tab: std.ArrayListUnmanaged(u8) = .{},
    frag_entries: std.ArrayListUnmanaged(FragEntry) = .{},
    enc_buf: []u8,
    raw_buf: []u8,
    dedup: Dedup,
    dedup_map: std.AutoHashMapUnmanaged(u64, FileRecord) = .{},
    compressor: ?u16 = null,
    blocks_copied: u64 = 0,
    frags_copied: u64 = 0,
    blocks_raw: u64 = 0,
    blocks_sparse: u64 = 0,
    files_deduped: u64 = 0,
    bytes_deduped: u64 = 0,

    fn emit(w: *Writer, bytes: []const u8) !void {
        try w.out.writeAll(bytes);
        w.pos += bytes.len;
    }

    // The image has a single compressor; the first verbatim copy decides it.
    fn lockCompressor(w: *Writer, comp: u16) bool {
        if (w.compressor) |locked| return locked == comp;
        w.compressor = comp;
        return true;
    }

    // Writes one squashfs data block for file range [off, off+span).
    // Returns the block-list entry.
    fn writeBlock(w: *Writer, file: std.fs.File, off: u64, span: u32) !u32 {
        const ext = try encodedRead(file.handle, off, w.enc_buf);
        // Verbatim copy is only valid if this extent is exactly the
        // squashfs block: starts at `off`, covers `span` bytes, and
        // decompresses to exactly `span` bytes.
        if (ext.len == span and ext.unencoded_len == span and ext.unencoded_offset == 0) {
            switch (ext.compression) {
                BTRFS_ENCODED_IO_COMPRESSION_ZSTD => if (w.lockCompressor(SQFS_COMP_ZSTD)) {
                    // The frame's declared content size is the authority on
                    // the decompressed size: unencoded_len understates it for
                    // sector-padded inline extents. squashfs zstd
                    // decompressors also reject trailing garbage, so trim the
                    // frame to its exact end.
                    const frame = try zstdFrameParse(w.enc_buf[0..ext.encoded_len]);
                    if (frame.size < span and frame.content_size == span) {
                        try w.emit(w.enc_buf[0..frame.size]);
                        w.blocks_copied += 1;
                        return @intCast(frame.size);
                    }
                },
                BTRFS_ENCODED_IO_COMPRESSION_ZLIB => if (w.lockCompressor(SQFS_COMP_GZIP)) {
                    // No trimming needed: zlib decompressors (both the kernel
                    // and squashfs-tools) stop at the stream end and ignore
                    // the sector padding btrfs appends. For a non-inline
                    // extent unencoded_len (ram_bytes) is the exact
                    // decompressed size, and only small files are inlined.
                    if (ext.encoded_len < span) {
                        try w.emit(w.enc_buf[0..ext.encoded_len]);
                        w.blocks_copied += 1;
                        return @intCast(ext.encoded_len);
                    }
                },
                else => {},
            }
        }

        // Fallback: store the decompressed data as an uncompressed block.
        const buf = w.raw_buf[0..span];
        try preadFull(file, buf, off);
        if (std.mem.allEqual(u8, buf, 0)) {
            w.blocks_sparse += 1;
            return 0; // sparse block
        }
        try w.emit(buf);
        w.blocks_raw += 1;
        return 0x1000000 | span; // uncompressed-block flag
    }

    // If the tail's extent decompresses to more than the tail itself (btrfs
    // pads compression input to the sector size; inline extents decompress
    // to a full sector), the frame can still be copied verbatim - as a
    // fragment block. The inode references bytes [0, tail) of the fragment,
    // so the padding is never read. Returns the fragment index, or null if
    // the tail doesn't qualify (the caller stores it as a data block).
    fn tryTailFragment(w: *Writer, file: std.fs.File, off: u64, tail: u32) !?u32 {
        const ext = try encodedRead(file.handle, off, w.enc_buf);
        if (ext.len != tail or ext.unencoded_offset != 0) return null;
        const frame_size: usize = switch (ext.compression) {
            BTRFS_ENCODED_IO_COMPRESSION_ZSTD => blk: {
                if (!w.lockCompressor(SQFS_COMP_ZSTD)) return null;
                const frame = zstdFrameParse(w.enc_buf[0..ext.encoded_len]) catch return null;
                if (frame.content_size < tail or frame.content_size > block_size) return null;
                break :blk frame.size;
            },
            BTRFS_ENCODED_IO_COMPRESSION_ZLIB => blk: {
                if (!w.lockCompressor(SQFS_COMP_GZIP)) return null;
                if (ext.unencoded_len > block_size) return null;
                break :blk ext.encoded_len;
            },
            else => return null,
        };
        if (frame_size >= tail) return null; // a raw data block would be smaller
        try w.frag_entries.append(w.alloc, .{ .start = w.pos, .size = @intCast(frame_size) });
        try w.emit(w.enc_buf[0..frame_size]);
        w.frags_copied += 1;
        return @intCast(w.frag_entries.items.len - 1);
    }

    fn inodeCommon(w: *Writer, node: *Node, itype: u16) !void {
        const iw = w.inode_tab.writer(w.alloc);
        node.ref_block = metaBlockOf(w.inode_tab.items.len);
        node.ref_offset = metaOffsetOf(w.inode_tab.items.len);
        try iw.writeInt(u16, itype, .little);
        try iw.writeInt(u16, node.mode, .little);
        try iw.writeInt(u16, node.uid_idx, .little);
        try iw.writeInt(u16, node.gid_idx, .little);
        try iw.writeInt(u32, node.mtime, .little);
        try iw.writeInt(u32, node.inum, .little);
    }

    // A matching dedup key only nominates a candidate: confirm the two files
    // would be stored identically by pread'ing the already-written copy back
    // from the image and comparing bytes (no blocks are kept in memory).
    fn sameAsRecord(w: *Writer, rec: FileRecord, range_begin: u64, frag_idx: u32, sizes: []const u32, size: u64) !bool {
        if (rec.size != size) return false;
        const len = w.pos - range_begin;
        if (rec.range_end - rec.range_begin != len) return false;
        if ((rec.frag_idx == 0xFFFFFFFF) != (frag_idx == 0xFFFFFFFF)) return false;
        if (frag_idx != 0xFFFFFFFF and rec.frag_size != w.frag_entries.items[frag_idx].size) return false;
        if (!std.mem.eql(u32, rec.sizes, sizes)) return false;
        const half = w.enc_buf.len / 2;
        var done: u64 = 0;
        while (done < len) {
            const n: usize = @intCast(@min(len - done, half));
            const a = w.enc_buf[0..n];
            const b = w.enc_buf[half..][0..n];
            try preadFull(w.out, a, rec.range_begin + done);
            try preadFull(w.out, b, range_begin + done);
            if (!std.mem.eql(u8, a, b)) return false;
            done += n;
        }
        return true;
    }

    fn writeFile(w: *Writer, node: *Node, dirh: std.fs.Dir) !void {
        var file = try dirh.openFile(node.name, .{});
        defer file.close();
        const size = node.size;
        const range_begin = w.pos;
        const frags_begin = w.frag_entries.items.len;
        const snap_copied = w.blocks_copied;
        const snap_frags = w.frags_copied;
        const snap_raw = w.blocks_raw;
        const snap_sparse = w.blocks_sparse;
        const tail: u32 = @intCast(size % block_size);
        var frag_idx: u32 = 0xFFFFFFFF;
        if (tail != 0) {
            if (try w.tryTailFragment(file, size - tail, tail)) |idx| frag_idx = idx;
        }
        const has_tail_block = tail != 0 and frag_idx == 0xFFFFFFFF;
        const n_blocks: usize = @intCast(size / block_size + @intFromBool(has_tail_block));
        const sizes = try w.alloc.alloc(u32, n_blocks);
        var sizes_in_map = false;
        defer if (!sizes_in_map) w.alloc.free(sizes);
        var start = w.pos;
        var sparse_bytes: u64 = 0;
        for (sizes, 0..) |*s, i| {
            const off = @as(u64, @intCast(i)) * block_size;
            const span: u32 = @intCast(@min(block_size, size - off));
            s.* = try w.writeBlock(file, off, span);
            if (s.* == 0) sparse_bytes += span;
        }

        // dedup: only worth it when the file wrote actual data
        if (w.pos > range_begin) {
            if (w.dedup.fileKey(file.handle, node.ino, size)) |key| {
                const gop = try w.dedup_map.getOrPut(w.alloc, key);
                if (gop.found_existing) {
                    if (try w.sameAsRecord(gop.value_ptr.*, range_begin, frag_idx, sizes, size)) {
                        // drop this copy and reference the first one
                        w.files_deduped += 1;
                        w.bytes_deduped += w.pos - range_begin;
                        w.frag_entries.items.len = frags_begin;
                        try w.out.seekTo(range_begin);
                        try w.out.setEndPos(range_begin);
                        w.pos = range_begin;
                        w.blocks_copied = snap_copied;
                        w.frags_copied = snap_frags;
                        w.blocks_raw = snap_raw;
                        w.blocks_sparse = snap_sparse;
                        start = gop.value_ptr.start;
                        frag_idx = gop.value_ptr.frag_idx;
                    }
                } else {
                    gop.value_ptr.* = .{
                        .size = size,
                        .start = start,
                        .range_begin = range_begin,
                        .range_end = w.pos,
                        .frag_idx = frag_idx,
                        .frag_size = if (frag_idx != 0xFFFFFFFF) w.frag_entries.items[frag_idx].size else 0,
                        .sizes = sizes,
                    };
                    sizes_in_map = true;
                }
            }
        }

        const iw = w.inode_tab.writer(w.alloc);
        if (start > std.math.maxInt(u32) or size > std.math.maxInt(u32)) {
            // extended file inode: 64-bit start and size
            try w.inodeCommon(node, 9);
            try iw.writeInt(u64, if (n_blocks == 0) 0 else start, .little);
            try iw.writeInt(u64, size, .little);
            try iw.writeInt(u64, sparse_bytes, .little);
            try iw.writeInt(u32, 1, .little); // nlink
            try iw.writeInt(u32, frag_idx, .little);
            try iw.writeInt(u32, 0, .little); // fragment offset
            try iw.writeInt(u32, 0xFFFFFFFF, .little); // no xattrs
        } else {
            try w.inodeCommon(node, @intFromEnum(node.kind));
            try iw.writeInt(u32, if (n_blocks == 0) 0 else @intCast(start), .little);
            try iw.writeInt(u32, frag_idx, .little);
            try iw.writeInt(u32, 0, .little); // fragment offset
            try iw.writeInt(u32, @intCast(size), .little);
        }
        for (sizes) |s| try iw.writeInt(u32, s, .little);
    }

    fn writeSymlink(w: *Writer, node: *Node, dirh: std.fs.Dir) !void {
        var buf: [4096]u8 = undefined;
        const target = try dirh.readLink(node.name, &buf);
        try w.inodeCommon(node, @intFromEnum(node.kind));
        const iw = w.inode_tab.writer(w.alloc);
        try iw.writeInt(u32, 1, .little); // nlink
        try iw.writeInt(u32, @intCast(target.len), .little);
        try iw.writeAll(target);
    }

    fn writeSpecial(w: *Writer, node: *Node) !void {
        try w.inodeCommon(node, @intFromEnum(node.kind));
        const iw = w.inode_tab.writer(w.alloc);
        try iw.writeInt(u32, 1, .little); // nlink
        if (node.kind == .blkdev or node.kind == .chrdev)
            try iw.writeInt(u32, node.rdev, .little);
    }

    fn writeDir(w: *Writer, node: *Node, dirh: std.fs.Dir, parent_inum: u32) !void {
        var n_subdirs: u32 = 0;
        for (node.children.items) |child| {
            switch (child.kind) {
                .dir => {
                    n_subdirs += 1;
                    var sub = try dirh.openDir(child.name, .{});
                    defer sub.close();
                    try w.writeDir(child, sub, node.inum);
                },
                .file => try w.writeFile(child, dirh),
                .symlink => try w.writeSymlink(child, dirh),
                else => try w.writeSpecial(child),
            }
        }
        // directory listing (children already have inode refs)
        const list_start = w.dir_tab.items.len;
        const list_block = metaBlockOf(list_start);
        const list_offset = metaOffsetOf(list_start);
        const dw = w.dir_tab.writer(w.alloc);
        const ents = node.children.items;
        var i: usize = 0;
        while (i < ents.len) {
            const base = ents[i];
            var j = i;
            while (j < ents.len and j - i < 256 and ents[j].ref_block == base.ref_block) {
                const delta = @as(i64, ents[j].inum) - @as(i64, base.inum);
                if (delta < -32768 or delta > 32767) break;
                j += 1;
            }
            try dw.writeInt(u32, @intCast(j - i - 1), .little);
            try dw.writeInt(u32, base.ref_block, .little);
            try dw.writeInt(u32, base.inum, .little);
            for (ents[i..j]) |e| {
                try dw.writeInt(u16, e.ref_offset, .little);
                try dw.writeInt(i16, @intCast(@as(i64, e.inum) - @as(i64, base.inum)), .little);
                try dw.writeInt(u16, @intFromEnum(e.kind), .little);
                try dw.writeInt(u16, @intCast(e.name.len - 1), .little);
                try dw.writeAll(e.name);
            }
            i = j;
        }
        const list_len = w.dir_tab.items.len - list_start;
        if (list_len + 3 > 0xFFFF) return error.DirTooLargeForBasicInode;

        try w.inodeCommon(node, @intFromEnum(node.kind));
        const iw = w.inode_tab.writer(w.alloc);
        try iw.writeInt(u32, list_block, .little);
        try iw.writeInt(u32, 2 + n_subdirs, .little); // nlink
        try iw.writeInt(u16, @intCast(list_len + 3), .little);
        try iw.writeInt(u16, list_offset, .little);
        try iw.writeInt(u32, parent_inum, .little);
    }

    // metadata stream -> uncompressed metadata blocks (u16 header, bit 15 set)
    fn emitMetaTable(w: *Writer, data: []const u8) !void {
        var p: usize = 0;
        while (p < data.len) {
            const n: usize = @min(meta_size, data.len - p);
            var hdr: [2]u8 = undefined;
            std.mem.writeInt(u16, &hdr, @intCast(0x8000 | n), .little);
            try w.emit(&hdr);
            try w.emit(data[p .. p + n]);
            p += n;
        }
    }

    // metadata block(s) of table entries, then an index of u64 offsets to
    // each block. Returns the index start (what the superblock points at).
    fn emitIndexedTable(w: *Writer, data: []const u8) !u64 {
        var block_offsets = std.ArrayListUnmanaged(u64){};
        defer block_offsets.deinit(w.alloc);
        var p: usize = 0;
        while (p < data.len) {
            try block_offsets.append(w.alloc, w.pos);
            const n: usize = @min(meta_size, data.len - p);
            var hdr: [2]u8 = undefined;
            std.mem.writeInt(u16, &hdr, @intCast(0x8000 | n), .little);
            try w.emit(&hdr);
            try w.emit(data[p .. p + n]);
            p += n;
        }
        const index_start = w.pos;
        for (block_offsets.items) |off| {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, off, .little);
            try w.emit(&b);
        }
        return index_start;
    }

    // Emits the metadata/fragment/id tables, pads to 4 KiB, and back-patches
    // the superblock. Returns the total image size (bytes_used).
    fn finish(w: *Writer, builder: *Builder, root: *Node) !u64 {
        const inode_table_start = w.pos;
        try w.emitMetaTable(w.inode_tab.items);
        const directory_table_start = w.pos;
        try w.emitMetaTable(w.dir_tab.items);

        var frag_bytes = std.ArrayListUnmanaged(u8){};
        defer frag_bytes.deinit(w.alloc);
        const fw = frag_bytes.writer(w.alloc);
        for (w.frag_entries.items) |e| {
            try fw.writeInt(u64, e.start, .little);
            try fw.writeInt(u32, e.size, .little); // compressed: bit 24 clear
            try fw.writeInt(u32, 0, .little); // unused
        }
        const fragment_table_start = try w.emitIndexedTable(frag_bytes.items);

        const ids = builder.ids.keys();
        var id_bytes = std.ArrayListUnmanaged(u8){};
        defer id_bytes.deinit(w.alloc);
        for (ids) |id| try id_bytes.writer(w.alloc).writeInt(u32, id, .little);
        const id_table_start = try w.emitIndexedTable(id_bytes.items);

        const bytes_used = w.pos;
        // pad to 4 KiB
        const pad = (4096 - bytes_used % 4096) % 4096;
        if (pad > 0) {
            const zeros = [_]u8{0} ** 4096;
            try w.emit(zeros[0..pad]);
        }

        // superblock
        var sb: [96]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&sb);
        const sw = fbs.writer();
        try sw.writeInt(u32, 0x73717368, .little); // magic "hsqs"
        try sw.writeInt(u32, builder.inode_count, .little);
        try sw.writeInt(u32, std.math.lossyCast(u32, std.time.timestamp()), .little);
        try sw.writeInt(u32, block_size, .little);
        try sw.writeInt(u32, @intCast(w.frag_entries.items.len), .little);
        try sw.writeInt(u16, w.compressor orelse SQFS_COMP_ZSTD, .little);
        try sw.writeInt(u16, block_log, .little);
        // NOI | NOID, plus NO_FRAG when no fragments were written
        const no_frag: u16 = if (w.frag_entries.items.len == 0) 0x0010 else 0;
        try sw.writeInt(u16, 0x0801 | no_frag, .little);
        try sw.writeInt(u16, @intCast(ids.len), .little);
        try sw.writeInt(u16, 4, .little); // version major
        try sw.writeInt(u16, 0, .little); // version minor
        try sw.writeInt(u64, (@as(u64, root.ref_block) << 16) | root.ref_offset, .little);
        try sw.writeInt(u64, bytes_used, .little);
        try sw.writeInt(u64, id_table_start, .little);
        try sw.writeInt(u64, 0xFFFFFFFFFFFFFFFF, .little); // xattr table
        try sw.writeInt(u64, inode_table_start, .little);
        try sw.writeInt(u64, directory_table_start, .little);
        try sw.writeInt(u64, fragment_table_start, .little);
        try sw.writeInt(u64, 0xFFFFFFFFFFFFFFFF, .little); // export table
        try w.out.pwriteAll(&sb, 0);

        return bytes_used;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    var args = std.process.args();
    const arg0 = args.next();
    const arg1 = args.next();
    const arg2 = args.next();
    var src_path: [:0]const u8 = undefined;
    var out_path: [:0]const u8 = undefined;
    if (arg2 == null) {
        std.log.err("usage: {s} <source-dir> <output.squashfs>", .{arg0 orelse "btrfs2squashfs"});
        return error.Usage;
    } else {
        src_path = arg1.?;
        out_path = arg2.?;
    }

    // phase 1: scan the tree
    var builder = Builder{ .alloc = alloc };
    var src = try std.fs.cwd().openDir(src_path, .{ .iterate = true });
    defer src.close();
    const root_st = try std.posix.fstat(src.fd);
    const root = try builder.nodeFromStat("", root_st);
    if (root.kind != .dir) return error.SourceNotADirectory;
    try builder.scan(src, root);
    builder.number(root);

    // phase 2: write the image (read access: dedup verifies candidates by
    // reading the already-written copy back)
    const out = try std.fs.cwd().createFile(out_path, .{ .truncate = true, .read = true });
    defer out.close();
    var w = Writer{
        .alloc = alloc,
        .out = out,
        .enc_buf = try alloc.alloc(u8, 2 * block_size),
        .raw_buf = try alloc.alloc(u8, block_size),
        .dedup = try Dedup.init(alloc, src.fd),
    };
    try w.emit(&[_]u8{0} ** 96); // superblock placeholder

    try w.writeDir(root, src, builder.inode_count + 1);

    const bytes_used = try w.finish(&builder, root);

    std.log.info(
        "{d} inodes, {d} blocks + {d} tail fragments copied verbatim ({s}), {d} blocks stored raw, {d} sparse, {d} files deduped ({d} bytes), {d} bytes",
        .{
            builder.inode_count,
            w.blocks_copied,
            w.frags_copied,
            if ((w.compressor orelse SQFS_COMP_ZSTD) == SQFS_COMP_GZIP) "gzip" else "zstd",
            w.blocks_raw,
            w.blocks_sparse,
            w.files_deduped,
            w.bytes_deduped,
            bytes_used,
        },
    );
}
