// Dedup keys from the btrfs checksum tree: identify candidate duplicate
// files without hashing their contents. btrfs already stores a checksum
// (crc32c by default) for every on-disk sector; fetch those with
// BTRFS_IOC_TREE_SEARCH_V2 and fold them - together with the file's extent
// layout - into a 64-bit key. Equal keys only nominate candidates: the
// csums cover on-disk (possibly compressed) bytes and the key is a lossy
// hash, so the caller must confirm byte identity itself.

const std = @import("std");
const linux = std.os.linux;

const SearchKey = extern struct {
    tree_id: u64,
    min_objectid: u64,
    max_objectid: u64,
    min_offset: u64,
    max_offset: u64,
    min_transid: u64 = 0,
    max_transid: u64 = std.math.maxInt(u64),
    min_type: u32,
    max_type: u32,
    nr_items: u32 = 0,
    unused: u32 = 0,
    unused1: u64 = 0,
    unused2: u64 = 0,
    unused3: u64 = 0,
    unused4: u64 = 0,
};

const SearchArgsV2 = extern struct {
    key: SearchKey,
    buf_size: u64,
    // result buffer follows in memory
};

const FsInfoArgs = extern struct {
    max_id: u64,
    num_devices: u64,
    fsid: [16]u8,
    nodesize: u32,
    sectorsize: u32,
    clone_alignment: u32,
    csum_type: u16,
    csum_size: u16,
    flags: u64,
    generation: u64,
    metadata_uuid: [16]u8,
    reserved: [944]u8,
};

const BTRFS_IOC_TREE_SEARCH_V2 = linux.IOCTL.IOWR(0x94, 17, SearchArgsV2);
const BTRFS_IOC_FS_INFO = linux.IOCTL.IOR(0x94, 31, FsInfoArgs);
const BTRFS_FS_INFO_FLAG_CSUM_INFO: u64 = 1 << 0;

const BTRFS_CSUM_TREE_OBJECTID: u64 = 7;
const BTRFS_EXTENT_CSUM_OBJECTID: u64 = 0xFFFFFFFFFFFFFFF6; // (u64)-10
const BTRFS_EXTENT_DATA_KEY: u32 = 108;
const BTRFS_EXTENT_CSUM_KEY: u32 = 128;
const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

const search_buf_size = 256 * 1024;
const header_size = 32; // struct btrfs_ioctl_search_header

const Item = struct {
    offset: u64, // key offset: file offset (EXTENT_DATA) or disk bytenr (EXTENT_CSUM)
    data: []const u8,
};

// Items are packed back to back in the result buffer, each a 32-byte header
// (transid, objectid, offset, type, len) followed by len bytes of item data.
const ItemIter = struct {
    buf: []const u8,
    remaining: u32,
    pos: usize = 0,

    fn next(it: *ItemIter) ?Item {
        if (it.remaining == 0) return null;
        it.remaining -= 1;
        const h = it.buf[it.pos..];
        const len = std.mem.readInt(u32, h[28..32], .little);
        const item = Item{
            .offset = std.mem.readInt(u64, h[16..24], .little),
            .data = h[header_size .. header_size + len],
        };
        it.pos += header_size + len;
        return item;
    }
};

// struct btrfs_file_extent_item, minus the inline case
const ExtentRec = struct {
    file_off: u64,
    extent_type: u8,
    compression: u8,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
};

fn hashInt(h: *std.hash.Wyhash, v: u64) void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    h.update(&b);
}

pub const Dedup = struct {
    alloc: std.mem.Allocator,
    enabled: bool,
    sectorsize: u64 = 4096,
    csum_size: u64 = 4,
    nodesize: u64 = 16384,
    args_mem: []u64, // SearchArgsV2 followed by the result buffer

    pub fn init(alloc: std.mem.Allocator, fs_fd: linux.fd_t) !Dedup {
        var d = Dedup{
            .alloc = alloc,
            .enabled = true,
            .args_mem = try alloc.alloc(u64, (@sizeOf(SearchArgsV2) + search_buf_size) / 8),
        };
        var fi = std.mem.zeroes(FsInfoArgs);
        fi.flags = BTRFS_FS_INFO_FLAG_CSUM_INFO;
        const rc = linux.ioctl(fs_fd, BTRFS_IOC_FS_INFO, @intFromPtr(&fi));
        if (@as(isize, @bitCast(rc)) < 0) {
            d.enabled = false; // not btrfs: no keys, dedup is off
        } else {
            if (fi.sectorsize != 0) d.sectorsize = fi.sectorsize;
            if (fi.nodesize != 0) d.nodesize = fi.nodesize;
            // old kernels don't fill the csum info; they only support crc32c (4 bytes)
            if (fi.flags & BTRFS_FS_INFO_FLAG_CSUM_INFO != 0 and fi.csum_size != 0)
                d.csum_size = fi.csum_size;
        }
        return d;
    }

    /// 64-bit content key for the file, or null when unavailable. Any
    /// failure disables dedup for the rest of the run rather than failing
    /// the conversion.
    pub fn fileKey(d: *Dedup, fd: linux.fd_t, ino: u64, size: u64) ?u64 {
        if (!d.enabled) return null;
        return d.computeKey(fd, ino, size) catch {
            d.enabled = false;
            return null;
        };
    }

    // One TREE_SEARCH_V2 round. The returned iterator points into args_mem,
    // so it must be fully consumed before the next runSearch call.
    fn runSearch(d: *Dedup, fd: linux.fd_t, sk: SearchKey) !ItemIter {
        const args: *SearchArgsV2 = @ptrCast(d.args_mem.ptr);
        args.key = sk;
        args.key.nr_items = std.math.maxInt(u32);
        args.buf_size = search_buf_size;
        const rc = linux.ioctl(fd, BTRFS_IOC_TREE_SEARCH_V2, @intFromPtr(args));
        if (@as(isize, @bitCast(rc)) < 0) return error.TreeSearchFailed;
        return .{
            .buf = std.mem.sliceAsBytes(d.args_mem)[@sizeOf(SearchArgsV2)..],
            .remaining = args.key.nr_items,
        };
    }

    fn computeKey(d: *Dedup, fd: linux.fd_t, ino: u64, size: u64) !u64 {
        var h = std.hash.Wyhash.init(0xb7df5);
        hashInt(&h, size);
        var recs = std.ArrayListUnmanaged(ExtentRec){};
        defer recs.deinit(d.alloc);
        var next_off: u64 = 0;
        while (true) {
            var it = try d.runSearch(fd, .{
                .tree_id = 0, // 0 = the subvolume `fd` lives in
                .min_objectid = ino,
                .max_objectid = ino,
                .min_type = BTRFS_EXTENT_DATA_KEY,
                .max_type = BTRFS_EXTENT_DATA_KEY,
                .min_offset = next_off,
                .max_offset = std.math.maxInt(u64),
            });
            if (it.remaining == 0) break;
            // Stash the batch first: hashing a regular extent runs a csum
            // search, which reuses the buffer `it` points into.
            recs.clearRetainingCapacity();
            var last: u64 = 0;
            while (it.next()) |item| {
                last = item.offset;
                const data = item.data;
                if (data.len < 21) return error.BadExtentItem;
                if (data[20] == BTRFS_FILE_EXTENT_INLINE) {
                    // an inline extent is always a file's sole extent; its
                    // payload lives in the leaf and has no data csums, so
                    // hash the (possibly compressed) payload itself
                    h.update("i");
                    h.update(data[16..17]); // compression
                    h.update(data[21..]);
                    hashInt(&h, item.offset);
                    continue;
                }
                if (data.len < 53) return error.BadExtentItem;
                try recs.append(d.alloc, .{
                    .file_off = item.offset,
                    .extent_type = data[20],
                    .compression = data[16],
                    .disk_bytenr = std.mem.readInt(u64, data[21..29], .little),
                    .disk_num_bytes = std.mem.readInt(u64, data[29..37], .little),
                    .offset = std.mem.readInt(u64, data[37..45], .little),
                    .num_bytes = std.mem.readInt(u64, data[45..53], .little),
                });
            }
            for (recs.items) |r| {
                hashInt(&h, r.file_off);
                if (r.extent_type == BTRFS_FILE_EXTENT_PREALLOC or r.disk_bytenr == 0) {
                    h.update("h"); // hole / unwritten: reads as zeros
                    hashInt(&h, r.num_bytes);
                    continue;
                }
                h.update("r");
                h.update(&[1]u8{r.compression});
                hashInt(&h, r.offset);
                hashInt(&h, r.num_bytes);
                // csums cover on-disk bytes: the whole extent when compressed
                // (it is read in full), only the referenced part when not
                const cs_start = if (r.compression != 0) r.disk_bytenr else r.disk_bytenr + r.offset;
                const cs_len = if (r.compression != 0) r.disk_num_bytes else r.num_bytes;
                const covered = try d.hashCsums(fd, cs_start, cs_start + cs_len, &h);
                if (covered == 0) {
                    // nodatasum extent: only sharing the physical extent
                    // (reflink) can vouch for the data
                    h.update("b");
                    hashInt(&h, r.disk_bytenr);
                }
            }
            if (last == std.math.maxInt(u64)) break;
            next_off = last + 1;
        }
        return h.final();
    }

    // Folds the csum-tree checksums covering disk range [start, end) into
    // the hasher. Returns how many bytes they covered (0 for nodatasum).
    fn hashCsums(d: *Dedup, fd: linux.fd_t, start: u64, end: u64, h: *std.hash.Wyhash) !u64 {
        var covered: u64 = 0;
        // adjacent extents' csums get merged into one item, so the item
        // covering `start` can be keyed up to a full leaf of csums earlier
        const max_item_span = d.nodesize / d.csum_size * d.sectorsize;
        var next = start -| max_item_span;
        while (next < end) {
            var it = try d.runSearch(fd, .{
                .tree_id = BTRFS_CSUM_TREE_OBJECTID,
                .min_objectid = BTRFS_EXTENT_CSUM_OBJECTID,
                .max_objectid = BTRFS_EXTENT_CSUM_OBJECTID,
                .min_type = BTRFS_EXTENT_CSUM_KEY,
                .max_type = BTRFS_EXTENT_CSUM_KEY,
                .min_offset = next,
                .max_offset = end - 1,
            });
            if (it.remaining == 0) break;
            while (it.next()) |item| {
                const item_start = item.offset;
                const item_end = item_start + item.data.len / d.csum_size * d.sectorsize;
                if (item_end > start and item_start < end) {
                    const lo = @max(start, item_start);
                    const hi = @min(end, item_end);
                    const a: usize = @intCast((lo - item_start) / d.sectorsize * d.csum_size);
                    const b: usize = @intCast((hi - item_start + d.sectorsize - 1) / d.sectorsize * d.csum_size);
                    h.update(item.data[a..b]);
                    covered += hi - lo;
                }
                next = item_start + 1;
            }
        }
        return covered;
    }
};
