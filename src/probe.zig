// Probe: read btrfs encoded (compressed) extents of a file and report their
// geometry. Dumps the first extent's raw bytes to "extent0.zst".
const std = @import("std");
const linux = std.os.linux;

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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    if (args.len < 2) return error.Usage;

    const file = try std.fs.cwd().openFile(args[1], .{});
    defer file.close();
    const size = (try file.stat()).size;

    var buf: [256 * 1024]u8 = undefined;
    var off: u64 = 0;
    var idx: usize = 0;
    const stdout = std.io.getStdOut().writer();
    while (off < size) : (idx += 1) {
        var iov = [_]std.posix.iovec{.{ .base = &buf, .len = buf.len }};
        var ea = std.mem.zeroes(EncodedIoArgs);
        ea.iov = &iov;
        ea.iovcnt = 1;
        ea.offset = @intCast(off);
        const rc = linux.ioctl(file.handle, BTRFS_IOC_ENCODED_READ, @intFromPtr(&ea));
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            try stdout.print("ioctl failed at off={d}: errno={d}\n", .{ off, -signed });
            return error.IoctlFailed;
        }
        const encoded_len: usize = @intCast(rc);
        try stdout.print(
            "extent {d}: file_off={d} encoded_len={d} len={d} unencoded_len={d} unencoded_off={d} compression={d} magic={x:0>2}{x:0>2}{x:0>2}{x:0>2}\n",
            .{ idx, off, encoded_len, ea.len, ea.unencoded_len, ea.unencoded_offset, ea.compression, buf[0], buf[1], buf[2], buf[3] },
        );
        if (idx == 0 and ea.compression != 0) {
            try std.fs.cwd().writeFile(.{ .sub_path = "extent0.zst", .data = buf[0..encoded_len] });
        }
        if (ea.len == 0) break;
        off += ea.len;
    }
}
