# btrfs2squashfs

Convert a directory on a compressed btrfs filesystem into a squashfs v4 image
**without recompressing file data**.

btrfs transparent compression stores each 128 KiB chunk of a file as an
independent, standard zstd frame (or zlib stream). squashfs, with its default
128 KiB block size, stores each block the same way. So the already-compressed
bytes can be copied **verbatim** out of btrfs extents (read via
`BTRFS_IOC_ENCODED_READ`) straight into squashfs data blocks — no decompress,
no recompress.

## Building

Built with **Zig 0.14.1**.

```sh
zig build        # builds both executables into zig-out/bin/
```

This produces two binaries:

- `btrfs2squashfs` — the converter.
- `btrfs-probe-extents` — a standalone debugging tool that dumps extent
  geometry for a file.

## Usage

```sh
sudo zig-out/bin/btrfs2squashfs <src-dir> <out.squashfs>
sudo zig-out/bin/btrfs-probe-extents <file>
```

`BTRFS_IOC_ENCODED_READ` requires `CAP_SYS_ADMIN`, so the converter must be run
with `sudo`. The output file is created with `O_EXCL` and mode `0o600`.

> Don't use `zig build run` — the binary needs `CAP_SYS_ADMIN` and must be
> launched manually under `sudo` after building.

## What it preserves

- **Verbatim compressed copy** where the btrfs extent maps exactly onto a
  squashfs block. The image is locked to a single compressor by the first
  verbatim copy (zstd → zstd, zlib → gzip); extents of the other algorithm
  then fall back to raw uncompressed blocks.
- **Tail fragments**: a file's final partial block is copied verbatim into a
  squashfs fragment block, with the inode referencing only the real tail bytes.
- **Raw fallback** for blocks that can't be copied verbatim (uncompressed,
  misaligned, or foreign-compressor extents) — still no recompression. All-zero
  blocks become sparse blocks.
- **Hard links**: names sharing a btrfs inode collapse onto one squashfs inode.
- **Deduplication**: distinct files with identical content are stored once.
  Candidates are found by hashing the per-sector checksums btrfs already keeps
  in its csum tree (via `BTRFS_IOC_TREE_SEARCH_V2`), then confirmed by
  byte-comparing the regenerated blocks against the earlier copy read back from
  the image.
- Symlinks, special files (devices, FIFOs, sockets), and metadata (uid/gid,
  mode, mtime).

## Comparison with other tools

| Tool | Recompresses data? | Random access in place? |
| --- | --- | --- |
| **btrfs2squashfs** | No — copies compressed bytes verbatim | Yes (squashfs mounts read-only) |
| `tar` (`--zstd`/`-z`) | Yes — decompresses from btrfs, recompresses into the archive | No — sequential stream; must extract first |
| `mksquashfs` | Yes — reads the files decompressed and recompresses every block | Yes, but only after the (re)compression pass |
| `btrfs send` | No | No — the stream must be `btrfs receive`d onto another btrfs filesystem first |

**Archiving tools (`tar`, `mksquashfs`) require recompression.** They read each
file through the kernel's transparent decompression and then compress it again
on the way into the archive. That spends CPU re-deriving data btrfs already
holds in compressed form, and the result generally differs byte-for-byte from
the original extents. btrfs2squashfs skips both steps by moving the
already-compressed bytes directly, so conversion is largely I/O-bound.

**`btrfs send` cannot be accessed in place.** It produces a serialized
replication stream, not a browsable filesystem: the data is unavailable until
it has been `btrfs receive`d onto another btrfs volume. It is also btrfs-to-
btrfs only. A squashfs image, by contrast, is a self-contained read-only
filesystem you can loop-mount and read directly.

## Limitations (POC)

- No xattrs.
- btrfs **lzo** extents are never copied verbatim — btrfs lzo is a segmented
  container format, not the plain `lzo1x` stream squashfs expects — so they
  fall back to raw uncompressed blocks.
- Metadata tables are stored uncompressed.

## Testing

```sh
tests/run.sh              # end-to-end tests (self-elevates with sudo)
COVERAGE=1 tests/run.sh   # same, plus kcov line coverage in zig-out/coverage/
```

`tests/run.sh` builds a real compressed btrfs loop filesystem in `/var/tmp` for
each of zstd/zlib/lzo, populates it with generated payloads (multi-block,
incompressible, inline, sparse 5 GiB, duplicates, hard links, symlinks, special
files), converts it, and asserts the squashfs round-trips byte-for-byte
(`unsquashfs` + `diff -r`), preserves metadata and hard links, deduplicates,
and copies verbatim where expected. It builds as the invoking user, then
re-execs under `sudo` (needs loop mount, `mknod`, and `CAP_SYS_ADMIN`).

Coverage uses `kcov` against the debug binary's DWARF (no instrumentation
needed); open `zig-out/coverage/merged/index.html` for line detail.

## How it works

See the header comment in `src/main.zig` for the full design, and `CLAUDE.md`
for an architecture overview. The pipeline has two phases: a **scan** that
walks the source tree and interns inode/uid/gid tables (collapsing hard links),
and a **write** that walks the tree depth-first emitting squashfs structures
and back-patches the superblock at the end.
