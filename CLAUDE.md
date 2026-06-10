# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`btrfs2squashfs` converts a directory on a compressed btrfs filesystem into a
squashfs v4 image **without recompressing file data**. It copies the already-
compressed bytes verbatim out of btrfs extents and into squashfs blocks. The
core insight (see the header comment in `src/main.zig`) is that btrfs stores
each 128 KiB chunk as an independent standard zstd frame / zlib stream, and
squashfs with a 128 KiB block size stores each block the same way — so the
compressed bytes are interchangeable.

Built with Zig 0.14.1.

## Commands

```sh
zig build                 # builds both executables into zig-out/bin/
sudo zig-out/bin/btrfs2squashfs <src-dir> <out.squashfs>   # needs CAP_SYS_ADMIN
sudo zig-out/bin/btrfs-probe-extents <file>                 # dump extent geometry
```

Do **not** use `zig build run` — `BTRFS_IOC_ENCODED_READ` requires
`CAP_SYS_ADMIN`, so the binary must be launched manually with `sudo` after
building.

```sh
tests/run.sh              # end-to-end tests (self-elevates with sudo)
COVERAGE=1 tests/run.sh   # same, plus kcov line coverage in zig-out/coverage/
```

Coverage uses `kcov` (reads the debug binary's DWARF — no instrumentation, a
plain `zig build` suffices). It runs the converter under kcov for each algo,
merges the runs, and prints a per-file summary; open
`zig-out/coverage/merged/index.html` for line detail. Currently ~98% of
`src/main.zig` + `src/dedup.zig`; the gaps are error/edge paths (usage error,
rare zstd header variants, dedup-disabled and nodatasum fallbacks).

`tests/run.sh` is the test suite (there is no lint config or CI). It builds a
real compressed btrfs loop filesystem in `/var/tmp` for each of zstd/zlib/lzo,
populates it with generated payloads (multi-block, incompressible, inline,
sparse 5 GiB, duplicates, hard links, symlinks, special files), converts it,
and asserts the squashfs round-trips byte-for-byte (`unsquashfs` + `diff -r`),
preserves metadata, deduplicates, and copies verbatim where expected. It builds
as the invoking user, then re-execs under `sudo` (needs loop mount + mknod +
`CAP_SYS_ADMIN`). Use `/var/tmp`, never `/tmp` — the payloads are large.

`BTRFS_IOC_ENCODED_READ` requires `CAP_SYS_ADMIN`, so real runs need `sudo`.

## Architecture

Three source files, two executables:

- `src/main.zig` — the `btrfs2squashfs` converter (the whole program).
- `src/dedup.zig` — the `Dedup` struct, imported by main; a standalone module.
- `src/probe.zig` — `btrfs-probe-extents`, an independent debugging tool with
  its own `main`. Not part of the converter.

### Conversion pipeline (`src/main.zig`)

Two phases, both driven from `main`:

1. **Scan** (`Builder`): walk the source tree into a `Node` tree, intern uid/gid
   into an id table, and assign inode numbers post-order (`Builder.number`).
2. **Write** (`Writer`): walk the `Node` tree depth-first (`writeDir`), emitting
   squashfs structures to the output file as it goes, then `finish` writes the
   metadata/fragment/id tables and back-patches the 96-byte superblock at
   offset 0.

### Key invariants and tricky bits

- **Single compressor lock.** A squashfs image has one compressor. The first
  verbatim copy decides it (`Writer.lockCompressor`: zstd→zstd, zlib→gzip);
  afterwards extents of the *other* algorithm can't be copied and fall back to
  raw uncompressed blocks. Code that adds new verbatim-copy paths must respect
  `lockCompressor`.
- **Verbatim vs. fallback** lives in `produceBlock` / `produceTailFragment`.
  A copy is valid only when the btrfs extent is *exactly* one squashfs block
  (right offset, decompresses to exactly `span`). Otherwise the block is
  pread decompressed and stored raw, or stored sparse if all-zero. btrfs lzo
  cannot be copied at all (segmented format).
- **zstd frame trimming** (`zstdFrameParse`): btrfs pads encoded data to the
  sector size but squashfs zstd decompressors reject trailing garbage, so the
  exact frame end is computed by walking block headers. The frame's *declared
  content size* — not `unencoded_len` — is the authority on decompressed size
  (inline extents understate `unencoded_len`). zlib needs no trimming.
- **Tail fragments** (`produceTailFragment`): a file's final partial block is
  stored as a fragment when its extent decompresses to more than the tail; the
  inode references only the first `tail` bytes. One fragment per tail (packing
  several would require recompression).
- **`produce*` vs `write*`.** `produceBlock`/`produceTailFragment` generate a
  block's bytes **without writing**. `writeBlock` etc. produce-then-emit. This
  split exists so dedup can regenerate a candidate's blocks and compare them
  without buffering.
- **Dedup** (`src/dedup.zig` + `Writer.matchesRecord`): candidate duplicates
  are found by hashing the per-sector checksums btrfs already keeps in its csum
  tree (read via `BTRFS_IOC_TREE_SEARCH_V2` — no checksum is computed here) into
  a lossy 64-bit `fileKey`. A matching key only *nominates*; it is confirmed by
  re-producing the new file's blocks and byte-comparing them against the earlier
  copy **pread back from the output image** (the output file is opened with
  `.read = true` for this). On confirmation nothing is written and the inode
  points at the earlier copy. Any btrfs/ioctl failure disables dedup for the
  rest of the run rather than aborting (`Dedup.enabled`).

### squashfs format details to keep in mind

- Metadata tables (inode, directory) are emitted **uncompressed** via
  `emitMetaTable` (u16 length header with bit 15 set). Fragment and id tables
  go through `emitIndexedTable` (data blocks + u64 offset index). Superblock
  flags `NOI | NOID` reflect this.
- Helpers `metaBlockOf` / `metaOffsetOf` translate a byte position in a metadata
  stream into the (block, offset) reference squashfs inodes use.
- Files needing 64-bit start/size emit the *extended* file inode (type 9);
  directories larger than 64 KiB are unsupported (`DirTooLargeForBasicInode`).

## Limitations (POC)

No xattrs; directory listings must be < 64 KiB. btrfs lzo extents are never
copied verbatim. The output file is created with `O_EXCL` and mode `0o600`.
