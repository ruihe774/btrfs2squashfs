#!/usr/bin/env bash
#
# End-to-end tests for btrfs2squashfs.
#
# Each case builds a real compressed btrfs filesystem on a loop device backed
# by a temp file in /var/tmp (NOT /tmp: the payloads include multi-GiB sparse
# files and large compressible data, which would blow up a tmpfs), populates
# it with on-the-fly payloads, converts it to squashfs, and checks the image
# round-trips byte-for-byte and preserves metadata.
#
# Needs root (loop mount + BTRFS_IOC_ENCODED_READ + mknod). The script builds
# the binary as the invoking user, then re-execs itself under sudo.
#
#   tests/run.sh            # run all cases
#   COVERAGE=1 tests/run.sh # also collect source coverage with kcov
#
# Coverage uses kcov (no instrumentation: it reads the binary's DWARF line
# info, so a plain debug `zig build` is enough). Results land in
# zig-out/coverage/ — open zig-out/coverage/merged/index.html for line detail.
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/zig-out/bin/btrfs2squashfs"
COVERAGE="${COVERAGE:-0}"
COVDIR="$REPO/zig-out/coverage"

if [ "$(id -u)" -ne 0 ]; then
    echo ">> building as $(id -un)"
    ( cd "$REPO" && zig build )
    [ "$COVERAGE" = 1 ] && command -v kcov >/dev/null || \
        { [ "$COVERAGE" = 1 ] && { echo "COVERAGE=1 but kcov not found"; exit 1; }; }
    echo ">> re-exec under sudo"
    exec sudo COVERAGE="$COVERAGE" "$0" "$@"
fi

[ -x "$BIN" ] || { echo "binary missing: $BIN (run 'zig build')"; exit 1; }
[ "$COVERAGE" = 1 ] && { rm -rf "$COVDIR"; mkdir -p "$COVDIR"; }

# Run the converter, under kcov when collecting coverage. Each case writes to
# its own kcov dir ($algo is in scope via the run_case caller); they are merged
# at the end.
convert() {
    if [ "$COVERAGE" = 1 ]; then
        kcov --include-path="$REPO/src" "$COVDIR/$algo" "$BIN" "$1" "$2"
    else
        "$BIN" "$1" "$2"
    fi
}

WORK=/var/tmp/btrfs2squashfs-tests
MNT="$WORK/mnt"
fails=0

cleanup() {
    umount "$MNT" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK" "$MNT"

# --------------------------------------------------------------- helpers

# deterministic, highly compressible text (so dup copies hash identically and
# btrfs actually compresses the extents -> exercises the verbatim-copy path)
gen_text() {
    local out="$1" n="$2"
    yes "lorem ipsum dolor sit amet consectetur adipiscing 0123456789" 2>/dev/null \
        | head -c "$n" > "$out" || true
}

# A line of attributes per entry: path, type, perms, and type-specific extras
# (symlink target / device numbers / regular-file size). Captures everything
# diff -r cannot: permissions, device major:minor, and the type itself.
emit_manifest() {
    ( cd "$1"
      find . -mindepth 1 -print0 | sort -z | while IFS= read -r -d '' p; do
          local kind perm extra=""
          kind=$(stat -c '%F' "$p")
          perm=$(stat -c '%a' "$p")
          case "$kind" in
            "symbolic link")        extra="-> $(readlink "$p")" ;;
            "character special file"|"block special file")
                                    extra="dev $(stat -c '%t:%T' "$p")" ;;
            "regular file"|"regular empty file")
                                    extra="size $(stat -c '%s' "$p")" ;;
          esac
          printf '%s\t%s\t%s\t%s\n' "$p" "$kind" "$perm" "$extra"
      done )
}

# extract "field-name <number>" from the converter's summary line
stat_num() { sed -nE "s/.*[, ]([0-9]+) $1.*/\1/p" <<<"$2"; }

check() {  # check <desc> <condition-result(0/1 via test)>
    if [ "$2" = 0 ]; then echo "    ok   - $1"; else echo "    FAIL - $1"; fails=$((fails+1)); fi
}

# --------------------------------------------------------------- payload tree

populate() {
    local src="$1"
    mkdir -p "$src/d/deep" "$src/specials"

    gen_text "$src/big.dat" 8000000          # multi-block, verbatim copy
    cp "$src/big.dat" "$src/dup.dat"         # identical content -> dedup
    ln "$src/big.dat" "$src/hard.dat"        # hard link -> dedup (same inode)
    head -c 1500000 /dev/urandom > "$src/rand.bin"   # incompressible -> raw blocks
    gen_text "$src/exact.dat" 262144         # exactly 2 blocks, no tail
    gen_text "$src/small.txt" 5000           # sub-block tail (-> fragment)
    printf 'hi' > "$src/tiny.txt"            # inline extent
    : > "$src/empty.dat"                     # empty file
    gen_text "$src/d/deep/nested.txt" 30000  # nested dirs
    ln -s big.dat "$src/link"                # symlink

    # 5 GiB sparse file: size > 4 GiB exercises the 64-bit extended inode, and
    # the holes exercise sparse-block handling
    truncate -s 5G "$src/sparse.img"
    printf 'end' | dd of="$src/sparse.img" bs=1 seek=5000000000 conv=notrunc status=none

    # special files (root only)
    mknod "$src/specials/null_c" c 1 3
    mknod "$src/specials/loop_b" b 7 0
    mknod "$src/specials/pipe" p

    # distinctive permissions to confirm mode preservation
    chmod 600 "$src/small.txt"
    chmod 750 "$src/d"
    chmod 711 "$src/d/deep"
    sync
}

# --------------------------------------------------------------- one case

run_case() {  # run_case <algo> <expect_verbatim: yes|no>
    local algo="$1" expect_verbatim="$2"
    local img="$WORK/$algo.img" src="$MNT/src" out="$WORK/$algo.sqfs" dst="$WORK/$algo.dst"
    echo "== case: compress-force=$algo =="

    truncate -s 3G "$img"
    mkfs.btrfs -q -f "$img"
    mount -o "loop,compress-force=$algo" "$img" "$MNT"

    populate "$src"

    local log
    log=$(convert "$src" "$out" 2>&1)
    echo "    $(grep '^info:' <<<"$log" || echo "$log")"

    local copied deduped
    copied=$(sed -nE 's/.* ([0-9]+) blocks \+ .*/\1/p' <<<"$log")  # "N blocks + ..." = verbatim
    deduped=$(stat_num "files deduped" "$log")

    # structural sanity + extraction
    unsquashfs -q -d "$dst" "$out" >/dev/null
    check "unsquashfs succeeded" $?

    # content + symlink round-trip (specials excluded: diff would block on the fifo)
    if diff -r --no-dereference -x specials "$src" "$dst" >/dev/null; then
        check "content matches source" 0
    else
        check "content matches source" 1
        diff -r --no-dereference -x specials "$src" "$dst" | head
    fi

    # metadata round-trip (perms, types, device numbers, symlink targets, sizes)
    if diff <(emit_manifest "$src") <(emit_manifest "$dst") >/dev/null; then
        check "metadata matches source" 0
    else
        check "metadata matches source" 1
        diff <(emit_manifest "$src") <(emit_manifest "$dst") | head
    fi

    # dedup: dup.dat + hard.dat must both collapse onto big.dat
    check "dedup collapsed >=2 files (got ${deduped:-0})" "$([ "${deduped:-0}" -ge 2 ] && echo 0 || echo 1)"

    # verbatim copy: present for zstd/zlib, impossible for lzo (segmented format)
    if [ "$expect_verbatim" = yes ]; then
        check "blocks copied verbatim (got ${copied:-0})" "$([ "${copied:-0}" -gt 0 ] && echo 0 || echo 1)"
    else
        check "no verbatim copies for lzo (got ${copied:-0})" "$([ "${copied:-0}" -eq 0 ] && echo 0 || echo 1)"
    fi

    rm -rf "$src" "$dst"
    umount "$MNT"
    rm -f "$img" "$out"
}

# --------------------------------------------------------------- drive

run_case zstd yes
run_case zlib yes
run_case lzo  no

if [ "$COVERAGE" = 1 ]; then
    echo
    echo "== coverage (kcov, merged over all cases) =="
    kcov --merge "$COVDIR/merged" "$COVDIR/zstd" "$COVDIR/zlib" "$COVDIR/lzo" >/dev/null 2>&1
    json="$COVDIR/merged/kcov-merged/coverage.json"
    jq -r '.files[] | "    \(.percent_covered)%  \(.covered_lines)/\(.total_lines)  \(.file | sub(".*/";""))"' "$json"
    jq -r '"    -----\n    \(.percent_covered)%  \(.covered_lines)/\(.total_lines)  TOTAL"' "$json"
    echo "    html: $COVDIR/merged/index.html"
    # written under sudo; hand it back so it can be browsed/removed as the user
    [ -n "${SUDO_UID:-}" ] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$COVDIR"
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "ALL TESTS PASSED"
else
    echo "$fails CHECK(S) FAILED"
    exit 1
fi
