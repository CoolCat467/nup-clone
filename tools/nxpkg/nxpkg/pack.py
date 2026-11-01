"""NXP packer: dump directory tree -> .nxp container.

Implements the producer conformance rules of SPEC.md v1:
- canonical tree shape (exefs/, romfs/), .listing artifacts excluded
- bytewise-sorted children, contiguous child slots
- per-file SHA-256, dedup by hash, 16-byte extent alignment
- per-file zstd with raw fallback, content size embedded in frame
- derived UUID, deterministic output for a given zstd version
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import sys

try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None

from . import format as F

ARTIFACT_NAMES = {b".listing"}  # SPEC §7.3 reserved artifact names
FILE_TAG = 0x8000_0000  # child-slot marker: slot >= FILE_TAG references files[]
_DEC = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-fA-F]{16}$")


def have_zstd() -> bool:
    return zstandard is not None


def parse_npdm_program_id(data: bytes) -> int | None:
    """Extract the program ID from an NPDM (any known header revision).

    ACI0 layout: magic 'ACI0' (4), reserved (0xC), program id (u64 LE) at +0x10.
    """
    off = data.find(b"ACI0")
    if off < 0 or off + 0x18 > len(data):
        return None
    return struct.unpack_from("<Q", data, off + 0x10)[0]


class DirObj:
    __slots__ = ("name", "children", "id", "first_child", "child_count")

    def __init__(self, name: bytes) -> None:
        self.name = name
        self.children: list[DirObj | FileObj] = []
        self.id = -1
        self.first_child = 0
        self.child_count = 0


class FileObj:
    __slots__ = ("name", "src_path", "size", "sha256", "extent_offset",
                 "extent_size", "codec", "codec_flags")

    def __init__(self, name: bytes, src_path: str) -> None:
        self.name = name
        self.src_path = src_path
        self.size = 0
        self.sha256 = b"\0" * 32
        self.extent_offset = 0
        self.extent_size = 0
        self.codec = F.CODEC_RAW
        self.codec_flags = 0


class PackInput:
    """One package to store: kind, ids, and the source directory of its tree."""

    def __init__(self, kind: int, src: str, title_id: int = 0, version: int = 0) -> None:
        self.kind = kind
        self.src = src
        self.title_id = title_id
        self.version = version
        self.npdm: bytes | None = None


def _find_npdm(src: str) -> str | None:
    for cand in ("exefs/main.npdm", "main.npdm"):
        p = os.path.join(src, cand)
        if os.path.isfile(p):
            return p
    return None


def _resolve_title_id(pkg: PackInput, override: int | None) -> None:
    npdm_path = _find_npdm(pkg.src)
    if npdm_path:
        with open(npdm_path, "rb") as fh:
            pkg.npdm = fh.read()
        pid = parse_npdm_program_id(pkg.npdm)
        if pid is not None and pid != 0:
            pkg.title_id = pid
    if override is not None:
        pkg.title_id = override


def _looks_like_content(d: str) -> bool:
    return os.path.isdir(os.path.join(d, "exefs")) or os.path.isdir(os.path.join(d, "romfs"))


def discover(src: str, base_title_id: int | None) -> list[PackInput]:
    """Discover packages in a dump directory (SPEC §4.1.3 conventions)."""
    packages: list[PackInput] = []

    if os.path.isdir(os.path.join(src, "base")):
        base = PackInput(F.KIND_BASE, os.path.join(src, "base"))
        _resolve_title_id(base, base_title_id)
        packages.append(base)
        upd_dir = os.path.join(src, "updates")
        if os.path.isdir(upd_dir):
            for name in sorted(os.listdir(upd_dir)):
                p = os.path.join(upd_dir, name)
                if not _DEC.match(name) or not os.path.isdir(p) or not _looks_like_content(p):
                    continue
                upd = PackInput(F.KIND_UPDATE, p, version=int(name, 10))
                _resolve_title_id(upd, None)
                if upd.title_id == 0:
                    upd.title_id = base.title_id
                packages.append(upd)
        dlc_dir = os.path.join(src, "dlc")
        if os.path.isdir(dlc_dir):
            for name in sorted(os.listdir(dlc_dir)):
                tdir = os.path.join(dlc_dir, name)
                if not _HEX.match(name) or not os.path.isdir(tdir):
                    continue
                for idx in sorted(os.listdir(tdir)):
                    cdir = os.path.join(tdir, idx)
                    if os.path.isdir(cdir) and _looks_like_content(cdir):
                        packages.append(PackInput(F.KIND_ADDON, cdir, title_id=int(name, 16)))
    elif _looks_like_content(src):
        base = PackInput(F.KIND_BASE, src)
        _resolve_title_id(base, base_title_id)
        packages.append(base)
    else:
        raise SystemExit(
            f"pack: {src!r} is neither a dump bundle (base/updates/dlc) nor a content "
            f"directory (exefs/ or romfs/)")
    return packages


class Tree:
    """Node store for one pack run (global across packages)."""

    def __init__(self, artifacts: set[bytes]) -> None:
        self.artifacts = artifacts
        self.dirs: list[DirObj] = []
        self.files: list[FileObj] = []
        self.children: list[int] = []  # serial ids; see assign()
        self.pool: dict[bytes, int] = {}
        self.pool_size = 0

    def intern(self, name: bytes) -> int:
        off = self.pool.get(name)
        if off is None:
            off = self.pool_size
            self.pool[name] = off
            self.pool_size += len(name)
        return off

    def add_tree(self, src: str) -> DirObj:
        return self._walk(src, b"")

    def _walk(self, src: str, name: bytes) -> DirObj:
        node = DirObj(name)
        try:
            entries = sorted(os.scandir(src),
                             key=lambda e: e.name.encode("utf-8", "surrogateescape"))
        except OSError as e:
            raise SystemExit(f"pack: cannot read {src}: {e}")
        for e in entries:
            ename = e.name.encode("utf-8", "surrogateescape")
            if e.is_dir(follow_symlinks=False):
                node.children.append(self._walk(e.path, ename))
            elif ename not in self.artifacts:
                node.children.append(FileObj(ename, e.path))
        return node

    def assign(self, roots: list[DirObj]) -> None:
        """Assign serial order: dirs pre-order, files in first-reference order,
        contiguous child slots per directory."""
        def rec(d: DirObj) -> int:
            did = len(self.dirs)
            d.id = did
            self.dirs.append(d)
            slot_base = len(self.children)
            self.children.extend([0] * len(d.children))
            for i, child in enumerate(d.children):
                if isinstance(child, FileObj):
                    self.children[slot_base + i] = FILE_TAG + len(self.files)
                    self.files.append(child)
            for i, child in enumerate(d.children):
                if isinstance(child, DirObj):
                    self.children[slot_base + i] = rec(child)
            d.first_child = slot_base
            d.child_count = len(d.children)
            return did

        for root in roots:
            rec(root)


def _meta_block(pkg: PackInput, display_version: str | None, dump_label: str) -> bytes:
    recs: list[tuple[int, bytes]] = []
    if pkg.npdm:
        recs.append((F.TLV_NPDM, pkg.npdm))
    if display_version:
        recs.append((F.TLV_DISPLAY_VERSION, display_version.encode("utf-8")))
    recs.append((F.TLV_SOURCE_DUMP, dump_label.encode("utf-8")))
    out = bytearray()
    for t, payload in recs:
        out += F._tlv_s.pack(t, 0, len(payload))
        out += payload
    return bytes(out)


def pack(out_path: str, src: str, *, level: int = 3, keep_listings: bool = False,
         base_title_id: int | None = None, display_version: str | None = None,
         progress=None) -> list[PackInput]:
    if os.path.exists(out_path):
        raise SystemExit(f"pack: refusing to overwrite {out_path}")
    if not have_zstd():
        print("pack: warning: zstandard not installed; writing raw (uncompressed) extents",
              file=sys.stderr)

    artifacts = set() if keep_listings else ARTIFACT_NAMES
    packages = discover(src, base_title_id)
    tree = Tree(artifacts)
    roots = [tree.add_tree(pkg.src) for pkg in packages]
    tree.assign(roots)

    dir_count = len(tree.dirs)
    file_count = len(tree.files)
    slot_count = len(tree.children)

    # Intern all names up front so pool_size is final before sizing the TOC.
    for d in tree.dirs:
        tree.intern(d.name)
    for fnode in tree.files:
        tree.intern(fnode.name)

    # Package records; exefs/romfs located from root children by name.
    pkg_records: list[F.Package] = []
    for pkg, root in zip(packages, roots):
        rec = F.Package(title_id=pkg.title_id, root_dir=root.id, version=pkg.version,
                        kind=pkg.kind)
        for child in root.children:
            if isinstance(child, DirObj):
                if child.name == b"exefs":
                    rec.exefs_dir = child.id
                elif child.name == b"romfs":
                    rec.romfs_dir = child.id
        pkg_records.append(rec)

    # UUID (SPEC §3.1): derived from package identities.
    h = hashlib.sha256()
    for rec in pkg_records:
        h.update(struct.pack("<QIB", rec.title_id, rec.version, rec.kind))
    uuid = h.digest()[:16]

    # ---- TOC plan ----
    toc_size = (F._toc_head_s.size + len(pkg_records) * F.PKG_SIZE
                + dir_count * F.DIR_SIZE + file_count * F.FILE_SIZE
                + slot_count * 4 + tree.pool_size)
    blob_offset = (F.HEADER_SIZE + toc_size + F.EXTENT_ALIGN - 1) & ~(F.EXTENT_ALIGN - 1)

    zc = zstandard.ZstdCompressor(level=level) if have_zstd() else None

    with open(out_path, "wb") as out:
        out.write(b"\0" * blob_offset)  # placeholder for header + TOC
        blob_cursor = blob_offset

        total = len(tree.files)
        seen: dict[bytes, tuple[int, int, int]] = {}  # sha256 -> (offset, size, codec)
        for i, fnode in enumerate(tree.files):
            with open(fnode.src_path, "rb") as fh:
                data = fh.read()
            fnode.size = len(data)
            fnode.sha256 = hashlib.sha256(data).digest()
            hit = seen.get(fnode.sha256)
            if hit is not None and fnode.size > 0:
                # Dedup (SPEC §4.6): identical content shares one extent.
                fnode.extent_offset, fnode.extent_size, fnode.codec = hit
            elif fnode.size == 0:
                fnode.extent_offset, fnode.extent_size, fnode.codec = 0, 0, F.CODEC_RAW
            else:
                payload, codec = data, F.CODEC_RAW
                if zc is not None:
                    comp = zc.compress(data)
                    if len(comp) < fnode.size:
                        payload, codec = comp, F.CODEC_ZSTD
                aligned = (blob_cursor + F.EXTENT_ALIGN - 1) & ~(F.EXTENT_ALIGN - 1)
                out.write(b"\0" * (aligned - blob_cursor))  # zero the gap
                blob_cursor = aligned
                fnode.extent_offset = blob_cursor
                fnode.extent_size = len(payload)
                fnode.codec = codec
                out.write(payload)
                blob_cursor += len(payload)
                seen[fnode.sha256] = (fnode.extent_offset, fnode.extent_size, fnode.codec)
            if progress:
                progress(i + 1, total, fnode)

        file_size = blob_cursor

        # ---- meta blocks (after blob region) ----
        meta_offsets: list[tuple[int, int]] = []
        dump_label = os.path.basename(os.path.normpath(src))
        for pkg in packages:
            block = _meta_block(pkg, display_version, dump_label)
            mo = blob_cursor  # == out.tell(); extents were appended sequentially
            out.write(block)
            blob_cursor += len(block)
            meta_offsets.append((mo, len(block)))
        file_size = blob_cursor

        # ---- serialize TOC ----
        toc = bytearray(toc_size)
        pos = F._toc_head_s.size
        for rec, (mo, ms) in zip(pkg_records, meta_offsets):
            F._pkg_s.pack_into(toc, pos, rec.title_id, rec.root_dir, rec.exefs_dir,
                               rec.romfs_dir, rec.version, rec.kind, rec.flags, 0,
                               mo, ms, 0)
            pos += F.PKG_SIZE
        for d in tree.dirs:
            off = tree.intern(d.name)
            F._dir_s.pack_into(toc, pos, off, len(d.name), d.first_child,
                               d.child_count, 0)
            pos += F.DIR_SIZE
        for fnode in tree.files:
            off = tree.intern(fnode.name)
            F._file_s.pack_into(toc, pos, off, len(fnode.name), 0, fnode.size,
                                fnode.sha256, fnode.extent_offset, fnode.extent_size,
                                fnode.codec, fnode.codec_flags, 0)
            pos += F.FILE_SIZE
        for cid in tree.children:
            if cid >= FILE_TAG:
                cid = dir_count + (cid - FILE_TAG)
            struct.pack_into("<I", toc, pos, cid)
            pos += 4
        pool_off = pos
        pool = bytearray(tree.pool_size)
        for name, off in tree.pool.items():
            pool[off:off + len(name)] = name
        toc[pool_off:pool_off + len(pool)] = pool
        F._toc_head_s.pack_into(toc, 0, F.TOC_MAGIC, len(pkg_records), dir_count,
                                file_count, pool_off, len(pool), 0)

        toc_sha = hashlib.sha256(toc).digest()
        superblock = F.pack_super(F.MAGIC, F.HEADER_SIZE, 1, F.HEADER_SIZE, toc_size,
                                  toc_sha, blob_offset, file_size, len(pkg_records), 0,
                                  uuid)
        out.seek(0)
        out.write(superblock)
        out.write(toc)
        out.truncate(file_size)
    return packages
