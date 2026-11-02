"""NUP packer: dump directory tree -> .nup container.

Writes the container: file extents (raw/zstd, deduped, 16-byte aligned),
per-package meta blocks, the TOC and the superblock. Dump discovery and
the tree model live in .discover; meta block assembly in .meta.

Implements the producer conformance rules of SPEC.md v1 and produces
deterministic output for a given zstd version.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys

try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None

from . import format as F
from . import meta as M
from .discover import ARTIFACT_NAMES, DirObj, FILE_TAG, PackInput, Tree, discover


def have_zstd() -> bool:
    return zstandard is not None


def _locate_content_dirs(packages: list[PackInput],
                         roots: list[DirObj]) -> list[F.Package]:
    """Package records; exefs/romfs located from root children by name."""
    pkg_records: list[F.Package] = []
    for pkg, root in zip(packages, roots):
        rec = F.Package(title_id=pkg.title_id, root_dir=root.id, version=pkg.version,
                        kind=pkg.kind, flags=pkg.flags)
        for child in root.children:
            if isinstance(child, DirObj):
                if child.name == b"exefs":
                    rec.exefs_dir = child.id
                elif child.name == b"romfs":
                    rec.romfs_dir = child.id
        pkg_records.append(rec)
    return pkg_records


def _derive_uuid(pkg_records: list[F.Package]) -> bytes:
    """UUID (SPEC §2.1): derived from package identities."""
    h = hashlib.sha256()
    for rec in pkg_records:
        h.update(struct.pack("<QIB", rec.title_id, rec.version, rec.kind))
    return h.digest()[:16]


def _write_extents(out, tree: Tree, zc, blob_cursor: int, progress) -> int:
    """Append file extents (dedup by hash, 16-byte aligned). Returns end offset."""
    total = len(tree.files)
    seen: dict[bytes, tuple[int, int, int]] = {}  # sha256 -> (offset, size, codec)
    for i, fnode in enumerate(tree.files):
        with open(fnode.src_path, "rb") as fh:
            data = fh.read()
        fnode.size = len(data)
        fnode.sha256 = hashlib.sha256(data).digest()
        hit = seen.get(fnode.sha256)
        if hit is not None and fnode.size > 0:
            # Dedup (SPEC §3.6): identical content shares one extent.
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
    return blob_cursor


def _write_meta_blocks(out, packages: list[PackInput], dump_label: str,
                       names, icons, display_version, blob_cursor: int,
                       publisher=None):
    """Append per-package meta blocks after the blob region.

    Returns (meta_offsets, end offset).
    """
    meta_offsets: list[tuple[int, int]] = []
    app_extra = M.app_meta(names, icons, display_version, dump_label,
                           publisher=publisher)
    app_pkg_idx = next((i for i, p in enumerate(packages) if p.kind == F.KIND_BASE), 0)
    for i, pkg in enumerate(packages):
        block = M.meta_block(pkg, dump_label, app_extra if i == app_pkg_idx else b"")
        mo = blob_cursor  # == out.tell(); extents were appended sequentially
        out.write(block)
        blob_cursor += len(block)
        meta_offsets.append((mo, len(block)))
    return meta_offsets, blob_cursor


def _build_toc(tree: Tree, pkg_records: list[F.Package],
               meta_offsets: list[tuple[int, int]],
               dir_count: int, file_count: int, toc_size: int) -> bytearray:
    """Serialize the TOC: package records, node arrays, children, string pool."""
    toc = bytearray(toc_size)
    pos = F._toc_head_s.size
    for rec, (mo, ms) in zip(pkg_records, meta_offsets):
        F._pkg_s.pack_into(toc, pos, rec.title_id, rec.root_dir, rec.exefs_dir,
                           rec.romfs_dir, rec.version, rec.kind, rec.flags, 0, 0,
                           mo, ms)
        pos += F.PKG_SIZE
    for d in tree.dirs:
        off = tree.intern(d.name)
        F._dir_s.pack_into(toc, pos, off, len(d.name), d.first_child,
                           d.child_count, 0)
        pos += F.DIR_SIZE
    for fnode in tree.files:
        off = tree.intern(fnode.name)
        F._file_s.pack_into(toc, pos, off, len(fnode.name), fnode.size,
                            fnode.extent_offset, fnode.extent_size, fnode.sha256,
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
    return toc


def pack(out_path: str, src: str, *, level: int = 3, keep_listings: bool = False,
         base_title_id: int | None = None, display_version: str | None = None,
         publisher: str | None = None,
         names: dict[str | None, str] | None = None,
         icons: dict[str | None, str] | None = None,
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

    pkg_records = _locate_content_dirs(packages, roots)
    uuid = _derive_uuid(pkg_records)

    # ---- TOC plan ----
    toc_size = (F._toc_head_s.size + len(pkg_records) * F.PKG_SIZE
                + dir_count * F.DIR_SIZE + file_count * F.FILE_SIZE
                + slot_count * 4 + tree.pool_size)
    blob_offset = (F.HEADER_SIZE + toc_size + F.EXTENT_ALIGN - 1) & ~(F.EXTENT_ALIGN - 1)

    zc = zstandard.ZstdCompressor(level=level) if have_zstd() else None

    with open(out_path, "wb") as out:
        out.write(b"\0" * blob_offset)  # placeholder for header + TOC
        blob_cursor = _write_extents(out, tree, zc, blob_offset, progress)
        dump_label = os.path.basename(os.path.normpath(src))
        meta_offsets, blob_cursor = _write_meta_blocks(out, packages, dump_label,
                                                       names, icons, display_version,
                                                       blob_cursor,
                                                       publisher=publisher)
        file_size = blob_cursor

        toc = _build_toc(tree, pkg_records, meta_offsets, dir_count, file_count,
                         toc_size)

        toc_sha = hashlib.sha256(toc).digest()
        superblock = F.pack_super(F.MAGIC, F.HEADER_SIZE, 1, F.HEADER_SIZE, toc_size,
                                  toc_sha, blob_offset, file_size, len(pkg_records), 0,
                                  uuid)
        out.seek(0)
        out.write(superblock)
        out.write(toc)
        out.truncate(file_size)
    return packages
