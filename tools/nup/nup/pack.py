"""NUP packer: dump directory tree -> .nup container.

Implements the producer conformance rules of SPEC.md v1:
- canonical tree shape (exefs/, romfs/), .listing artifacts excluded
- bytewise-sorted children, contiguous child slots
- per-file SHA-256, dedup by hash, 16-byte extent alignment
- per-file zstd with raw fallback, content size embedded in frame
- build ID TLV (ModuleId from exefs/main) when the dump provides it
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

    def __init__(self, kind: int, src: str, title_id: int = 0, version: int = 0,
                 flags: int = 0) -> None:
        self.kind = kind
        self.src = src
        self.title_id = title_id
        self.version = version
        self.flags = flags
        self.npdm: bytes | None = None
        self.build_id: bytes | None = None


def _find_npdm(src: str) -> str | None:
    for cand in ("exefs/main.npdm", "main.npdm"):
        p = os.path.join(src, cand)
        if os.path.isfile(p):
            return p
    return None


def _read_build_id(src: str) -> bytes | None:
    """ModuleId: bytes 0x40..0x60 of exefs/main (NSO0/NRO0 build-id field).

    Returns None when main is absent, shorter than 0x60 bytes, or has an
    unknown magic - the TLV is optional metadata.
    """
    for cand in ("exefs/main", "main"):
        p = os.path.join(src, cand)
        if os.path.isfile(p):
            with open(p, "rb") as fh:
                head = fh.read(0x60)
            if len(head) == 0x60 and (head[:4] == b"NSO0" or head[0x10:0x14] == b"NRO0"):
                return head[0x40:0x60]
            return None
    return None


def _resolve_title_id(pkg: PackInput, override: int | None) -> None:
    npdm_path = _find_npdm(pkg.src)
    if npdm_path:
        with open(npdm_path, "rb") as fh:
            pkg.npdm = fh.read()
        pid = parse_npdm_program_id(pkg.npdm)
        if pid is not None and pid != 0:
            pkg.title_id = pid
    pkg.build_id = _read_build_id(pkg.src)
    if override is not None:
        pkg.title_id = override


def _looks_like_content(d: str) -> bool:
    return os.path.isdir(os.path.join(d, "exefs")) or os.path.isdir(os.path.join(d, "romfs"))


def _collect_updates(upd_dir: str, base_title_id: int, flags: int) -> list[PackInput]:
    """updates/<decimal version>/ content dirs; flags propagates standalone_update."""
    out: list[PackInput] = []
    for name in sorted(os.listdir(upd_dir)):
        p = os.path.join(upd_dir, name)
        if not _DEC.match(name) or not os.path.isdir(p) or not _looks_like_content(p):
            continue
        upd = PackInput(F.KIND_UPDATE, p, version=int(name, 10), flags=flags)
        _resolve_title_id(upd, None)
        if upd.title_id == 0:
            upd.title_id = base_title_id
        out.append(upd)
    return out


def discover(src: str, base_title_id: int | None) -> list[PackInput]:
    """Discover packages in a dump directory (SPEC §4.1.3 conventions)."""
    packages: list[PackInput] = []
    upd_dir = os.path.join(src, "updates")
    has_updates = os.path.isdir(upd_dir)

    if os.path.isdir(os.path.join(src, "base")):
        base = PackInput(F.KIND_BASE, os.path.join(src, "base"))
        _resolve_title_id(base, base_title_id)
        packages.append(base)
        if has_updates:
            packages.extend(_collect_updates(upd_dir, base.title_id, flags=0))
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
    elif has_updates:
        # Update-only dump:
        # every update package carries standalone_update (SPEC §4.1.2, flags
        # bit 0 at offset 0x19). DLC may still ride along in dlc/.
        packages.extend(_collect_updates(upd_dir, base_title_id or 0,
                                         flags=F.PKG_FLAG_STANDALONE_UPDATE))
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
            f"pack: {src!r} is neither a dump bundle (base/updates/dlc), an update-only "
            f"dump (updates/), nor a content directory (exefs/ or romfs/)")
    if not packages:
        raise SystemExit(f"pack: no packages found in {src!r}")
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


def _meta_block(pkg: PackInput, dump_label: str, app_extra: bytes = b"") -> bytes:
    recs: list[tuple[int, bytes]] = []
    if pkg.npdm:
        recs.append((F.TLV_NPDM, pkg.npdm))
    if pkg.build_id:
        recs.append((F.TLV_BUILD_ID, pkg.build_id))
    recs.append((F.TLV_SOURCE_DUMP, dump_label.encode("utf-8")))
    if app_extra:
        # merge prebuilt application-level TLVs (names/icons/display version)
        pos = 0
        while pos + 8 <= len(app_extra):
            t, _r, size = F._tlv_s.unpack_from(app_extra, pos)
            recs.append((t, app_extra[pos + 8:pos + 8 + size]))
            pos += 8 + size
    recs.sort(key=lambda t: t[0])
    deduped: list[tuple[int, bytes]] = []
    for rec in recs:  # app_extra may repeat per-package types; keep first
        if deduped and deduped[-1][0] == rec[0]:
            continue
        deduped.append(rec)
    out = bytearray()
    for t, payload in deduped:
        out += F._tlv_s.pack(t, 0, len(payload))
        out += payload
    return bytes(out)


def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _app_meta(names: dict[str | None, str] | None, icons: dict[str | None, str] | None,
              display_version: str | None, dump_label: str) -> bytes:
    """Application-level meta TLVs (SPEC §6.1): names/icons localized, plus
    display version and provenance. Attached to the base package (or first)."""
    recs: list[tuple[int, bytes]] = []
    names = names or {}
    icons = icons or {}
    if names.get(None):
        recs.append((F.TLV_TITLE_NAME, names[None].encode("utf-8")))
    if names.keys() - {None}:
        body = bytearray()
        for lang in sorted(k for k in names if k is not None):
            tag = lang.lower().encode("ascii")
            if not 0 < len(tag) <= 255:
                raise SystemExit(f"pack: bad language tag {lang!r}")
            body += bytes([len(tag)]) + tag
            data = names[lang].encode("utf-8")
            body += struct.pack("<I", len(data)) + data
        recs.append((F.TLV_LOCALIZED_TITLES, bytes(body)))
    if icons.get(None):
        recs.append((F.TLV_ICON, _read_file(icons[None])))
    if icons.keys() - {None}:
        body = bytearray()
        for lang in sorted(k for k in icons if k is not None):
            tag = lang.lower().encode("ascii")
            if not 0 < len(tag) <= 255:
                raise SystemExit(f"pack: bad language tag {lang!r}")
            body += bytes([len(tag)]) + tag
            data = _read_file(icons[lang])
            body += struct.pack("<I", len(data)) + data
        recs.append((F.TLV_LOCALIZED_ICONS, bytes(body)))
    if display_version:
        recs.append((F.TLV_DISPLAY_VERSION, display_version.encode("utf-8")))
    recs.append((F.TLV_SOURCE_DUMP, dump_label.encode("utf-8")))
    recs.sort(key=lambda t: t[0])  # deterministic order
    out = bytearray()
    for t, payload in recs:
        out += F._tlv_s.pack(t, 0, len(payload)) + payload
    return bytes(out)


def pack(out_path: str, src: str, *, level: int = 3, keep_listings: bool = False,
         base_title_id: int | None = None, display_version: str | None = None,
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

    # Package records; exefs/romfs located from root children by name.
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
        app_extra = _app_meta(names, icons, display_version, dump_label)
        app_pkg_idx = next((i for i, p in enumerate(packages) if p.kind == F.KIND_BASE), 0)
        for i, pkg in enumerate(packages):
            block = _meta_block(pkg, dump_label, app_extra if i == app_pkg_idx else b"")
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

        toc_sha = hashlib.sha256(toc).digest()
        superblock = F.pack_super(F.MAGIC, F.HEADER_SIZE, 1, F.HEADER_SIZE, toc_size,
                                  toc_sha, blob_offset, file_size, len(pkg_records), 0,
                                  uuid)
        out.seek(0)
        out.write(superblock)
        out.write(toc)
        out.truncate(file_size)
    return packages
