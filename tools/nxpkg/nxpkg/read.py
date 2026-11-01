"""NXP reader: validated parsing, virtual-tree access, extraction.

Reader conformance (SPEC §7.1): validate superblock, verify TOC SHA-256
before trusting TOC-derived values, bounds-check every offset/size, treat
title_id/version/NPDM/NACP as opaque, reject unknown codecs and flags.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import struct
from dataclasses import dataclass

from . import format as F


@dataclass(frozen=True)
class PackageInfo:
    index: int
    title_id: int
    kind: int
    version: int
    flags: int
    root_dir: int
    exefs_dir: int
    romfs_dir: int
    meta_offset: int
    meta_size: int

    @property
    def kind_name(self) -> str:
        return F.KIND_NAMES.get(self.kind, f"kind{self.kind}")

    @property
    def version_str(self) -> str:
        return f"{self.version >> 16}.{(self.version >> 8) & 0xFF}.{self.version & 0xFF}"


@dataclass(frozen=True)
class NodeRef:
    """A child reference: is_dir + index into the respective array."""
    is_dir: bool
    index: int
    name: bytes


class NxpReader:
    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "rb")
        try:
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:  # empty file
            self._mm = b""
        self.super = F.parse_super(self._mm[:F.HEADER_SIZE])
        real_size = os.fstat(self._fh.fileno()).st_size
        if self.super["file_size"] != real_size:
            raise F.NxpError(
                f"file_size {self.super['file_size']} != actual {real_size}")
        if self.super["toc_offset"] < F.HEADER_SIZE:
            raise F.NxpError("toc_offset before header end")
        if self.super["blob_offset"] < self.super["toc_offset"] + self.super["toc_size"]:
            raise F.NxpError("blob region overlaps TOC")
        if self.super["toc_size"] % 1 or self.super["blob_offset"] % F.EXTENT_ALIGN:
            raise F.NxpError("misaligned toc/blob offsets")

        toc_start = self.super["toc_offset"]
        raw_toc = self._mm[toc_start:toc_start + self.super["toc_size"]]
        if hashlib.sha256(raw_toc).digest() != self.super["toc_sha256"]:
            raise F.NxpError("TOC SHA-256 mismatch — file corrupt or tampered")
        self._parse_toc(raw_toc)
        self._check_bounds()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "NxpReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- TOC parsing ----

    def _parse_toc(self, toc: bytes) -> None:
        magic, pkg_count, dir_count, file_count, pool_off, pool_size, _r = \
            F._toc_head_s.unpack_from(toc, 0)
        if magic != F.TOC_MAGIC:
            raise F.NxpError(f"bad TOC magic {magic!r}")
        if pkg_count != self.super["package_count"]:
            raise F.NxpError("package_count mismatch between superblock and TOC")
        need = (F._toc_head_s.size + pkg_count * F.PKG_SIZE
                + dir_count * F.DIR_SIZE + file_count * F.FILE_SIZE)
        if len(toc) < need:
            raise F.NxpError("TOC truncated")
        if pool_off + pool_size > len(toc) or pool_off < need:
            raise F.NxpError("string pool out of TOC bounds")

        self.dir_count = dir_count
        self.file_count = file_count
        self.pool = toc[pool_off:pool_off + pool_size]

        pos = F._toc_head_s.size
        self.packages: list[PackageInfo] = []
        for i in range(pkg_count):
            p = F.parse_pkg(toc, pos)
            pos += F.PKG_SIZE
            self.packages.append(PackageInfo(
                index=i, title_id=p.title_id, kind=p.kind, version=p.version,
                flags=p.flags, root_dir=p.root_dir, exefs_dir=p.exefs_dir,
                romfs_dir=p.romfs_dir, meta_offset=p.meta_offset,
                meta_size=p.meta_size))

        self.dirs: list[tuple[bytes, int, int]] = []  # (name, first_child, child_count)
        for _ in range(dir_count):
            off, ln, first, count, _r2 = F._dir_s.unpack_from(toc, pos)
            pos += F.DIR_SIZE
            self.dirs.append((self._pool_str(off, ln), first, count))

        self.files: list[tuple] = []  # (name, size, sha256, ext_off, ext_size, codec)
        for _ in range(file_count):
            (off, ln, _r3, size, sha, eoff, esz, codec, cflags, _r4) = \
                F._file_s.unpack_from(toc, pos)
            pos += F.FILE_SIZE
            if codec not in (F.CODEC_RAW, F.CODEC_ZSTD):
                raise F.NxpError(f"unknown extent codec {codec}")
            if cflags != 0:
                raise F.NxpError(f"unknown codec_flags {cflags}")
            if size == 0 and (eoff != 0 or esz != 0 or codec != F.CODEC_RAW):
                raise F.NxpError("zero-size file with nonempty extent")
            if size != 0 and esz == 0:
                raise F.NxpError(f"file with nonzero size but empty extent")
            self.files.append((self._pool_str(off, ln), size, sha, eoff, esz, codec))

        slot_end = pool_off
        if (slot_end - pos) % 4:
            raise F.NxpError("children array not 4-byte aligned")
        self.children = list(struct.unpack_from(f"<{(slot_end - pos) // 4}I", toc, pos))

    def _pool_str(self, off: int, ln: int) -> bytes:
        if off + ln > len(self.pool):
            raise F.NxpError("string reference out of pool bounds")
        return self.pool[off:off + ln]

    def _check_bounds(self) -> None:
        file_size = self.super["file_size"]
        blob_start = self.super["blob_offset"]
        for name, size, sha, eoff, esz, codec in self.files:
            if size == 0:
                continue
            if eoff < blob_start or eoff + esz > file_size:
                raise F.NxpError(f"extent out of bounds for file {name!r}")
            if eoff % F.EXTENT_ALIGN:
                raise F.NxpError(f"extent not {F.EXTENT_ALIGN}-aligned for {name!r}")
        slot_total = len(self.children)
        used = 0
        for name, first, count in self.dirs:
            if first + count > slot_total:
                raise F.NxpError(f"child range out of bounds for dir {name!r}")
            used += count
        if used != slot_total:
            raise F.NxpError(f"child slots used {used} != total {slot_total}")
        for p in self.packages:
            if p.root_dir >= self.dir_count:
                raise F.NxpError(f"package {p.index}: root_dir out of bounds")
            for d in (p.exefs_dir, p.romfs_dir):
                if d != F.NO_DIR and d >= self.dir_count:
                    raise F.NxpError(f"package {p.index}: exefs/romfs dir out of bounds")
            if p.meta_size and (p.meta_offset + p.meta_size > file_size):
                raise F.NxpError(f"package {p.index}: meta block out of bounds")

    # ---- tree access ----

    def node_name(self, ref: NodeRef) -> bytes:
        if ref.is_dir:
            return self.dirs[ref.index][0]
        return self.files[ref.index][0]

    def iter_children(self, dir_index: int) -> list[NodeRef]:
        _, first, count = self.dirs[dir_index]
        out = []
        for slot in range(first, first + count):
            cid = self.children[slot]
            if cid >= self.dir_count:
                fi = cid - self.dir_count
                out.append(NodeRef(False, fi, self.files[fi][0]))
            else:
                out.append(NodeRef(True, cid, self.dirs[cid][0]))
        return out

    def find_child(self, dir_index: int, name: bytes) -> NodeRef | None:
        children = self.iter_children(dir_index)
        lo, hi = 0, len(children)
        while lo < hi:
            mid = (lo + hi) // 2
            if children[mid].name < name:
                lo = mid + 1
            else:
                hi = mid
        if lo < len(children) and children[lo].name == name:
            return children[lo]
        return None

    def file_info(self, file_index: int) -> tuple:
        return self.files[file_index]

    def read_file(self, file_index: int) -> bytes:
        name, size, sha, eoff, esz, codec = self.files[file_index]
        if size == 0:
            data = b""
        elif codec == F.CODEC_RAW:
            data = self._mm[eoff:eoff + esz]
            if len(data) != esz:
                raise F.NxpError(f"short read for {name!r}")
        elif codec == F.CODEC_ZSTD:
            import zstandard
            comp = self._mm[eoff:eoff + esz]
            if len(comp) != esz:
                raise F.NxpError(f"short read for {name!r}")
            dctx = zstandard.ZstdDecompressor()
            data = dctx.decompress(comp, max_output_size=size)
        else:
            raise F.NxpError(f"unknown codec {codec}")
        if len(data) != size:
            raise F.NxpError(f"size mismatch for {name!r}: {len(data)} != {size}")
        return data

    def meta_records(self, pkg: PackageInfo) -> list[tuple[int, bytes]]:
        out = []
        pos = 0
        block = self._mm[pkg.meta_offset:pkg.meta_offset + pkg.meta_size]
        while pos + 8 <= len(block):
            t, _r, size = F._tlv_s.unpack_from(block, pos)
            if pos + 8 + size > len(block):
                raise F.NxpError("meta TLV overruns block")
            out.append((t, bytes(block[pos + 8:pos + 8 + size])))
            pos += 8 + size
        return out

    def _localized(self, pkg: PackageInfo, tlv_type: int) -> dict[bytes, bytes]:
        out: dict[bytes, bytes] = {}
        for t, payload in self.meta_records(pkg):
            if t != tlv_type:
                continue
            pos = 0
            while pos < len(payload):
                lang_len = payload[pos]
                pos += 1
                lang = payload[pos:pos + lang_len]
                pos += lang_len
                (data_len,) = struct.unpack_from("<I", payload, pos)
                pos += 4
                if pos + data_len > len(payload):
                    raise F.NxpError("localized record overruns TLV")
                out[lang.lower()] = payload[pos:pos + data_len]
                pos += data_len
        return out

    def localized_titles(self, pkg: PackageInfo) -> dict[bytes, bytes]:
        """BCP-47 tag (lowercase bytes) -> UTF-8 title name. SPEC §6.1, TLV 0x0009."""
        return self._localized(pkg, F.TLV_LOCALIZED_TITLES)

    def localized_icons(self, pkg: PackageInfo) -> dict[bytes, bytes]:
        """BCP-47 tag (lowercase bytes) -> image bytes. SPEC §6.1, TLV 0x000A."""
        return self._localized(pkg, F.TLV_LOCALIZED_ICONS)

    def app_meta(self, pkg: PackageInfo) -> dict[int, bytes]:
        """TLV type -> payload, preferring the base (or first) package's block."""
        return dict(self.meta_records(pkg))

    # ---- convenience ----

    def find_package(self, kind: int | None = None, title_id: int | None = None,
                     version: int | None = None) -> PackageInfo | None:
        for p in self.packages:
            if kind is not None and p.kind != kind:
                continue
            if title_id is not None and p.title_id != title_id:
                continue
            if version is not None and p.version != version:
                continue
            return p
        return None

    def resolve_path(self, pkg: PackageInfo, relpath: str) -> NodeRef | None:
        """Resolve a '/'-separated path from the package root."""
        cur = NodeRef(True, pkg.root_dir, b"")
        for part in relpath.split("/"):
            if not part:
                continue
            if not cur.is_dir:
                return None
            nxt = self.find_child(cur.index, part.encode("utf-8"))
            if nxt is None:
                return None
            cur = nxt
        return cur

    def extract_tree(self, dest: str, dir_index: int, progress=None) -> int:
        """Extract a directory subtree to dest. Returns number of files written."""
        n = 0
        os.makedirs(dest, exist_ok=True)
        stack = [(dir_index, dest)]
        while stack:
            di, dpath = stack.pop()
            os.makedirs(dpath, exist_ok=True)
            for child in self.iter_children(di):
                cpath = os.path.join(dpath, child.name.decode("utf-8", "surrogateescape"))
                if child.is_dir:
                    stack.append((child.index, cpath))
                else:
                    data = self.read_file(child.index)
                    with open(cpath, "wb") as fh:
                        fh.write(data)
                    n += 1
                    if progress:
                        progress(n, child)
        return n
