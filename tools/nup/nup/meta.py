"""NUP package meta block: TLV assembly for per-package metadata.

Builds the per-package meta block (NPDM, build ID, provenance) and the
application-level TLVs (names, icons, display version, SPEC §5.1) that
ride along in the base package's block. Serialization is deterministic:
records are sorted by TLV type and written without padding.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from . import format as F

if TYPE_CHECKING:
    from .pack import PackInput


def read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def meta_block(pkg: PackInput, dump_label: str, app_extra: bytes = b"") -> bytes:
    """Serialize one package's meta block (SPEC §5)."""
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


def _encode_localized(entries: dict[str, bytes]) -> bytes:
    """Encode {lang tag: data} as a LocalizedRecord sequence (SPEC §5.1)."""
    body = bytearray()
    for lang in sorted(entries):
        tag = lang.lower().encode("ascii")
        if not 0 < len(tag) <= 255:
            raise SystemExit(f"pack: bad language tag {lang!r}")
        data = entries[lang]
        body += bytes([len(tag)]) + tag
        body += struct.pack("<I", len(data)) + data
    return bytes(body)


def app_meta(names: dict[str | None, str] | None, icons: dict[str | None, str] | None,
             display_version: str | None, dump_label: str) -> bytes:
    """Application-level meta TLVs (SPEC §5.1): names/icons localized, plus
    display version and provenance. Attached to the base package (or first)."""
    names = names or {}
    icons = icons or {}
    recs: list[tuple[int, bytes]] = []
    if names.get(None):
        recs.append((F.TLV_TITLE_NAME, names[None].encode("utf-8")))
    if names.keys() - {None}:
        localized = {lang: text.encode("utf-8")
                     for lang, text in names.items() if lang is not None}
        recs.append((F.TLV_LOCALIZED_TITLES, _encode_localized(localized)))
    if icons.get(None):
        recs.append((F.TLV_ICON, read_file(icons[None])))
    if icons.keys() - {None}:
        localized = {lang: read_file(path)
                     for lang, path in icons.items() if lang is not None}
        recs.append((F.TLV_LOCALIZED_ICONS, _encode_localized(localized)))
    if display_version:
        recs.append((F.TLV_DISPLAY_VERSION, display_version.encode("utf-8")))
    recs.append((F.TLV_SOURCE_DUMP, dump_label.encode("utf-8")))
    recs.sort(key=lambda t: t[0])  # deterministic order
    out = bytearray()
    for t, payload in recs:
        out += F._tlv_s.pack(t, 0, len(payload)) + payload
    return bytes(out)
