# NXP — NX Package Format

**Version:** 1.0-draft · **Status:** working draft · **Extension:** `.nxp` · **Magic:** `NXP\x01`

NXP is a clean-room container format for **unencrypted NX (Nintendo Switch family) game dumps**.
It stores the loose directory trees that dump tools produce — ExeFS program files and full
RomFS trees — for a base application together with its updates and add-on content, in a single
random-access, integrity-checked, optionally compressed file.

It is deliberately **generation-agnostic**: nothing in the format is specific to Switch 1 or
Switch 2. Title IDs (`0100…` or `0400…`), NPDM revisions, key generations and firmware
variants are carried as opaque data. The format is also **encryption-free and signature-free**
by design; it is a packaging layer for content that has already been decrypted at dump time.

---

## 1. Design goals

| # | Goal | Rationale |
|---|------|-----------|
| G1 | **Mountable, not just extractable** — a reader maps any subtree directly into a virtual filesystem | Emulator PRs become a thin FS adapter, not a NCA/IVFC reimplementation |
| G2 | **Integrity** — every file content-addressed by SHA-256 | Verify dumps, detect corruption, enable safe dedup |
| G3 | **Dedup** — identical files stored once, across base/update/DLC | Updates share 90 %+ of files with the base title |
| G4 | **Compression with fallback** — per-file zstd, "stored" when it doesn't help | RomFS is frequently pre-compressed (`.zs`, `.zarc`); zstd on those wastes space |
| G5 | **Trivially implementable** — no encryption, no signatures, fixed-size records, little-endian only | A reader is ~300 lines in any language |
| G6 | **Forward-compatible** — reserved fields, per-extent codec IDs, meta TLV registry | v2 can add chunked codecs without breaking v1 readers |
| G7 | **Deterministic builds** — same input tree ⇒ byte-identical output (for a given zstd version) | Reproducible packaging, diffable, cacheable |

Non-goals: encryption, title-key handling, tickets, CNMT/CERT emulation, homebrew-signing,
escaping from consoles. NXP is not an NSP/XCI replacement for console installs; it targets
emulators, archivists, and tooling.

---

## 2. File layout overview

An NXP file is a sequence of three regions, all offsets absolute from file start:

```
┌─────────────────────────────┐ offset 0x00
│ Superblock (0x80 bytes)     │  magic, sizes, TOC hash, UUID
├─────────────────────────────┤ offset = header_size (0x80)
│ Table of Contents (TOC)     │  string pool · package records · node arrays
├─────────────────────────────┤ offset = blob_offset (16-byte aligned)
│ Blob region                 │  concatenated file extents (raw or zstd)
└─────────────────────────────┘ file_size
```

All integers are **little-endian**. All strings are **UTF-8** (stored byte-exact; producers
should emit NFC). All padding/reserved bytes **must be zero**. Writers must refuse to emit
and readers must reject nonconforming files (fail closed).

---

## 3. Superblock

Exactly 0x80 bytes at offset 0.

```c
struct NxpSuperblock {           // offset  size
    uint8_t  magic[4];           // 0x00   4    'N','X','P', format_major_version (1)
    uint16_t header_size;        // 0x04   2    = 0x80 for v1
    uint16_t header_version;     // 0x06   2    = 1
    uint64_t toc_offset;         // 0x08   8    == header_size in v1
    uint64_t toc_size;           // 0x10   8    bytes
    uint8_t  toc_sha256[32];     // 0x18  32    SHA-256 over the whole TOC region
    uint64_t blob_offset;        // 0x38   8    start of blob region, 16-byte aligned
    uint64_t file_size;          // 0x40   8    total size of this .nxp file
    uint32_t package_count;      // 0x48   4    number of package records
    uint32_t flags;              // 0x4C   4    0 for v1; unknown bits ⇒ reject
    uint8_t  uuid[16];           // 0x50  16    content-derived, see §3.1
    uint8_t  reserved[32];       // 0x60  32    zero
};                               // total  0x80
```

Validation rules for a reader:

1. `magic` is `NXP\x01` (byte 3 is the major version this file obeys).
2. `header_size >= 0x80`; fields beyond v1's 0x80 (if `header_version > 1`) are ignored.
3. `toc_offset == header_size`, `toc_size` and `blob_offset` are 16-byte-aligned sizes/offsets,
   `blob_offset >= toc_offset + toc_size`, `file_size ==` actual stream length.
4. `SHA-256(TOC bytes)` equals `toc_sha256`.
5. `package_count >= 1`.

### 3.1 UUID

The UUID makes packages addressable by managers/libraries without parsing titles, and makes
builds reproducible. It is **derived, not random**:

```
uuid[0..16] = SHA-256( concat over packages, in TOC order:
                         title_id(u64 LE) ‖ version(u32 LE) ‖ kind(u8) ) [0..16]
```

Identical logical content ⇒ identical UUID. Two different dumps of the same title+version
repack to the same UUID; that is intentional (UUID identifies *logical* content, TOC hash
identifies *this file*).

---

## 4. Table of Contents

One contiguous region starting at `toc_offset`. Internal offsets are **relative to the TOC
start**. Layout:

```c
struct NxpToc {
    uint32_t magic;              // 0x00  'T','O','C', 1
    uint32_t package_count;      // 0x04  (redundant with superblock, cross-checked)
    uint64_t dir_count;          // 0x08
    uint64_t file_count;         // 0x10
    uint64_t string_pool_off;    // 0x18  relative to TOC start
    uint64_t string_pool_size;   // 0x20
    uint64_t reserved;           // 0x28  zero
    NxpPackage packages[package_count];   // 0x30, each 0x40 bytes
    NxpDir     dirs[dir_count];           // each 0x18 bytes
    NxpFile    files[file_count];         // each 0x50 bytes
    uint32_t   children[child_slot_count];// 4 bytes each, see §4.3
    uint8_t    string_pool[];             // at string_pool_off
};
```

### 4.1 Package record — `NxpPackage` (0x40 bytes)

One record per stored content unit (base program, update, add-on content, …).

```c
struct NxpPackage {              // offset  size
    uint64_t title_id;           // 0x00   8   raw 64-bit application/add-on ID, verbatim from dump
    uint32_t root_dir;           // 0x08   4   index into dirs[]; package tree root
    uint32_t exefs_dir;          // 0x0C   4   index into dirs[], or 0xFFFFFFFF
    uint32_t romfs_dir;          // 0x10   4   index into dirs[], or 0xFFFFFFFF
    uint32_t version;            // 0x14   4   NCM content version, verbatim (see §4.1.1)
    uint8_t  kind;               // 0x18   1   see §4.1.2
    uint8_t  flags;              // 0x19   1   0 for v1
    uint16_t reserved;           // 0x1A   2   zero
    uint64_t meta_offset;        // 0x1C   8   absolute file offset of meta block, or 0
    uint32_t meta_size;          // 0x24   4   meta block size in bytes, or 0
    uint32_t reserved2;          // 0x28   4   zero
    uint8_t  reserved3[24];      // 0x2C  24   zero
};                               // total  0x40
```

#### 4.1.1 Version encoding

`version` is stored **verbatim** as the u32 that dump tools expose (the NCM application
version). For Switch-era titles the conventional packing is
`version = (major << 16) | (minor << 8) | micro`, e.g. directory `458752` (0x70000) ⇒ 7.0.0.
Producers MUST additionally store a human-readable display version in the package meta block
(TLV 0x0004) whenever it is known, because a few titles are known to encode versions
non-standardly. Readers MUST treat `version` as opaque.

#### 4.1.2 Package kinds

| kind | name | meaning |
|------|------|---------|
| 0 | `base`   | base application program (the game itself) |
| 1 | `update` | patch program for a base (a container may hold several, distinct `version`s) |
| 2 | `addon`  | add-on content (DLC), own `title_id` |
| 3 | `addon_update` | reserved |
| 4 | `system` | reserved for future system-data packages |
| 5–255 | reserved |

Rules: a container MUST contain at most one `base` package. `update` packages MUST NOT
appear without their `base` in the same file **or** be marked standalone via flags bit 0
(`standalone_update`, used for update-only dumps; consumers need a matching base elsewhere).
`addon` packages carry their add-on `title_id` (e.g. Switch 1 `0100…801`, Switch 2 `0400…3001`).

#### 4.1.3 Canonical tree shape

The package root is a directory whose top-level children follow the dump convention so that
generic tools can navigate without interpreting the record:

```
<root>/exefs/…        ← ExeFS payload (main, main.npdm, rtld, sdk, subsdk*, code.bin, …)
<root>/romfs/…        ← full RomFS tree, arbitrary depth
<root>/data/…         ← anything else the dump provided (optional)
```

`exefs_dir`/`romfs_dir` point at these directories when present. The canonical shape is a
convention, not a parser requirement: readers MUST resolve content through the record fields,
not by path guessing. Producers MUST exclude dump-tool artifacts — `.listing` files and
anything else matching the reserved-artifact list (§7.3) — unless explicitly asked not to.

#### 4.1.4 Update semantics

An `update` package's tree is the **complete** tree of the patched content (as dumps provide),
not a delta. Consumers apply it by overlaying the update tree onto the base tree (paths in the
update shadow base paths). Cross-package dedup (§4.4) makes the shared files cheap. Delta
packaging is a possible v2 extension via flags.

### 4.2 Directory record — `NxpDir` (0x18 bytes)

```c
struct NxpDir {                  // offset  size
    uint32_t name_off;           // 0x00   4   byte offset into string pool
    uint32_t name_len;           // 0x04   4   bytes (not counting terminator)
    uint32_t first_child;        // 0x08   4   index into children[]
    uint32_t child_count;        // 0x0C   4   may be 0 (empty directory)
    uint64_t reserved;           // 0x10   8   zero
};
```

### 4.3 Children array and node IDs

`children[]` is a flat `uint32` array; each slot holds a **node id**:

- node id `< dir_count`  → index into `dirs[]`
- node id `>= dir_count` → index into `files[]` (subtract `dir_count`)

A directory's children occupy the contiguous slot range
`[first_child, first_child + child_count)`. Producers MUST lay out slots so that every
directory's range is contiguous, MUST sort children by name using **bytewise UTF-8
lexicographic order** (determinism + binary search on mount), and MUST keep child names
unique within a directory (case-sensitive).

`child_slot_count` is the sum of all `child_count` values (not stored; derivable).

### 4.4 File record — `NxpFile` (0x50 bytes)

```c
struct NxpFile {                 // offset  size
    uint32_t name_off;           // 0x00   4   byte offset into string pool
    uint32_t name_len;           // 0x04   4
    uint8_t  reserved[4];        // 0x08   4   zero
    uint64_t size;               // 0x0C   8   uncompressed size in bytes
    uint8_t  sha256[32];         // 0x14  32   SHA-256 of the uncompressed content
    uint64_t extent_offset;      // 0x34   8   absolute offset of extent in blob region
    uint64_t extent_size;        // 0x3C   8   stored (compressed) size in bytes
    uint8_t  codec;              // 0x44   1   0 = raw, 1 = zstd
    uint8_t  codec_flags;        // 0x45   1   codec-specific, 0 for v1
    uint16_t reserved2;          // 0x46   2   zero
    uint8_t  reserved3[8];       // 0x48   8   zero
};                               // total  0x50
```

### 4.5 String pool

A byte array of UTF-8 strings; entries need not be null-terminated (`name_len` bounds them).
Producers SHOULD intern (dedup) strings and SHOULD place the pool after the children array.
Strings are referenced by (offset, length) pairs from node records.

### 4.6 Dedup

Two file nodes with equal `sha256` SHOULD share one extent. Producers MUST NOT share an
extent between files with different `sha256`, sizes, or codecs. Readers MUST NOT assume
dedup — two files may also have separate, identical extents. Zero-length files have
`extent_size == 0`, `codec == 0`, `extent_offset == 0` (no blob bytes).

---

## 5. Blob region

Starts at `blob_offset`, runs to end of file. It is a concatenation of **extents**; every
extent begins at a **16-byte-aligned** absolute offset. An extent's bytes are exactly
`extent_size` long; alignment gaps are zero padding (not part of any extent).

### 5.1 Codecs

| codec | name | framing |
|-------|------|---------|
| 0 | `raw`   | `extent_size == size` bytes, uncompressed |
| 1 | `zstd`  | one standard Zstandard frame containing the whole file; frame MUST embed the content size in its header (producers compress with known size) |
| 2 | `lz4`   | reserved for v2 (frame: LZ4 skippable-frame container, TBD) |
| 3 | `zstd-chunked` | reserved for v2 (chunk index in meta TLV, TBD) |

Readers MUST reject unknown codecs. A reader MAY implement only codec 0 and still be
conformant for raw-only files; a general-purpose reader SHOULD implement codecs 0–1.

Compression policy (producer): compress each file with zstd level 3 (MAY use higher levels);
use `raw` when the compressed result is `>= size` or compression fails. Per-file choice only —
there is no global toggle in the format.

---

## 6. Package meta block

Optional per-package TLV list at `meta_offset` (absolute), `meta_size` bytes:

```c
struct TlvRecord {               // offset  size
    uint16_t type;               // 0x00   2
    uint16_t reserved;           // 0x02   2   zero
    uint32_t size;               // 0x04   4   payload size in bytes
    uint8_t  payload[size];      // 0x08   …   no padding between records
};
```

The block ends when the next record header would exceed `meta_size`. Readers MUST skip
unknown types. Registered types:

| type | payload | notes |
|------|---------|-------|
| 0x0001 | NPDM | verbatim `main.npdm` bytes (any NPDM revision; opaque to this spec) |
| 0x0002 | NACP | verbatim ApplicationControlProperty, if the dump provides one |
| 0x0003 | Icon | JPEG, typically 256×256, as distributed on-console |
| 0x0004 | Display version | UTF-8, e.g. `1.0.0`; authority over decoding `version` |
| 0x0005 | Title name | UTF-8 |
| 0x0006 | Publisher | UTF-8 |
| 0x0007 | Build ID | 32 raw bytes = SHA-256 of `main` when known (mods/cheats lookup) |
| 0x0008 | Source dump name | UTF-8, provenance |
| 0x0100–0x7FFF | reserved for future spec versions | readers skip |
| 0x8000–0xFFFF | vendor/tool private | readers skip |

Producers MUST write the NPDM TLV when the ExeFS contains `main.npdm` (it is the authoritative
source of the program ID). If a TLV and the tree disagree, the tree wins for content and the
TLV wins for metadata.

---

## 7. Conformance & registries

### 7.1 Reader conformance (MUST)

1. Validate superblock per §3; verify TOC SHA-256 before trusting any TOC-derived value.
2. Bounds-check every offset/size against `file_size`; reject overlaps between regions.
3. Treat `version`, `title_id`, NPDM/NACP payloads as opaque.
4. Reject unknown `codec`, unknown `kind >= 5`, unknown superblock `flags` bits.
5. Never execute or trust file names as paths (they are labels; overlay logic is the
   consumer's responsibility).

### 7.2 Producer conformance (MUST)

1. All record fields documented "zero" are zero; all extents 16-aligned; children sorted.
2. Per-file SHA-256 computed over the exact uncompressed bytes.
3. Superblock/TOC/blob layout per §2–§5; TOC hash correct.
4. `.listing` and other dump artifacts excluded per §4.1.3 unless the operator overrides.

### 7.3 Reserved artifact names

Producers exclude by default: `.listing` (dump-tool FTP listings). The name is reserved in
NXP trees; producers MAY support opt-in retention with `flags` bit 1 in the package record
(defined in a future revision before use).

### 7.4 Extension registry

- New codecs: allocate next free `codec` id, specify framing here, bump nothing else.
- New package kinds / meta types: document in this section.
- v2 candidates (explicitly *not* in v1): chunked zstd with per-chunk hashes, delta updates,
  sparse-file representation, zstd dictionary per package.

---

## 8. Worked example (minimal)

A 1-file base package, raw codec, 2-level tree:

```
Superblock:   magic NXP\x01, header_size 0x80, toc_offset 0x80
TOC:          1 package, 2 dirs (root, romfs), 1 file (romfs/hello.bin)
              children[] = [ romfs ]          (root's child)
              files[0] = "hello.bin", size 5, sha256 = …, extent raw 5 bytes
Blob:         5 bytes at 0x… (aligned up to 16)
```

Package record: `title_id = 0x040074A01BF12000` (DK Bananza-style Switch 2 ID),
`kind = 0` (base), `version = 0x10000` (1.0.0), `root_dir = 0`,
`exefs_dir = -1`, `romfs_dir = 1`.

---

## 9. Reference constants

| constant | value |
|----------|-------|
| extension | `.nxp` |
| magic | `4E 58 50 01` (`NXP` + major 1) |
| superblock size | `0x80` |
| package record size | `0x40` |
| dir record size | `0x18` |
| file record size | `0x50` |
| extent alignment | 16 |
| default zstd level | 3 |
| hash | SHA-256 (FIPS 180-4) |
| byte order | little-endian |
| string encoding | UTF-8 (NFC recommended) |

---

## Appendix A — Emulator integration notes (informational)

How an NXP container maps onto the two loader families, as of Nov 2026. None of this is
normative for the format; it exists so implementers know the target interfaces.

### Ryujinx / Ryubing (C#, LibHac-based)

- Existing keyless entry point: `Switch.LoadCart(exeFsDir, romFsPath)` →
  `ProcessLoader.LoadUnpackedNca` — loose ExeFS dir + RomFS stream, zeroed NACP is
  acceptable to launch. NXP support = produce an `IFileSystem` (ExeFS view over the
  package's `exefs_dir` subtree) and an `IStorage`/stream factory (romfs files), or a
  `LoadNxp(path)` that fans out per package.
- Game-list metadata: `ApplicationLibrary.TryGetApplicationsFromFile` needs
  `ApplicationData { Id, Name, Developer, Version, Icon }` — served by meta TLVs
  0x0005 (title name), 0x0006 (publisher), 0x0004 (display version), 0x0003 (icon);
  `title_id` from the package record. When a TLV is absent, consumers fall back to the
  title ID (same as the extracted path today).
- Switch 2 NPDMs (ACID signature area 0x300 instead of 0x200) need a parser fix in
  `Ryujinx.HLE/Loaders/Npdm/` — NXP carries NPDMs verbatim, so this fix benefits NXP and
  extracted dumps identically.

### Eden / yuzu forks (C++)

- Existing keyless loader: `AppLoader_DeconstructedRomDirectory` (plus the `eden-nx2`
  branch's loose-RomFS handling, which builds an on-the-fly RomFS from a directory).
- NXP support = an `AppLoader_Nxp` producing `VirtualFile`/`VirtualDir` views over the
  package subtrees, or a `ContentProvider` implementation feeding the existing
  `RegisteredCache`/`PatchManager` layering (updates overlay via `patch_manager`,
  DLC via AoC registration).
- Switch 2 NACP (`ApparentPlatform`/`ApplicationControlDataCondition`) already parses in
  Eden; S2 "upgrade packs" ride the AddOnContent channel, matching NXP `addon` packages.

### Cross-cutting

- Update layering: consumer overlays the `update` package tree onto `base` (path shadowing),
  then DLC — mirroring how patch NCAs overlay base NCAs today.
- Multi-program titles: `title_id & ~0xF` grouping applies as on-console; package records
  need no special support (multiple `base` packages are disallowed in v1 — revisit if
  multi-program dumps appear; §4.1.2).
- No key handling anywhere: NXP content is plaintext; consumers skip ticket/key paths.
