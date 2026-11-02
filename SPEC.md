# NUP - NX Package Format

**Version:** 1.0-draft · **Extension:** `.nup` · **Magic:** `NUP\x01`

NUP is a clean-room container format for **unencrypted NX (Nintendo Switch 1/2) game dumps**.

It stores ExeFS program files and full RomFS trees, this means it stores updates, base content 
and addons in one compressed file.

It can be used for either Switch 1 or Switch 2 games, of course that means you would have to
decrypt the game and package it into an nup. (which i am not aware of for Switch 1 Games).

---

## 1. File layout overview

```
┌─────────────────────────────┐ offset 0x00
│ Superblock (0x80 bytes)     │  magic, sizes, TOC hash, UUID
├─────────────────────────────┤ offset = header_size (0x80)
│ Table of Contents (TOC)     │  string pool - package records - node arrays
├─────────────────────────────┤ offset = blob_offset (16-byte aligned)
│ Blob region                 │  concatenated file extents (raw or zstd)
└─────────────────────────────┘ file_size
```

All ints are **little-endian**.
All strings are **UTF-8** (producers should emit NFC).

---

## 2. Superblock

Exactly 0x80 bytes at offset 0.

```c
struct NupSuperblock {           // offset  size
    uint8_t  magic[4];           // 0x00   4    'N','U','P', format_major_version (1)
    uint16_t header_size;        // 0x04   2    = 0x80 for v1
    uint16_t header_version;     // 0x06   2    = 1
    uint64_t toc_offset;         // 0x08   8    == header_size in v1
    uint64_t toc_size;           // 0x10   8    bytes
    uint8_t  toc_sha256[32];     // 0x18  32    SHA-256 over the whole TOC region
    uint64_t blob_offset;        // 0x38   8    start of blob region, 16-byte aligned
    uint64_t file_size;          // 0x40   8    total size of this .nup file
    uint32_t package_count;      // 0x48   4    number of package records
    uint32_t flags;              // 0x4C   4    0 for v1; unknown bits ⇒ reject
    uint8_t  uuid[16];           // 0x50  16    content-derived, see §2.1
    uint8_t  reserved[32];       // 0x60  32    zero
};                               // total  0x80
```

Validation rules:

1. `magic` is `NUP\x01` (byte 3 is the major version this file obeys).
2. `header_size >= 0x80`; fields beyond v1's 0x80 (if `header_version > 1`) are ignored.
3. `toc_offset == header_size`, `toc_size` and `blob_offset` are 16-byte-aligned sizes/offsets,
   `blob_offset >= toc_offset + toc_size`, `file_size ==` actual stream length.
4. `SHA-256(TOC bytes)` equals `toc_sha256`.
5. `package_count >= 1`.

### 2.1 UUID

```
uuid[0..16] = SHA-256( concat over packages, in TOC order:
                         title_id(u64 LE) ‖ version(u32 LE) ‖ kind(u8) ) [0..16]
```

---

## 3. Table of Contents

Contiguous region starting at `toc_offset`. 
Offsets **relative to the TOC start**.

```c
struct NupToc {
    uint32_t magic;              // 0x00  'T','O','C', 1
    uint32_t package_count;      // 0x04  (redundant with superblock, cross-checked)
    uint64_t dir_count;          // 0x08
    uint64_t file_count;         // 0x10
    uint64_t string_pool_off;    // 0x18  relative to TOC start
    uint64_t string_pool_size;   // 0x20
    uint64_t reserved;           // 0x28  zero
    NupPackage packages[package_count];   // 0x30, each 0x40 bytes
    NupDir     dirs[dir_count];           // each 0x18 bytes
    NupFile    files[file_count];         // each 0x50 bytes
    uint32_t   children[child_slot_count];// 4 bytes each, see §3.3
    uint8_t    string_pool[];             // at string_pool_off
};
```

### 3.1 Package record - `NupPackage` (0x40 bytes)

```c
struct NupPackage {              // offset  size
    uint64_t title_id;           // 0x00   8   raw 64-bit application/add-on ID, verbatim from dump
    uint32_t root_dir;           // 0x08   4   index into dirs[]; package tree root
    uint32_t exefs_dir;          // 0x0C   4   index into dirs[], or 0xFFFFFFFF
    uint32_t romfs_dir;          // 0x10   4   index into dirs[], or 0xFFFFFFFF
    uint32_t version;            // 0x14   4   NCM content version, verbatim (see §3.1.1)
    uint8_t  kind;               // 0x18   1   see §3.1.2
    uint8_t  flags;              // 0x19   1   bit0 = standalone_update (§3.1.2); other bits zero for v1
    uint16_t reserved;           // 0x1A   2   zero
    uint32_t reserved2;          // 0x1C   4   zero
    uint64_t meta_offset;        // 0x20   8   absolute file offset of meta block, or 0
    uint32_t meta_size;          // 0x28   4   meta block size in bytes, or 0
    uint8_t  reserved3[20];      // 0x2C  20   zero
};                               // total  0x40
```

#### 3.1.1 Version encoding

`version` is stored as the u32 that dump tools export (NCM application
version).
Packing is `version = (major << 16) | (minor << 8) | micro`, 
e.g. directory `458752` (0x70000) ⇒ 7.0.0.
Producers additionally store a display version in the package meta block
(TLV 0x0004), because a few titles are known to encode versions non-standardly. 
Readers treat `version` as opaque.

#### 3.1.2 Package kinds

| kind | name | meaning |
|------|------|---------|
| 0 | `base`   | base application program (the game itself) |
| 1 | `update` | patch program for a base (a container may hold several, distinct `version`s) |
| 2 | `addon`  | add-on content (DLC), own `title_id` |
| 3 | `addon_update` | reserved |
| 4 | `system` | reserved for future system-data packages (mew) |
| 5–255 | reserved |

Rules: a container contains at most one `base` package however in the case that a dump
does not contain a base package, they must be marked standalone via flags bit 0.
(`standalone_update`, used for update-only dumps; consumers need a matching base elsewhere).
The bit is package record `flags`, offset `0x19`, bit 0 (value `0x01`) - set it on **every**
`update` package in a base-less container, and leave it clear when the container has a base.
`addon` packages carry their add-on `title_id` (e.g. Switch 1 `0100...801`, Switch 2 `0400...3001`).

#### 3.1.3 Canonical tree shape

```
<root>/exefs/...        ← ExeFS payload (main, main.npdm, rtld, sdk, subsdk*, code.bin, ...)
<root>/romfs/...        ← full RomFS tree, arbitrary depth
<root>/data/...         ← anything else the dump provided (optional)
```

`exefs_dir`/`romfs_dir` point at these directories when present.
Readers MUST resolve content through the record fields.
Producers MUST exclude dump-tool artifacts - `.listing` files and
anything else matching the reserved-artifact list (§6.3) unless otherwise.

#### 3.1.4 Update semantics

Cross-package dedup (§3.6) makes the shared files cheap.
Delta packaging is a possible v2 extension via flags.

### 3.2 Directory record - `NupDir` (0x18 bytes)

```c
struct NupDir {                  // offset  size
    uint32_t name_off;           // 0x00   4   byte offset into string pool
    uint32_t name_len;           // 0x04   4   bytes (not counting terminator)
    uint32_t first_child;        // 0x08   4   index into children[]
    uint32_t child_count;        // 0x0C   4   may be 0 (empty directory)
    uint64_t reserved;           // 0x10   8   zero
};
```

### 3.3 Children array and node IDs

`children[]` is a flat `uint32` array; each slot holds a **node id**:

- node id `< dir_count`  → index into `dirs[]`
- node id `>= dir_count` → index into `files[]` (subtract `dir_count`)

A directory's children occupy the slot range
`[first_child, first_child + child_count)`.
Producers lay out slots so that every directory's range is contiguous, 
sort children by name using **bytewise UTF-8 lexicographic order** 
(determinism + binary search on mount) and keep child names
unique within a directory (case-sensitive).

`child_slot_count` is the sum of all `child_count` values (not stored; can be derived if needed).

### 3.4 File record - `NupFile` (0x50 bytes)

```c
struct NupFile {                 // offset  size
    uint32_t name_off;           // 0x00   4   byte offset into string pool
    uint32_t name_len;           // 0x04   4
    uint64_t size;               // 0x08   8   uncompressed size in bytes
    uint64_t extent_offset;      // 0x10   8   absolute offset of extent in blob region
    uint64_t extent_size;        // 0x18   8   stored (compressed) size in bytes
    uint8_t  sha256[32];         // 0x20  32   SHA-256 of the uncompressed content
    uint8_t  codec;              // 0x40   1   0 = raw, 1 = zstd
    uint8_t  codec_flags;        // 0x41   1   codec-specific, 0 for v1
    uint16_t reserved2;          // 0x42   2   zero
    uint8_t  reserved3[12];      // 0x44  12   zero
};                               // total  0x50
```

### 3.5 String pool

A byte array of UTF-8 strings; entries do not need to be null-terminated (`name_len` bounds them).
Producers should intern (dedup) strings and should place the pool after the children array.
Strings are referenced by (offset, length) pairs from node records.

### 3.6 Dedup

Two file nodes with equal `sha256` should share one extent.
Producers must not share an extent between files with different 
`sha256`, sizes, or codecs.
Readers must not assume dedup - two files may also have separate, 
identical extents.
Zero-length files have `extent_size == 0`, `codec == 0`, 
`extent_offset == 0` (no blob bytes).

---

## 4. Blob region

Starts at `blob_offset`, runs to end of file.
It is a concatenation of **extents**; every
extent begins at a **16-byte-aligned** absolute offset.
An extent's bytes are exactly `extent_size` long; 
alignment gaps are zero padding (not part of any extent).

### 4.1 Codecs

| codec | name | framing |
|-------|------|---------|
| 0 | `raw`   | `extent_size == size` bytes, uncompressed |
| 1 | `zstd`  | one standard Zstandard frame containing the whole file; frame must embed the content size in its header (producers compress with known size) |
| 2 | `lz4`   | reserved for v2 (frame: LZ4 skippable-frame container, TBD) |
| 3 | `zstd-chunked` | reserved for v2 (chunk index in meta TLV, TBD) |

Readers must reject unknown codecs. A reader may implement only codec 0 and still be
conformant for raw-only files; a general-purpose reader should implement codecs 0–1.

Compression policy (producer): compress each file with zstd level 3 (may use higher levels);
use `raw` when the compressed result is `>= size` or compression fails. Per-file choice only -
there is no global toggle in the format.

---

## 5. Package meta block

Optional per-package TLV list at `meta_offset` (absolute), `meta_size` bytes:

```c
struct TlvRecord {               // offset  size
    uint16_t type;               // 0x00   2
    uint16_t reserved;           // 0x02   2   zero
    uint32_t size;               // 0x04   4   payload size in bytes
    uint8_t  payload[size];      // 0x08   ...   no padding between records
};
```

The block ends when the next record header would exceed `meta_size`.
Readers must skip unknown types. Registered types:

| type | payload | notes |
|------|---------|-------|
| 0x0001 | NPDM | verbatim `main.npdm` bytes (any NPDM revision; opaque to this spec) |
| 0x0002 | NACP | verbatim ApplicationControlProperty, if the dump provides one |
| 0x0003 | Icon | image bytes for the default language; 256×256 JPEG as distributed on-console. Consumers SHOULD sniff the magic (`FF D8` JPEG, `89 50 4E 47` PNG) rather than assume |
| 0x0004 | Display version | UTF-8, e.g. `1.0.0`; authority over decoding `version` |
| 0x0005 | Title name | UTF-8, default language |
| 0x0006 | Publisher | UTF-8 |
| 0x0007 | Build ID | 32 raw bytes = ModuleId: bytes `0x40..0x60` of the package's `main` ExeFS file (NSO0 or NRO0 header) |
| 0x0008 | Source dump name | UTF-8, provenance |
| 0x0009 | Localized titles | repeated `LocalizedRecord`s (§5.1); `lang` MUST NOT be empty |
| 0x000A | Localized icons | repeated `LocalizedRecord`s (§5.1); image bytes as for 0x0003 |
| 0x0100–0x7FFF | reserved for future spec versions | readers skip |
| 0x8000–0xFFFF | vendor/tool private | readers skip |

### 5.1 Localized records (types 0x0009 / 0x000A)
Japanese title shows `ゼルダの伝説` on a `ja` console, `The Legend of Zelda` on `en-US`.
These types carry that data as a sequence of records filling the payload up to `size`:

```c
struct LocalizedRecord {
    uint8_t  lang_len;           // 0x00   1   language tag length in bytes
    uint8_t  lang[lang_len];     // 0x01   ...   BCP-47 tag, lowercase ("ja", "en-us", "zh-hans")
    uint32_t data_len;           //        4   payload size in bytes
    uint8_t  data[data_len];     //        ...   UTF-8 name (0x0009) or image bytes (0x000A)
};
```

Rules: records are read sequentially until the payload is exhausted; duplicate tags are
invalid; an empty `lang` is invalid inside 0x0009/0x000A (0x0005/0x0003 are the default
language records). Tags match case-insensitively; consumers pick the exact tag, else apply
normal language-matching fallbacks, else use 0x0005/0x0003. Application-level metadata
(names, icons, display version) belongs in the `base` package's meta block; containers
without a base attach it to the first package.

Producers must write the NPDM TLV when the ExeFS contains `main.npdm` (it is the authoritative
source of the program ID). If a TLV and the tree disagree, the tree wins for content and the
TLV wins for metadata.

---

## 6. Conformance & registries

### 6.1 Reader conformance (must)

1. Validate superblock per §2; verify TOC SHA-256 before trusting any TOC-derived value.
2. Bounds-check every offset/size against `file_size`; reject overlaps between regions.
3. Treat `version`, `title_id`, NPDM/NACP payloads as opaque.
4. Reject unknown `codec`, unknown `kind >= 5`, unknown superblock `flags` bits.
5. Never execute or trust file names as paths (they are labels; overlay logic is the
   consumer's responsibility).

### 6.2 Producer conformance (must)

1. All record fields documented "zero" are zero; all extents 16-aligned; children sorted.
2. Per-file SHA-256 computed over the exact uncompressed bytes.
3. Superblock/TOC/blob layout per §2–§4; TOC hash correct.
4. `.listing` and other dump artifacts excluded per §6.3 unless the operator overrides.

### 6.3 Reserved artifact names

Producers exclude by default: `.listing` (dump-tool FTP listings). The name is reserved in
NUP trees; producers MAY support opt-in retention with `flags` bit 1 in the package record
(defined in a future revision before use).

### 6.4 Extension registry

- New codecs: allocate next free `codec` id, specify framing here, bump nothing else.
- New package kinds / meta types: document in this section.
- v2 candidates (explicitly *not* in v1): chunked zstd with per-chunk hashes, delta updates,
  sparse-file representation, zstd dictionary per package.

---

## 7. Worked example (minimal)

A 1-file base package, raw codec, 2-level tree:

```
Superblock:   magic NUP\x01, header_size 0x80, toc_offset 0x80
TOC:          1 package, 2 dirs (root, romfs), 1 file (romfs/hello.bin)
              children[] = [ romfs ]          (root's child)
              files[0] = "hello.bin", size 5, sha256 = ..., extent raw 5 bytes
Blob:         5 bytes at 0x... (aligned up to 16)
```

Package record: `title_id = 0x040074A01BF12000` (DK Bananza-style Switch 2 ID),
`kind = 0` (base), `version = 0x10000` (1.0.0), `root_dir = 0`,
`exefs_dir = -1`, `romfs_dir = 1`.

---

## 8. Reference constants

| constant | value |
|----------|-------|
| extension | `.nup` |
| magic | `4E 55 50 01` (`NUP` + major 1) |
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

## Appendix A - Emulator integration notes (informational)

How an NUP container maps onto the two loader families, as of Nov 2026. None of this is
normative for the format.

### Ryujinx / Ryubing (C#, LibHac-based)

- Existing keyless entry point: `Switch.LoadCart(exeFsDir, romFsPath)` →
  `ProcessLoader.LoadUnpackedNca` - loose ExeFS dir + RomFS stream, zeroed NACP is
  acceptable to launch. NUP support = produce an `IFileSystem` (ExeFS view over the
  package's `exefs_dir` subtree) and an `IStorage`/stream factory (romfs files), or a
  `LoadNup(path)` that fans out per package.
- Game-list metadata: `ApplicationLibrary.TryGetApplicationsFromFile` needs
  `ApplicationData { Id, Name, Developer, Version, Icon }` - served by meta TLVs
  0x0005 (title name), 0x0006 (publisher), 0x0004 (display version), 0x0003 (icon);
  `title_id` from the package record. When a TLV is absent, consumers fall back to the
  title ID (same as the extracted path today).
- Switch 2 NPDMs (ACID signature area 0x300 instead of 0x200) need a parser fix in
  `Ryujinx.HLE/Loaders/Npdm/` - NUP carries NPDMs verbatim, so this fix benefits NUP and
  extracted dumps identically.

### Eden / yuzu forks (C++)

- Existing keyless loader: `AppLoader_DeconstructedRomDirectory` (plus the `eden-nx2`
  branch's loose-RomFS handling, which builds an on-the-fly RomFS from a directory).
- NUP support = an `AppLoader_Nup` producing `VirtualFile`/`VirtualDir` views over the
  package subtrees, or a `ContentProvider` implementation feeding the existing
  `RegisteredCache`/`PatchManager` layering (updates overlay via `patch_manager`,
  DLC via AoC registration).
- Switch 2 NACP (`ApparentPlatform`/`ApplicationControlDataCondition`) already parses in
  Eden; S2 "upgrade packs" ride the AddOnContent channel, matching NUP `addon` packages.

### Cross-cutting

- Update layering: consumer overlays the `update` package tree onto `base` (path shadowing),
  then DLC - mirroring how patch NCAs overlay base NCAs today.
- Multi-program titles: `title_id & ~0xF` grouping applies as on-console; package records
  need no special support (multiple `base` packages are disallowed in v1 - revisit if
  multi-program dumps appear; §3.1.2).
- No key handling anywhere: NUP content is plaintext; consumers skip ticket/key paths.

---

## Appendix B - NACP language table (informational, Switch-specific)

The console's ApplicationControlProperty stores 16 per-language title entries plus a
default. Consumers synthesizing an NACP from NUP meta TLVs can use this mapping from
BCP-47 tags to NACP title indices (the NACP entry at index 0x10/`Default` holds the
fallback name; TLV 0x0005/0x0003 map there):

| BCP-47 tag (NUP) | NACP index | NACP entry |
|------------------|-----------|-------------|
| `en-us` | 0 | AmericanEnglish |
| `en-gb` | 1 | BritishEnglish |
| `ja` | 2 | Japanese |
| `fr` | 3 | French |
| `de` | 4 | German |
| `es-419` | 5 | LatinAmericanSpanish |
| `es` | 6 | Spanish |
| `it` | 7 | Italian |
| `nl` | 8 | Dutch |
| `fr-ca` | 9 | CanadianFrench |
| `pt` | 10 | Portuguese |
| `ru` | 11 | Russian |
| `ko` | 12 | Korean |
| `zh-hant` | 13 | TraditionalChinese |
| `zh-hans` | 14 | SimplifiedChinese |
| `pt-br` | 15 | BrazilianPortuguese |

Language-matching for consumers: exact tag → tag prefix (`en-us` falls back to `en`) →
primary subtag (`en`) → 0x0005 default → title ID.
