# NXP — NX Package Format

A clean-room, generation-agnostic container for unencrypted Nintendo Switch / Switch 2
game dumps. Spec-first project: **[SPEC.md](SPEC.md)** is the normative document.

```
base/            updates/458752/      dlc/040074a01bf13001/0/
├─ exefs/        ├─ exefs/            └─ romfs/          ──►  game.nxp
└─ romfs/        └─ romfs/
```

One `.nxp` file holds a title's base program, any number of updates, and add-on content,
with per-file SHA-256 integrity, content-addressed dedup (identical files across
base/update stored once), and per-file zstd compression with a raw fallback for
already-compressed assets. No encryption, no signatures, no NCA/IVFC reconstruction —
the container stores loose ExeFS/RomFS trees exactly as dump tools produce them, and a
reader mounts them directly as a virtual filesystem.

Works for Switch 1 (`0100…` IDs, NCA3-era dumps) and Switch 2 (`0400…` IDs, new NPDM
revisions) alike: identity data is carried verbatim, never interpreted.

## Tools

`tools/nxpkg/` is the Python reference implementation:

```
pip install ./tools/nxpkg          # or: PYTHONPATH=tools/nxpkg python3 -m nxpkg.cli
nxpkg pack   <dump_dir> <out.nxp>  [--level N] [--title-id HEX] [--display-version V]
nxpkg info   <file.nxp>            [--tree]
nxpkg list   <file.nxp>
nxpkg extract <file.nxp> <dest>    [--package base|update|addon] [--subtree romfs]
nxpkg verify <file.nxp>            [--fast]
```

`pack` auto-discovers `base/`, `updates/<version>/`, `dlc/<titleid>/<index>/`; a bare
content directory (`exefs/`+`romfs/`) packs as a single base package. Title IDs come from
`main.npdm`; dump-tool `.listing` artifacts are excluded by default.

## Status

- [x] Spec v1 (drafted against real Switch 2 dumps: DK Bananza, Mario Kart World,
      Splatoon Raiders, Welcome Tour, Yoshi demo)
- [x] Reference packer/reader/verifier (Python)
- [x] Round-trip validation: byte-exact extract, deep-verified, dedup confirmed
- [ ] Larger dumps + fuzzing
- [ ] Rust library (canonical lib)
- [ ] Emulator PRs — see SPEC.md Appendix A for the integration surfaces
      (Ryujinx `LoadCart` path, Eden `DeconstructedRomDirectory` path)

## Layout

```
SPEC.md            format specification (normative)
tools/nxpkg/       reference implementation (Python)
```
