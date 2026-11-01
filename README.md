# NXP - NX Package Format

A container for unencrypted Nintendo Switch / Switch 2 game dumps. 
Spec sheet: **[SPEC.md](SPEC.md)**

```
base/            updates/458752/      dlc/040074a01bf13001/0/
├─ exefs/        ├─ exefs/            └─ romfs/          ──►  game.nxp
└─ romfs/        └─ romfs/
```

NXP is a clean-room container format for **unencrypted NX (Nintendo Switch 1/2) game dumps**.

It stores ExeFS program files and full RomFS trees, this means it stores updates, base content 
and addons in one compressed file.

It can be used for either Switch 1 or Switch 2 games, of course that means you would have to
decrypt the game and package it into an nxp. (which i am not aware of for Switch 1 Games).

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
content directory (`exefs/`+`romfs/`) packs as a single base package.
Title IDs come from `main.npdm`; dump-tool `.listing` artifacts are excluded by default.

## Layout

```
SPEC.md            format specification
tools/nxpkg/       reference implementation (Python)
```
