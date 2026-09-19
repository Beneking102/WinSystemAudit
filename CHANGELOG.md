# Changelog

## 1.1.0

- Added DriverStore duplicate-package detection with a working fix path:
  groups packages by original INF, resolves which version is newest from
  `pnputil`'s own `Treiberversion`/`Driver Version` field (date +
  version combined), and offers to remove the superseded ones. Ambiguous
  groups (date not parseable) are surfaced but never guessed at.
- Added a Downloads-folder duplicate detector (files/folders Windows
  itself suffixed with `(1)`, `(2)`, ...). **Report-only** — this tool
  will never offer to delete anything in your personal Downloads folder,
  only point out what's there to look at yourself.
- Fixed a real bug found while dogfooding this exact logic on a live
  machine: the field name used to extract driver dates
  (`Treiberdatum und -version`) does not exist in `pnputil` output — the
  actual field is `Treiberversion` (English: `Driver Version`), and it
  combines the date and version number in one string. The date itself is
  `MM/DD/YYYY` regardless of system locale. A German-locale dry run had
  silently found zero duplicates to clean because of this before the fix.

## 1.0.0

Initial public release, extracted and generalized from an interactive
Windows 11 system-hardening session.

- Read-only inventory: hardware/microcode, RAM/XMP, disk health, SMART
  (elevated), stability (WHEA/BSOD/unexpected restarts/reliability index),
  system file integrity check (DISM, elevated), orphaned autostart entries,
  dead/duplicated PATH entries, developer cache sizes, game-launcher
  download-buffer sizes (never installed games), duplicate/orphaned VS Code
  extension folders, optional Windows Store apps present, HAGS/Game DVR/
  Defender/Fast-Startup status.
- Optional fixes, each behind an individual confirmation: remove orphaned
  autostart entries, clean the User `PATH`, clear developer caches, clear
  game-launcher download buffers, remove old/orphaned VS Code extension
  folders, remove selected optional Store apps, empty the Recycle Bin.
- Markdown report export.

### Known limitations in this release

- `code` CLI detection prefers `code.cmd` over `Code.exe` (the GUI binary
  resolves via `Get-Command code` on some systems and produces no CLI
  output) — if neither is found, the VS Code duplicate-version check is
  skipped entirely rather than guessing.
- Microcode revision parsing handles both the 4-byte and 8-byte
  `Update Revision` registry value layouts seen across different
  chipsets/OEMs; if the layout is unrecognized, no verdict is given rather
  than reporting a false positive.
