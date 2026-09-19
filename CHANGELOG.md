# Changelog

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
