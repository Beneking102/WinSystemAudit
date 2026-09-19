# WinSystemAudit

A single, transparent PowerShell script that inventories a Windows 11
machine — hardware, stability, drivers, autostart, `PATH`, developer
caches, VS Code extensions, optional Store apps — and then lets you apply
**individually confirmed** fixes for exactly what it found. Nothing runs
unattended, nothing is hidden in a compiled binary, and nothing touches
your games or your data.

It grew out of a real interactive system-hardening session on an
over-grown Windows 11 dev/gaming rig, then got generalized so it's safe
to point at any machine.

## Why a `.ps1` and not a `.exe`

A security-conscious user should be able to read exactly what a tool does
*before* running it as Administrator. A signed or unsigned compiled
binary asks for blind trust; a plain-text script doesn't. Open it in
Notepad, read every line, then run it. That's also why the whole thing
is one file — no hidden modules, no download-on-first-run.

## The three rules this tool will not break

1. **It will never reset, reinstall, or "Reset this PC" Windows.**
2. **It will never touch a game installation or a game's own files.**
   The only game-related cleanup candidate is a launcher's own
   *incomplete-download buffer* (e.g. Steam's `steamapps\downloading`) —
   and even that only after the launcher process is confirmed not to be
   mid-transfer. `steamapps\common` (your installed games) is never
   sized, listed, or touched.
3. **Every fix uses only Windows built-ins, PowerShell cmdlets, or
   `winget`.** No bundled third-party "optimizer", no registry cleaner,
   no telemetry phoning home anywhere.

## What it checks (read-only, always safe)

| Area | What it looks at | Why it matters |
|---|---|---|
| CPU / Microcode | Model, microcode revision from the registry | Flags 13th/14th-gen Intel systems missing the microcode revision that addresses the known desktop-CPU degradation issue |
| RAM | Specified vs. currently-running memory clock | Catches XMP/EXPO not being enabled — a common, easily-fixed, meaningful performance gap |
| Disks | `Get-PhysicalDisk` health, SMART reliability counters (elevated) | Surfaces unhealthy drives and uncorrected read/write errors before they become data loss |
| Stability | WHEA hardware errors, bluescreens, unexpected restarts (Kernel-Power 41), reliability index, all over the last 90 days | Distinguishes "this machine has a real hardware problem" from "it's just full of junk" |
| System integrity | `DISM /CheckHealth` (elevated, read-only) | Tells you *before* you clean WinSxS whether the component store is even healthy enough for that to be safe |
| **Drivers** | Every non-Microsoft driver, cross-referenced by device class and age; devices with a Device-Manager error code; orphaned/ghost device entries grouped by class; duplicate DriverStore packages for the same INF (elevated) | The most-overlooked cause of both instability and slow networking — a 4-year-old LAN or Wi-Fi driver is a frequent root cause that "just reinstall the OS" would have papered over |
| Autostart | Every `Run` key entry whose target file no longer exists on disk | Registry rot from long-uninstalled software |
| `PATH` | Dead entries and exact duplicates between the System and User `PATH` | Silent tool-resolution bugs and a `PATH` variable creeping toward the 2047-character legacy limit |
| Developer caches | npm, pip, NuGet, Yarn, GPU shader caches, VS Code caches, Temp, Windows Update download cache — sized individually | All fully regenerable; the script never guesses a size, it always measures it first |
| Game-launcher download buffers | Steam libraries discovered from `libraryfolders.vdf`; only the `downloading` subfolder | Abandoned/failed downloads can silently eat hundreds of GB and are trivially safe to clear |
| VS Code extensions | Duplicate version folders (only the *currently active* version, verified via `code --list-extensions`, is ever kept) and orphaned GUID folders from interrupted installs | Extension folders don't clean up after themselves; this does it correctly without ever guessing which version is "the right one" |
| Optional Store apps | Presence-check against a curated list (Bing apps, Solitaire, Clipchamp, Instagram, Maps, Feedback Hub, GetHelp, DevHome, Zune apps, Xbox overlay, Quick Assist, ...) | Purely informational — the script explicitly does **not** assume you don't use these; it just tells you they're there |
| Security/perf posture | Hardware-accelerated GPU scheduling, Game DVR, Defender real-time protection, Fast-Startup capability | Quick read of settings that are commonly wrong for either gaming or dev workloads |

## What it can fix (menu option 2 — only after running the inventory)

Every single action below prints its exact target and measured size,
then asks `[j/N]` before doing anything. A System Restore point is
offered before the first change in a session (elevated only).

- Remove a specific orphaned autostart entry
- Rebuild the User `PATH` with dead/duplicate entries stripped
- Clear a specific developer/shader/Temp/Windows-Update cache
- Clear a specific game-launcher download buffer (launcher-running check first)
- Remove a specific old or orphaned VS Code extension folder
- Remove a specific optional Store app
- Empty the Recycle Bin

Nothing here is a "clean everything" button. There isn't one, on purpose.

## Sample run (abridged)

```
======================================================================
 Treiber-Inventur (alle Geraeteklassen)
======================================================================
  Treiber gesamt: 278  |  Nicht-Microsoft: 33

  Kernkomponenten (Netzwerk/Storage/Audio/GPU/USB/Bluetooth), sortiert nach Alter:
  [!!] 4,8 J  2021-12-17  Marvell            Marvell AQtion 10GBASE-T Network Adapter
  [!!] 4,6 J  2022-01-31  Intel              Intel(R) Wi-Fi 6E AX211 160MHz
  [!]  3,3 J  2023-05-22  TC-Helicon         TC-HELICON GoXLR
       1,9 J  2024-10-18  Intel Corporation  Intel(R) UHD Graphics 770

  [!!] 4 Geraet(e) mit Fehlerstatus im Geraete-Manager:
  [!]   Generic Bluetooth Radio (Code 31) - USB\VID_0A12&PID_0001\...
```

```
--- Spiele-Downloadpuffer ---
  Download-Puffer loeschen? 120,23 GB - C:\Program Files (x86)\Steam\steamapps\downloading\2344520 [j/N]: j
  -> Spiele-Downloadpuffer geleert: ...2344520 (~120.23 GB) - NUR dieser Ordner, keine installierten Spiele beruehrt.
  [OK] Geleert.
```

## Usage

```powershell
# Read-only inventory works without elevation. SMART data, DISM/CheckHealth,
# Defender status, and reliable DriverStore-duplicate detection need an
# elevated PowerShell for the full picture.
.\WinSystemAudit.ps1
```

Pick `1` for the inventory, read what it found, and only then pick `2` if
you want to act on any of it — one confirmation per action, no bulk
"yes to all". Reports are written to
`%USERPROFILE%\WinSystemAudit-Report\` as Markdown.

## Requirements

- Windows 10 or 11
- PowerShell 5.1 or later (built into Windows — no install needed)
- Administrator elevation recommended, not required, for full depth

## Roadmap / ideas

- `winget upgrade` cross-reference for installed developer tooling
- Optional CSV export alongside the Markdown report
- WSL/Docker disk-image (VHDX) size reporting with a guarded, opt-in
  compact step
- A `-Silent`/`-ReportOnly` switch for scheduled, non-interactive
  inventory-only runs (no fixes are ever offered in that mode)

Contributions toward any of these are welcome — see below.

## Contributing

Issues and PRs welcome. Please keep the three rules at the top of this
document intact in any contribution: no OS resets, no game-data deletion
beyond download buffers, and no third-party tool dependency for any fix
path. If you add a new check, follow the existing pattern: an
`Invoke-*Inventory` function that only reads and calls `Add-Finding`,
paired with an `Invoke-Fix*` function that only acts on what the
inventory already found, one `Confirm-Action` per item.

## License

MIT — see [LICENSE](LICENSE).
