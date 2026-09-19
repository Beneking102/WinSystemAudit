# Sample report

This is an anonymized, shortened example of the Markdown report
`WinSystemAudit.ps1` writes to `%USERPROFILE%\WinSystemAudit-Report\`
after an inventory run. Real reports list every individual finding with
its full path and measured size; this file exists only to show the
shape of the output before you run the tool yourself.

```markdown
# WinSystemAudit Report - 2026-09-19 23:45

Elevated: True

## Befunde

| Kategorie | Befund | Groesse (GB) | Risiko | Detail |
|---|---|---:|---|---|
| Treiber | Marvell AQtion 10GBASE-T Network Adapter | 0 | hoch | Klasse=NET Anbieter=Marvell Datum=2021-12-17 (4.8 Jahre alt) |
| Treiber | Intel(R) Wi-Fi 6E AX211 160MHz | 0 | hoch | Klasse=NET Anbieter=Intel Datum=2022-01-31 (4.6 Jahre alt) |
| Treiber | Geraet mit Fehlerstatus | 0 | mittel | Generic Bluetooth Radio - ConfigManagerErrorCode=31 |
| Autostart | NVIDIA Broadcast | 0 | niedrig | Registry: HKCU:\...\Run\NVIDIA Broadcast . Ziel existiert nicht. |
| PATH | Duplizierte PATH-Eintraege | 0 | niedrig | 13 Eintraege im User-PATH sind exakte Duplikate des System-PATH |
| Cache | npm-Cache | 5.07 | niedrig | C:\Users\...\AppData\Local\npm-cache |
| Cache | NVIDIA DXCache | 27.70 | niedrig | C:\Users\...\AppData\Local\NVIDIA\DXCache |
| Spiele-Puffer | Steam AppID 2344520 | 120.23 | niedrig | C:\...\Steam\steamapps\downloading\2344520 |
| VS Code | Alte Extension-Version | 0.21 | niedrig | C:\Users\...\.vscode\extensions\ms-python.python-2026.3.0-win32-x64 |

## Durchgefuehrte Aenderungen

- [2026-09-19 23:47:12] Remove-ItemProperty -Path 'HKCU:\...\Run' -Name 'NVIDIA Broadcast '
- [2026-09-19 23:47:20] Cache geleert: C:\Users\...\AppData\Local\NVIDIA\DXCache (~27.7 GB)
- [2026-09-19 23:48:05] Spiele-Downloadpuffer geleert: C:\...\downloading\2344520 (~120.23 GB) - NUR dieser Ordner, keine installierten Spiele beruehrt.
```

Note the pattern in every row: a category, an exact path, a measured
size, and (for the change log) the literal command that ran. Nothing in
this tool ever reports a finding it can't point at, and nothing in the
change log summarizes — it logs the actual command.
