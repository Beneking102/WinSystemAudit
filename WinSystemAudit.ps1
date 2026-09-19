#Requires -Version 5.1
<#
.SYNOPSIS
    WinSystemAudit - read-only Windows 11 system inventory with optional, individually-confirmed cleanup actions.

.DESCRIPTION
    A single self-contained PowerShell script for security-conscious users who want to know
    exactly what a "system optimizer" would touch before it touches anything.

    Design principles (non-negotiable, mirrored from the original hardening session this tool grew out of):
      - Never resets or reinstalls Windows.
      - Never touches game installations or game library folders. Only a game launcher's own
        "downloading" (incomplete-download) buffer is ever a cleanup candidate, and only that folder.
      - No third-party "optimizer" tools, no registry cleaners. Only Windows built-ins, PowerShell,
        and winget are used to apply any fix.
      - Every finding is shown with its exact size/path BEFORE anything is offered for cleanup.
      - Every cleanup action requires an explicit, individual confirmation. Nothing runs unattended.
      - A System Restore point is offered before the first change in a session.
      - Every log line doubles as a changelog entry with the exact command that ran.

.NOTES
    Run from an elevated PowerShell for the full picture (SMART data, DriverStore, DISM/SFC checks,
    Defender exclusions). Without elevation the script still runs and clearly marks what it could not read.

    Author: community-maintained, originally extracted from an interactive system-hardening session.
    License: MIT (see LICENSE).
#>

[CmdletBinding()]
param(
    [string]$ReportDir = (Join-Path $env:USERPROFILE "WinSystemAudit-Report")
)

$ErrorActionPreference = 'SilentlyContinue'
$script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:ChangeLog = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
}

function Write-Info    { param($t) Write-Host "  $t" -ForegroundColor Gray }
function Write-Ok      { param($t) Write-Host "  [OK] $t" -ForegroundColor Green }
function Write-Warn2   { param($t) Write-Host "  [!] $t" -ForegroundColor Yellow }
function Write-Bad     { param($t) Write-Host "  [!!] $t" -ForegroundColor Red }

function Get-DirSizeBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $bytes = 0L
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Path, '*', [System.IO.SearchOption]::AllDirectories)) {
            try { $bytes += (New-Object System.IO.FileInfo $f).Length } catch {}
        }
    } catch {}
    return $bytes
}

function Format-GB { param([double]$Bytes) [math]::Round($Bytes / 1GB, 2) }

function Confirm-Action {
    param([string]$Prompt)
    Write-Host ""
    $resp = Read-Host "  $Prompt [j/N]"
    return ($resp -match '^(j|ja|y|yes)$')
}

function Add-Finding {
    param([string]$Category, [string]$Name, [string]$Detail, [double]$SizeGB = 0, [string]$Risk = 'niedrig')
    $script:Findings.Add([pscustomobject]@{
        Category = $Category; Name = $Name; Detail = $Detail; SizeGB = $SizeGB; Risk = $Risk
    })
}

function Log-Change {
    param([string]$Text)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text
    $script:ChangeLog.Add($line)
    Write-Host "  -> $Text" -ForegroundColor DarkGreen
}

function New-SafetyRestorePoint {
    if (-not $script:IsElevated) {
        Write-Warn2 "Kein Wiederherstellungspunkt moeglich - Skript laeuft nicht elevated."
        return
    }
    if (-not (Confirm-Action "Vor der ersten Aenderung einen Systemwiederherstellungspunkt anlegen? (empfohlen)")) { return }
    try {
        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord -EA SilentlyContinue
        Checkpoint-Computer -Description "Vor WinSystemAudit-Bereinigung" -RestorePointType MODIFY_SETTINGS -EA Stop
        Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name SystemRestorePointCreationFrequency -EA SilentlyContinue
        Log-Change "Systemwiederherstellungspunkt 'Vor WinSystemAudit-Bereinigung' angelegt."
        Write-Ok "Wiederherstellungspunkt angelegt."
    } catch {
        Write-Bad "Wiederherstellungspunkt konnte nicht angelegt werden: $($_.Exception.Message)"
    }
}

# =====================================================================
# INVENTORY MODULES (read-only)
# =====================================================================

function Invoke-HardwareInventory {
    Write-Section "Hardware & Firmware"
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    Write-Info ("CPU: {0} | Kerne={1} Threads={2}" -f $cpu.Name, $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors)

    $mc = Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -EA SilentlyContinue
    $rev = $null
    if ($mc -and $mc.'Update Revision') {
        $revBytes = $mc.'Update Revision'
        # Layout variiert je nach System: mal 8 Byte (relevante Revision ab Offset 4), mal nur 4 Byte (Revision ab Offset 0).
        if ($revBytes.Length -ge 8)      { $rev = [BitConverter]::ToUInt32($revBytes, 4) }
        elseif ($revBytes.Length -ge 4)  { $rev = [BitConverter]::ToUInt32($revBytes, 0) }
    }
    if ($null -ne $rev) {
        Write-Info ("Microcode-Revision: 0x{0:X}" -f $rev)
        if ($cpu.Name -match '1[34]th Gen Intel' -and $rev -lt 0x125) {
            Add-Finding 'Kritisch' 'Microcode veraltet' "Revision 0x$($rev.ToString('X')) - unter dem 13./14th-Gen-Fix (0x125+). BIOS-Update pruefen." 0 'hoch'
            Write-Bad "Microcode unter 0x125 - BIOS-Update auf 13./14th-Gen-Systemen dringend pruefen."
        } else {
            Write-Ok "Microcode-Revision wirkt aktuell (kein bekannter 13./14th-Gen-Degradations-Fix noetig oder bereits vorhanden)."
        }
    } else {
        Write-Warn2 "Microcode-Revision konnte nicht ausgelesen werden (unerwartetes Registry-Format)."
    }

    $bios = Get-CimInstance Win32_BIOS
    Write-Info ("BIOS: {0} {1} vom {2}" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion, $bios.ReleaseDate)

    $ram = Get-CimInstance Win32_PhysicalMemory
    $totalRamGB = [math]::Round((($ram | Measure-Object Capacity -Sum).Sum) / 1GB, 0)
    $specSpeed = ($ram | Select-Object -First 1).Speed
    $curSpeed  = ($ram | Select-Object -First 1).ConfiguredClockSpeed
    Write-Info ("RAM: {0} GB, {1} Module, spezifiziert {2} MT/s, aktuell {3} MT/s" -f $totalRamGB, $ram.Count, $specSpeed, $curSpeed)
    if ($curSpeed -and $specSpeed -and $curSpeed -lt ($specSpeed * 0.9)) {
        Add-Finding 'Performance' 'XMP/EXPO nicht aktiv' "RAM laeuft mit $curSpeed statt $specSpeed MT/s. XMP/EXPO im BIOS aktivieren (danach Memtest86 empfohlen)." 0 'mittel'
        Write-Warn2 "RAM laeuft deutlich unter Spezifikation - XMP/EXPO vermutlich nicht aktiv (Aenderung nur im BIOS moeglich, dieses Skript kann das nicht setzen)."
    }

    Write-Host ""
    Write-Info "Laufwerke:"
    Get-PhysicalDisk | ForEach-Object {
        Write-Info ("  {0} | {1} | {2} GB | Health={3}" -f $_.FriendlyName, $_.BusType, [math]::Round($_.Size/1GB,0), $_.HealthStatus)
        if ($_.HealthStatus -ne 'Healthy') {
            Add-Finding 'Kritisch' 'Laufwerk-Gesundheit' "$($_.FriendlyName): HealthStatus=$($_.HealthStatus)" 0 'hoch'
        }
    }

    if ($script:IsElevated) {
        Write-Host ""
        Write-Info "SMART / Reliability Counter (elevated):"
        foreach ($d in Get-PhysicalDisk) {
            $r = $d | Get-StorageReliabilityCounter -EA SilentlyContinue
            if ($r) {
                Write-Info ("  {0}: Temp={1}C Wear={2}% LesefehlerUnkorr={3} SchreibfehlerUnkorr={4}" -f $d.FriendlyName, $r.Temperature, $r.Wear, $r.ReadErrorsUncorrected, $r.WriteErrorsUncorrected)
                if ($r.ReadErrorsUncorrected -gt 0 -or $r.WriteErrorsUncorrected -gt 0) {
                    Add-Finding 'Kritisch' 'Unkorrigierbare Laufwerksfehler' "$($d.FriendlyName) meldet unkorrigierbare Lese-/Schreibfehler." 0 'hoch'
                }
            }
        }
    } else {
        Write-Warn2 "SMART-Daten nicht lesbar ohne Administratorrechte."
    }
}

function Invoke-StabilityCheck {
    Write-Section "Stabilitaet (letzte 90 Tage)"
    $since = (Get-Date).AddDays(-90)

    $whea = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$since } -EA SilentlyContinue
    $wheaCount = @($whea).Count
    if ($wheaCount -gt 0) {
        Write-Bad "$wheaCount WHEA-Hardwarefehler in 90 Tagen - moeglicher Hinweis auf CPU/RAM/PCIe-Instabilitaet."
        Add-Finding 'Kritisch' 'WHEA-Fehler' "$wheaCount Ereignisse in 90 Tagen." 0 'hoch'
    } else {
        Write-Ok "Keine WHEA-Hardwarefehler in 90 Tagen."
    }

    $bsod = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=1001; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; StartTime=$since } -EA SilentlyContinue
    $bsodCount = @($bsod).Count
    if ($bsodCount -gt 0) {
        Write-Bad "$bsodCount Bluescreen(s) in 90 Tagen."
        Add-Finding 'Kritisch' 'Bluescreens' "$bsodCount BugCheck-Ereignisse in 90 Tagen." 0 'hoch'
    } else {
        Write-Ok "Keine Bluescreens in 90 Tagen."
    }

    $kp41 = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=$since } -EA SilentlyContinue
    $kp41Count = @($kp41).Count
    if ($kp41Count -gt 2) {
        Write-Warn2 "$kp41Count harte Neustarts (Kernel-Power 41) in 90 Tagen ohne Bluescreen - Netzteil/RAM/Treiber pruefen."
        Add-Finding 'Auffaellig' 'Harte Neustarts' "$kp41Count Kernel-Power-41-Ereignisse in 90 Tagen." 0 'mittel'
    } elseif ($kp41Count -gt 0) {
        Write-Info "$kp41Count harter Neustart in 90 Tagen (im Toleranzbereich)."
    } else {
        Write-Ok "Keine unerwarteten harten Neustarts in 90 Tagen."
    }

    $rel = Get-CimInstance Win32_ReliabilityStabilityMetrics -EA SilentlyContinue
    if ($rel) {
        $avg = [math]::Round((($rel | Measure-Object SystemStabilityIndex -Average).Average), 2)
        Write-Info "Durchschnittlicher Zuverlaessigkeitsindex: $avg von 10"
    }

    if ($script:IsElevated) {
        Write-Host ""
        Write-Info "Systemdatei-Integritaet (DISM CheckHealth, nur pruefend):"
        $dismOut = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1
        if ($dismOut -match 'repariert werden|be repaired') {
            Write-Bad "DISM meldet reparierbare Beschaedigungen im Komponentenspeicher."
            Add-Finding 'Kritisch' 'Systemdateien beschaedigt' "DISM /CheckHealth meldet reparierbare Schaeden. Vor jeder WinSxS-Bereinigung 'DISM /RestoreHealth' + 'sfc /scannow' ausfuehren." 0 'hoch'
        } else {
            Write-Ok "DISM meldet keinen erkannten Schaden am Komponentenspeicher."
        }
    } else {
        Write-Warn2 "Systemdatei-Integritaetspruefung braucht Administratorrechte (DISM/SFC)."
    }
}

function Invoke-AutostartInventory {
    Write-Section "Autostart-Eintraege (Orphans)"
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $orphans = New-Object System.Collections.Generic.List[object]
    foreach ($rk in $runKeys) {
        if (-not (Test-Path $rk)) { continue }
        $props = Get-ItemProperty $rk
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $cmd = [string]$p.Value
            $exePath = $cmd.Trim('"')
            if ($cmd -match '^"([^"]+)"') { $exePath = $Matches[1] }
            elseif ($cmd -match '^(\S+\.exe)') { $exePath = $Matches[1] }
            $expanded = [Environment]::ExpandEnvironmentVariables($exePath)
            if ($expanded -and -not (Test-Path -LiteralPath $expanded)) {
                $orphans.Add([pscustomobject]@{ Key = $rk; Name = $p.Name; Command = $cmd })
            }
        }
    }
    if ($orphans.Count -eq 0) {
        Write-Ok "Keine verwaisten Autostart-Eintraege gefunden."
    } else {
        foreach ($o in $orphans) {
            Write-Warn2 "Verwaist: [$($o.Key)] $($o.Name) -> $($o.Command)"
            Add-Finding 'Autostart' $o.Name "Registry: $($o.Key)\$($o.Name). Ziel existiert nicht. Command: $($o.Command)" 0 'niedrig'
        }
    }
    return $orphans
}

function Invoke-PathInventory {
    Write-Section "PATH-Umgebungsvariable"
    $sys = ([Environment]::GetEnvironmentVariable('Path','Machine') -split ';') | Where-Object { $_ -ne '' }
    $usr = ([Environment]::GetEnvironmentVariable('Path','User') -split ';') | Where-Object { $_ -ne '' }

    $deadUser = $usr | Where-Object { -not (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($_))) }
    $dupUser  = $usr | Where-Object { $sys -contains $_ }

    Write-Info "System-PATH: $($sys.Count) Eintraege | User-PATH: $($usr.Count) Eintraege"
    if ($deadUser) {
        Write-Warn2 "$($deadUser.Count) tote(r) Eintrag/Eintraege im User-PATH (Verzeichnis existiert nicht):"
        $deadUser | ForEach-Object { Write-Info "  - $_" }
        Add-Finding 'PATH' 'Tote PATH-Eintraege' ($deadUser -join ' | ') 0 'niedrig'
    }
    if ($dupUser) {
        Write-Warn2 "$($dupUser.Count) Eintrag/Eintraege im User-PATH sind exakte Duplikate des System-PATH:"
        Add-Finding 'PATH' 'Duplizierte PATH-Eintraege' ($dupUser -join ' | ') 0 'niedrig'
    }
    if (-not $deadUser -and -not $dupUser) { Write-Ok "PATH sieht sauber aus." }

    return [pscustomobject]@{ Dead = $deadUser; Dup = $dupUser; Sys = $sys; Usr = $usr }
}

function Invoke-DevCacheInventory {
    Write-Section "Entwickler-Caches"
    $caches = @(
        @{ Name = 'npm-Cache';           Path = "$env:LOCALAPPDATA\npm-cache" }
        @{ Name = 'pip-Cache';           Path = "$env:LOCALAPPDATA\pip\Cache" }
        @{ Name = 'NuGet http-cache';    Path = "$env:LOCALAPPDATA\NuGet\v3-cache" }
        @{ Name = 'Yarn-Cache';          Path = "$env:LOCALAPPDATA\Yarn\Cache" }
        @{ Name = 'NVIDIA DXCache';      Path = "$env:LOCALAPPDATA\NVIDIA\DXCache" }
        @{ Name = 'NVIDIA GLCache';      Path = "$env:LOCALAPPDATA\NVIDIA\GLCache" }
        @{ Name = 'D3D Shader Cache';    Path = "$env:LOCALAPPDATA\D3DSCache" }
        @{ Name = 'VS Code CachedData';  Path = "$env:APPDATA\Code\CachedData" }
        @{ Name = 'VS Code Cache';       Path = "$env:APPDATA\Code\Cache" }
        @{ Name = 'User-Temp';           Path = $env:TEMP }
        @{ Name = 'Windows Update Cache';Path = "$env:WinDir\SoftwareDistribution\Download" }
    )
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($c in $caches) {
        if (-not (Test-Path $c.Path)) { continue }
        $bytes = Get-DirSizeBytes $c.Path
        if ($bytes -lt 10MB) { continue }
        $gb = Format-GB $bytes
        Write-Info ("{0,-20} {1,8:N2} GB   {2}" -f $c.Name, $gb, $c.Path)
        Add-Finding 'Cache' $c.Name $c.Path $gb 'niedrig'
        $results.Add([pscustomobject]@{ Name = $c.Name; Path = $c.Path; GB = $gb })
    }
    if ($results.Count -eq 0) { Write-Ok "Keine nennenswert grossen Dev-Caches gefunden." }
    return $results
}

function Invoke-GameDownloadBufferInventory {
    Write-Section "Spiele-Launcher: Download-Puffer (NICHT installierte Spiele)"
    Write-Info "Es werden ausschliesslich 'downloading'-Zwischenspeicher geprueft - niemals installierte Spiele oder Bibliotheken."
    $results = New-Object System.Collections.Generic.List[object]

    # Steam: alle Bibliotheken aus libraryfolders.vdf ermitteln
    $steamPaths = @('C:\Program Files (x86)\Steam')
    $vdf = Join-Path $steamPaths[0] 'steamapps\libraryfolders.vdf'
    if (Test-Path $vdf) {
        (Get-Content $vdf | Select-String -Pattern '"path"\s+"([^"]+)"') | ForEach-Object {
            $p = $_.Matches[0].Groups[1].Value -replace '\\\\','\'
            if ($p -and (Test-Path $p) -and ($steamPaths -notcontains $p)) { $steamPaths += $p }
        }
    }
    foreach ($sp in $steamPaths) {
        $dl = Join-Path $sp 'steamapps\downloading'
        if (-not (Test-Path $dl)) { continue }
        Get-ChildItem $dl -Directory -Force -EA SilentlyContinue | ForEach-Object {
            $bytes = Get-DirSizeBytes $_.FullName
            if ($bytes -lt 50MB) { return }
            $gb = Format-GB $bytes
            Write-Warn2 ("Steam-Downloadpuffer (AppID {0}): {1:N2} GB  [{2}]" -f $_.Name, $gb, $_.FullName)
            Add-Finding 'Spiele-Puffer' "Steam AppID $($_.Name)" $_.FullName $gb 'niedrig'
            $results.Add([pscustomobject]@{ Launcher='Steam'; Path=$_.FullName; GB=$gb })
        }
    }
    if ($results.Count -eq 0) { Write-Ok "Keine relevanten Download-Puffer gefunden." }
    Write-Info "Hinweis: nur der 'downloading'-Ordner ist ein Kandidat. 'steamapps\common' (installierte Spiele) wird von diesem Tool nie angefasst."
    return $results
}

function Invoke-VSCodeExtensionInventory {
    Write-Section "VS Code: doppelte/verwaiste Extension-Ordner"
    $extDir = "$env:USERPROFILE\.vscode\extensions"
    if (-not (Test-Path $extDir)) { Write-Info "VS Code nicht gefunden."; return @() }

    # "code" allein loest haeufig auf Code.exe auf (die GUI, keine CLI-Ausgabe) statt auf den
    # code.cmd-Wrapper. Explizit zuerst nach dem .cmd suchen, sonst bleibt $active leer und
    # JEDE gefundene Version wuerde faelschlich als "alt" markiert.
    $codeCmd = Get-Command code.cmd -EA SilentlyContinue
    if (-not $codeCmd) { $codeCmd = Get-Command code -EA SilentlyContinue }
    $active = @{}
    if ($codeCmd) {
        $out = & $codeCmd.Source --list-extensions --show-versions 2>$null
        foreach ($line in $out) {
            if ($line -match '^(.+)@([\d.]+)$') { $active[$Matches[1].ToLower()] = $Matches[2] }
        }
    }
    if ($active.Count -eq 0) {
        Write-Warn2 "Aktive Extension-Versionen konnten nicht ermittelt werden - Abgleich wird uebersprungen, es wird nichts als 'alt' markiert."
        Write-Info "Verwaiste Installationsreste (GUID-Ordner) werden trotzdem erkannt."
    }

    $folders = Get-ChildItem $extDir -Directory -EA SilentlyContinue
    # Ordnernamen: <publisher>.<name>-<semver>[-<platform>-<arch>], z.B. "ms-python.python-2026.4.0-win32-x64".
    # Die Version wird bewusst NICHT gierig erfasst, sonst landet "-win32-x64" mit im Versionsstring
    # und der Abgleich mit der aktiven Version (ohne Plattform-Suffix) schlaegt faelschlich fehl.
    $groups = $folders | Where-Object { $_.Name -match '^(.+?)-(\d+\.\d+\.\d+)(?:-.+)?$' } | ForEach-Object {
        [pscustomobject]@{ Id = $Matches[1]; Version = $Matches[2]; Folder = $_ }
    } | Group-Object Id

    $removable = New-Object System.Collections.Generic.List[object]
    if ($active.Count -gt 0) {
        foreach ($g in $groups) {
            if ($g.Count -le 1) { continue }
            $activeVer = $active[$g.Name.ToLower()]
            if (-not $activeVer) { continue }   # Extension nicht (mehr) installiert oder Name-Mismatch - lieber nichts anfassen als raten
            foreach ($item in $g.Group) {
                if ($item.Version -eq $activeVer) { continue }
                $bytes = Get-DirSizeBytes $item.Folder.FullName
                $gb = Format-GB $bytes
                Write-Warn2 ("Alte Version: {0} ({1:N1} MB)" -f $item.Folder.Name, ($bytes/1MB))
                Add-Finding 'VS Code' 'Alte Extension-Version' $item.Folder.FullName $gb 'niedrig'
                $removable.Add($item.Folder)
            }
        }
    }
    # verwaiste GUID-Ordner (abgebrochene Installationen)
    $orphanGuid = $folders | Where-Object { $_.Name -match '^\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' }
    foreach ($o in $orphanGuid) {
        $bytes = Get-DirSizeBytes $o.FullName
        Write-Warn2 ("Verwaister Installationsrest: {0} ({1:N1} MB)" -f $o.Name, ($bytes/1MB))
        Add-Finding 'VS Code' 'Verwaister Extension-Rest' $o.FullName (Format-GB $bytes) 'niedrig'
        $removable.Add($o)
    }
    if ($removable.Count -eq 0) { Write-Ok "Keine doppelten oder verwaisten Extension-Ordner gefunden." }
    return $removable
}

function Invoke-BloatwareInventory {
    Write-Section "Optionale Windows-Store-Apps (nur Anzeige - deine Entscheidung, was 'Bloat' ist)"
    $candidates = @(
        'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.BingSearch',
        'Microsoft.MicrosoftSolitaireCollection','Clipchamp.Clipchamp','Facebook.InstagramBeta',
        'Microsoft.People','Microsoft.WindowsMaps','Microsoft.WindowsFeedbackHub',
        'Microsoft.GetHelp','Microsoft.Windows.DevHome','Microsoft.Todos',
        'Microsoft.MicrosoftOfficeHub','Microsoft.ZuneMusic','Microsoft.ZuneVideo',
        'Microsoft.GamingApp','Microsoft.XboxGamingOverlay','MicrosoftCorporationII.QuickAssist'
    )
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($c in $candidates) {
        $pkg = Get-AppxPackage -Name $c -EA SilentlyContinue
        if ($pkg) {
            Write-Info "installiert: $c ($($pkg.Version))"
            Add-Finding 'Optionale App' $c $pkg.PackageFullName 0 'niedrig'
            $found.Add($pkg)
        }
    }
    if ($found.Count -eq 0) { Write-Ok "Keine der bekannten optionalen Apps gefunden (bereits schlank)." }
    Write-Info "Diese Apps sind NICHT automatisch 'Bloatware' - manche nutzen sie aktiv. Nur entfernen, was du wirklich nicht brauchst."
    return $found
}

function Invoke-DriverInventory {
    Write-Section "Treiber-Inventur (alle Geraeteklassen)"
    $cutoff2y = (Get-Date).AddYears(-2)
    $cutoff4y = (Get-Date).AddYears(-4)

    $drivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName } | ForEach-Object {
        $date = $null
        if ($_.DriverDate) { try { $date = [datetime]$_.DriverDate } catch {} }
        [pscustomobject]@{
            Device      = $_.DeviceName
            Class       = $_.DeviceClass
            Provider    = $_.DriverProviderName
            Version     = $_.DriverVersion
            Date        = $date
            IsMicrosoft = ($_.DriverProviderName -match '^Microsoft')
            DeviceID    = $_.DeviceID
        }
    }

    $thirdParty = $drivers | Where-Object { -not $_.IsMicrosoft }
    Write-Info ("Treiber gesamt: {0}  |  Nicht-Microsoft: {1}" -f $drivers.Count, $thirdParty.Count)

    # Kernkomponenten zuerst: Netzwerk, Storage, Audio, GPU - hier tut Alter am meisten weh
    $coreClasses = 'NET','SCSIADAPTER','HDC','MEDIA','DISPLAY','USB','BLUETOOTH'
    $core = $thirdParty | Where-Object { $_.Class -in $coreClasses -and $_.Date }

    Write-Host ""
    Write-Info "Kernkomponenten (Netzwerk/Storage/Audio/GPU/USB/Bluetooth), sortiert nach Alter:"
    $core | Sort-Object Date | ForEach-Object {
        $ageY = [math]::Round(((Get-Date) - $_.Date).TotalDays / 365, 1)
        $marker = if ($_.Date -lt $cutoff4y) { '[!!]' } elseif ($_.Date -lt $cutoff2y) { '[!]' } else { '   ' }
        Write-Host ("  {0} {1,-5:N1}J  {2,-14} {3,-10} {4}" -f $marker, $ageY, $_.Date.ToString('yyyy-MM-dd'), $_.Provider, $_.Device) -ForegroundColor $(if($_.Date -lt $cutoff4y){'Red'}elseif($_.Date -lt $cutoff2y){'Yellow'}else{'Gray'})
        if ($_.Date -lt $cutoff2y) {
            Add-Finding 'Treiber' $_.Device ("Klasse=$($_.Class) Anbieter=$($_.Provider) Datum=$($_.Date.ToString('yyyy-MM-dd')) ($([math]::Round($ageY,1)) Jahre alt) - Update ueber Windows Update, winget oder Hersteller-Support-Seite pruefen.") 0 $(if($_.Date -lt $cutoff4y){'hoch'}else{'mittel'})
        }
    }
    if (-not $core -or $core.Count -eq 0) { Write-Ok "Keine Kernkomponenten-Treiber mit auswertbarem Datum gefunden." }

    # Geraete mit Fehlerstatus
    Write-Host ""
    $probDevices = Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
    if ($probDevices) {
        Write-Bad "$($probDevices.Count) Geraet(e) mit Fehlerstatus im Geraete-Manager:"
        $probDevices | ForEach-Object {
            Write-Warn2 ("  {0} (Code {1}) - {2}" -f $_.Name, $_.ConfigManagerErrorCode, $_.DeviceID)
            Add-Finding 'Treiber' 'Geraet mit Fehlerstatus' "$($_.Name) - ConfigManagerErrorCode=$($_.ConfigManagerErrorCode) - $($_.DeviceID)" 0 'mittel'
        }
    } else {
        Write-Ok "Keine Geraete mit Fehlerstatus."
    }

    # Nicht verbundene "Phantom"-Geraete, gruppiert nach Klasse
    Write-Host ""
    $ghosts = Get-PnpDevice -EA SilentlyContinue | Where-Object { $_.Present -eq $false }
    if ($ghosts) {
        $ghostGroups = $ghosts | Group-Object Class | Sort-Object Count -Descending
        Write-Info "Nicht verbundene (verwaiste) Geraetedefinitionen nach Klasse:"
        $ghostGroups | Select-Object -First 10 | ForEach-Object { Write-Info ("  {0,-24} {1} Stueck" -f $_.Name, $_.Count) }
        $bigGhost = $ghostGroups | Where-Object { $_.Count -ge 10 }
        foreach ($gg in $bigGhost) {
            Add-Finding 'Treiber' "Viele verwaiste $($gg.Name)-Geraete" "$($gg.Count) nicht verbundene Geraetedefinitionen dieser Klasse - typisch nach Deinstallation von Tuning-/Diagnose-Software mit vielen virtuellen Sub-Devices." 0 'niedrig'
        }
    } else {
        Write-Ok "Keine verwaisten Geraetedefinitionen gefunden."
    }

    # DriverStore: mehrfach vorliegende Versionen desselben INF (nur elevated zuverlaessig lesbar)
    if ($script:IsElevated) {
        Write-Host ""
        Write-Info "DriverStore: Pakete mit mehreren Versionen desselben Treibers (pnputil):"
        $pnp = & pnputil.exe /enum-drivers 2>$null
        $pkgs = New-Object System.Collections.Generic.List[object]
        $cur = @{}
        foreach ($line in $pnp) {
            if     ($line -match '^\s*(Ver.ffentlichter Name|Published Name)\s*:\s*(.+)$') { if ($cur.Count) { $pkgs.Add([pscustomobject]$cur) }; $cur = @{ Published = $Matches[2].Trim() } }
            elseif ($line -match '^\s*(Originalname|Original Name)\s*:\s*(.+)$')           { $cur.Original = $Matches[2].Trim() }
            elseif ($line -match '^\s*(Anbietername|Provider Name)\s*:\s*(.+)$')           { $cur.Provider = $Matches[2].Trim() }
        }
        if ($cur.Count) { $pkgs.Add([pscustomobject]$cur) }
        $dupGroups = $pkgs | Group-Object Original | Where-Object { $_.Count -gt 1 } | Sort-Object Count -Descending
        if ($dupGroups) {
            foreach ($dg in $dupGroups) {
                Write-Warn2 ("  {0} - {1}x im DriverStore (jeweils alle bis auf die neueste Version entfernbar via 'pnputil /delete-driver')" -f $dg.Name, $dg.Count)
                Add-Finding 'Treiber' "DriverStore-Duplikate: $($dg.Name)" "$($dg.Count) Versionen dieses INF im DriverStore. Aeltere ueber 'pnputil /delete-driver oemXX.inf' entfernbar - niemals im Dateisystem loeschen." 0 'niedrig'
            }
        } else {
            Write-Ok "Keine mehrfach vorliegenden DriverStore-Pakete gefunden."
        }
    } else {
        Write-Warn2 "DriverStore-Duplikate koennen nur elevated zuverlaessig ermittelt werden."
    }

    return $drivers
}

function Invoke-WindowsConfigCheck {
    Write-Section "Windows-Konfiguration (Performance & Privatsphaere, Anzeige only)"

    $hags = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -EA SilentlyContinue).HwSchMode
    Write-Info "Hardware-beschl. GPU-Planung (HAGS): $(if($hags -eq 2){'aktiv'}elseif($hags -eq 1){'inaktiv'}else{'Standard/nicht gesetzt'})"

    $gamedvr = (Get-ItemProperty 'HKCU:\System\GameConfigStore' -EA SilentlyContinue).GameDVR_Enabled
    Write-Info "Game DVR: $(if($gamedvr -eq 0){'aus'}else{'an'})"
    if ($gamedvr -ne 0) { Add-Finding 'Performance' 'Game DVR aktiv' 'Kann DistributedCOM-Fehler durch AppCaptureManager-Timeouts erzeugen.' 0 'niedrig' }

    $gamemode = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\GameBar' -EA SilentlyContinue).AutoGameModeEnabled
    Write-Info "Game Mode: $(if($gamemode -eq 1){'an'}else{'aus'})"

    $defender = Get-MpComputerStatus -EA SilentlyContinue
    if ($defender) {
        Write-Info "Defender Echtzeitschutz: $(if($defender.RealTimeProtectionEnabled){'aktiv'}else{'INAKTIV'})"
        if (-not $defender.RealTimeProtectionEnabled) { Add-Finding 'Sicherheit' 'Echtzeitschutz aus' 'Windows Defender Echtzeitschutz ist deaktiviert.' 0 'hoch' }
    }

    $hib = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -EA SilentlyContinue).HibernateEnabled
    Write-Info "Hibernate/Fast-Startup-faehig: $(if($hib -eq 1){'ja'}else{'nein (Fast Startup kann dadurch nicht wirken)'})"
}

# =====================================================================
# FIX MODULES (destructive, always behind Confirm-Action)
# =====================================================================

function Invoke-FixOrphanAutostart {
    param($Orphans)
    if (-not $Orphans -or $Orphans.Count -eq 0) { Write-Info "Nichts zu tun."; return }
    foreach ($o in $Orphans) {
        if (Confirm-Action "Verwaisten Autostart-Eintrag '$($o.Name)' entfernen? ($($o.Command))") {
            try {
                Remove-ItemProperty -Path $o.Key -Name $o.Name -EA Stop
                Log-Change "Remove-ItemProperty -Path '$($o.Key)' -Name '$($o.Name)'"
                Write-Ok "Entfernt."
            } catch { Write-Bad "Fehler: $($_.Exception.Message)" }
        }
    }
}

function Invoke-FixPath {
    param($PathInfo)
    if (-not $PathInfo.Dead -and -not $PathInfo.Dup) { Write-Info "Nichts zu tun."; return }
    $toRemove = @($PathInfo.Dead) + @($PathInfo.Dup) | Select-Object -Unique
    Write-Info "Folgende $($toRemove.Count) Eintraege wuerden aus dem User-PATH entfernt:"
    $toRemove | ForEach-Object { Write-Info "  - $_" }
    if (Confirm-Action "User-PATH bereinigen (tote + duplizierte Eintraege entfernen)?") {
        $newPath = ($PathInfo.Usr | Where-Object { $toRemove -notcontains $_ }) -join ';'
        $before = [Environment]::GetEnvironmentVariable('Path','User')
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Log-Change "PATH (User) bereinigt. Vorher: $before | Nachher: $newPath"
        Write-Ok "User-PATH aktualisiert. Neue PowerShell-Fenster verwenden den neuen PATH."
    }
}

function Invoke-FixCaches {
    param($Caches)
    if (-not $Caches -or $Caches.Count -eq 0) { Write-Info "Nichts zu tun."; return }
    foreach ($c in $Caches) {
        if (Confirm-Action ("'{0}' leeren? ({1:N2} GB, {2})" -f $c.Name, $c.GB, $c.Path)) {
            try {
                if ($c.Path -eq $env:TEMP) {
                    # Eigenen Prozess-Temp-Bereich schuetzen: nur Inhalte loeschen, Fehler bei gesperrten Dateien ignorieren
                    Get-ChildItem $c.Path -Force -EA SilentlyContinue | ForEach-Object {
                        try { Remove-Item $_.FullName -Recurse -Force -EA Stop } catch {}
                    }
                } else {
                    Get-ChildItem $c.Path -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue
                }
                Log-Change "Cache geleert: $($c.Path) (~$($c.GB) GB)"
                Write-Ok "Geleert."
            } catch { Write-Bad "Fehler: $($_.Exception.Message)" }
        }
    }
}

function Invoke-FixGameBuffers {
    param($Buffers)
    if (-not $Buffers -or $Buffers.Count -eq 0) { Write-Info "Nichts zu tun."; return }
    foreach ($b in $Buffers) {
        if (Confirm-Action ("Download-Puffer loeschen? {0:N2} GB - {1}" -f $b.GB, $b.Path)) {
            $procName = $b.Launcher.ToLower()
            $running = Get-Process -Name $procName -EA SilentlyContinue
            if ($running) {
                Write-Warn2 "$($b.Launcher) laeuft noch. Zum sicheren Loeschen bitte zuerst schliessen."
                if (-not (Confirm-Action "$($b.Launcher) nur fuer diesen Ordner nicht schliessen - trotzdem versuchen?")) { continue }
            }
            try {
                Get-ChildItem $b.Path -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA Stop
                Log-Change "Spiele-Downloadpuffer geleert: $($b.Path) (~$($b.GB) GB) - NUR dieser Ordner, keine installierten Spiele beruehrt."
                Write-Ok "Geleert."
            } catch { Write-Bad "Fehler (evtl. gesperrt, Launcher schliessen und erneut versuchen): $($_.Exception.Message)" }
        }
    }
}

function Invoke-FixVSCodeExtensions {
    param($Folders)
    if (-not $Folders -or $Folders.Count -eq 0) { Write-Info "Nichts zu tun."; return }
    if (Get-Process -Name Code -EA SilentlyContinue) {
        Write-Warn2 "VS Code laeuft. Alte, inaktive Extension-Ordner sind trotzdem in der Regel unproblematisch zu entfernen; nur die AKTIVE Version bleibt geladen."
    }
    foreach ($f in $Folders) {
        if (Confirm-Action "Alten/verwaisten Extension-Ordner entfernen? $($f.Name)") {
            try {
                Remove-Item $f.FullName -Recurse -Force -EA Stop
                Log-Change "VS-Code-Extension-Ordner entfernt: $($f.FullName)"
                Write-Ok "Entfernt."
            } catch { Write-Bad "Konnte nicht vollstaendig entfernt werden (vermutlich durch eine laufende VS-Code-Instanz gesperrt): $($_.Exception.Message)" }
        }
    }
}

function Invoke-FixBloatware {
    param($Apps)
    if (-not $Apps -or $Apps.Count -eq 0) { Write-Info "Nichts zu tun."; return }
    foreach ($a in $Apps) {
        if (Confirm-Action "App entfernen? $($a.Name) ($($a.PackageFullName))") {
            try {
                Remove-AppxPackage -Package $a.PackageFullName -EA Stop
                Log-Change "Remove-AppxPackage -Package '$($a.PackageFullName)'"
                Write-Ok "Entfernt."
            } catch { Write-Bad "Fehler: $($_.Exception.Message)" }
        }
    }
}

function Invoke-FixRecycleBin {
    Write-Section "Papierkorb"
    $totalBytes = 0
    foreach ($drv in (Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter) {
        $rb = "${drv}:\`$Recycle.Bin"
        $totalBytes += Get-DirSizeBytes $rb
    }
    $gb = Format-GB $totalBytes
    Write-Info ("Papierkorb gesamt (alle Laufwerke): {0:N2} GB" -f $gb)
    if ($gb -gt 0.05 -and (Confirm-Action "Papierkorb JETZT UNWIDERRUFLICH leeren? ($gb GB)")) {
        Clear-RecycleBin -Force -EA SilentlyContinue
        Log-Change "Papierkorb geleert (~$gb GB, alle Laufwerke)."
        Write-Ok "Papierkorb geleert."
    }
}

# =====================================================================
# REPORT EXPORT
# =====================================================================

function Export-Report {
    $mdPath = Join-Path $ReportDir ("Report_{0}.md" -f (Get-Date -Format 'yyyy-MM-dd_HHmm'))
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# WinSystemAudit Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    $lines.Add("")
    $lines.Add("Elevated: $script:IsElevated")
    $lines.Add("")
    $lines.Add("## Befunde")
    $lines.Add("")
    $lines.Add("| Kategorie | Befund | Groesse (GB) | Risiko | Detail |")
    $lines.Add("|---|---|---:|---|---|")
    foreach ($f in $script:Findings) {
        $lines.Add("| $($f.Category) | $($f.Name) | $($f.SizeGB) | $($f.Risk) | $($f.Detail -replace '\|','/') |")
    }
    if ($script:ChangeLog.Count -gt 0) {
        $lines.Add("")
        $lines.Add("## Durchgefuehrte Aenderungen")
        $lines.Add("")
        $script:ChangeLog | ForEach-Object { $lines.Add("- $_") }
    }
    $lines | Out-File $mdPath -Encoding utf8
    Write-Ok "Report gespeichert: $mdPath"
}

# =====================================================================
# MAIN MENU
# =====================================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  WinSystemAudit" -ForegroundColor Cyan
    Write-Host "  Read-only Windows-Inventur mit optionalen, einzeln bestaetigten Fixes." -ForegroundColor Gray
    Write-Host "  Elevated: $(if($script:IsElevated){'Ja'}else{'Nein - fuer volle Tiefe (SMART, DISM, Defender) bitte als Administrator starten'})" -ForegroundColor $(if($script:IsElevated){'Green'}else{'Yellow'})
    Write-Host ""
}

function Invoke-FullInventory {
    $script:Findings.Clear()
    Invoke-HardwareInventory
    Invoke-StabilityCheck
    $script:LastOrphans  = Invoke-AutostartInventory
    $script:LastPathInfo = Invoke-PathInventory
    Invoke-DriverInventory | Out-Null
    $script:LastCaches   = Invoke-DevCacheInventory
    $script:LastBuffers  = Invoke-GameDownloadBufferInventory
    $script:LastVSCode   = Invoke-VSCodeExtensionInventory
    $script:LastBloat    = Invoke-BloatwareInventory
    Invoke-WindowsConfigCheck

    Write-Section "Zusammenfassung"
    $totalGB = [math]::Round((($script:Findings | Measure-Object SizeGB -Sum).Sum), 2)
    Write-Host "  Befunde gesamt: $($script:Findings.Count)  |  Potenzieller Platzgewinn: ~$totalGB GB" -ForegroundColor Cyan
    $script:Findings | Where-Object { $_.Risk -eq 'hoch' } | ForEach-Object { Write-Bad "$($_.Category): $($_.Name)" }
}

function Show-FixMenu {
    if (-not $script:Findings -or $script:Findings.Count -eq 0) {
        Write-Warn2 "Bitte zuerst Option 1 (Inventur) ausfuehren."
        return
    }
    New-SafetyRestorePoint

    Write-Section "Fixes - jede Aktion wird einzeln bestaetigt"
    if ($script:LastOrphans.Count  -gt 0) { Write-Host "`n--- Verwaiste Autostart-Eintraege ---"; Invoke-FixOrphanAutostart $script:LastOrphans }
    if ($script:LastPathInfo.Dead -or $script:LastPathInfo.Dup) { Write-Host "`n--- PATH-Bereinigung ---"; Invoke-FixPath $script:LastPathInfo }
    if ($script:LastCaches.Count  -gt 0) { Write-Host "`n--- Caches ---"; Invoke-FixCaches $script:LastCaches }
    if ($script:LastBuffers.Count -gt 0) { Write-Host "`n--- Spiele-Downloadpuffer ---"; Invoke-FixGameBuffers $script:LastBuffers }
    if ($script:LastVSCode.Count  -gt 0) { Write-Host "`n--- VS-Code-Extensions ---"; Invoke-FixVSCodeExtensions $script:LastVSCode }
    if ($script:LastBloat.Count   -gt 0) { Write-Host "`n--- Optionale Apps ---"; Invoke-FixBloatware $script:LastBloat }
    Write-Host "`n--- Papierkorb ---"; Invoke-FixRecycleBin

    Export-Report
}

function Main {
    do {
        Show-Banner
        Write-Host "  [1] Vollstaendige Inventur ausfuehren (read-only, sicher)"
        Write-Host "  [2] Fixes anwenden (nur nach [1], jede Aktion einzeln bestaetigt)"
        Write-Host "  [3] Report exportieren (Markdown)"
        Write-Host "  [4] Beenden"
        Write-Host ""
        $choice = Read-Host "  Auswahl"
        switch ($choice) {
            '1' { Invoke-FullInventory; Read-Host "`n  Weiter mit Enter" }
            '2' { Show-FixMenu; Read-Host "`n  Weiter mit Enter" }
            '3' { Export-Report; Read-Host "`n  Weiter mit Enter" }
            '4' { return }
            default { }
        }
    } while ($true)
}

Main
