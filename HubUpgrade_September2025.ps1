<# 
.SYNOPSIS
  In-place update of Workspace ONE Intelligent Hub for Windows using AW.WinPC.Updater.exe (no uninstall),
  with preflight (Unblock + Authenticode + size checks) and post-run copy of latest updater log.

.EXIT CODES
  0   = Success
  10  = MSI not found
  11  = Updater not found
  12  = MSI invalid (size/signature)
  13  = Updater invalid (size/signature)
  20  = Updater returned non-zero
  30  = Unexpected exception

.DEPLOYMENT SYNTAX
  powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File "HubUpgrade_September2025.ps1"

.SETUP
 Script, MSI file, and UpdaterEXE must be on the same directory

.NOTES
  Author: James Romeo Gaspar
  Date: September 26, 2025

#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory=$false)]
  [string]$MsiPath,

  [Parameter(Mandatory=$false)]
  [string]$UpdaterPath, 

  [Parameter(Mandatory=$false)]
  [string]$LogDir = 'C:\Temp',

  [switch]$ReadProductCode,
  [int]$SinceMinutes = 120
)

# --- Resolve script root robustly (PSScriptRoot - MyInvocation - CWD) ---
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
  $invPath = $MyInvocation.MyCommand.Path
  if ($invPath) { $ScriptRoot = Split-Path -Parent $invPath }
  if ([string]::IsNullOrWhiteSpace($ScriptRoot)) { $ScriptRoot = (Get-Location).Path }
}

# Ensure LogDir exists early
if (-not [string]::IsNullOrWhiteSpace($LogDir)) {
  try { if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null } } catch {}
}

# Temporary minimal logger until Write-Log is defined
function _PreLog([string]$m){ try { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] $m" | Out-Host } catch {} }

_PreLog "ScriptRoot resolved to: $ScriptRoot"

# --- Auto-resolve MSI path when not provided ---
if ([string]::IsNullOrWhiteSpace($MsiPath)) {
  $candidateMsi = Join-Path $ScriptRoot 'AirwatchAgent.msi'
  if (Test-Path -LiteralPath $candidateMsi) {
    $MsiPath = $candidateMsi
  } else {
    $MsiPath = 'C:\Temp\AirwatchAgent.msi'
  }
}
_PreLog "MSI will be used from: $MsiPath"

# --- Auto-discover Updater if not provided ---
if ([string]::IsNullOrWhiteSpace($UpdaterPath)) {
  $updCandidates = @(
    'C:\Program Files (x86)\Airwatch\AgentUI\AW.WinPC.Updater.exe',
    'C:\Program Files\Airwatch\AgentUI\AW.WinPC.Updater.exe',
    (Join-Path $ScriptRoot 'AW.WinPC.Updater.exe')
  )
  $found = $null
  foreach ($c in $updCandidates) { if (Test-Path -LiteralPath $c) { $found = $c; break } }
  $UpdaterPath = $found
}
$updShow = if ([string]::IsNullOrWhiteSpace($UpdaterPath)) { '<not found yet>' } else { $UpdaterPath }
_PreLog "Updater will be used from: $updShow"

# --- helpers ---
function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
  $line | Tee-Object -FilePath $Script:LogFile -Append | Out-Null
}

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-MsiProductCode {
  param([string]$Path)
  try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember("OpenDatabase","InvokeMethod",$null,$installer,@($Path,0))
    $view = $db.GetType().InvokeMember("OpenView","InvokeMethod",$null,$db,("SELECT * FROM Property"))
    $view.GetType().InvokeMember("Execute","InvokeMethod",$null,$view,$null) | Out-Null
    $rec = $view.GetType().InvokeMember("Fetch","InvokeMethod",$null,$view,$null)
    $props = @{}
    while ($rec -ne $null) {
      $k = $rec.GetType().InvokeMember("StringData","GetProperty",$null,$rec,1)
      $v = $rec.GetType().InvokeMember("StringData","GetProperty",$null,$rec,2)
      $props[$k] = $v
      $rec = $view.GetType().InvokeMember("Fetch","InvokeMethod",$null,$view,$null)
    }
    return $props['ProductCode']
  } catch { return $null }
}

function Export-UpgradeLogs {
  param([string]$DestDir)

  if (-not (Test-Path -LiteralPath $DestDir)) {
    New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
  }

  $logRoot = "C:\ProgramData\AirWatch\UnifiedAgent\Logs"

  if (-not (Test-Path -LiteralPath $logRoot)) {
    Write-Log "Updater log directory not found: $logRoot" 'WARN'
    return $null
  }

  try {
    $latest = Get-ChildItem -LiteralPath $logRoot -Filter 'AW.WinPC.Updater-*.log' -ErrorAction SilentlyContinue |
              Where-Object { -not $_.PSIsContainer } |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1

    if (-not $latest) {
      Write-Log "No updater log files found in $logRoot" 'WARN'
      return $null
    }

    $destPath = Join-Path $DestDir $latest.Name
    Copy-Item -LiteralPath $latest.FullName -Destination $destPath -Force
    Write-Log "Most recent updater log copied: $destPath"
    return $destPath
  } catch {
    Write-Log "Failed to collect updater log: $($_.Exception.Message)" 'ERROR'
    return $null
  }
}


function Test-SignedFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][int64]$MinBytes,
    [Parameter(Mandatory)][string]$Label
  )
  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Log "$Label not found: $Path" 'ERROR'
    $code = if ($Label -eq 'MSI') { 10 } else { 11 }
    return @{ Ok = $false; Code = $code }
  }

  # Unblock to remove MOTW if present
  try {
    Unblock-File -LiteralPath $Path -ErrorAction SilentlyContinue
    Write-Log "$Label Unblock-File completed (if MOTW existed)."
  } catch {
    Write-Log "$Label Unblock-File threw (continuing): $($_.Exception.Message)" 'WARN'
  }

  try {
    $fi = Get-Item -LiteralPath $Path
    Write-Log "$Label size: $($fi.Length) bytes; path: $($fi.FullName)"
    if ($fi.Length -lt $MinBytes) {
      Write-Log "$Label suspiciously small (min $MinBytes): $($fi.Length) bytes" 'ERROR'
      $code = if ($Label -eq 'MSI') { 12 } else { 13 }
      return @{ Ok = $false; Code = $code }
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $subj = $sig.SignerCertificate.Subject
    $iss  = $sig.SignerCertificate.Issuer
    Write-Log "$Label signature status: $($sig.Status); Subject: $subj; Issuer: $iss"

    if ($sig.Status -ne 'Valid') {
      Write-Log "$Label signature not valid (Status=$($sig.Status))." 'ERROR'
      $code = if ($Label -eq 'MSI') { 12 } else { 13 }
      return @{ Ok = $false; Code = $code }
    }
    return @{ Ok = $true; Code = 0 }
  } catch {
    Write-Log "$Label verification error: $($_.Exception.Message)" 'ERROR'
    $code = if ($Label -eq 'MSI') { 12 } else { 13 }
    return @{ Ok = $false; Code = $code }
  }
}

function Get-HubVersion {
  try {
    $paths = @(
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
      "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($p in $paths) {
      $apps = Get-ItemProperty $p -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName -like "Workspace ONE Intelligent Hub*" }
      if ($apps) {
        foreach ($a in $apps) { return $a.DisplayVersion }
      }
    }
  } catch { return $null }
}

function Set-UpdaterBinary {
  param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$TargetDir
  )
  try {
    if (-not (Test-Path -LiteralPath $TargetDir)) {
      New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $targetPath = Join-Path $TargetDir 'AW.WinPC.Updater.exe'
    $backupPath = "$targetPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    if (Test-Path -LiteralPath $targetPath) {
      try {
        Rename-Item -LiteralPath $targetPath -NewName (Split-Path $backupPath -Leaf) -Force
        Write-Log "Existing updater backed up to: $backupPath"
      } catch {
        Write-Log "Failed to backup existing updater ($targetPath): $($_.Exception.Message). Will try overwrite." 'WARN'
      }
    }

    Copy-Item -LiteralPath $SourcePath -Destination $targetPath -Force
    Write-Log "Updater replaced from '$SourcePath' -> '$targetPath'"
    return $targetPath
  } catch {
    Write-Log "Set-UpdaterBinary error: $($_.Exception.Message)" 'ERROR'
    return $null
  }
}


# --- main ---
$global:LASTEXITCODE = 0
$ErrorActionPreference = 'Stop'
$startTime = Get-Date

try {
  if (-not (Test-Admin)) { Write-Warning "This script should be run as Administrator. Attempting to continue." }

  if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $Script:LogFile = Join-Path $LogDir "HubUpgrade.log"

  Write-Log "Starting Hub in-place upgrade."
  Write-Log "Updater: $UpdaterPath"
  Write-Log "MSI: $MsiPath"

  # Capture Hub version BEFORE upgrade
  $beforeVer = Get-HubVersion
    if ($beforeVer) {
      Write-Log "Current Hub version detected: $beforeVer"

      if ($beforeVer -match '^25\.') {
        Write-Log "Hub is already at version $beforeVer. Exiting."
        exit 0
      }
    } else {
      Write-Log "Unable to detect existing Hub version. Proceeding with upgrade." 'WARN'
    }


  # --- Updater preflight with repair path ---
    $agentUiDir   = 'C:\Program Files (x86)\Airwatch\AgentUI'
    $resDir       = Join-Path $agentUiDir 'Resources'
    $resUpdater   = Join-Path $resDir     'AW.WinPC.Updater.exe'
    $bundledUpd   = Join-Path $ScriptRoot 'AW.WinPC.Updater.exe'
    $minUpdBytes  = 100000 

    # Validate the currently resolved updater (if any)
    $needFix = $true
    if (-not [string]::IsNullOrWhiteSpace($UpdaterPath)) {
      $chkUpd = Test-SignedFile -Path $UpdaterPath -MinBytes $minUpdBytes -Label 'Updater'
      if ($chkUpd.Ok) { $needFix = $false }
      else { Write-Log "Installed updater validation failed. Will attempt repair." 'WARN' }
    } else {
      Write-Log "Updater path not resolved. Will attempt repair." 'WARN'
    }

    if ($needFix) {
      # Try the Resources copy on the target machine
      if (Test-Path -LiteralPath $resUpdater) {
        $chkRes = Test-SignedFile -Path $resUpdater -MinBytes $minUpdBytes -Label 'Resources Updater'
        if ($chkRes.Ok) {
          $replaced = Set-UpdaterBinary -SourcePath $resUpdater -TargetDir $agentUiDir
          if ($replaced) {
            $UpdaterPath = $replaced
            $chkUpd2 = Test-SignedFile -Path $UpdaterPath -MinBytes $minUpdBytes -Label 'Updater (post-replace from Resources)'
            if ($chkUpd2.Ok) {
              Write-Log "Using updater from Resources after successful replace: $UpdaterPath"
              $needFix = $false
            }
          }
        } else {
          Write-Log "Resources updater is not valid. Will try bundled updater." 'WARN'
        }
      } else {
        Write-Log "No updater found in Resources: $resUpdater" 'WARN'
      }

      # If still not fixed, try the bundled updater next to the script
      if ($needFix -and (Test-Path -LiteralPath $bundledUpd)) {
        $chkBundled = Test-SignedFile -Path $bundledUpd -MinBytes $minUpdBytes -Label 'Bundled Updater'
        if ($chkBundled.Ok) {
          $replaced = Set-UpdaterBinary -SourcePath $bundledUpd -TargetDir $agentUiDir
          if ($replaced) {
            $UpdaterPath = $replaced
            $chkUpd3 = Test-SignedFile -Path $UpdaterPath -MinBytes $minUpdBytes -Label 'Updater (post-replace from Bundled)'
            if ($chkUpd3.Ok) {
              Write-Log "Using updater from bundled copy after successful replace: $UpdaterPath"
              $needFix = $false
            }
          }
        } else {
          Write-Log "Bundled updater is also invalid." 'ERROR'
        }
      } elseif ($needFix) {
        Write-Log "No bundled updater found at: $bundledUpd" 'ERROR'
      }

      if ($needFix) {
        Write-Log "Unable to validate or repair updater. Aborting upgrade." 'ERROR'
        exit 13
      }
    }


  # Validate MSI presence/size/signature (25 MB sanity floor; adjust as needed)
  $chkMsi = Test-SignedFile -Path $MsiPath -MinBytes 25000000 -Label 'MSI'
  if (-not $chkMsi.Ok) { exit $chkMsi.Code }

  if ($ReadProductCode) {
    $pc = Get-MsiProductCode -Path $MsiPath
    if ($pc) { Write-Log "MSI ProductCode: $pc" } else { Write-Log "MSI ProductCode: <unavailable>" 'WARN' }
  }

  $argList = @('msipath', $MsiPath)

  if ($PSCmdlet.ShouldProcess("Hub upgrade", "Run $UpdaterPath msipath `"$MsiPath`" and wait")) {
    Write-Log "Invoking updater..."
    $p = Start-Process -FilePath $UpdaterPath -ArgumentList $argList -PassThru -WindowStyle Hidden -Wait
    $code = $p.ExitCode
    Write-Log "Updater exit code: $code"

    # Always copy latest updater log to LogDir
    $since = $startTime.AddMinutes(-[math]::Abs($SinceMinutes))
    Write-Log "Collecting latest updater log modified since $since to: $LogDir"
    $copied = Export-UpgradeLogs -UpdaterPath $UpdaterPath -DestDir $LogDir -Since $since
    if ($copied) { Write-Log "Updater log copied: $copied" } else { Write-Log "No updater log copied." 'WARN' }

    # Capture Hub version AFTER upgrade and compare
    $afterVer = Get-HubVersion
    if ($afterVer) {
      Write-Log "Hub version after upgrade (detected): $afterVer"
      if ($beforeVer -and ($afterVer -eq $beforeVer)) {
        Write-Log "Warning: Hub version did not change (still $afterVer)" 'WARN'
      }
    } else {
      Write-Log "Unable to detect Hub version post-upgrade." 'WARN'
    }

    if ($code -ne 0) { Write-Log "Upgrade reported non-zero exit code ($code)." 'ERROR'; exit 20 }
    Write-Log "Upgrade completed successfully."; exit 0
  } else {
    Write-Log "WhatIf: Skipped invoking updater due to -WhatIf."
    Write-Log "WhatIf: Skipping log collection as well."
    exit 0
  }

} catch {
  Write-Log ("Unexpected error: " + $_.Exception.Message) 'ERROR'
  exit 30
}
