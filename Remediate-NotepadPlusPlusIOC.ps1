<#
Remediate-NotepadPlusPlusIOC.ps1
Intune Remediations remediation script: runs when detection exits 1. [1](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations)
Quarantines suspicious artifacts rather than deleting.
#>

$LogDir  = 'C:\ProgramData\NppIOC\logs'
$LogFile = Join-Path $LogDir 'Remediate-NotepadPlusPlusIOC.log'

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    Ensure-Dir $LogDir
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Rotate-LogIfNeeded {
    param([int]$MaxMB = 5)

    try {
        if (Test-Path $LogFile) {
            $sizeMB = (Get-Item $LogFile).Length / 1MB
            if ($sizeMB -ge $MaxMB) {
                $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                $arch  = Join-Path $LogDir ("{0}.{1}.log" -f ([IO.Path]::GetFileNameWithoutExtension($LogFile)), $stamp)
                Move-Item -Path $LogFile -Destination $arch -Force
            }
        }
    } catch { }
}

$ErrorActionPreference = 'SilentlyContinue'

Rotate-LogIfNeeded -MaxMB 5
Log "=== Starting Notepad++ IOC Remediation (running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)) ==="

# -----------------------------
# CONFIG (keep in sync with detection)
# -----------------------------
$StagingRelativeDirs = @(
  'AppData\Roaming\ProShow',
  'AppData\Roaming\Adobe\Scripts',
  'AppData\Roaming\Bluetooth'
)

$SuspiciousProcessNames = @('ProShow', 'GUP', 'BluetoothService')

$C2Domains = @(
  # paste your domains if you want DNS cache cleanup
)

$MaliciousSHA1 = @(
  # paste your SHA1 list to safely quarantine only known-bad
)

$SuspiciousFileNames = @('AutoUpdater.exe', 'a.txt')

$QuarantineRoot = 'C:\ProgramData\NppIOC\Quarantine'
$LogPath        = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\NppIOCRemediation.log'

# -----------------------------
# Helpers
# -----------------------------

function Get-UserProfilePaths {
  $paths = @()
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
    $p = (Get-ItemProperty $k.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($p -and (Test-Path $p)) {
      $leaf = Split-Path $p -Leaf
      if ($leaf -notin @('Default', 'Default User', 'Public', 'All Users')) {
        $paths += $p
      }
    }
  }
  $paths | Sort-Object -Unique
}

function Ensure-Dir([string]$path) {
  if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
}

function Quarantine-Item {
  param([string]$Path)

  if (-not (Test-Path $Path)) { return }

  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $destRoot = Join-Path $QuarantineRoot $stamp
  Ensure-Dir $destRoot

  # preserve some structure
  $safeName = ($Path -replace '[:\\]', '_')
  $dest = Join-Path $destRoot $safeName

  try {
    Log "Quarantining: $Path -> $dest"
    Move-Item -Path $Path -Destination $dest -Force
  } catch {
    # fallback: copy then remove
    try {
      Log "Move failed, copying then removing: $Path"
      Copy-Item -Path $Path -Destination $dest -Recurse -Force
      Remove-Item -Path $Path -Recurse -Force
    } catch {
      Log "FAILED to quarantine: $Path ; $_" 'ERROR'
    }
  }
}

# -----------------------------
# Remediation
# -----------------------------
try {
  Ensure-Dir (Split-Path $LogPath -Parent)
  Ensure-Dir $QuarantineRoot
  Log "=== Starting Notepad++ IOC remediation ==="

  # 1) Stop suspicious processes
  foreach ($pname in $SuspiciousProcessNames) {
    $procs = Get-Process -Name $pname -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
      Log "Stopping process: $($p.ProcessName) PID=$($p.Id)" 'INFO'
      try { Stop-Process -Id $p.Id -Force } catch { Log "Failed stopping PID=$($p.Id): $_" }
    }
  }

  # 2) Quarantine known-bad files (prefer hash matches), otherwise minimal filename heuristic
  foreach ($profile in (Get-UserProfilePaths)) {
    foreach ($rel in $StagingRelativeDirs) {
      $dir = Join-Path $profile $rel
      if (-not (Test-Path $dir)) { continue }

      Log "Inspecting staging dir: $dir"

      # Hash-based quarantine
      if ($MaliciousSHA1.Count -gt 0) {
        foreach ($f in (Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue)) {
          try {
            $h = (Get-FileHash -Path $f.FullName -Algorithm SHA1 -ErrorAction Stop).Hash
            if ($MaliciousSHA1 -contains $h) {
              Quarantine-Item -Path $f.FullName
            }
          } catch { }
        }
      }

      # Minimal filename-based quarantine (only for well-known artifacts)
      foreach ($name in $SuspiciousFileNames) {
        $candidate = Join-Path $dir $name
        if (Test-Path $candidate) {
          Quarantine-Item -Path $candidate
        }
      }

      # If the directory is now empty, quarantine it (optional)
      try {
        $remaining = Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue
        if (-not $remaining) {
          Log "Dir is empty after cleanup, quarantining dir: $dir"
          Quarantine-Item -Path $dir
        }
      } catch { }
    }
  }

  # 3) Clear DNS cache if you provided domains (optional)
  if ($C2Domains.Count -gt 0) {
    try {
      Log "Clearing DNS client cache"
      Clear-DnsClientCache
    } catch {
      Log "Failed to clear DNS cache: $_"
    }
  }

  Log "=== Remediation completed ==="
  exit 0
}
catch {
  Log "FATAL remediation failure: $_"
  exit 1
}