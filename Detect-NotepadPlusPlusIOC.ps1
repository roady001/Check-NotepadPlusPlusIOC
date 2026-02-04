<#
Detect-NotepadPlusPlusIOC.ps1
Intune Remediations detection script: exit 1 if IOC found; exit 0 if clean.
Scans ALL local user profiles for %APPDATA%-style IOCs (because Intune usually runs as SYSTEM).
#>

$LogDir  = 'C:\ProgramData\NppIOC\logs'
$LogFile = Join-Path $LogDir 'Detect-NotepadPlusPlusIOC.log'

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

$ErrorActionPreference = 'SilentlyContinue'

Log "=== Starting Notepad++ IOC Detection (running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)) ==="

# -----------------------------
# CONFIG (align with your repo)
# -----------------------------

# Staging directories noted by the original project/README (under %APPDATA%) [2](https://github.com/roady001/Check-NotepadPlusPlusIOC)
$StagingRelativeDirs = @(
  'AppData\Roaming\ProShow',
  'AppData\Roaming\Adobe\Scripts',
  'AppData\Roaming\Bluetooth'
)

# Suspicious process names referenced in the project README [2](https://github.com/roady001/Check-NotepadPlusPlusIOC)
$SuspiciousProcessNames = @('ProShow', 'GUP', 'BluetoothService')

# Known C2 indicators are checked via TCP connections / DNS cache in the original project [2](https://github.com/roady001/Check-NotepadPlusPlusIOC)
# TODO: Paste your exact arrays from Check-NotepadPlusPlusIOC.ps1 to match your repo.
$C2IPs = @(
  # '45.76.155.202', '45.32.144.255'
)
$C2Domains = @(
  # 'cdncheck.it.com', 'self-dns.it.com'
)

# File hash matching is part of the original script (SHA1 list). [2](https://github.com/roady001/Check-NotepadPlusPlusIOC)
# TODO: Paste your SHA1 hashes from your script:
$MaliciousSHA1 = @(
  # 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
)

# Optional: suspicious filenames frequently mentioned in public reporting (example: AutoUpdater.exe, recon output a.txt). [4](https://www.bleepingcomputer.com/news/security/notepad-plus-plus-fixes-flaw-that-let-attackers-push-malicious-update-files/)
# Keep this list minimal to avoid false positives—hashes are more reliable.
$SuspiciousFileNames = @(
  'AutoUpdater.exe', 'a.txt'
)

# Set to $true if you also want to flag "non-default plugin folders"
# (this can generate false positives because plugin sets vary). [2](https://github.com/roady001/Check-NotepadPlusPlusIOC)
$EnablePluginHeuristic = $false

# -----------------------------
# Helpers
# -----------------------------

function Get-UserProfilePaths {
  $paths = @()
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
    $p = (Get-ItemProperty $k.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($p -and (Test-Path $p)) {
      # filter out system profiles
      $leaf = Split-Path $p -Leaf
      if ($leaf -notin @('Default', 'Default User', 'Public', 'All Users')) {
        $paths += $p
      }
    }
  }
  $paths | Sort-Object -Unique
}

function Add-Finding {
  param(
    [string]$Type,
    [string]$PathOrValue,
    [string]$Details
  )
  $script:Findings.Add([pscustomobject]@{
    Type   = $Type
    Value  = $PathOrValue
    Detail = $Details
  }) | Out-Null

  Log "FINDING: Type=$Type Value=$PathOrValue Details=$Details" 'WARN'
}


# -----------------------------
# Scan
# -----------------------------

$Findings = New-Object System.Collections.Generic.List[object]

# 1) File system staging dirs + suspicious files
foreach ($profile in (Get-UserProfilePaths)) {
  foreach ($rel in $StagingRelativeDirs) {
    $full = Join-Path $profile $rel
    if (Test-Path $full) {
      Add-Finding -Type 'StagingDir' -PathOrValue $full -Details "Directory exists"
      
      # Check suspicious filenames (light heuristic)
      foreach ($name in $SuspiciousFileNames) {
        $candidate = Join-Path $full $name
        if (Test-Path $candidate) {
          Add-Finding -Type 'SuspiciousFileName' -PathOrValue $candidate -Details "Matched name '$name'"
        }
      }

      # SHA1 hash check (more reliable)
      if ($MaliciousSHA1.Count -gt 0) {
        foreach ($f in (Get-ChildItem -Path $full -File -Recurse -ErrorAction SilentlyContinue)) {
          try {
            $h = (Get-FileHash -Path $f.FullName -Algorithm SHA1 -ErrorAction Stop).Hash
            if ($MaliciousSHA1 -contains $h) {
              Add-Finding -Type 'MaliciousSHA1' -PathOrValue $f.FullName -Details "SHA1 match: $h"
            }
          } catch { }
        }
      }
    }
  }
}

# 2) Processes
foreach ($pname in $SuspiciousProcessNames) {
  foreach ($p in (Get-Process -Name $pname -ErrorAction SilentlyContinue)) {
    $path = $null
    try { $path = $p.Path } catch { }
    if (-not $path) { try { $path = $p.MainModule.FileName } catch { } }

    Add-Finding -Type 'Process' -PathOrValue $p.ProcessName -Details ("PID={0}; Path={1}" -f $p.Id, ($path ?? 'unknown'))
  }
}

# 3) TCP connections to known C2 IPs
if ($C2IPs.Count -gt 0) {
  try {
    foreach ($c in (Get-NetTCPConnection -State Established -ErrorAction Stop)) {
      if ($C2IPs -contains $c.RemoteAddress) {
        Add-Finding -Type 'C2IP' -PathOrValue $c.RemoteAddress -Details ("Local={0}:{1} Remote={2}:{3} OwningPID={4}" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.OwningProcess)
      }
    }
  } catch {
    Add-Finding -Type 'Warning' -PathOrValue 'Get-NetTCPConnection' -Details 'Could not enumerate TCP connections (permissions/OS).'
  }
}

# 4) DNS cache entries for known C2 domains
if ($C2Domains.Count -gt 0) {
  $hit = $false
  try {
    foreach ($e in (Get-DnsClientCache -ErrorAction Stop)) {
      if ($e.Entry -and ($C2Domains -contains $e.Entry)) {
        Add-Finding -Type 'C2Domain' -PathOrValue $e.Entry -Details 'Found in DNS client cache'
        $hit = $true
      }
    }
  } catch {
    # fallback: parse ipconfig /displaydns
    try {
      $txt = (ipconfig /displaydns) | Out-String
      foreach ($d in $C2Domains) {
        if ($txt -match [regex]::Escape($d)) {
          Add-Finding -Type 'C2Domain' -PathOrValue $d -Details 'Found via ipconfig /displaydns (fallback)'
          $hit = $true
        }
      }
    } catch {
      Add-Finding -Type 'Warning' -PathOrValue 'DNSCache' -Details 'Could not read DNS cache.'
    }
  }
}

# 5) Optional plugin heuristic (disabled by default)
if ($EnablePluginHeuristic) {
  $possible = @(
    "$env:ProgramFiles\Notepad++\plugins",
    "${env:ProgramFiles(x86)}\Notepad++\plugins"
  ) | Where-Object { $_ -and (Test-Path $_) }

  foreach ($pp in $possible) {
    $folders = Get-ChildItem $pp -Directory -ErrorAction SilentlyContinue
    foreach ($f in $folders) {
      Add-Finding -Type 'PluginFolder' -PathOrValue $f.FullName -Details 'Plugin folder present (heuristic)'
    }
  }
}

# -----------------------------
# Output + Exit
# -----------------------------

if ($Findings.Count -gt 0) {
  $out = [pscustomobject]@{
    Result   = 'IOC_FOUND'
    Count    = $Findings.Count
    Findings = $Findings
  } | ConvertTo-Json -Depth 6

  Write-Output $out
  Log "IntuneOutput(JSON): $out"
  Log "Detection result: IOC_FOUND ($($Findings.Count) findings)" 'WARN'
  exit 1
} 
else {
  Write-Output '{"Result":"CLEAN","Count":0}'
  Log "Detection result: CLEAN" 'INFO'
  exit 0
}