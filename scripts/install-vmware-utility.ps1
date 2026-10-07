<#
  install-vmware-utility.ps1 - install the Vagrant VMware Utility, unattended.

  This is the one VMware prerequisite people get stuck on. HashiCorp's docs say
  to download and install it by hand, but the MSI supports a silent install, so
  we do it for you: fetch the latest release, verify its SHA256 against
  HashiCorp's published checksums, install with msiexec /qn, and start the
  service. Needs admin (installs a Windows service).

  Standalone:
    powershell -ExecutionPolicy Bypass -File .\scripts\install-vmware-utility.ps1
#>
[CmdletBinding()]
param([string]$Version)   # pin a version; default = latest stable

$ErrorActionPreference = 'Stop'
function Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Ok($m){   Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Die($m){  Write-Host "[ERR ] $m" -ForegroundColor Red; exit 1 }

# The installed service's NAME is 'VagrantVMware' (its DISPLAY name is
# 'vagrant-vmware-utility'), so resolve it by pattern rather than a fixed name.
function Get-UtilService {
  Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'vagrant.*vmware|vagrantvmware' -or $_.DisplayName -match 'vagrant.*vmware' } |
    Select-Object -First 1
}
function Start-UtilService {
  $svc = Get-UtilService
  if ($svc) {
    try { Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
    try { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue } catch {}
  }
  return $svc
}

# already there? make sure it's running and stop.
if (Get-UtilService) {
  Step "Vagrant VMware Utility already installed - ensuring the service runs"
  $svc = Start-UtilService
  Ok "Vagrant VMware Utility present (service '$($svc.Name)' is $($svc.Status))."
  exit 0
}

# admin check - msiexec install needs it.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
  Die "Run this in an ADMIN PowerShell (installs a service). Right-click PowerShell > Run as administrator, then re-run."
}

$base = 'https://releases.hashicorp.com/vagrant-vmware-utility'

# resolve version
if (-not $Version) {
  Step "Finding the latest Vagrant VMware Utility release"
  try {
    $idx = Invoke-RestMethod "$base/index.json" -TimeoutSec 30
    $Version = ($idx.versions.PSObject.Properties.Name |
                Where-Object { $_ -notmatch '-' } |
                ForEach-Object { [version]$_ } |
                Sort-Object -Descending | Select-Object -First 1).ToString()
  } catch {
    $Version = '1.0.24'
    Warn "Could not query releases; falling back to $Version"
  }
}
Step "Target version: $Version"

$msiName = "vagrant-vmware-utility_${Version}_windows_amd64.msi"
$msiUrl  = "$base/$Version/$msiName"
$sumUrl  = "$base/$Version/vagrant-vmware-utility_${Version}_SHA256SUMS"
$msiPath = Join-Path $env:TEMP $msiName

Step "Downloading $msiName"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest $msiUrl -OutFile $msiPath -UseBasicParsing

# verify checksum against HashiCorp's published SHA256SUMS
Step "Verifying SHA256"
try {
  $sums = (Invoke-WebRequest $sumUrl -UseBasicParsing).Content
  $want = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($msiName) } |
           Select-Object -First 1).Split(' ')[0].Trim().ToLower()
  $got  = (Get-FileHash $msiPath -Algorithm SHA256).Hash.ToLower()
  if (-not $want) { Warn "checksum for $msiName not found in SHA256SUMS - skipping verify" }
  elseif ($want -ne $got) { Remove-Item $msiPath -Force; Die "SHA256 mismatch - refusing to install (expected $want, got $got)" }
  else { Ok "checksum verified" }
} catch { Warn "could not verify checksum ($_) - continuing" }

Step "Installing silently (msiexec /qn)"
$log = Join-Path $env:TEMP 'vmware-utility-install.log'
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
  '/i', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$log`""
)
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
  Die "msiexec failed (exit $($p.ExitCode)). See $log"
}

# bring the service up
Step "Starting the Vagrant VMware Utility service"
for ($i = 0; $i -lt 15 -and -not (Get-UtilService); $i++) { Start-Sleep 2 }
$svc = Start-UtilService
if (-not $svc) { Die "The utility service did not register after install. See $log" }

Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
Ok "Vagrant VMware Utility $Version installed; service '$($svc.Name)' is $($svc.Status)."
Write-Host ""
Write-Host "  Next: re-run the preflight, then build the VM:" -ForegroundColor Cyan
Write-Host "    powershell -ExecutionPolicy Bypass -File .\scripts\check-windows.ps1"
Write-Host "    powershell -ExecutionPolicy Bypass -File .\install.ps1 -WithWindowsVictim"
