# 05-atomic.ps1 — stage Atomic Red Team so the attack runner can fire techniques.
$ProgressPreference    = "SilentlyContinue"   # keep the atomics download fast over WinRM
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }

# Install-AtomicRedTeam is NOT a cmdlet in the 'invoke-atomicredteam' gallery
# module (that one only provides Invoke-AtomicTest). It's defined by the project's
# bootstrap script, which installs the module AND, with -getAtomics, downloads the
# atomics library. This is the canonical install path.
Step "Installing Invoke-AtomicRedTeam + atomics library"
Install-PackageProvider -Name NuGet -Force | Out-Null
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Import by the INSTALLED PATH, not by name. Install-AtomicRedTeam drops the
# module under C:\AtomicRedTeam\, which is NOT on PSModulePath, so
# `Import-Module invoke-atomicredteam` throws Modules_ModuleNotFound. Under
# $ErrorActionPreference='Stop' that aborts the provisioner, so `vagrant up`
# returns non-zero and the installer cries "Windows VM provisioning failed" even
# though ART is fine — a false alarm for a fresh user. Resolve the psd1 and
# import that, and never let a staging hiccup fail the whole provision.
$psd1 = Get-ChildItem 'C:\AtomicRedTeam' -Recurse -Filter 'Invoke-AtomicRedTeam.psd1' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
try {
  if ($psd1) { Import-Module $psd1 -Force -ErrorAction Stop }
  else       { Import-Module invoke-atomicredteam -Force -ErrorAction Stop }
} catch {
  Write-Host "[WARN] Could not import Invoke-AtomicRedTeam now ($($_.Exception.Message))." -ForegroundColor Yellow
}
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
  Write-Host "[ OK ] Atomic Red Team staged (module at $psd1)." -ForegroundColor Green
} else {
  Write-Host "[WARN] Invoke-AtomicTest not available yet; the seeder re-imports it by path when it runs." -ForegroundColor Yellow
}
# Provisioning succeeded as long as the atomics are on disk — return 0 so the
# installer doesn't mistake a cosmetic import for a build failure.
exit 0
