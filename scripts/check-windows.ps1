<#
  check-windows.ps1 - preflight "doctor" for the optional Windows victim VM.
  Run this FIRST. It checks every prerequisite and prints exactly what to fix.
  It changes nothing. When all checks pass, the Windows VM will build cleanly.

      powershell -ExecutionPolicy Bypass -File .\scripts\check-windows.ps1
#>
$ok=0; $bad=0
function Pass($m){ Write-Host "[PASS] $m" -ForegroundColor Green; $script:ok++ }
function Fail($m,$fix){ Write-Host "[FAIL] $m" -ForegroundColor Red; Write-Host "       fix: $fix" -ForegroundColor Yellow; $script:bad++ }
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Blue }

Write-Host ""
Info "Windows-VM preflight - checking the whole chain"
Write-Host ""

# 1) CPU virtualization enabled in firmware (VT-x/AMD-V)
$vt = (Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled
if ($vt) { Pass "CPU virtualization (VT-x/AMD-V) enabled in BIOS" }
else { Fail "CPU virtualization appears OFF" "Enable Intel VT-x / AMD-V in your BIOS/UEFI." }

# 2) VMware Workstation/Player installed
$vmware = $false
if (Get-Command vmrun -ErrorAction SilentlyContinue) { $vmware=$true }
foreach ($d in @("$env:ProgramFiles\VMware\VMware Workstation","${env:ProgramFiles(x86)}\VMware\VMware Workstation")) {
  if ($d -and (Test-Path (Join-Path $d 'vmware.exe'))) { $vmware=$true }
}
if (Get-Service -Name 'VMAuthdService' -ErrorAction SilentlyContinue) { $vmware=$true }
if ($vmware) { Pass "VMware Workstation detected" }
else { Fail "VMware Workstation not found" "Install VMware Workstation, then re-run this check." }

# 3) Vagrant installed
if (Get-Command vagrant -ErrorAction SilentlyContinue) {
  Pass "Vagrant installed ($((vagrant --version) 2>$null))"
} else {
  Fail "Vagrant not found" "winget install HashiCorp.Vagrant  (then reopen PowerShell)"
}

# 4) vagrant-vmware-desktop plugin
$plugin = $false
if (Get-Command vagrant -ErrorAction SilentlyContinue) {
  if ((vagrant plugin list 2>$null) -match 'vagrant-vmware-desktop') { $plugin=$true }
}
if ($plugin) { Pass "vagrant-vmware-desktop plugin installed" }
else { Fail "vagrant-vmware-desktop plugin missing" "vagrant plugin install vagrant-vmware-desktop" }

# 5) Vagrant VMware Utility (separate HashiCorp download; runs as a service)
$util = (Get-Service -Name '*vagrant*vmware*' -ErrorAction SilentlyContinue) -or `
        (Test-Path "$env:ProgramFiles\HashiCorp\Vagrant VMware Utility") -or `
        (Test-Path "$env:ProgramFiles (x86)\HashiCorp\Vagrant VMware Utility")
if ($util) { Pass "Vagrant VMware Utility installed" }
else { Fail "Vagrant VMware Utility missing" "Auto-install (admin PowerShell): .\scripts\install-vmware-utility.ps1" }

# 6) RAM headroom for a Windows guest
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB)
if ($ram -ge 16) { Pass "RAM ${ram} GB (comfortable)" }
elseif ($ram -ge 12) { Info "RAM ${ram} GB - workable but tight with the Docker stack" }
else { Fail "RAM ${ram} GB - too low for Docker stack + Windows VM" "Use the Linux victim, or add RAM." }

# 7) Docker running (the rest of the lab)
docker info *> $null
if ($LASTEXITCODE -eq 0) { Pass "Docker engine is up" }
else { Info "Docker not running yet - install.ps1 handles that separately" }

Write-Host ""
if ($bad -eq 0) {
  Write-Host "  ALL CHECKS PASSED - build the Windows VM with:" -ForegroundColor Green
  Write-Host "    powershell -ExecutionPolicy Bypass -File .\install.ps1 -WithWindowsVictim"
} else {
  Write-Host "  $bad item(s) need fixing above. Fix them, then re-run this check." -ForegroundColor Yellow
  Write-Host "  The Docker-only lab still works now:  .\install.ps1 -NoWindowsVictim"
}
Write-Host ""

if ($bad -gt 0) { exit 1 } else { exit 0 }
