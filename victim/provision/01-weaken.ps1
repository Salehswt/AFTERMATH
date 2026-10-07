# 01-weaken.ps1 — deliberate misconfiguration. WEAK ON PREVENTION.
# Idempotent: safe to re-run. This box is isolated on the lab network only.
$ErrorActionPreference = "Continue"
function Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }

Step "Keeping the VM awake (Windows' 30-min idle sleep suspends the whole VM)"
# Windows 10 defaults to standby after 30 minutes idle. In a VM that is not a
# power saving - the hypervisor suspends the guest, the Elastic Agent stops
# checking in, and Fleet shows the victim "Offline" on a lab that was healthy
# minutes earlier. It can also kill a long provisioning run's WinRM channel
# mid-flight. There is no VMX setting for this (the guest is ASKING to sleep and
# VMware is obeying), so it has to be turned off inside the guest. 0 = never.
foreach ($s in @('standby-timeout-ac','standby-timeout-dc',
                 'hibernate-timeout-ac','hibernate-timeout-dc',
                 'monitor-timeout-ac','monitor-timeout-dc',
                 'disk-timeout-ac','disk-timeout-dc')) {
  powercfg /change $s 0 2>&1 | Out-Null
}
powercfg /hibernate off 2>&1 | Out-Null
# Read one value back so a silent failure can't masquerade as success.
$sb = (powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null | Select-String 'Current AC Power Setting Index').ToString()
if ($sb -match '0x0{8}$|0x00000000') {
  Write-Host "[ OK ] Sleep/hibernate disabled - the VM will stay up." -ForegroundColor Green
} else {
  Write-Host "[WARN] Could not confirm sleep is disabled ($sb). If the victim goes" -ForegroundColor Yellow
  Write-Host "       Offline in Fleet later, resume it with: cd victim ; vagrant up" -ForegroundColor Yellow
}

Step "Creating weak local accounts"
$weak = @{ "j.doe" = "Password123"; "svc_backup" = "Summer2023!"; "helpdesk" = "Welcome1" }
foreach ($u in $weak.Keys) {
  $p = ConvertTo-SecureString $weak[$u] -AsPlainText -Force
  if (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $u -Password $p -PasswordNeverExpires -AccountNeverExpires | Out-Null
  }
}
# service account is local admin (privilege-escalation path)
Add-LocalGroupMember -Group "Administrators" -Member "svc_backup" -ErrorAction SilentlyContinue

Step "Disabling lockout + password expiry (lets spray/brute-force land)"
net accounts /lockoutthreshold:0 | Out-Null
net accounts /maxpwage:unlimited | Out-Null

Step "Exposing services: RDP on, SMB signing off, open share, WinRM"
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force
New-Item -Path "C:\Share" -ItemType Directory -Force | Out-Null
New-SmbShare -Name "Public" -Path "C:\Share" -FullAccess "Everyone" -ErrorAction SilentlyContinue
# NOTE: do NOT call Enable-PSRemoting here. The box already has WinRM enabled
# (that's how Vagrant is running this), and Enable-PSRemoting -Force RESTARTS the
# WinRM service, which drops Vagrant's own connection -> "Bad HTTP response (500)"
# and a rolled-back/deleted VM. WinRM is already on; nothing to do.

Step "Turning down controls: Defender RT, UAC, Office macros"
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
# Read it back. Tamper Protection silently REVERTS Set-MpPreference: the call
# reports success and real-time protection stays on, and -ErrorAction
# SilentlyContinue hides that. This is the usual reason Atomic Red Team tests
# later "did not report back" with no obvious cause, so say it plainly here
# rather than letting the install claim a weakened host it did not get.
$rt = (Get-MpPreference -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
if ($rt -eq $true) {
  Write-Host "[ OK ] Defender real-time protection disabled." -ForegroundColor Green
} else {
  Write-Host "[WARN] Defender real-time protection is STILL ON - Tamper Protection" -ForegroundColor Yellow
  Write-Host "       blocked Set-MpPreference. Some Atomic Red Team tests will be" -ForegroundColor Yellow
  Write-Host "       blocked and their scenarios may seed little or no telemetry." -ForegroundColor Yellow
  Write-Host "       To fix: in the VM, Windows Security > Virus & threat protection" -ForegroundColor Yellow
  Write-Host "       > Manage settings > turn Tamper Protection OFF, then re-run:" -ForegroundColor Yellow
  Write-Host "         cd victim ; vagrant provision --provision-with 01-weaken" -ForegroundColor Yellow
}
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0
# enable macros without prompt for the office versions present
foreach ($v in @("16.0","15.0")) {
  $k = "HKCU:\Software\Microsoft\Office\$v\Word\Security"
  New-Item $k -Force | Out-Null
  Set-ItemProperty $k -Name VBAWarnings -Value 1
}
Write-Host "[ OK ] Host weakened." -ForegroundColor Green
