# 02-logging.ps1 — RICH ON DETECTION. The other half of the tension: controls
# are weak, but telemetry is maxed so the analyst can actually see the attack.
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"   # keep Invoke-WebRequest fast over WinRM
function Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }

Step "Installing Sysmon with SwiftOnSecurity config"
$sysmonZip = "$env:TEMP\Sysmon.zip"
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip
Expand-Archive $sysmonZip "$env:TEMP\Sysmon" -Force
# Prefer a config synced from the repo (victim/config/), else download one to a
# path that actually exists. The old code wrote to C:\vagrant\config\ which isn't
# present unless the repo ships that file, so the download threw
# DirectoryNotFoundException and Sysmon installed with NO config.
$cfg = "C:\vagrant\config\sysmon-config.xml"
if (-not (Test-Path $cfg)) {
  $cfg = "$env:TEMP\sysmonconfig.xml"
  Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $cfg
}
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i $cfg

Step "Enabling PowerShell script-block + module logging (4104)"
$psk = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $psk -Force | Out-Null
Set-ItemProperty $psk -Name EnableScriptBlockLogging -Value 1

Step "Enabling command-line auditing + enhanced audit policy"
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -ErrorAction SilentlyContinue
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null

Write-Host "[ OK ] Telemetry maximized." -ForegroundColor Green
