<#
  install.ps1  -  AFTERMATH  v1   (author: Saleh)
  One-command setup for the AFTERMATH SOC range.

  DEFAULT PATH (fresh analyst, zero experience):
    ONE dependency - Docker Desktop. No hypervisor. Everything, including the
    victim, runs as containers. Just run:

        powershell -ExecutionPolicy Bypass -File .\install.ps1

  OPTIONAL WINDOWS VICTIM:
    V2 adds a real Windows workstation VM for higher-fidelity DFIR. This is
    OPT-IN and the script tells you exactly what it will install first
    (Vagrant + a hypervisor, a large download, longer setup). You approve
    before anything is installed. The Linux container victim is always built
    either way, so the lab works even if you say no.

  Flags (skip the prompt):
    -WithWindowsVictim   also build the Windows VM (implies the extra installs)
    -NoWindowsVictim     Docker-only, don't ask
    -NoSeed              bring the lab up but don't seed the compromise
    -Auto                don't prompt before installing Docker
#>

[CmdletBinding()]
param(
  [switch]$WithWindowsVictim,
  [switch]$NoWindowsVictim,
  [switch]$NoSeed,
  [switch]$Auto
)

$ErrorActionPreference = 'Stop'
$LabRoot = $PSScriptRoot
$EnvFile = Join-Path $LabRoot '.env'

# Every `docker compose` call below uses relative -f paths (docker-compose.yml),
# so they only resolve from the project root. When already-admin (no re-elevation
# with -WorkingDirectory), the shell's CWD can be C:\WINDOWS\system32, which makes
# those calls fail with "cannot find docker-compose.yml". Anchor to the script dir.
Set-Location $LabRoot

# ---- self-elevate once (single UAC click) so installs / WSL / reboot work ---
$principal = New-Object Security.Principal.WindowsPrincipal(
  [Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
  $fwd = @()
  foreach ($k in $PSBoundParameters.Keys) { $fwd += "-$k" }
  $argList = @('-NoExit','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath)) + $fwd
  Start-Process powershell -Verb RunAs -WorkingDirectory $LabRoot -ArgumentList $argList | Out-Null
  exit 0
}

# ---- helpers used by stage 0 ------------------------------------------------
function Refresh-Path {
  # Re-read PATH from the registry so tools winget just installed are visible
  # in THIS session - no need to reopen PowerShell (FLARE-VM style).
  $m = [Environment]::GetEnvironmentVariable('Path','Machine')
  $u = [Environment]::GetEnvironmentVariable('Path','User')
  $extra = @(
    "C:\Program Files\Docker\Docker\resources\bin",
    "C:\Program Files\Vagrant\bin",
    "C:\HashiCorp\Vagrant\bin",
    "C:\Program Files\Oracle\VirtualBox"
  ) -join ';'
  $env:Path = "$m;$u;$extra"
}
function Find-VMware {
  # True if VMware Workstation/Player is installed on this host. Checks several
  # signals because vmrun.exe is usually NOT on PATH.
  if (Have vmrun) { return $true }
  $dirs = @(
    "$env:ProgramFiles\VMware\VMware Workstation",
    "${env:ProgramFiles(x86)}\VMware\VMware Workstation",
    "$env:ProgramFiles\VMware\VMware Player",
    "${env:ProgramFiles(x86)}\VMware\VMware Player"
  )
  foreach ($d in $dirs) {
    if ($d -and (Test-Path (Join-Path $d 'vmware.exe'))) { return $true }
    if ($d -and (Test-Path (Join-Path $d 'vmrun.exe')))  { return $true }
  }
  if (Get-Service -Name 'VMAuthdService','VMwareHostd' -ErrorAction SilentlyContinue) { return $true }
  foreach ($r in @(
      'HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation',
      'HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation')) {
    if (Test-Path $r) { return $true }
  }
  return $false
}
function Ensure-Wsl {
  # Set the installer to resume automatically after the reboot, then enable WSL2.
  $resume = 'powershell -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
  New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Force | Out-Null
  Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'SocLabResume' -Value $resume
  Log-Step "Enabling WSL2 (a one-time reboot is needed; the lab resumes on its own)"
  try { wsl --install --no-distribution *> $null } catch { try { wsl --install *> $null } catch {} }
  if ($Auto) {
    Log-Warn "Rebooting in 20s to finish WSL2 setup..."
    shutdown /r /t 20
  } else {
    $r = Read-Host "  Reboot now to finish WSL2 setup? It will resume automatically [Y/n]"
    if ($r -notmatch '^[Nn]$') { shutdown /r /t 10 }
    else { Log-Warn "Reboot when convenient, then just log in - the lab resumes itself." }
  }
}

# ============================================================================
#  UI: SOC / IR theme (24-bit truecolor) with automatic 16-color fallback
#  Deep azure -> signal cyan brand gradient; triage-semantic status colors
#  (green = healthy, amber = warning, red = critical). On any console that
#  can't do truecolor (output redirected, NO_COLOR set, pre-Win10) every
#  helper falls back to the plain 16-color [TAG] output.
# ============================================================================
$E = [char]27
$script:UI_TC = $false
function Init-Ui {
  # Enable the console's VT/ANSI processing + UTF-8 so gradients and glyphs render.
  try { $k='HKCU:\Console'; if(-not(Test-Path $k)){New-Item $k -Force|Out-Null}
        Set-ItemProperty $k VirtualTerminalLevel 1 -Type DWord -ErrorAction SilentlyContinue } catch {}
  try { [Console]::OutputEncoding=[Text.Encoding]::UTF8 } catch {}
  $script:UI_TC = (-not [Console]::IsOutputRedirected) -and
                  (-not $env:NO_COLOR) -and
                  ([Environment]::OSVersion.Version.Major -ge 10)
}
Init-Ui

function fg($r,$g,$b){ "$E[38;2;$r;$g;${b}m" }
function bg($r,$g,$b){ "$E[48;2;$r;$g;${b}m" }
$RST="$E[0m"; $BOLD="$E[1m"; $DIM="$E[2m"

# SOC/IR palette (RGB). Swap $C1/$C2 to reskin the whole installer.
$C1=@(20,96,224); $C2=@(0,214,255)                 # brand gradient: azure -> cyan
$OK=(fg 46 214 126); $WARN=(fg 255 181 38); $ERR=(fg 247 71 71); $SLATE=(fg 108 124 148)

# Colour a string char-by-char along the C1 -> C2 gradient (smooth fade).
function Grad($s){
  $o=''; $len=[math]::Max(1,$s.Length-1)
  for($i=0;$i -lt $s.Length;$i++){ $t=$i/$len
    $r=[int]($C1[0]+$t*($C2[0]-$C1[0])); $g=[int]($C1[1]+$t*($C2[1]-$C1[1])); $b=[int]($C1[2]+$t*($C2[2]-$C1[2]))
    $o+="$(fg $r $g $b)$($s[$i])" }
  "$o$RST"
}
function Ui-Rail($w){ if($UI_TC){ "  "+(Grad (([string][char]0x2501)*$w)) } else { "  "+('-'*$w) } }
function Ui-Panel($title){
  if($UI_TC){
    $w=58; $t=" $title "; $rest=[string]([char]0x2500)*([math]::Max(0,$w-$t.Length-3))
    Write-Host ("  "+(Grad ("$([char]0x256D)$([char]0x2500)$([char]0x2524)$t$([char]0x251C)$rest$([char]0x256E)")))
  } else {
    Write-Host ("  +-[ $title ]-").PadRight(62,'-') -ForegroundColor Cyan
  }
}
function Ui-Kv($k,$v){
  if($UI_TC){ Write-Host ("  $(fg $C2[0] $C2[1] $C2[2])$BOLD{0,-11}$RST{1}" -f $k,$v) }
  else       { Write-Host ("  {0,-11}{1}" -f $k,$v) }
}

# ---- logging: INFO / STEP / OK / WARN / ERR ---------------------------------
function Log-Info($m){ if($UI_TC){ Write-Host "  $SLATE$([char]0x25CF)$RST $m" }            else { Write-Host "[INFO] $m" -ForegroundColor Blue } }
function Log-Step($m){ if($UI_TC){ Write-Host ""; Write-Host "  $(Grad ([char]0x276F)) $BOLD$(Grad $m)" } else { Write-Host "[STEP] $m" -ForegroundColor Cyan } }
function Log-Ok  ($m){ if($UI_TC){ Write-Host "  $OK$([char]0x2714)$RST $m" }               else { Write-Host "[ OK ] $m" -ForegroundColor Green } }
function Log-Warn($m){ if($UI_TC){ Write-Host "  $WARN$([char]0x25B2) $m$RST" }              else { Write-Host "[WARN] $m" -ForegroundColor Yellow } }
function Log-Err ($m){ if($UI_TC){ Write-Host "  $ERR$([char]0x2716) $BOLD$m$RST" }          else { Write-Host "[ERR ] $m" -ForegroundColor Red } }
function Die($m){ Log-Err $m; exit 1 }

function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function New-Secret {
  -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object {[char]$_})
}
function Get-HostRamGb {
  [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
}

# `vagrant up` can hang indefinitely: when the guest's WinRM output channel dies
# mid-provisioner the script still runs to completion INSIDE the VM, but Vagrant
# waits on a stream that will never produce another byte. There is no error and
# no timeout to trap, so watch for SILENCE instead - that catches the fault
# whatever caused it. Vagrant's output is relayed as it arrives so a long box
# download still looks alive.
function Invoke-VagrantUp {
  param([string]$Provider, [int]$StallMinutes = 12)
  $dir = (Get-Location).Path
  $out = Join-Path $env:TEMP 'soclab-vagrant-up.out'
  $err = Join-Path $env:TEMP 'soclab-vagrant-up.err'
  Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
  New-Item -ItemType File -Path $out -Force | Out-Null
  New-Item -ItemType File -Path $err -Force | Out-Null

  $p = Start-Process vagrant -ArgumentList @('up', '--provider', $Provider) -PassThru -NoNewWindow `
         -WorkingDirectory $dir -RedirectStandardOutput $out -RedirectStandardError $err
  # Touch .Handle while the process is alive. Without this, a Start-Process
  # -PassThru object returns a NULL ExitCode after exit - so `$p.ExitCode -eq 0`
  # is false even for a clean run, and every build would be reported as failed.
  $null = $p.Handle
  $shown = 0; $lastSize = -1L; $lastMove = Get-Date
  while (-not $p.HasExited) {
    Start-Sleep 5
    $lines = @(Get-Content $out -ErrorAction SilentlyContinue)
    if ($lines.Count -gt $shown) {
      $lines[$shown..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
      $shown = $lines.Count
    }
    # Stall detection counts BYTES, not lines: the box download reports progress
    # with \r on one unterminated line, so the line count can sit still for
    # minutes while the download is perfectly healthy.
    $size = 0L
    try { $size = (Get-Item $out).Length + (Get-Item $err).Length } catch {}
    if ($size -ne $lastSize) { $lastSize = $size; $lastMove = Get-Date; continue }
    if (((Get-Date) - $lastMove).TotalMinutes -ge $StallMinutes) {
      Log-Warn "Vagrant has produced no output for $StallMinutes min - the VM's WinRM"
      Log-Warn "channel has stalled. Abandoning this attempt."
      # Vagrant runs its work in a ruby child process. Collect OUR child PIDs
      # before killing the parent (afterwards they get reparented and can no
      # longer be identified) - never `Get-Process ruby | Stop-Process`, which
      # would kill unrelated Ruby work running elsewhere on the machine.
      $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty ProcessId)
      try { $p.Kill() } catch {}
      Start-Sleep 3
      foreach ($k in $kids) { Stop-Process -Id $k -Force -ErrorAction SilentlyContinue }
      return 'stalled'
    }
  }
  $lines = @(Get-Content $out -ErrorAction SilentlyContinue)
  if ($lines.Count -gt $shown) { $lines[$shown..($lines.Count - 1)] | ForEach-Object { Write-Host $_ } }
  if ($p.ExitCode -eq 0) { return 'ok' }
  # Show what Vagrant actually complained about - it goes to stderr, which is
  # redirected here and would otherwise be swallowed, leaving a bare "failed".
  $etail = @(Get-Content $err -Tail 20 -ErrorAction SilentlyContinue)
  if ($etail) { Log-Warn "vagrant reported:"; $etail | ForEach-Object { Log-Warn "  $_" } }
  return 'failed'
}
function Show-Banner {
  $art = @(
'     _    _____ _____ _____ ____  __  __    _  _____ _   _',
'    / \  |  ___|_   _| ____|  _ \|  \/  |  / \|_   _| | | |',
'   / _ \ | |_    | | |  _| | |_) | |\/| | / _ \ | | | |_| |',
'  / ___ \|  _|   | | | |___|  _ <| |  | |/ ___ \| | |  _  |',
' /_/   \_\_|     |_| |_____|_| \_\_|  |_/_/   \_\_| |_| |_|')
  Write-Host ""
  if ($UI_TC) {
    foreach ($ln in $art) { Write-Host ("  "+(Grad $ln)) }
    Write-Host "  $DIM     you arrive once it's over$RST"
    Write-Host (Ui-Rail 58)
  } else {
    foreach ($ln in $art) { Write-Host ("  "+$ln) -ForegroundColor Cyan }
    Write-Host "                    you arrive once it's over" -ForegroundColor DarkGray
  }
  Write-Host ""
}

Show-Banner
Log-Info "AFTERMATH installer - Docker by default, optional Windows victim VM"

# =============================================================================
#  0. Docker Desktop - the ONE required dependency. Install if missing.
# =============================================================================
Log-Step "0/6  Checking Docker (fully automatic - nothing to install by hand)"
if (-not (Have docker)) {
  if (-not (Have winget)) {
    Die "winget not available. Install Docker Desktop manually: https://www.docker.com/products/docker-desktop/"
  }
  Log-Step "Installing Docker Desktop (a few minutes; no action needed)"
  winget install --silent --accept-package-agreements --accept-source-agreements Docker.DockerDesktop
  Refresh-Path
}
if (-not (Have docker)) { Refresh-Path }   # make the CLI visible in THIS session

# Auto-launch Docker Desktop if the engine isn't already up.
# Probe via cmd: `docker info *> $null` lets PowerShell wrap the daemon-down
# stderr in a NativeCommandError, which $ErrorActionPreference='Stop' turns into
# a terminating error - killing the script in exactly the case this branch
# exists to handle. cmd swallows stderr before PowerShell sees it; $LASTEXITCODE
# is still the native exit code.
cmd /c "docker info >nul 2>&1"
if ($LASTEXITCODE -ne 0) {
  $dd = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
  if (Test-Path $dd) { Log-Step "Starting Docker Desktop for you"; Start-Process $dd | Out-Null }
}

# Wait for the engine. First start also finishes WSL2 setup, so allow time.
Log-Step "Waiting for the Docker engine (first start can take several minutes)"
$deadline = (Get-Date).AddSeconds(600)
do {
  Start-Sleep 8
  cmd /c "docker info >nul 2>&1"   # see the note above - must not be *> $null
  $ready = ($LASTEXITCODE -eq 0)
  if (-not $ready -and (Get-Date) -gt $deadline) {
    Log-Warn "Docker engine did not come up - this is almost always WSL2 not being ready yet."
    Ensure-Wsl
    Die "The lab will continue automatically after the reboot."
  }
  if (-not $ready) { Log-Info "  still starting..." }
} until ($ready)
Log-Ok "Docker is ready"

$ram = Get-HostRamGb
$heap = if ($ram -lt 12) { '1g' } else { '2g' }

# =============================================================================
#  0b. Decide on the OPTIONAL Windows victim VM - with full disclosure.
# =============================================================================
$buildWin = $false
if ($WithWindowsVictim) {
  $buildWin = $true
} elseif ($NoWindowsVictim) {
  $buildWin = $false
} else {
  Write-Host ""
  Ui-Panel "OPTIONAL  //  ADD A REAL WINDOWS VICTIM VM"
  Write-Host "   The lab already includes a Linux victim (no extra setup)."
  Write-Host "   A Windows VM gives higher-fidelity DFIR (Sysmon, event logs,"
  Write-Host "   Office macros) BUT requires the following to be INSTALLED and"
  Write-Host "   downloaded first:"
  Write-Host ""
  Write-Host "     * Vagrant                (~100 MB install)"
  Write-Host "     * A hypervisor           (VirtualBox is installed only if you"
  Write-Host "                               have none; VMware is used if present)"
  Write-Host "     * A Windows eval box     (~10 GB download, first run only)"
  Write-Host ""
  Write-Host "   Extra time: 20-40 min on first run. The eval image expires"
  Write-Host "   after ~90 days (rebuildable). You will be asked to approve"
  Write-Host "   each install before it happens."
  Write-Host ""
  $ans = Read-Host "  Build the Windows victim VM too? [y/N]"
  $buildWin = ($ans -match '^[Yy]$')
}
if ($buildWin) { Log-Info "Windows victim: YES (extra installs will be confirmed)" }
else           { Log-Info "Windows victim: no - Linux victim only (easy path)" }

# ---- prepare Windows VM prerequisites, each with explicit consent -----------
function Approve($prompt){
  if ($Auto) { return $true }
  $r = Read-Host "  $prompt [Y/n]"
  return (-not ($r -match '^[Nn]$'))
}
if ($buildWin) {
  Log-Step "Running Windows-VM preflight check first"
  & powershell -ExecutionPolicy Bypass -File (Join-Path $LabRoot 'scripts\check-windows.ps1')
  if ($LASTEXITCODE -ne 0) {
    Log-Warn "Preflight found blockers (see above). Skipping the Windows VM for now."
    Log-Warn "Fix them, run scripts\check-windows.ps1 until green, then re-run with -WithWindowsVictim."
    $buildWin = $false
  }
}
if ($buildWin) {
  Log-Step "Preparing Windows VM prerequisites"

  if (-not (Have vagrant)) {
    Log-Warn "Vagrant is needed to build and provision the Windows VM."
    if (Approve "Install Vagrant now via winget?") {
      winget install --silent --accept-package-agreements --accept-source-agreements HashiCorp.Vagrant
      Refresh-Path
      if (-not (Have vagrant)) {
        # PATH still not visible in this session: relaunch ourselves in a fresh
        # elevated window that inherits the refreshed PATH, then close this one.
        # No manual step - it continues on its own.
        Log-Step "Reloading environment and continuing automatically..."
        $argList = @('-NoExit','-ExecutionPolicy','Bypass','-File',
                     ('"{0}"' -f $PSCommandPath),'-WithWindowsVictim')
        Start-Process powershell -Verb RunAs -WorkingDirectory $LabRoot -ArgumentList $argList | Out-Null
        exit 0
      }
      Log-Ok "Vagrant installed and ready."
    } else {
      Log-Warn "Skipping Windows VM. Continuing with the Linux victim only."
      $buildWin = $false
    }
  }

  # hypervisor check: auto-detect VMware or VirtualBox; only install VirtualBox
  # as a last resort. If VMware is present we use it - no env var needed.
  if ($buildWin) {
    $hasVbox = (Have VBoxManage)
    $hasVmware = Find-VMware

    if ($hasVmware) {
      $env:LAB_PROVIDER = 'vmware_desktop'
      Log-Ok "VMware detected - using the VMware provider."
      Log-Info "  Needs the Vagrant VMware plugin + VMware Utility (one-time)."
      # Probe via cmd, not `2>$null`: redirecting a native command's stderr
      # inside PowerShell wraps it in a NativeCommandError, which
      # $ErrorActionPreference='Stop' makes terminating - so a Vagrant that
      # writes ANY warning here (no plugins yet, stale manifest, licence notice)
      # would kill the installer. Same trap as the docker probe above, and this
      # one sits on the fresh-machine path where Vagrant has just been installed.
      $plugins = cmd /c "vagrant plugin list 2>nul"
      if (-not ($plugins | Select-String 'vagrant-vmware-desktop')) {
        if (Approve "Install the vagrant-vmware-desktop plugin now?") {
          & vagrant plugin install vagrant-vmware-desktop
        } else {
          Log-Warn "Without the plugin Vagrant can't drive VMware. Skipping Windows VM."
          $buildWin = $false
        }
      }
      # The utility installs under HashiCorp\ and registers a Windows service -
      # detect by the service, not a guessed path.
      $hasUtil = [bool](Get-Service -Name 'vagrant-vmware-utility' -ErrorAction SilentlyContinue) `
                 -or (Test-Path "$env:ProgramFiles\HashiCorp\Vagrant VMware Utility")
      if ($buildWin -and -not $hasUtil) {
        Log-Warn "VMware also needs the free 'Vagrant VMware Utility' (a service)."
        if (Approve "Install the Vagrant VMware Utility now (automatic)?") {
          & powershell -ExecutionPolicy Bypass -File (Join-Path $LabRoot 'scripts\install-vmware-utility.ps1')
          $hasUtil = [bool](Get-Service -Name 'vagrant-vmware-utility' -ErrorAction SilentlyContinue)
        }
        if (-not $hasUtil) {
          Log-Warn "Utility not installed. Run scripts\install-vmware-utility.ps1 in an admin"
          Log-Warn "PowerShell, then re-run with -WithWindowsVictim. Skipping VM for now."
          $buildWin = $false
        } else { Log-Ok "Vagrant VMware Utility ready." }
      }
    }
    elseif ($hasVbox) {
      $env:LAB_PROVIDER = 'virtualbox'
      Log-Ok "VirtualBox detected - using it."
    }
    else {
      Log-Warn "No hypervisor found (neither VMware nor VirtualBox)."
      Write-Host "   VirtualBox needs VT-x enabled in BIOS and can clash with Hyper-V/WSL2."
      Write-Host "   (If you prefer VMware, install VMware Workstation first, then re-run.)"
      if (Approve "Install VirtualBox now via winget?") {
        winget install --silent --accept-package-agreements --accept-source-agreements Oracle.VirtualBox
        $env:LAB_PROVIDER = 'virtualbox'
        Log-Ok "VirtualBox installed."
      } else {
        Log-Warn "Skipping Windows VM. Continuing with the Linux victim only."
        $buildWin = $false
      }
    }
  }
}

# =============================================================================
#  1. Secrets (.env)
# =============================================================================
Log-Step "1/6  Generating secrets (.env)"
if (-not (Test-Path $EnvFile)) {
  @(
    "# Auto-generated by install.ps1 - DO NOT COMMIT"
    "ELASTIC_PASSWORD=$(New-Secret)"
    "KIBANA_PASSWORD=$(New-Secret)"
    "FLEET_TOKEN="
    "STACK_VERSION=8.14.3"
    "ES_JAVA_OPTS=-Xms$heap -Xmx$heap"
    "LAB_NETWORK=172.30.0.0/24"
  ) | Set-Content -Path $EnvFile -Encoding ascii
  Log-Ok ".env created"
} else {
  Log-Info ".env already exists - reusing"
}
$elasticPass = ((Get-Content $EnvFile | Select-String '^ELASTIC_PASSWORD=') -split '=',2)[1]

# =============================================================================
#  2. Bring up the container stack (Linux victim always included)
# =============================================================================
Log-Step "2/6  Starting the lab (SIEM, WAF, proxy, sensors, attacker, Linux victim)"
$composeArgs = @('-f','docker-compose.yml','-f','docker-compose.linux-victim.yml')

# Host address the external Windows VM uses to reach the SIEM (it maps the
# in-Docker hostnames to this in its hosts file). VMware on Windows does NOT
# configure the private/host-only adapter inside the guest, so on VMware the VM
# reaches the host over the NAT network - use the VMnet8 (NAT) host adapter IP.
# VirtualBox configures the host-only adapter, so 192.168.56.1 works there.
$LabHostIp =
  if ($env:LAB_HOST_IP) { $env:LAB_HOST_IP }
  elseif ($env:LAB_PROVIDER -eq 'vmware_desktop') {
    $nat = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'VMware Network Adapter VMnet8' -ErrorAction SilentlyContinue |
            Select-Object -First 1).IPAddress
    if ($nat) { $nat } else { '192.168.56.1' }
  }
  else { '192.168.56.1' }
if ($buildWin) { Log-Info "Windows VM will reach the SIEM via $LabHostIp (override with `$env:LAB_HOST_IP)" }

# Where 9200/8220 get published. Loopback unless the Windows VM has to reach
# them, and then only on the host-only/NAT adapter it actually sits on - never
# 0.0.0.0, which would put Elasticsearch and Fleet on the physical LAN. Kibana
# and the vulnerable web apps are pinned to 127.0.0.1 in docker-compose.yml.
$bindIp = if ($buildWin) { $LabHostIp } else { '127.0.0.1' }
if (Select-String -Path $EnvFile -Pattern '^LAB_BIND_IP=' -Quiet) {
  (Get-Content $EnvFile) -replace '^LAB_BIND_IP=.*', "LAB_BIND_IP=$bindIp" | Set-Content $EnvFile -Encoding ascii
} else {
  Add-Content -Path $EnvFile -Value "LAB_BIND_IP=$bindIp" -Encoding ascii
}
Log-Info "Publishing Elasticsearch/Fleet on ${bindIp} only; Kibana + web apps on 127.0.0.1"

Push-Location $LabRoot
try {
  # --build so edits to the victim/attacker Dockerfiles always take effect; a
  # plain `up -d` silently reuses a stale cached image.
  & docker compose @composeArgs up -d --build
  if ($LASTEXITCODE -ne 0) { Die "Failed to start the Docker stack." }
} finally { Pop-Location }

Log-Step "Waiting for Kibana to become AVAILABLE (first run can take 10-15 min)"
$maxSec = 900
$start  = Get-Date
$spin   = if ($UI_TC) { @([char]0x280B,[char]0x2819,[char]0x2839,[char]0x2838,[char]0x283C,[char]0x2834,[char]0x2826,[char]0x2827,[char]0x2807,[char]0x280F) } else { @('|','/','-','\') }
$i      = 0
do {
  Start-Sleep 3
  $level = 'starting'
  try { $level = (Invoke-RestMethod 'http://localhost:5601/api/status' -TimeoutSec 5).status.overall.level } catch { $level = 'no response yet' }
  $elapsed = [int]((Get-Date) - $start).TotalSeconds
  $mm = '{0:d2}:{1:d2}' -f [int]($elapsed/60), ($elapsed%60)
  $c  = $spin[$i % $spin.Count]; $i++
  # single self-overwriting line: spinner  elapsed / max  status (colour tracks state)
  if ($UI_TC) {
    $lc = if ($level -eq 'available') { $OK } elseif ($level -match 'no response|starting') { $WARN } else { $SLATE }
    Write-Host ("`r  $(fg $C2[0] $C2[1] $C2[2])$c$RST  waiting for Kibana   $DIM{1} / {2:d2}:00$RST   $lc{3}$RST            " -f $c,$mm,[int]($maxSec/60),$level) -NoNewline
  } else {
    Write-Host ("`r  {0}  {1} / {2:d2}:00 elapsed   Kibana: {3}           " -f $c,$mm,[int]($maxSec/60),$level) -NoNewline -ForegroundColor Cyan
  }
  if ($elapsed -gt $maxSec) {
    Write-Host ""
    Die "Timed out waiting for Kibana. It may just need more time - check 'docker compose logs kibana', or re-run install.ps1 (images are cached now)."
  }
} until ($level -eq 'available')
Write-Host ""
Log-Ok "SIEM is up (Kibana available in $mm)"

# =============================================================================
#  3. Fleet policy + enrollment token (native PowerShell)
# =============================================================================
Log-Step "3/6  Fetching the Fleet enrollment token for the victim policy"
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:$elasticPass"))
$headers = @{ Authorization = "Basic $auth"; 'kbn-xsrf' = 'true' }
$kb = 'http://localhost:5601'
$policyId = 'victim-policy'

# The policy is preconfigured in siem/kibana.yml WITH the System integration -
# that integration is what ships auth.log/syslog. Don't create a second policy
# by the same name here; and never just take the first enrollment key, because
# Fleet lists the fleet-server policy's key first and enrolling the victim with
# it looks like it worked while shipping no host logs at all.
function Get-VictimToken {
  try {
    $r = Invoke-RestMethod -Headers $headers `
      -Uri "$kb/api/fleet/enrollment_api_keys?kuery=policy_id:%22$policyId%22"
    return ($r.list | Select-Object -First 1).api_key
  } catch { return $null }
}

# Fleet finishes applying preconfigured policies shortly after Kibana reports
# "available" - wait rather than lose the race.
$token = $null
for ($t = 0; $t -lt 30 -and -not $token; $t++) {
  $token = Get-VictimToken
  if (-not $token) { Start-Sleep 4 }
}
if (-not $token) {
  Log-Warn "No enrollment key for '$policyId' - creating the policy as a fallback"
  try {
    Invoke-RestMethod -Uri "$kb/api/fleet/agent_policies?sys_monitoring=true" -Method Post `
      -Headers $headers -ContentType 'application/json' `
      -Body "{`"id`":`"$policyId`",`"name`":`"Victim Policy`",`"namespace`":`"default`",`"monitoring_enabled`":[`"logs`",`"metrics`"]}" *> $null
  } catch { Log-Info "  policy already exists - reusing" }
  for ($t = 0; $t -lt 15 -and -not $token; $t++) {
    $token = Get-VictimToken
    if (-not $token) { Start-Sleep 4 }
  }
}
if (-not $token) { Die "Could not obtain a Fleet enrollment token for '$policyId'." }
(Get-Content $EnvFile) -replace '^FLEET_TOKEN=.*', "FLEET_TOKEN=$token" | Set-Content $EnvFile -Encoding ascii
Log-Ok "Fleet enrollment token ready"

# =============================================================================
#  4. Enroll victims (Linux always; Windows VM if chosen)
# =============================================================================
Log-Step "4/6  Enrolling the Linux victim"
& docker compose @composeArgs exec -T linux-victim /opt/enroll.sh $token
if ($LASTEXITCODE -ne 0) { Log-Warn "Linux victim enroll returned non-zero; check its logs." }
Log-Ok "Linux victim enrolled"

if ($buildWin) {
  Log-Step "4b/6  Building + enrolling the Windows VM (this is the long part)"

  # The VM uses the SHARED default output/Fleet host (single in-Docker hostnames
  # 'elasticsearch'/'fleet-server' - Basic license forbids a per-policy output).
  # It can't resolve those Docker names, so its provisioner (04-elastic-agent.ps1)
  # adds hosts-file entries mapping them to $LabHostIp, where Docker publishes
  # 9200/8220. So the VM enrolls at the SAME fleet URL the containers use.
  $fleetUrl  = "http://fleet-server:8220"
  $winPolicy = 'windows-victim'

  function Kb($method, $path, $body) {
    $call = @{ Uri = "$kb$path"; Method = $method; Headers = $headers; ContentType = 'application/json' }
    if ($body) { $call.Body = $body }
    try { return Invoke-RestMethod @call } catch { $script:KbErr = $_.ErrorDetails.Message; return $null }
  }

  # 1) The Windows policy (uses the shared default output; sys_monitoring adds
  #    the System integration for Security/System/Application event logs).
  if (-not (Kb 'Post' '/api/fleet/agent_policies?sys_monitoring=true' (@{
      id=$winPolicy; name='Windows Victim Policy'; namespace='default'
      monitoring_enabled=@('logs','metrics')
    } | ConvertTo-Json))) {
    if ($KbErr -match 'already exists|409') { Log-Info "  Windows policy already exists - reusing" }
    else { Log-Warn "  Could not create the Windows policy: $KbErr" }
  }

  # 2) The Windows integration - ships Sysmon/Operational and PowerShell/
  #    Operational (event ids 1/3/13 and 4104), which the System integration does
  #    NOT collect. Input key is '<policy_template>-<input_type>' = windows-winlog;
  #    the channel names come from the package, so enabling the streams is enough.
  $winVer = (Kb 'Get' '/api/fleet/epm/packages/windows' $null).item.version
  if ($winVer) {
    $winPkg = @{
      name='windows-1'; policy_id=$winPolicy; namespace='default'
      package=@{ name='windows'; version=$winVer }
      inputs=@{
        'windows-winlog'=@{ enabled=$true; streams=@{
          'windows.sysmon_operational'=@{ enabled=$true }
          'windows.powershell_operational'=@{ enabled=$true }
          'windows.powershell'=@{ enabled=$true }
          'windows.forwarded'=@{ enabled=$true }
        } }
      }
    } | ConvertTo-Json -Depth 8
    if (-not (Kb 'Post' '/api/fleet/package_policies' $winPkg)) {
      if ($KbErr -match 'already exists|409') { Log-Info "  Windows integration already present" }
      else {
        Log-Warn "Could not auto-add the Windows integration ($KbErr)."
        Log-Warn "Add 'Windows' to the '$winPolicy' policy in Kibana for Sysmon +"
        Log-Warn "PowerShell channels. The VM still ships Security/System logs."
      }
    } else { Log-Ok "Windows integration added (Sysmon + PowerShell channels)" }
  }

  # 3) Enrollment token for the Windows policy (NOT the Linux one).
  $winToken = $null
  for ($t = 0; $t -lt 20 -and -not $winToken; $t++) {
    $r = Kb 'Get' "/api/fleet/enrollment_api_keys?kuery=policy_id:%22$winPolicy%22" $null
    $winToken = ($r.list | Select-Object -First 1).api_key
    if (-not $winToken) { Start-Sleep 3 }
  }
  if (-not $winToken) {
    Log-Warn "No enrollment token for '$winPolicy' - skipping the VM build."
  } else {
    Push-Location (Join-Path $LabRoot 'victim')
    try {
      $env:FLEET_TOKEN   = $winToken
      $env:FLEET_URL     = $fleetUrl
      $env:LAB_HOST_IP   = $LabHostIp
      $env:STACK_VERSION = '8.14.3'
      $prov = if ($env:LAB_PROVIDER) { $env:LAB_PROVIDER } else { 'virtualbox' }
      # Did a VM already exist BEFORE this `vagrant up`? Vagrant records a
      # machine id under .vagrant/machines once one is created, so the id file is
      # the reliable signal - and it has to be read before `vagrant up`, which
      # writes it. This decides whether the extra agent provision below is needed
      # or actively harmful; see the two branches.
      $vmExisted = [bool](Get-ChildItem '.vagrant\machines' -Recurse -Filter 'id' -ErrorAction SilentlyContinue)
      $upResult = Invoke-VagrantUp -Provider $prov
      if ($upResult -ne 'ok') {
        # A stalled or failed attempt leaves a half-provisioned VM (booted, but
        # missing Sysmon / Atomic / the agent), so provisioning on top of it would
        # produce a lab that looks built and ships nothing. Destroy and rebuild
        # once from scratch - the fault is intermittent, so a clean retry usually
        # succeeds.
        Log-Warn "VM attempt did not complete ($upResult). Rebuilding once from scratch."
        cmd /c "vagrant destroy -f >nul 2>&1"
        $vmExisted = $false     # whatever was there is gone; this is now a fresh build
        $upResult = Invoke-VagrantUp -Provider $prov
      }
      if ($upResult -ne 'ok') {
        Log-Warn "Windows VM provisioning failed twice; the Linux lab still works."
        Log-Warn "Retry later with: cd victim ; vagrant destroy -f ; vagrant up --provider $prov"
      } elseif (-not $vmExisted) {
        # Fresh build: `vagrant up` CREATED the VM and therefore already ran every
        # provisioner, including 04-agent, against the token issued moments ago.
        # Re-provisioning here would enroll a second time and strand the first
        # enrollment as a permanently "offline" agent in Fleet - on every new
        # install, so a first-time user opens Fleet to an unhealthy-looking agent.
        Log-Ok "Windows victim provisioned and enrolled"
      } else {
        # Existing VM: `vagrant up` runs provisioners ONLY when it creates the VM,
        # so it did nothing here and the agent still holds its old enrollment
        # token - now invalid because this install reissued Fleet, which would
        # leave every Windows detection reading empty. Re-run just the agent
        # provisioner; it re-enrolls in place if the agent is already installed.
        Log-Step "Ensuring the VM agent is enrolled against the current Fleet"
        & vagrant provision --provision-with 04-agent
        if ($LASTEXITCODE -ne 0) {
          Log-Warn "VM agent re-enrollment returned non-zero. If Windows detections read"
          Log-Warn "empty, re-run: cd victim ; vagrant provision --provision-with 04-agent"
        } else {
          Log-Ok "Windows victim provisioned and enrolled"
        }
      }
    } finally { Pop-Location }
  }
}

# =============================================================================
#  4c. Guarantee the Linux victim policy carries the System integration
# =============================================================================
# The System integration (which ships auth.log/syslog) is preconfigured onto
# victim-policy in siem/kibana.yml. But when the Windows VM is built, its policy
# is created with sys_monitoring=true, and that auto-added System integration
# claims the DEFAULT name 'system-1' - the same name Fleet's preconfiguration
# wants for the Linux one. Depending on which wins the race, victim-policy can
# end up with NO System integration, and then every Linux auth/sudo detection
# reads empty even though the agent is healthy. Verify and, if missing, add it
# under a distinct name so the collision can't recur.
Log-Step "Verifying the Linux victim policy has the System integration"
try {
  $allPp = (Invoke-RestMethod -Headers $headers -Uri "$kb/api/fleet/package_policies?perPage=100").items
  $hasSys = [bool]($allPp | Where-Object { $_.policy_id -eq $policyId -and $_.package.name -eq 'system' })
  if ($hasSys) {
    Log-Ok "System integration present on the victim policy"
  } else {
    Log-Warn "System integration missing from the victim policy (Fleet preconfig race) - adding it"
    $sysVer = (Invoke-RestMethod -Headers $headers -Uri "$kb/api/fleet/epm/packages/system").item.version
    $sysBody = @{
      name='system-victim'; policy_id=$policyId; namespace='default'
      package=@{ name='system'; version=$sysVer }
      inputs=@{
        'system-logfile'=@{ enabled=$true; streams=@{ 'system.auth'=@{enabled=$true}; 'system.syslog'=@{enabled=$true} } }
        'system-system/metrics'=@{ enabled=$true }
      }
    } | ConvertTo-Json -Depth 8
    Invoke-RestMethod -Uri "$kb/api/fleet/package_policies" -Method Post -Headers $headers -ContentType 'application/json' -Body $sysBody | Out-Null
    Log-Ok "System integration added to the victim policy"
    # Give the agent a moment to receive the updated policy before we seed, so
    # its auth.log harvester is running when the compromise is generated.
    Start-Sleep 20
  }
} catch {
  Log-Warn "Could not verify/add the System integration ($($_.Exception.Message)); Linux auth detections may read empty."
}

# =============================================================================
#  5. Seed the historical compromise
# =============================================================================
if (-not $NoSeed) {
  Log-Step "5/6  Seeding the Linux compromise (attacker container)"
  # The attacker container only does network-observable Linux attacks; it always
  # targets 'linux' and cleanly SKIPS Windows scenarios (those run on the VM in
  # step 5b). Passing 'windows' here just makes it fail on techniques it can't do.
  & docker compose @composeArgs exec -T `
      -e LAB_TARGETS=linux -e ELASTIC_PASSWORD=$elasticPass `
      attacker /attacks/seed.sh --all
  if ($LASTEXITCODE -ne 0) {
    Log-Warn "Seeding reported problems - some techniques generated no telemetry."
    Log-Warn "Check 'docker compose logs attacker' and the enroll step above before hunting."
  } else {
    Log-Ok "Linux telemetry seeded"
  }

  # 5b) Windows scenarios run ON the VM via Atomic Red Team (host-based telemetry
  #     that the Windows agent ships). Best-effort - a failed atomic must not
  #     break the lab.
  if ($buildWin) {
    Log-Step "5b/6  Seeding Windows scenarios on the VM (Atomic Red Team)"
    & powershell -ExecutionPolicy Bypass -File (Join-Path $LabRoot 'scripts\seed-windows.ps1') `
        -ElasticPass $elasticPass -HostIp $LabHostIp
    if ($LASTEXITCODE -ne 0) { Log-Warn "Windows seeding had problems; see above. The Linux lab is unaffected." }
    else { Log-Ok "Windows telemetry seeded" }
  }
} else {
  Log-Warn "5/6  Skipping seed (-NoSeed)."
}

# =============================================================================
#  6. Validate the answer key against the telemetry we just seeded
# =============================================================================
if (-not $NoSeed) {
  Log-Step "6/6  Validating detections (each answer-key query must return hits)"
  $vt = if ($buildWin) { 'linux,windows' } else { 'linux' }
  & docker compose @composeArgs exec -T `
      -e ELASTIC_PASSWORD=$elasticPass -e LAB_TARGETS=$vt `
      attacker python3 /attacks/validate_detections.py /scenarios
  if ($LASTEXITCODE -ne 0) {
    Log-Warn "Some detections returned no hits (see above). The lab still works,"
    Log-Warn "but an answer-key query is out of sync with the telemetry."
  } else { Log-Ok "All detections match the seeded telemetry" }

  # The Security detection rules were imported at stack startup, BEFORE any
  # logs-* data existed, and they run on a schedule - so they sit in "partial
  # failure / no matching index" until their next cycle and Security > Alerts
  # stays empty. Now that the compromise is seeded, force a prompt run (disable
  # then enable) so the rules fire against the backdated telemetry and alerts are
  # there when the installer finishes.
  Log-Step "Triggering the detection rules against the seeded telemetry"
  try {
    $ba = @{ Uri = "$kb/api/detection_engine/rules/_bulk_action"; Headers = $headers; Method = 'Post'; ContentType = 'application/json' }
    Invoke-RestMethod @ba -Body '{"query":"","action":"disable"}' | Out-Null
    Start-Sleep 2
    Invoke-RestMethod @ba -Body '{"query":"","action":"enable"}' | Out-Null
    Log-Ok "Detection rules triggered - alerts populate Security > Alerts within ~1-2 min"
    Log-Info "  Alerts inherit the backdated event time, so widen the Alerts time picker to 'Last 30 days'."
  } catch {
    Log-Warn "Could not trigger the detection rules ($($_.Exception.Message)); they fire on their next 5-min cycle."
  }
}

# ---- summary ----------------------------------------------------------------
Write-Host ""
Log-Ok "Lab is ready."
Write-Host ""
Ui-Panel "ACCESS  //  YOUR LAB IS LIVE"
Ui-Kv "Kibana"    "http://localhost:5601"
Ui-Kv "Login"     "user: elastic   pass: $elasticPass"
# Deliberately no IP for the VM: it only gets 192.168.56.20 on VirtualBox. VMware
# leaves that adapter unconfigured and the guest lands on the NAT network with a
# different address, so printing a fixed IP here would be wrong half the time.
# The forwarded ports work on both providers.
Ui-Kv "Victims"   "linux-victim (container)$(if($buildWin){' + WKSTN-01 (Windows VM - RDP localhost:53389)'})"
Ui-Kv "Scenarios" "open SCENARIOS.md  (answers in SOLUTIONS.md - no peeking)"
Write-Host (Ui-Rail 58)
Ui-Kv "Live"      "docker compose exec attacker /attacks/seed.sh --live T1059.004"
Ui-Kv "Stop"      "docker compose down"
Ui-Kv "Wipe"      "docker compose down -v ; .\install.ps1"
Write-Host ""
