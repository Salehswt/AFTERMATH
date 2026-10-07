<#
  seed-windows.ps1 - seed the WINDOWS scenarios by running their Atomic Red Team
  tests ON the Windows VM (via `vagrant winrm`). This is where scenario 01's
  Office->PowerShell chain actually happens; the Windows agent ships the
  resulting Sysmon/PowerShell telemetry to the SIEM.

  The attacker container cannot do this - it only does network-observable Linux
  attacks. Called by install.ps1 step 5b after the VM is enrolled.

  Best-effort: an atomic that fails a prereq must not break the lab.
#>
[CmdletBinding()]
param(
  [string]$ElasticPass,
  [string]$HostIp = '192.168.56.1'
)
# Quiet by default: a single self-overwriting progress bar, matching the Linux
# seed in attacks/seed.sh. Set LAB_VERBOSE=1 for the per-atomic trace, or
# LAB_NO_PROGRESS=1 for one plain line per scenario when the output is captured
# to a log. Failures/warnings are always shown, in every mode.
$Verbose    = ($env:LAB_VERBOSE -eq '1')
$NoProgress = ($env:LAB_NO_PROGRESS -eq '1')
$BarFull    = '####################'   # 20 cells
$BarNone    = '--------------------'
$SeedStart  = Get-Date

# The bar owns the current line, so every other writer wipes it first.
function Clear-Line {
  if ($Verbose -or $NoProgress) { return }
  Write-Host ("`r" + (' ' * 78) + "`r") -NoNewline
}
function Log ($m){ Clear-Line; Write-Host "[win-seed] $m" -ForegroundColor Cyan }
function Warn($m){ Clear-Line; Write-Host "[win-seed] $m" -ForegroundColor Yellow }
function VLog($m){ if ($Verbose) { Log $m } }

function Show-Progress($idx, $total, $label) {
  if ($Verbose -or $total -le 0) { return }
  if ($NoProgress) { Log "($idx/$total) deploying $label ..."; return }
  $filled = [int]($idx * 20 / $total)
  $el = [int]((Get-Date) - $script:SeedStart).TotalSeconds
  Write-Host ("`r  [{0}{1}]  {2,2}/{3,-2}  {4:d2}:{5:d2}  {6,-34}" -f `
      $BarFull.Substring(0, $filled), $BarNone.Substring(0, 20 - $filled), `
      $idx, $total, [int]($el / 60), ($el % 60), $label) -NoNewline -ForegroundColor Cyan
}

$LabRoot = Split-Path $PSScriptRoot -Parent
# Absolute -f paths: this script cd's into victim/ for vagrant, so compose must
# not depend on the current directory.
$CF = @('-f',(Join-Path $LabRoot 'docker-compose.yml'),'-f',(Join-Path $LabRoot 'docker-compose.linux-victim.yml'))
function Attacker { docker compose @CF exec -T attacker @args 2>$null }

if (-not (Get-Command vagrant -ErrorAction SilentlyContinue)) { Warn "vagrant not found; cannot seed Windows scenarios."; exit 1 }

# Which scenarios are Windows? Reuse the container's YAML parser so we never
# drift from the single source of truth.
$winFiles = @()
Get-ChildItem "$LabRoot\scenarios\scenario_*.yml" | ForEach-Object {
  $req = (Attacker python3 /attacks/runner.py --requires "/scenarios/$($_.Name)" | Out-String).Trim()
  if ($req -eq 'windows') { $winFiles += $_.Name }
}
if (-not $winFiles) { Log "No Windows scenarios to seed."; exit 0 }

Push-Location (Join-Path $LabRoot 'victim')
$hadError = $false
try {
  # Confirm the VM answers WinRM before we try a dozen atomics against it.
  Log "Checking the VM is reachable over WinRM..."
  vagrant winrm -s powershell -c "hostname" 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Warn "VM not reachable over WinRM (is it running? 'cd victim; vagrant status')."
    Warn "Seed later with: powershell -File scripts\seed-windows.ps1"
    exit 1
  }

  # The VM's address depends on the hypervisor: VirtualBox configures the
  # host-only adapter (192.168.56.20) inside the guest, VMware does not - there
  # the guest ends up on the NAT network with a completely different address.
  # backdate.py matches events by IP as well as hostname, so a hardcoded IP means
  # that on the "wrong" provider any Windows event carrying only an IP never gets
  # backdated. Ask the guest what it actually has.
  $vmIps = @()
  try {
    $ipCmd = 'Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "^(127\.|169\.254\.)" } | ForEach-Object { $_.IPAddress }'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ipCmd))
    $vmIps = @((vagrant winrm -s powershell -c "powershell -EncodedCommand $enc" 2>$null | Out-String) -split "`r?`n" |
               ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
  } catch { }
  if ($vmIps.Count) { Log "VM addresses used for backdating: $($vmIps -join ', ')" }
  else { Warn "Could not read the VM's IP; backdating will match on hostname only." }

  $seeded = 0; $atomicTotal = 0; $failTotal = 0; $idx = 0; $total = $winFiles.Count
  if (-not $Verbose) { Log "Deploying $total Windows scenarios via Atomic Red Team (set LAB_VERBOSE=1 for per-atomic detail)" }
  $SeedStart = Get-Date
  foreach ($name in $winFiles) {
    $idx++
    $short  = [IO.Path]::GetFileNameWithoutExtension($name)
    $offset = (Attacker python3 /attacks/runner.py --offset "/scenarios/$name" | Out-String).Trim()
    $pairs  = (Attacker python3 /attacks/runner.py --parse "/scenarios/$name" | Out-String)
    # Announce each scenario as it STARTS so progress is visible during the wait.
    if ($Verbose) { Log "Seeding $name via Atomic Red Team" } else { Show-Progress $idx $total $short }
    $scenAtomics = 0; $scenFail = 0
    # Use a real UTC epoch. Get-Date -UFormat %s is UNRELIABLE here: on a non-UTC
    # host it emits local-time-as-epoch (e.g. +3h), putting the window start in
    # the future so backdate.py's time filter matches nothing.
    $winStart = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    foreach ($line in ($pairs -split "`r?`n")) {
      $line = $line.Trim(); if (-not $line) { continue }
      $parts = $line.Split(' '); $t = $parts[0]; $n = if ($parts.Count -gt 1) { $parts[1] } else { '1' }
      $scenAtomics++
      VLog "  seeding $t (test $n)"
      # Run the atomic QUIETLY. Atomics are noisy: they print a full execution
      # transcript, and some (BloodHound/SharpHound, Mimikatz, anything needing
      # Office) throw stack traces or fail a prereq loudly. We only want the
      # on-host SIDE EFFECT (the telemetry), never a wall of attack output and
      # errors scrolling past during install. So every stream from the atomic is
      # redirected to $null (`*>$null`) - the action still runs, its output just
      # doesn't come back - and the remote script echoes a single clean marker.
      #
      # Import the module by its INSTALLED PATH, not by name: Install-AtomicRedTeam
      # drops it under C:\AtomicRedTeam\, which is NOT on PSModulePath, so
      # `Import-Module invoke-atomicredteam` would resolve to nothing.
      $atomic = "`$ErrorActionPreference='SilentlyContinue'; " +
                "`$m = Get-ChildItem 'C:\AtomicRedTeam' -Recurse -Filter Invoke-AtomicRedTeam.psd1 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName; " +
                "if (`$m) { Import-Module `$m -Force *>`$null } else { Import-Module invoke-atomicredteam -Force *>`$null }; " +
                "Invoke-AtomicTest $t -TestNumbers $n -GetPrereqs *>`$null; " +
                "Invoke-AtomicTest $t -TestNumbers $n *>`$null; " +
                "'AT_SEEDED'"
      # -EncodedCommand so the module path and quoting survive vagrant winrm's
      # argument passing (it strips double-quotes from -c strings).
      $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($atomic))
      $out = (vagrant winrm -s powershell -c "powershell -EncodedCommand $enc" 2>$null | Out-String)
      if ($out -notmatch 'AT_SEEDED') {
        Warn "  $short - $t (test $n) did not report back (blocked by AV/Tamper Protection, or VM unreachable)"; $hadError = $true; $scenFail++
      }
    }

    # Shift this scenario's Windows telemetry back to match the ticket dates.
    if ($offset -and $ElasticPass) {
      VLog "  Backdating $name by $offset (waiting 60s for the agent to ship)"
      Start-Sleep 60
      docker compose @CF exec -T -e ELASTIC_PASSWORD=$ElasticPass attacker `
        python3 /attacks/backdate.py $offset $winStart "WKSTN-01" @vmIps "172.30.0.99" 2>$null
    }

    $seeded++; $atomicTotal += $scenAtomics; $failTotal += $scenFail
    # Success rolls up into the final tally; only shout about failures here.
    if ($scenFail -ne 0) { Warn "($idx/$total) $short - $scenFail/$scenAtomics atomic(s) did not report" }
  }
} finally { Pop-Location }

if ($hadError) {
  Warn "Windows scenarios: $seeded seeded, $atomicTotal atomic(s), $failTotal did NOT report (usually AV / Tamper Protection) - check Kibana for what landed."
  exit 1
}
Log "Windows scenarios seeded - $seeded scenario(s), $atomicTotal atomic(s), 0 failed."
exit 0
