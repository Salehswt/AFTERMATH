<#
  lab.ps1 - AFTERMATH lab control for Windows (the native twin of lab.sh).
  Author: Saleh

  Runs on the HOST and drives the WHOLE lab via Docker (and Vagrant for the VM).
  It is NOT run inside the Linux victim - it acts ON the victims from outside,
  the same way lab.sh does on Linux/macOS.

    .\lab.ps1 status               component health
    .\lab.ps1 attack <id|scenario> fire a technique/chain LIVE and watch it land
    .\lab.ps1 list-attacks         techniques + scenarios available
    .\lab.ps1 validate <file.yml>  quick sanity check on a scenario file
    .\lab.ps1 validate-detections  assert every answer-key query still returns hits
    .\lab.ps1 new-scenario         scaffold scenarios\scenario_NN.yml
    .\lab.ps1 ssh                  SSH into the Linux victim  (jdoe / Password123)
    .\lab.ps1 rdp                  RDP to the Windows victim  (vagrant / vagrant)
    .\lab.ps1 winssh               SSH into the Windows victim (vagrant / vagrant)
    .\lab.ps1 down                 stop everything (keeps data)
    .\lab.ps1 reset                wipe volumes + rebuild the victim, then reseed
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Command = 'help',
  [Parameter(Position = 1)][string]$Arg1,
  [Parameter(Position = 2)][string]$Arg2
)

$ErrorActionPreference = 'Stop'
$LabRoot = $PSScriptRoot
$EnvFile = Join-Path $LabRoot '.env'
# Address the same set of compose files the installer used, or the Linux victim
# (and its sensor) look like orphans to down/status.
$CF = @('-f', (Join-Path $LabRoot 'docker-compose.yml'),
        '-f', (Join-Path $LabRoot 'docker-compose.linux-victim.yml'))

function Log-Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Log-Ok  ($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Log-Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Die($m){ Write-Host "[ERR ] $m" -ForegroundColor Red; exit 1 }
function Dc { docker compose @CF @args }
function Get-Pass {
  if (-not (Test-Path $EnvFile)) { return '' }
  $l = Get-Content $EnvFile | Select-String '^ELASTIC_PASSWORD='
  if ($l) { ($l.ToString() -split '=', 2)[1] } else { '' }
}

switch ($Command) {

  'status' {
    Log-Step 'Docker components'
    Dc ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
    Write-Host ''
    Log-Step 'SIEM health'
    try { Invoke-RestMethod 'http://localhost:5601/api/status' -TimeoutSec 5 | Out-Null; Log-Ok 'Kibana reachable' }
    catch { Log-Warn 'Kibana not reachable' }
    Log-Step 'Windows victim'
    Push-Location (Join-Path $LabRoot 'victim')
    try { vagrant status 2>$null | Select-String 'running|poweroff|suspended|not created' } catch { Log-Warn 'no VM found' }
    Pop-Location
  }

  'attack' {
    if (-not $Arg1) { Die 'Usage: .\lab.ps1 attack <technique-id|scenario_NN>' }
    if ($Arg1 -like 'scenario_*') {
      if (-not (Test-Path (Join-Path $LabRoot "scenarios\$Arg1.yml"))) { Die "no such scenario: scenarios\$Arg1.yml" }
      Log-Step "Replaying $Arg1 LIVE against the victim"
      # Single-quoted parts keep $t/$n literal for the container's bash.
      $bash = 'python3 /attacks/runner.py --parse /scenarios/' + $Arg1 +
              '.yml | while read -r t n; do /attacks/seed.sh --live "$t" "$n"; done'
      Dc exec -T attacker bash -c $bash
    } else {
      Log-Step "Firing technique '$Arg1' LIVE against the victim"
      $test = if ($Arg2) { $Arg2 } else { '1' }
      Dc exec -T attacker /attacks/seed.sh --live $Arg1 $test
    }
    Log-Ok 'Done - check Kibana for fresh alerts'
  }

  'list-attacks' {
    Log-Step 'Scenarios (chains)'
    Get-ChildItem (Join-Path $LabRoot 'scenarios\scenario_[0-9]*.yml') | ForEach-Object {
      $nm = (Select-String -Path $_.FullName -Pattern '^name:' | Select-Object -First 1).Line
      $nm = ($nm -replace '^name:\s*"?', '') -replace '"\s*$', ''
      '  {0,-28} {1}' -f $_.BaseName, $nm
    }
    Write-Host ''
    Log-Step 'Techniques with a lab implementation'
    Dc exec -T attacker python3 -c "import runner; [print('  '+t) for t in sorted(runner.ACTIONS)]"
  }

  'validate' {
    if (-not $Arg1) { Die 'Usage: .\lab.ps1 validate scenarios\scenario_NN.yml' }
    $base = Split-Path $Arg1 -Leaf
    Log-Step "Parsing /scenarios/$base (loads the YAML, lists the chain)"
    Dc exec -T attacker python3 /attacks/runner.py --parse "/scenarios/$base"
    Log-Ok 'Parsed. Full check: seed it, then .\lab.ps1 validate-detections'
  }

  'validate-detections' {
    $pass = Get-Pass
    if (-not $pass) { Die 'No .env / ELASTIC_PASSWORD - is the lab installed?' }
    $targets = if ($env:LAB_TARGETS) { $env:LAB_TARGETS } else { 'linux,windows' }
    Log-Step 'Validating detections against the seeded telemetry'
    Dc exec -T -e ELASTIC_PASSWORD=$pass -e LAB_TARGETS=$targets attacker python3 /attacks/validate_detections.py /scenarios
  }

  'new-scenario' {
    $n = '{0:d2}' -f ((Get-ChildItem (Join-Path $LabRoot 'scenarios\scenario_*.yml')).Count + 1)
    $dest = Join-Path $LabRoot "scenarios\scenario_$n.yml"
    Copy-Item (Join-Path $LabRoot 'scenarios\scenario_template.yml') $dest
    Log-Ok "Created scenarios\scenario_$n.yml - edit it, then: .\lab.ps1 validate scenarios\scenario_$n.yml"
  }

  'ssh' {
    # The Linux victim publishes 22 on 127.0.0.1:2022 (see docker-compose.linux-victim.yml).
    Log-Step 'SSH to the Linux victim (jdoe / Password123)'
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL jdoe@localhost -p 2022
  }

  'rdp' {
    # The VM forwards 3389 -> host 53389 (see victim/Vagrantfile). auto_correct
    # may pick a different port; 'cd victim; vagrant port' shows the live map.
    Log-Step 'Opening RDP to the Windows victim (localhost:53389, user vagrant / vagrant)'
    Start-Process mstsc -ArgumentList '/v:localhost:53389'
  }

  'winssh' {
    # The box forwards guest 22 -> host 2222 by default ('vagrant port' to confirm).
    Log-Step 'SSH to the Windows victim (vagrant / vagrant)'
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL vagrant@localhost -p 2222
  }

  'down' {
    Dc down
    Push-Location (Join-Path $LabRoot 'victim'); try { vagrant halt 2>$null } catch {} finally { Pop-Location }
    Log-Ok "Stopped (data preserved). '.\lab.ps1 status' or '.\install.ps1' to resume."
  }

  'reset' {
    Log-Warn 'This wipes SIEM data and rebuilds the victim.'
    if ($env:LAB_AUTO -ne '1') {
      $a = Read-Host '    Continue? [y/N]'; if ($a -notmatch '^[Yy]$') { exit 0 }
    }
    Dc down -v
    Push-Location (Join-Path $LabRoot 'victim'); try { vagrant destroy -f 2>$null } catch {} finally { Pop-Location }
    Log-Ok 'Torn down. Re-running the installer...'
    & (Join-Path $LabRoot 'install.ps1')
  }

  default {
    # Print the header comment block as help.
    Get-Content $PSCommandPath | Where-Object { $_ -match '^\s{0,4}\.\\lab\.ps1|^\s+lab\.ps1 -|^\s+Runs on|^\s+It is NOT' } |
      ForEach-Object { $_.TrimEnd() }
    Write-Host ''
    Write-Host '  (this is the Windows twin of lab.sh; it runs on the host, not inside a victim)'
  }
}
