# 04-elastic-agent.ps1 - install Elastic Agent and enroll into Fleet. This is the
# arrow that connects the VM to the SIEM.
#
# The whole lab shares ONE Fleet output that addresses Elasticsearch and Fleet by
# their in-Docker hostnames (Basic license forbids a per-policy output). The VM
# can't resolve those names, so we map them to the host in the VM's hosts file;
# Docker publishes 9200/8220 there, so the agent reaches the SAME endpoints the
# containers use, over http.
$ErrorActionPreference = "Stop"
# CRITICAL over WinRM: without this, Invoke-WebRequest renders a progress bar for
# every chunk of the ~500 MB agent download, which makes it 10x+ slower and can
# look like a hang. Silence it.
$ProgressPreference = "SilentlyContinue"
function Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }

$token  = $env:FLEET_TOKEN
$url    = $env:FLEET_URL
$hostIp = if ($env:LAB_HOST_IP) { $env:LAB_HOST_IP } else { "192.168.56.1" }
$ver    = if ($env:STACK_VERSION) { $env:STACK_VERSION } else { "8.14.3" }

if (-not $token) { Warn "No FLEET_TOKEN - skipping enroll (host-based logs only)"; exit 0 }
if (-not $url)   { $url = "http://fleet-server:8220" }

# Map the in-Docker names to the host so the agent (told to use them) reaches
# the published ports. Idempotent.
Step "Mapping elasticsearch/fleet-server -> $hostIp in the VM hosts file"
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$existing  = (Get-Content $hostsFile -ErrorAction SilentlyContinue) -join "`n"
foreach ($name in @('elasticsearch','fleet-server')) {
  if ($existing -notmatch "(?m)^\s*[0-9.]+\s+$name\s*$") {
    Add-Content $hostsFile "`n$hostIp`t$name"
  }
}

# Fail early with a useful message if the VM can't reach Fleet on the host - by
# far the most common problem with this optional VM.
try {
  $u = [Uri]$url
  Step "Checking reachability of Fleet at $($u.Host):$($u.Port) (-> $hostIp)"
  $t = Test-NetConnection -ComputerName $u.Host -Port $u.Port -WarningAction SilentlyContinue
  if (-not $t.TcpTestSucceeded) {
    Warn "Cannot reach $($u.Host):$($u.Port) from the VM."
    Warn "The host must publish Docker's 8220/9200 on the host-only adapter"
    Warn "($hostIp). Check Docker is up and the host firewall allows it, then:"
    Warn "  cd victim ; vagrant provision --provision-with 04-agent"
    exit 0   # don't fail the whole build; host-based Sysmon/EventLog still work
  }
} catch { Warn "reachability check skipped: $_" }

# If the agent is ALREADY installed, this is a re-provision - typically after the
# stack was re-installed and Fleet reissued its enrollment tokens. A plain re-run
# would leave the VM shipping nothing, because its old enrollment key is now
# invalid ("invalid api key to authenticate with fleet"). Re-enroll in place with
# the current token instead of trying to install over an existing service.
$installed = Join-Path $env:ProgramFiles 'Elastic\Agent\elastic-agent.exe'
if (Test-Path $installed) {
  Step "Agent already installed - re-enrolling into Fleet at $url with the current token"
  & $installed enroll --url=$url --enrollment-token=$token --force --insecure
  if ($LASTEXITCODE -ne 0) { Warn "re-enroll returned $LASTEXITCODE - check 'elastic-agent status' in the VM"; exit 0 }
  Start-Sleep 5
  Restart-Service 'Elastic Agent' -ErrorAction SilentlyContinue
  Write-Host "[ OK ] Agent re-enrolled against the current Fleet." -ForegroundColor Green
  exit 0
}

Step "Downloading Elastic Agent $ver"
$pkg = "elastic-agent-$ver-windows-x86_64"
Invoke-WebRequest "https://artifacts.elastic.co/downloads/beats/elastic-agent/$pkg.zip" -OutFile "$env:TEMP\agent.zip"
Expand-Archive "$env:TEMP\agent.zip" "$env:TEMP\agent" -Force

Step "Enrolling into Fleet at $url"
& "$env:TEMP\agent\$pkg\elastic-agent.exe" install -f --url=$url --enrollment-token=$token --insecure
if ($LASTEXITCODE -ne 0) { Warn "enroll returned $LASTEXITCODE - check 'elastic-agent status' in the VM"; exit 0 }
Write-Host "[ OK ] Agent enrolled." -ForegroundColor Green
