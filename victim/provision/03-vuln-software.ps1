# 03-vuln-software.ps1 — install old/vulnerable software your scenarios exploit.
# Kept minimal here; extend per the CVEs you want in play.
function Step($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
Step "Installing outdated third-party software (placeholder)"
# Example: choco install -y firefox --version=60.0 ; old java/reader, etc.
# For a maintained vuln set, base the box on Metasploitable3 instead.
Write-Host "[ OK ] Vulnerable software stage complete." -ForegroundColor Green
