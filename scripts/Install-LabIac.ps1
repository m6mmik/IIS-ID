# Install-LabIac.ps1
#
# Puts ansible-core + pywinrm + the Windows collections on this machine so
# .\lab.ps1 ansible can configure the Hyper-V guest. Ansible's control node is
# officially Linux, so this prefers WSL. Native Windows pip is tried only as a
# fallback and often refuses to install.
#
#   powershell -File scripts\Install-LabIac.ps1
#   powershell -File scripts\Install-LabIac.ps1 -Preview

param([switch]$Preview)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Req = Join-Path $Root "ansible\requirements.yml"

function ConvertTo-WslPath([string]$winPath) {
    $full = [System.IO.Path]::GetFullPath($winPath)
    if ($full -notmatch '^([A-Za-z]):\\') { throw "Not a drive path: $full" }
    $drive = $Matches[1].ToLowerInvariant()
    $rest = $full.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$rest"
}

Write-Host "Repo: $Root"
Write-Host "WSL : $(if (Get-Command wsl.exe -ErrorAction SilentlyContinue) { 'present' } else { 'missing' })"
Write-Host "tf  : $(if (Get-Command terraform -ErrorAction SilentlyContinue) { (terraform version -json | ConvertFrom-Json).terraform_version } else { 'missing (optional for Hyper-V lab)' })"

if ($Preview) {
    Write-Host ""
    Write-Host "Would install ansible-core + pywinrm in WSL and then:"
    Write-Host "  ansible-galaxy collection install -r $(ConvertTo-WslPath $Req)"
    return
}

function Get-LabWslDistro {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $null }
    $raw = & wsl.exe -l -q 2>$null
    $names = @($raw | ForEach-Object { ($_ -replace "`0", "").Trim() } | Where-Object { $_ })
    foreach ($n in $names) {
        if ($n -notmatch "docker-desktop") { return $n }
    }
    return $null
}

$wslconfig = Join-Path $env:USERPROFILE ".wslconfig"
$want = "[wsl2]`r`nnetworkingMode=mirrored`r`n"
if (-not (Test-Path $wslconfig) -or ((Get-Content $wslconfig -Raw) -notmatch "networkingMode\s*=\s*mirrored")) {
    Set-Content -Path $wslconfig -Value $want -Encoding ASCII
    Write-Host "Wrote $wslconfig (networkingMode=mirrored). Restarting WSL..."
    & wsl.exe --shutdown
    Start-Sleep -Seconds 3
}

$distro = Get-LabWslDistro
if (-not $distro -and (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Ubuntu (docker-desktop is not an Ansible control node)..."
    & wsl.exe --install -d Ubuntu --no-launch
    $distro = Get-LabWslDistro
    if (-not $distro) { $distro = "Ubuntu" }
}

if ($distro) {
    $wslReq = ConvertTo-WslPath $Req
    $script = @"
set -e
export DEBIAN_FRONTEND=noninteractive
if ! command -v python3 >/dev/null; then
  apt-get update
  apt-get install -y python3 python3-pip python3-venv python3-winrm || apt-get install -y python3 python3-pip python3-venv
fi
if [ ! -x /opt/iis-id-ansible/bin/ansible-playbook ]; then
  python3 -m venv /opt/iis-id-ansible
  /opt/iis-id-ansible/bin/pip install -q --upgrade pip
  /opt/iis-id-ansible/bin/pip install -q 'ansible-core>=2.16' pywinrm
fi
export PATH=/opt/iis-id-ansible/bin:`$HOME/.local/bin:`$PATH
ansible-galaxy collection install -r '$wslReq'
ansible --version | head -n 1
"@
    Write-Host "Installing Ansible in WSL '$distro' as root (venv /opt/iis-id-ansible)."
    & wsl.exe -d $distro -u root -- bash -lc $script
    if ($LASTEXITCODE -ne 0) { throw "WSL Ansible install failed (exit $LASTEXITCODE)." }
    Write-Host ""
    Write-Host "Mirrored WSL should see 192.168.56.10. Next: .\lab.ps1 ansible-ping"
    return
}

Write-Host ""
Write-Host "WSL is not installed. Ansible will not run on this Windows host by itself."
Write-Host "Either:"
Write-Host "  wsl --install"
Write-Host "  (then re-run this script)"
Write-Host "or use any Linux machine that can reach 192.168.56.10:5985 and run:"
Write-Host "  pip install ansible-core pywinrm"
Write-Host "  ansible-galaxy collection install -r ansible/requirements.yml"
Write-Host "  ansible-playbook -i ansible/inventories/lab.yml ansible/iis.yml"
throw "No Ansible control node yet."
