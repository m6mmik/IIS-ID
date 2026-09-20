# When Ansible has no Linux control node (WSL is only docker-desktop), do the
# same IIS work over PowerShell Direct. Same script the guest would run by hand.

param(
    [string]$Name = "IIS-ID-Server",
    [string]$Password = "IisId2026!",
    [string]$GuestIp = "192.168.56.10",
    [string]$ProxyServer = "192.168.56.2:3128"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Lab = Join-Path $Root ".lab"
New-Item -ItemType Directory -Force -Path $Lab | Out-Null

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell required."
    }
}

Assert-Admin
Write-Host "== Build on the host"
& (Join-Path $Root "lab.ps1") build

$stage = Join-Path $Lab "guest-payload"
$zip = Join-Path $Lab "guest-payload.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
foreach ($rel in @("src\Demo.Service", "certs", "scripts\Install-LabServer.ps1", "scripts\Install-EeIdTrust.ps1")) {
    $src = Join-Path $Root $rel
    if (-not (Test-Path $src)) { Write-Host "skip missing $rel"; continue }
    $dest = Join-Path $stage $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    Copy-Item $src $dest -Recurse -Force
}
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force
Write-Host "payload $zip ($([math]::Round((Get-Item $zip).Length/1MB, 1)) MB)"

$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("Administrator", $secure)

Write-Host "== Copy zip into the guest"
Enable-VMIntegrationService -VMName $Name -Name "Guest Service Interface" -ErrorAction SilentlyContinue
Invoke-Command -VMName $Name -Credential $cred -ScriptBlock {
    New-Item -ItemType Directory -Force -Path C:\IIS-ID | Out-Null
    if (Test-Path C:\IIS-ID\guest-payload.zip) { Remove-Item C:\IIS-ID\guest-payload.zip -Force }
}
Copy-VMFile -Name $Name -SourcePath $zip -DestinationPath C:\IIS-ID\guest-payload.zip -FileSource Host -CreateFullPath -Force

Write-Host "== Install-LabServer.ps1 inside the guest"
Invoke-Command -VMName $Name -Credential $cred -ScriptBlock {
    param($proxy, $ip)
    $ErrorActionPreference = "Stop"
    Expand-Archive -Path C:\IIS-ID\guest-payload.zip -DestinationPath C:\IIS-ID -Force
    & C:\IIS-ID\scripts\Install-LabServer.ps1 -StaticIp $ip -ProxyServer $proxy
} -ArgumentList $ProxyServer, $GuestIp

Write-Host "DONE via PowerShell Direct (Ansible playbook was not used)."
