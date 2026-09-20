# Enable-LabWinRm.ps1
#
# Run INSIDE the Windows Server guest, as Administrator, once:
#   powershell -ExecutionPolicy Bypass -File C:\IIS-ID\scripts\Enable-LabWinRm.ps1 -StaticIp 192.168.56.10
#
# After this the host can reach WinRM on http://192.168.56.10:5985 (NTLM).
# That is the only door Ansible needs. The internal switch has no DHCP, so the
# static address is part of the same step.

param(
    [string]$StaticIp = "192.168.56.10",
    [int]$PrefixLength = 24,
    [switch]$SkipAddress,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell required."
    }
}

if ($Preview) {
    Write-Host "Would set $StaticIp/$PrefixLength (no gateway), enable WinRM HTTP:5985, NTLM, AllowUnencrypted,"
    Write-Host "LocalAccountTokenFilterPolicy=1, inbound firewall 5985."
    return
}

Assert-Admin

if (-not $SkipAddress -and $StaticIp) {
    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $adapter) { $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $adapter) { throw "No network adapter found." }
    Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $StaticIp -PrefixLength $PrefixLength | Out-Null
    Write-Host "$($adapter.Name): $StaticIp/$PrefixLength, no default gateway"
}

Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Lab is an isolated switch. HTTP + NTLM is enough; HTTPS would need another cert.
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

# Workgroup UAC otherwise filters the local Administrator token over the network
# and every Ansible task comes back Access Denied.
$uac = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
New-ItemProperty -Path $uac -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null

if (-not (Get-NetFirewallRule -DisplayName "IIS-ID WinRM HTTP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "IIS-ID WinRM HTTP" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 5985 | Out-Null
}

Restart-Service WinRM
Write-Host ""
Write-Host "WinRM listening on HTTP :5985"
Write-Host "From the host:"
Write-Host "  Test-NetConnection $StaticIp -Port 5985"
Write-Host "  `$env:LAB_WINRM_PASSWORD = '<Administrator password of this VM>'"
Write-Host "  .\lab.ps1 iac"
Write-Host "  .\lab.ps1 ansible-ping"
Write-Host "  .\lab.ps1 ansible"
