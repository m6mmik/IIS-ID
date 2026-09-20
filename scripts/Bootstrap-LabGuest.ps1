# Host-side: wait until the Hyper-V guest can take PowerShell Direct, then set
# IP + WinRM and run Ansible. No console clicking.
#
#   scripts\Bootstrap-LabGuest.ps1
#   .\lab.ps1 bootstrap
#
# Existing mid-Setup VMs: types IisId2026! until Direct works, then configures.
# New VMs: attach .lab\unattend.iso (New-LabVm.ps1) so Setup is silent.

param(
    [string]$Name = "IIS-ID-Server",
    [string]$Password = "IisId2026!",
    [string]$GuestIp = "192.168.56.10",
    [int]$PrefixLength = 24,
    [int]$TimeoutMinutes = 90,
    [switch]$SkipAnsible
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Lab = Join-Path $Root ".lab"
New-Item -ItemType Directory -Force -Path $Lab | Out-Null
$transcript = Join-Path $Lab "bootstrap.log"
Start-Transcript -Path $transcript -Force | Out-Null
try {
Set-Content -Path (Join-Path $Lab "lab-admin.pass") -Value $Password -NoNewline

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell required."
    }
}

function Step([string]$t) { Write-Host ""; Write-Host "== $t" }

Assert-Admin

$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("Administrator", $secure)

$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
if (-not $vm) { throw "VM '$Name' missing. .\lab.ps1 tf apply  (iso_path in terraform.tfvars)" }

Enable-VMIntegrationService -VMName $Name -Name "Guest Service Interface" -ErrorAction SilentlyContinue
if ($vm.State -eq "Off") {
    Start-Process vmconnect.exe -ArgumentList @("localhost", $Name) -ErrorAction SilentlyContinue | Out-Null
    Start-VM -Name $Name
    Start-Sleep -Seconds 5
}

$sendKeys = Join-Path $Root "scripts\Send-LabVmText.ps1"
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$lastType = [datetime]::MinValue
$ready = $false

Step "Waiting for PowerShell Direct on $Name (up to $TimeoutMinutes min)"
Write-Host "Setup can sit on the password page - this script types $Password until Windows answers."

while ((Get-Date) -lt $deadline) {
    try {
        $nameIn = Invoke-Command -VMName $Name -Credential $cred -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
        Write-Host "PowerShell Direct OK ($nameIn)"
        $ready = $true
        break
    }
    catch {
        $age = (Get-Date) - $lastType
        if ($age.TotalSeconds -ge 45 -and (Test-Path $sendKeys)) {
            try {
                & $sendKeys -Name $Name -Password $Password
                $lastType = Get-Date
            }
            catch {
                Write-Host "key inject skipped: $($_.Exception.Message)"
            }
        }
        Write-Host ("  still installing... {0:n0}s left" -f ($deadline - (Get-Date)).TotalSeconds)
        Start-Sleep -Seconds 20
    }
}

if (-not $ready) {
    throw "Timed out waiting for PowerShell Direct. Finish Setup or raise -TimeoutMinutes."
}

Step "Static IP + WinRM inside the guest"
Invoke-Command -VMName $Name -Credential $cred -ScriptBlock {
    param($ip, $prefix)
    $ErrorActionPreference = "Stop"
    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $adapter) { $adapter = Get-NetAdapter | Select-Object -First 1 }
    Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne $ip } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    $have = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $ip }
    if (-not $have) {
        New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength $prefix -ErrorAction SilentlyContinue | Out-Null
    }
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
    Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
    if (-not (Get-NetFirewallRule -DisplayName "IIS-ID WinRM HTTP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "IIS-ID WinRM HTTP" -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 5985 | Out-Null
    }
    Restart-Service WinRM
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } |
        ForEach-Object { "$($_.InterfaceAlias) $($_.IPAddress)" }
} -ArgumentList $GuestIp, $PrefixLength

Step "hosts demo.local"
$hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$line = "$GuestIp demo.local"
$now = Get-Content $hosts -ErrorAction Stop
if ($now -notcontains $line) {
    Add-Content -Path $hosts -Value $line
    Write-Host "added $line"
}
else { Write-Host "hosts already has demo.local" }

Step "Host address on the Hyper-V switch (not VirtualBox 192.168.56.1)"
& (Join-Path $Root "scripts\Set-LabHyperVHostNet.ps1")

Step "WinRM from the host"
function Test-TcpPort([string]$ip, [int]$port, [int]$timeoutMs = 2000) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ip, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}
$ok = $false
foreach ($n in 1..15) {
    if (Test-TcpPort $GuestIp 5985) { $ok = $true; break }
    Write-Host "  5985 not open yet ($n/15)"
    Start-Sleep -Seconds 2
}
if (-not $ok) { throw "WinRM is on in the guest but $GuestIp`:5985 is not reachable. Check the internal switch (192.168.56.1)." }
Write-Host "TCP 5985 open on $GuestIp"

if ($SkipAnsible) {
    Write-Host "Skip Ansible (-SkipAnsible). Next: `$env:LAB_WINRM_PASSWORD='$Password'; .\lab.ps1 ansible"
    return
}

$env:LAB_WINRM_PASSWORD = $Password
$labPs1 = Join-Path $Root "lab.ps1"
Step "Ansible (IIS + ESTEID + WinHTTP)"
$ansibleOk = $false
try {
    & $labPs1 iac
    $code = 0
    & $labPs1 ansible
    if ($LASTEXITCODE -eq 0) { $ansibleOk = $true }
}
catch {
    Write-Host "Ansible control node failed: $($_.Exception.Message)"
}
if (-not $ansibleOk) {
    Step "Fallback: Install-LabServer over PowerShell Direct (no Ansible)"
    & (Join-Path $Root "scripts\Invoke-LabServerDirect.ps1") -Name $Name -Password $Password -GuestIp $GuestIp
}
Write-Host ""
Write-Host "DONE. Client: .\lab.ps1 client   address https://demo.local:8443/Demo.svc"
}
catch {
    Write-Host "FAILED: $($_.Exception.Message)"
    throw
}
finally {
    Stop-Transcript | Out-Null
}
