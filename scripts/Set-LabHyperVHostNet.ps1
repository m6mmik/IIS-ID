# 192.168.56.1 is already on VirtualBox Host-Only (Ethernet 2). The Hyper-V
# internal switch is a different NIC and had only APIPA, so packets to
# 192.168.56.10 never reached the guest. Put 192.168.56.2 on the Hyper-V
# adapter and a /32 route for the guest.

param(
    [string]$SwitchName = "IIS-ID-Closed",
    [string]$HostIp = "192.168.56.2",
    [string]$GuestIp = "192.168.56.10",
    [int]$PrefixLength = 24
)

$ErrorActionPreference = "Stop"
$alias = "vEthernet ($SwitchName)"

$adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
if (-not $adapter) { throw "Adapter '$alias' missing. Is the Internal switch created?" }

$have = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $HostIp }
if (-not $have) {
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $HostIp -PrefixLength $PrefixLength | Out-Null
    Write-Host "host $HostIp/$PrefixLength on $alias"
}
else { Write-Host "host already $HostIp on $alias" }

$route = Get-NetRoute -DestinationPrefix "$GuestIp/32" -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -eq $alias }
if (-not $route) {
    New-NetRoute -DestinationPrefix "$GuestIp/32" -InterfaceAlias $alias | Out-Null
    Write-Host "route $GuestIp/32 -> $alias"
}
else { Write-Host "route $GuestIp/32 already on $alias" }

Write-Host "WinHTTP proxy for the guest should be ${HostIp}:3128 (not 192.168.56.1 on VirtualBox)."
