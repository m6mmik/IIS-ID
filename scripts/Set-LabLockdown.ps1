# Set-LabLockdown.ps1
#
# Turns this lab machine into a "closed network" server: the state a hardened
# production host is in by default, where every outbound URL has to be ordered
# separately. A machine with plain internet access can never show you these
# failures, because AIA/OCSP/CRL silently succeed and hide the real dependency.
#
# Every change is written to .lab\lockdown.json and can be undone:
#   powershell -ExecutionPolicy Bypass -File scripts\Set-LabLockdown.ps1 restore
#
# Scenarios (run one at a time, or stack them, then restore):
#   status          show what is currently in effect
#   hosts-blackhole PKI hostnames -> unroutable IP + firewall drop (URL level, all processes)
#   system-no-net   block outbound 80/443 for lsass/iisexpress/w3wp only
#                   (your PowerShell tests still pass -> shows why they prove nothing)
#   proxy-only      blackhole + WinHTTP proxy to the lab proxy (see Start-LabProxy.ps1)
#   dead-proxy      WinHTTP proxy to a port nobody listens on ("proxy not ordered yet")
#   no-aia          disableaia=enable on the lab bindings + remove ESTEID intermediates
#                   (closed network cannot repair a missing chain link)
#   no-issuer       empty the ClientAuthIssuer store while ClientAuthTrustMode=2
#                   (every client cert becomes 403.16 untrusted root, app still says "valid")
#
# ADMIN REQUIRED. Lab machines only: this edits hosts, firewall, WinHTTP and cert stores.
#
# WHAT THIS DOES NOT DO: it never blocks general internet access. Blocking is
# surgical on purpose:
#   - hosts/firewall entries only cover the PKI hostnames listed below and one
#     unroutable IP range, nothing else
#   - process rules only cover lsass / iisexpress / w3wp, so browsers, IDEs and
#     everything else keep working
#   - the WinHTTP scenarios change a machine-level setting that services use
#     (browsers use their own). Other WinHTTP users (e.g. Windows Update) are
#     also affected while a blocking proxy mode is on - keep those sessions short.
# Use -Preview to print the exact planned changes without touching anything.

param(
    [Parameter(Position = 0)]
    [ValidateSet("status", "hosts-blackhole", "system-no-net", "proxy-only", "dead-proxy", "no-aia", "no-issuer", "restore")]
    [string]$Scenario = "status",
    [int]$ProxyPort = 3128,
    [string[]]$PkiHost,
    [switch]$KeepCache,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Lab = Join-Path $Root ".lab"
$StateFile = Join-Path $Lab "lockdown.json"
$CertBackup = Join-Path $Lab "lockdown-certs"
$HostsFile = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"

# TEST-NET-3 (RFC 5737): never routed anywhere, so a SYN there is a silent drop,
# exactly like a corporate firewall. 127.0.0.x would give an instant RST instead,
# and "refused" looks nothing like "timed out" in the logs.
$SinkIp = "203.0.113.9"
$SinkRange = "203.0.113.0/24"
$RulePrefix = "IIS-ID lab lockdown"
$HostsBegin = "# IIS-ID lab lockdown BEGIN"
$HostsEnd = "# IIS-ID lab lockdown END"
$LabBindings = @("127.0.0.1:8443", "127.0.0.1:8444", "0.0.0.0:8443", "0.0.0.0:8444")

$DefaultPkiHosts = @(
    "c.sk.ee", "aia.sk.ee", "ocsp.sk.ee", "crl.sk.ee", "esteid.ldap.sk.ee", "ldap.sk.ee",
    "crt.eidpki.ee", "aia.eidpki.ee", "ocsp.eidpki.ee", "crl.eidpki.ee"
)
if (-not $PkiHost -or $PkiHost.Count -eq 0) { $PkiHost = $DefaultPkiHosts }

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script needs an Administrator PowerShell."
    }
}

function New-State {
    @{
        Applied     = @()
        Hosts       = $false
        Rules       = @()
        WinHttpPrev = $null
        Aia         = @()
        Certs       = @()
    }
}

function Get-State {
    if (-not (Test-Path $StateFile)) { return New-State }
    $raw = Get-Content $StateFile -Raw | ConvertFrom-Json
    $state = New-State
    if ($raw.Applied) { $state.Applied = @($raw.Applied) }
    if ($raw.Hosts) { $state.Hosts = [bool]$raw.Hosts }
    if ($raw.Rules) { $state.Rules = @($raw.Rules) }
    if ($raw.WinHttpPrev) { $state.WinHttpPrev = [string]$raw.WinHttpPrev }
    if ($raw.Aia) { $state.Aia = @($raw.Aia) }
    if ($raw.Certs) { $state.Certs = @($raw.Certs) }
    return $state
}

function Save-State($state) {
    New-Item -ItemType Directory -Force -Path $Lab | Out-Null
    ($state | ConvertTo-Json -Depth 6) | Set-Content -Path $StateFile -Encoding ASCII
}

function Get-SslBindings {
    $text = & netsh http show sslcert 2>$null
    $bindings = @()
    $current = $null
    foreach ($line in $text) {
        if ($line -match '^\s*IP:port\s*:\s*(\S+)') {
            if ($current) { $bindings += $current }
            $current = @{ IpPort = $Matches[1]; Hash = ""; AppId = ""; Store = "MY"; Aia = "" }
            continue
        }
        if (-not $current) { continue }
        if ($line -match '^\s*Certificate Hash\s*:\s*(\S+)') { $current.Hash = $Matches[1] }
        elseif ($line -match '^\s*Application ID\s*:\s*(\S+)') { $current.AppId = $Matches[1] }
        elseif ($line -match '^\s*Certificate Store Name\s*:\s*(\S+)') { $current.Store = $Matches[1] }
        elseif ($line -match '^\s*Disable Authority Info Access\s*:\s*(\S+)') { $current.Aia = $Matches[1] }
    }
    if ($current) { $bindings += $current }
    return $bindings
}

function Get-WinHttpProxyText {
    ((& netsh winhttp show proxy 2>$null) -join " ").Trim()
}

function Clear-CryptoCache {
    if ($KeepCache) {
        Write-Host "  (cache kept: -KeepCache). Old AIA/CRL entries may still make it look healthy."
        return
    }
    & certutil -urlcache * delete | Out-Null
    & ipconfig /flushdns | Out-Null
    Write-Host "  CryptoAPI URL cache + DNS cache cleared"
}

function Add-HostsBlock($state) {
    $lines = @(Get-Content $HostsFile -ErrorAction Stop)
    if ($lines -contains $HostsBegin) {
        Write-Host "  hosts block already present"
    }
    else {
        $block = @($HostsBegin)
        foreach ($h in $PkiHost) { $block += "$SinkIp $h" }
        $block += $HostsEnd
        Add-Content -Path $HostsFile -Value ("`r`n" + ($block -join "`r`n"))
        Write-Host ("  hosts: " + $PkiHost.Count + " PKI hostnames -> $SinkIp")
    }
    $state.Hosts = $true
    Add-FwRule $state "$RulePrefix : sink range" @{
        Direction     = "Outbound"
        Action        = "Block"
        RemoteAddress = $SinkRange
    }
}

function Remove-HostsBlock {
    if (-not (Test-Path $HostsFile)) { return }
    $lines = @(Get-Content $HostsFile)
    if ($lines -notcontains $HostsBegin) { return }
    $keep = @()
    $inside = $false
    foreach ($line in $lines) {
        if ($line -eq $HostsBegin) { $inside = $true; continue }
        if ($line -eq $HostsEnd) { $inside = $false; continue }
        if (-not $inside) { $keep += $line }
    }
    # drop the empty line that Add-Content left behind
    while ($keep.Count -gt 0 -and [string]::IsNullOrWhiteSpace($keep[-1])) {
        $keep = $keep[0..($keep.Count - 2)]
    }
    Set-Content -Path $HostsFile -Value $keep -Encoding ASCII
    Write-Host "  hosts block removed"
}

function Add-FwRule($state, [string]$name, [hashtable]$spec) {
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  firewall rule exists: $name"
    }
    else {
        $spec["DisplayName"] = $name
        $spec["Description"] = "IIS-ID lab: simulates a locked down production network. Safe to delete."
        New-NetFirewallRule @spec | Out-Null
        Write-Host "  firewall rule added: $name"
    }
    if ($state.Rules -notcontains $name) { $state.Rules = @($state.Rules) + $name }
}

function Remove-FwRules {
    $rules = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
    foreach ($rule in $rules) {
        Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
        Write-Host "  firewall rule removed: $($rule.DisplayName)"
    }
}

function Block-ProcessNetwork($state) {
    # The TLS handshake and its chain building do NOT happen in your PowerShell.
    # Blocking only these processes is the whole point: every hand-written test
    # still passes while the real path is dead.
    $targets = @(
        @{ Name = "lsass"; Path = (Join-Path $env:SystemRoot "System32\lsass.exe") }
        @{ Name = "iisexpress"; Path = (Join-Path ${env:ProgramFiles} "IIS Express\iisexpress.exe") }
        @{ Name = "w3wp"; Path = (Join-Path $env:SystemRoot "System32\inetsrv\w3wp.exe") }
    )
    foreach ($t in $targets) {
        if (-not (Test-Path $t.Path)) {
            Write-Host "  skip $($t.Name): not installed"
            continue
        }
        Add-FwRule $state "$RulePrefix : $($t.Name) 80/443" @{
            Direction  = "Outbound"
            Action     = "Block"
            Program    = $t.Path
            Protocol   = "TCP"
            RemotePort = @(80, 443)
        }
    }
}

function Set-WinHttpProxy($state, [string]$server) {
    if (-not $state.WinHttpPrev) { $state.WinHttpPrev = Get-WinHttpProxyText }
    & netsh winhttp set proxy proxy-server="$server" bypass-list="<local>" | Out-Null
    Write-Host "  WinHTTP proxy -> $server (bypass <local>)"
    Write-Host "  NB: this is the setting HTTP.sys/Schannel/lsass use. Web.config and IE do not matter here."
}

function Restore-WinHttpProxy($state) {
    if (-not $state.WinHttpPrev) { return }
    if ($state.WinHttpPrev -match 'Direct access') {
        & netsh winhttp reset proxy | Out-Null
        Write-Host "  WinHTTP proxy reset to direct access"
    }
    else {
        $server = ""
        $bypass = ""
        if ($state.WinHttpPrev -match 'Proxy Server\(s\)\s*:\s*(\S+)') { $server = $Matches[1] }
        if ($state.WinHttpPrev -match 'Bypass List\s*:\s*(\S+)') { $bypass = $Matches[1] }
        if ($server) {
            if ($bypass) { & netsh winhttp set proxy proxy-server="$server" bypass-list="$bypass" | Out-Null }
            else { & netsh winhttp set proxy proxy-server="$server" | Out-Null }
            Write-Host "  WinHTTP proxy restored: $server"
        }
        else {
            & netsh winhttp reset proxy | Out-Null
            Write-Host "  WinHTTP proxy reset (previous value could not be parsed)"
        }
    }
    $state.WinHttpPrev = $null
}

function Set-BindingAia($state, [string]$value) {
    foreach ($binding in (Get-SslBindings)) {
        if ($LabBindings -notcontains $binding.IpPort) { continue }
        if (-not $binding.Hash -or -not $binding.AppId) {
            Write-Host "  skip $($binding.IpPort): could not read certhash/appid"
            continue
        }
        $known = @($state.Aia | Where-Object { $_.IpPort -eq $binding.IpPort })
        if ($known.Count -eq 0) {
            $state.Aia = @($state.Aia) + @{ IpPort = $binding.IpPort; Previous = $binding.Aia }
        }
        $out = & netsh http update sslcert ipport=$($binding.IpPort) certhash=$($binding.Hash) `
            appid=$($binding.AppId) certstorename=$($binding.Store) disableaia=$value 2>&1
        Write-Host "  $($binding.IpPort) disableaia=$value  ($($out -join ' '))"
    }
}

function Restore-BindingAia($state) {
    foreach ($entry in @($state.Aia)) {
        $value = "disable"
        if ($entry.Previous -match 'Enabled') { $value = "enable" }
        foreach ($binding in (Get-SslBindings)) {
            if ($binding.IpPort -ne $entry.IpPort) { continue }
            & netsh http update sslcert ipport=$($binding.IpPort) certhash=$($binding.Hash) `
                appid=$($binding.AppId) certstorename=$($binding.Store) disableaia=$value | Out-Null
            Write-Host "  $($binding.IpPort) disableaia restored to $value"
        }
    }
    $state.Aia = @()
}

function Move-CertsOut($state, [string]$storeName, [string]$subjectPattern) {
    New-Item -ItemType Directory -Force -Path $CertBackup | Out-Null
    $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
    $store.Open("ReadWrite")
    try {
        $moved = 0
        foreach ($cert in @($store.Certificates)) {
            if ($subjectPattern -and $cert.Subject -notmatch $subjectPattern) { continue }
            $file = Join-Path $CertBackup ("{0}-{1}.cer" -f $storeName, $cert.Thumbprint)
            [IO.File]::WriteAllBytes($file, $cert.Export("Cert"))
            $store.Remove($cert)
            $state.Certs = @($state.Certs) + @{ Store = $storeName; Thumbprint = $cert.Thumbprint; File = $file }
            Write-Host ("  removed from $storeName : " + $cert.Subject)
            $moved++
        }
        if ($moved -eq 0) { Write-Host "  nothing matched in $storeName (pattern: $subjectPattern)" }
    }
    finally { $store.Close() }
}

function Restore-Certs($state) {
    foreach ($entry in @($state.Certs)) {
        if (-not (Test-Path $entry.File)) {
            Write-Host "  MISSING backup $($entry.File) - reinstall with .\lab.ps1 eid-ca / bind"
            continue
        }
        & certutil -f -addstore $entry.Store $entry.File | Out-Null
        Write-Host "  restored into $($entry.Store): $($entry.Thumbprint)"
    }
    $state.Certs = @()
}

function Show-Status {
    Write-Host ""
    Write-Host "LOCKDOWN STATUS"
    Write-Host "---------------"

    $state = Get-State
    if ($state.Applied -and @($state.Applied).Count -gt 0) {
        Write-Host ("applied scenarios : " + (@($state.Applied) -join ", "))
    }
    else {
        Write-Host "applied scenarios : (none recorded in .lab\lockdown.json)"
    }

    $hostsHit = $false
    if (Test-Path $HostsFile) { $hostsHit = @(Get-Content $HostsFile) -contains $HostsBegin }
    Write-Host ("hosts blackhole   : " + $(if ($hostsHit) { "ON  ($SinkIp)" } else { "off" }))

    $rules = @(Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue)
    Write-Host ("firewall rules    : " + $(if ($rules.Count -gt 0) { "$($rules.Count) active" } else { "none" }))
    foreach ($rule in $rules) { Write-Host "    $($rule.DisplayName)" }

    Write-Host ("WinHTTP proxy     : " + (Get-WinHttpProxyText))

    foreach ($binding in (Get-SslBindings)) {
        if ($LabBindings -notcontains $binding.IpPort) { continue }
        Write-Host ("binding $($binding.IpPort) : disableaia=$($binding.Aia)")
    }

    $schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    $mode = (Get-ItemProperty -Path $schannel -ErrorAction SilentlyContinue).ClientAuthTrustMode
    if ($null -eq $mode) { $mode = "(not set = 0, machine trust)" }
    Write-Host ("ClientAuthTrustMode: $mode")

    foreach ($storeName in @("CA", "ClientAuthIssuer")) {
        $count = @(Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction SilentlyContinue).Count
        Write-Host (("store " + $storeName).PadRight(19) + ": $count certificates")
    }

    Write-Host ""
    Write-Host "Undo everything: scripts\Set-LabLockdown.ps1 restore"
}

function Show-Plan([string]$name) {
    Write-Host ""
    Write-Host "PREVIEW (nothing is changed)"
    Write-Host "scenario: $name"
    Write-Host ""
    switch ($name) {
        "hosts-blackhole" {
            Write-Host "would add to $HostsFile (between markers):"
            foreach ($h in $PkiHost) { Write-Host "    $SinkIp $h" }
            Write-Host "would add firewall rule: block outbound to $SinkRange"
            Write-Host "would clear CryptoAPI URL cache + DNS cache"
            Write-Host "NOT touched: any other hostname, any other process, general internet"
        }
        "system-no-net" {
            Write-Host "would add outbound TCP 80/443 BLOCK rules for these programs only:"
            Write-Host "    $(Join-Path $env:SystemRoot 'System32\lsass.exe')"
            Write-Host "    $(Join-Path ${env:ProgramFiles} 'IIS Express\iisexpress.exe')"
            Write-Host "    $(Join-Path $env:SystemRoot 'System32\inetsrv\w3wp.exe')"
            Write-Host "NOT touched: hosts file, proxy settings, every other process"
        }
        "proxy-only" {
            Write-Host "would do hosts-blackhole (see above) AND"
            Write-Host "would set machine WinHTTP proxy to 127.0.0.1:$ProxyPort, bypass <local>"
            Write-Host "current WinHTTP setting (saved for restore): $(Get-WinHttpProxyText)"
            Write-Host "NOT touched: browser/IDE proxy settings (they do not read WinHTTP)"
        }
        "dead-proxy" {
            Write-Host "would set machine WinHTTP proxy to 127.0.0.1:$($ProxyPort + 1) (no listener)"
            Write-Host "current WinHTTP setting (saved for restore): $(Get-WinHttpProxyText)"
        }
        "no-aia" {
            Write-Host "would set disableaia=enable on: $($LabBindings -join ', ')"
            Write-Host "would export+remove from LocalMachine\CA (backup in $CertBackup):"
            foreach ($cert in @(Get-ChildItem "Cert:\LocalMachine\CA" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Subject -match 'CN=ESTEID' })) {
                Write-Host "    $($cert.Subject)"
            }
            Write-Host "NOT touched: network, Root store, other intermediates"
        }
        "no-issuer" {
            Write-Host "would export+remove EVERYTHING from LocalMachine\ClientAuthIssuer"
            Write-Host "(backup in $CertBackup, restored by 'restore'):"
            foreach ($cert in @(Get-ChildItem "Cert:\LocalMachine\ClientAuthIssuer" -ErrorAction SilentlyContinue)) {
                Write-Host "    $($cert.Subject)"
            }
            Write-Host "NOT touched: network, Root, CA. This scenario is offline-only."
        }
        "restore" {
            $state = Get-State
            Write-Host "would undo: hosts markers, firewall rules '$RulePrefix*',"
            Write-Host "            WinHTTP proxy, disableaia, removed certificates"
            Write-Host "recorded scenarios: $((@($state.Applied) -join ', '))"
        }
    }
    Write-Host ""
    Write-Host "Run without -Preview to apply. Undo: scripts\Set-LabLockdown.ps1 restore"
}

if ($Preview -and $Scenario -ne "status") {
    Show-Plan $Scenario
    return
}

switch ($Scenario) {
    "status" { Show-Status }

    "hosts-blackhole" {
        Assert-Admin
        $state = Get-State
        Write-Host "Scenario: hosts-blackhole (URL level, every process on this machine)"
        Add-HostsBlock $state
        Clear-CryptoCache
        $state.Applied = @($state.Applied | Where-Object { $_ -ne "hosts-blackhole" }) + "hosts-blackhole"
        Save-State $state
        Write-Host ""
        Write-Host "Expect: AIA/CRL/OCSP fetches now time out instead of failing fast."
        Write-Host "Check : scripts\Get-EidReport.ps1 -CertFile .lab\lastclient.cer  (section 3c)"
    }

    "system-no-net" {
        Assert-Admin
        $state = Get-State
        Write-Host "Scenario: system-no-net (only lsass/iisexpress/w3wp lose 80/443)"
        Block-ProcessNetwork $state
        Clear-CryptoCache
        $state.Applied = @($state.Applied | Where-Object { $_ -ne "system-no-net" }) + "system-no-net"
        Save-State $state
        Write-Host ""
        Write-Host "Point of this scenario: Invoke-WebRequest and certutil still succeed."
        Write-Host "A report that only tests URLs from PowerShell will say PASS while the"
        Write-Host "handshake path has no network at all. Compare: probe + report."
    }

    "proxy-only" {
        Assert-Admin
        $state = Get-State
        Write-Host "Scenario: proxy-only (direct dies, everything must go through the proxy)"
        Add-HostsBlock $state
        Set-WinHttpProxy $state "127.0.0.1:$ProxyPort"
        Clear-CryptoCache
        $state.Applied = @($state.Applied | Where-Object { $_ -ne "proxy-only" }) + "proxy-only"
        Save-State $state
        Write-Host ""
        Write-Host "Start the proxy in another window so you can SEE the requested URLs:"
        Write-Host "  .\lab.ps1 proxy            (forwards and logs)"
        Write-Host "  .\lab.ps1 proxy auth407    (proxy demands authentication)"
        Write-Host "  .\lab.ps1 proxy allowlist  (only c.sk.ee is ordered)"
    }

    "dead-proxy" {
        Assert-Admin
        $state = Get-State
        Write-Host "Scenario: dead-proxy (WinHTTP points at a port nobody listens on)"
        Set-WinHttpProxy $state "127.0.0.1:$($ProxyPort + 1)"
        Clear-CryptoCache
        $state.Applied = @($state.Applied | Where-Object { $_ -ne "dead-proxy" }) + "dead-proxy"
        Save-State $state
        Write-Host ""
        Write-Host "This is what an un-ordered / mistyped proxy looks like from the OS side."
    }

    "no-aia" {
        Assert-Admin
        $state = Get-State
        Write-Host "Scenario: no-aia (no downloading of missing chain links)"
        Set-BindingAia $state "enable"
        Move-CertsOut $state "CA" "CN=ESTEID"
        Clear-CryptoCache
        $state.Applied = @($state.Applied | Where-Object { $_ -ne "no-aia" }) + "no-aia"
        Save-State $state
        Write-Host ""
        Write-Host "Now a real card cannot be validated: the intermediate is gone and HTTP.sys"
        Write-Host "is not allowed to fetch it. Expect 403.16 with win32 0x800B0109/0x800B010A."
        Write-Host "On an internet-connected machine WITHOUT disableaia this repairs itself"
        Write-Host "silently - that is the difference you cannot see at home by default."
    }

    "no-issuer" {
        Assert-Admin
        $state = Get-State
        Write-Host "Scenario: no-issuer (ClientAuthIssuer emptied, ClientAuthTrustMode stays as is)"
        Move-CertsOut $state "ClientAuthIssuer" ""
        Clear-CryptoCache
        $state.Applied = @($state.Applied | Where-Object { $_ -ne "no-issuer" }) + "no-issuer"
        Save-State $state
        Write-Host ""
        Write-Host "With ClientAuthTrustMode=1/2 every client certificate is now rejected as"
        Write-Host "untrusted root (403.16) while the application's own X509Chain still says"
        Write-Host "valid, because Root and CA are untouched. No network involved at all."
    }

    "restore" {
        Assert-Admin
        $state = Get-State
        Write-Host "Restoring..."
        Remove-HostsBlock
        Remove-FwRules
        Restore-WinHttpProxy $state
        Restore-BindingAia $state
        Restore-Certs $state
        Clear-CryptoCache
        $state.Applied = @()
        $state.Hosts = $false
        $state.Rules = @()
        Save-State $state
        Write-Host ""
        Write-Host "Restored. Verify with: scripts\Set-LabLockdown.ps1 status"
        Write-Host "If cert stores look thin, re-run: .\lab.ps1 eid-ca  and  .\lab.ps1 bind"
        Show-Status
    }
}
