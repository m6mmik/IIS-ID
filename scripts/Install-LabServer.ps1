# Install-LabServer.ps1
#
# Runs INSIDE a Windows Server VM and turns it into the real thing the home lab
# only imitates: full IIS, real application pools, real W3C substatus logging and
# optionally Failed Request Tracing. IIS Express cannot show you app pool
# recycling, FREB or true HTTP.sys behaviour, so a VM is where the remaining
# "works at home, fails at work" differences become visible.
#
# Copy this repository into the VM (e.g. C:\IIS-ID) and run as Administrator:
#   powershell -ExecutionPolicy Bypass -File scripts\Install-LabServer.ps1
#
# The VM has no internet in the closed-network setup, so build on the host first
# (.\lab.ps1 build) and copy the whole folder in - bin\ must come along.
#
# After this:
#   scripts\Install-EeIdTrust.ps1        ID-card chain (needs network ONCE, or copy certs\eid-ca)
#   scripts\Set-LabLockdown.ps1 status   see the closed-network knobs
#   scripts\Get-EidReport.ps1            one report after a failed PIN1

param(
    [string]$SitePath,
    [string]$StaticIp,
    [int]$PrefixLength = 24,
    [string]$ProxyServer,
    [switch]$Revocation,
    [switch]$Tracing,
    [switch]$SkipFeatures,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $SitePath) { $SitePath = Join-Path $Root "src\Demo.Service" }

$Features = @(
    "Web-Server", "Web-Common-Http", "Web-Default-Doc", "Web-Static-Content",
    "Web-Http-Errors", "Web-Http-Logging", "Web-Request-Monitor", "Web-Http-Tracing",
    "Web-Net-Ext45", "Web-Asp-Net45", "Web-ISAPI-Ext", "Web-ISAPI-Filter",
    "Web-Client-Auth", "Web-Cert-Auth", "Web-Mgmt-Console", "Web-Scripting-Tools",
    "NET-Framework-45-ASPNET", "NET-WCF-HTTP-Activation45"
)

$LogFields = "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,ServerPort,Method,UriStem,UriQuery,HttpStatus,HttpSubStatus,Win32Status,TimeTaken,ProtocolVersion,Host,UserAgent"

$Sites = @(
    @{ Name = "Backend1"; Pool = "Backend1Pool"; Http = 8080; Https = 8443 }
    @{ Name = "Backend2"; Pool = "Backend2Pool"; Http = 8081; Https = 8444 }
)

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script needs an Administrator PowerShell."
    }
}

function Step([string]$text) {
    Write-Host ""
    Write-Host "== $text"
}

if ($Preview) {
    Write-Host ""
    Write-Host "PREVIEW (nothing is changed)"
    Write-Host "site path        : $SitePath"
    Write-Host "windows features : $($Features -join ', ')"
    foreach ($site in $Sites) {
        Write-Host ("site $($site.Name) : http :$($site.Http)  https :$($site.Https)  pool $($site.Pool)")
    }
    Write-Host "revocation       : $(if ($Revocation) { 'enable (production-like)' } else { 'disable (lab)' })"
    Write-Host "failed req trace : $(if ($Tracing) { 'on for status 403' } else { 'off' })"
    Write-Host "static address   : $(if ($StaticIp) { "$StaticIp/$PrefixLength (no gateway)" } else { '(unchanged)' })"
    Write-Host "WinHTTP proxy    : $(if ($ProxyServer) { $ProxyServer } else { '(unchanged)' })"
    return
}

Assert-Admin

if ($StaticIp) {
    Step "Static address (an internal switch has no DHCP)"
    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $adapter) { $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $adapter) { throw "No network adapter found." }
    Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $StaticIp -PrefixLength $PrefixLength | Out-Null
    # Deliberately no default gateway: the host proxy is the only way out.
    Write-Host "$($adapter.Name): $StaticIp/$PrefixLength, no default gateway"
}

if ($ProxyServer) {
    Step "WinHTTP proxy (this is what HTTP.sys / Schannel / lsass use)"
    & netsh winhttp set proxy proxy-server="$ProxyServer" bypass-list="<local>" | Out-Null
    Write-Host "WinHTTP proxy -> $ProxyServer"
    Write-Host "Web.config <defaultProxy> would NOT affect this path - see README."
}

if (-not (Test-Path (Join-Path $SitePath "Demo.svc"))) {
    throw "Demo.svc not found in $SitePath. Copy the built repository into the VM."
}
if (-not (Test-Path (Join-Path $SitePath "bin"))) {
    Write-Host "WARNING: $SitePath\bin is missing. Build on the host (.\lab.ps1 build) and copy again."
}

Step "Windows features"
if ($SkipFeatures) {
    Write-Host "skipped (-SkipFeatures)"
}
elseif (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
    $result = Install-WindowsFeature -Name $Features -IncludeManagementTools
    Write-Host "Success=$($result.Success)  RestartNeeded=$($result.RestartNeeded)"
}
else {
    Write-Host "Install-WindowsFeature not available - this is not Windows Server."
    Write-Host "On a client OS enable IIS + ASP.NET 4.8 + WCF HTTP activation by hand,"
    Write-Host "but remember: app pool behaviour is only realistic on Server."
}

Import-Module WebAdministration -ErrorAction Stop

Step "Certificates (lab CA + server certificate)"
$thumbFile = Join-Path $Root "certs\server.thumbprint"
$pfx = Join-Path $Root "certs\lab-server.pfx"
$caCer = Join-Path $Root "certs\lab-root.cer"
if (-not (Test-Path $pfx)) {
    & (Join-Path $Root "scripts\New-DevCertificates.ps1")
}
$thumb = (Get-Content $thumbFile -Raw).Trim()
& certutil -f -addstore Root $caCer | Out-Null
& certutil -f -addstore CA $caCer | Out-Null
& certutil -f -addstore ClientAuthIssuer $caCer | Out-Null
$password = ConvertTo-SecureString "lab" -AsPlainText -Force
if (-not (Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb })) {
    Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\My -Password $password | Out-Null
}
Write-Host "server certificate $thumb in LocalMachine\My"

# The chain must terminate where HTTP.sys looks, and that depends on this value.
$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
if (-not (Test-Path $schannel)) { New-Item -Path $schannel -Force | Out-Null }
New-ItemProperty -Path $schannel -Name ClientAuthTrustMode -Value 2 -PropertyType DWord -Force | Out-Null
Write-Host "SCHANNEL ClientAuthTrustMode=2 (chain must end in ClientAuthIssuer)"

Step "Application pools and sites"
foreach ($site in $Sites) {
    if (Test-Path "IIS:\AppPools\$($site.Pool)") { Remove-WebAppPool -Name $site.Pool }
    New-WebAppPool -Name $site.Pool | Out-Null
    Set-ItemProperty "IIS:\AppPools\$($site.Pool)" managedRuntimeVersion "v4.0"
    Set-ItemProperty "IIS:\AppPools\$($site.Pool)" managedPipelineMode "Integrated"
    # Keep-alive tests are only honest if the pool does not recycle underneath them.
    Set-ItemProperty "IIS:\AppPools\$($site.Pool)" processModel.idleTimeout ([TimeSpan]::Zero)
    Set-ItemProperty "IIS:\AppPools\$($site.Pool)" recycling.periodicRestart.time ([TimeSpan]::Zero)
    Write-Host "app pool $($site.Pool): v4.0, no idle timeout, no periodic recycle"

    if (Test-Path "IIS:\Sites\$($site.Name)") { Remove-Website -Name $site.Name }
    New-Website -Name $site.Name -PhysicalPath $SitePath -Port $site.Http -ApplicationPool $site.Pool | Out-Null
    New-WebBinding -Name $site.Name -Protocol https -Port $site.Https -IPAddress "*" | Out-Null

    $binding = Get-WebBinding -Name $site.Name -Protocol https
    $binding.AddSslCertificate($thumb, "My")
    Write-Host "site $($site.Name): http :$($site.Http), https :$($site.Https)"
}

Step "Client certificate negotiation on the HTTP.sys bindings"
$revocationFlag = if ($Revocation) { "enable" } else { "disable" }
foreach ($site in $Sites) {
    $ipPort = "0.0.0.0:$($site.Https)"
    $out = & netsh http update sslcert ipport=$ipPort certhash=$thumb `
        appid="{4dc3e181-e14b-4a21-b022-59fc669b0914}" certstorename=MY `
        clientcertnegotiation=enable verifyclientcertrevocation=$revocationFlag 2>&1
    Write-Host "$ipPort clientcertnegotiation=enable verifyclientcertrevocation=$revocationFlag"
    Write-Host "  $($out -join ' ')"
}

Step "ClickOnce /install (no client certificate)"
$installPath = Join-Path $Root "publish\clickonce"
New-Item -ItemType Directory -Force -Path $installPath | Out-Null
foreach ($site in $Sites) {
    $vdir = "IIS:\Sites\$($site.Name)\install"
    if (Test-Path $vdir) {
        Set-ItemProperty $vdir -Name physicalPath -Value $installPath
    } else {
        New-WebVirtualDirectory -Site $site.Name -Name install -PhysicalPath $installPath | Out-Null
    }
    & appcmd set config "$($site.Name)/install" /section:access /sslFlags:"None" /commit:apphost | Out-Null
    Write-Host "$($site.Name)/install -> $installPath (sslFlags None)"
}

Step "SSL flags: ask for the card only on Demo.svc"
foreach ($site in $Sites) {
    & appcmd set config "$($site.Name)" /section:access /sslFlags:"None" /commit:apphost | Out-Null
    & appcmd set config "$($site.Name)/Demo.svc" /section:access /sslFlags:"Ssl,SslNegotiateCert,SslRequireCert" /commit:apphost | Out-Null
    Write-Host "$($site.Name)/Demo.svc : Ssl,SslNegotiateCert,SslRequireCert   (health and /install stay certificate-free)"
}

Step "W3C logging with substatus and win32 status"
& appcmd set config /section:system.applicationHost/sites "/siteDefaults.logFile.logFormat:W3C" /commit:apphost | Out-Null
& appcmd set config /section:system.applicationHost/sites "/siteDefaults.logFile.logExtFileFlags:$LogFields" /commit:apphost | Out-Null
Write-Host "sc-substatus + sc-win32-status are now logged (without them 403.16 and 403.13 look identical)"

if ($Tracing) {
    Step "Failed Request Tracing for 403 (only possible on full IIS)"
    foreach ($site in $Sites) {
        try {
            & appcmd set site "$($site.Name)" /traceFailedRequestsLogging.enabled:true /traceFailedRequestsLogging.maxLogFiles:20 | Out-Null
            & appcmd set config "$($site.Name)" /section:system.webServer/tracing/traceFailedRequests /+"[path='*']" /commit:apphost | Out-Null
            & appcmd set config "$($site.Name)" /section:system.webServer/tracing/traceFailedRequests "/+[path='*'].traceAreas.[provider='WWW Server',areas='Security,Authentication,RequestNotifications',verbosity='Verbose']" /commit:apphost | Out-Null
            & appcmd set config "$($site.Name)" /section:system.webServer/tracing/traceFailedRequests "/[path='*'].failureDefinitions.statusCodes:403" /commit:apphost | Out-Null
            Write-Host "$($site.Name): FREB on for 403, logs under C:\inetpub\logs\FailedReqLogFiles"
        }
        catch {
            Write-Host "FREB setup failed for $($site.Name): $($_.Exception.Message)"
        }
    }
}

Step "Firewall: let the client machine reach this VM"
foreach ($port in @(8080, 8081, 8443, 8444)) {
    $name = "IIS-ID lab inbound $port"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $port | Out-Null
    }
}
Write-Host "inbound 8080/8081/8443/8444 allowed"

Write-Host ""
Write-Host "DONE. Next steps:"
Write-Host "  1. ID-card chain:    scripts\Install-EeIdTrust.ps1   (or copy certs\eid-ca and re-run)"
Write-Host "  2. On the CLIENT machine add a hosts entry: <this VM ip>  demo.local"
Write-Host "  3. Install page:     http://demo.local:8080/install/   (no PIN1)"
Write-Host "  4. Client talks to:  https://demo.local:8443/Demo.svc"
Write-Host "  5. Closed network:   scripts\Set-LabLockdown.ps1 proxy-only   (host runs the proxy)"
Write-Host "  6. After a failure:  scripts\Get-EidReport.ps1 -Minutes 15"
Write-Host ""
Write-Host "Snapshot the VM here. Every lockdown scenario is then one revert away."
