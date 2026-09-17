# Diagnose PIN1 / mTLS failure on the IIS (or lab) machine.
# ASCII-only: Windows PowerShell 5.1.
#
# Run AFTER the client asked for PIN1 and WCF/IIS still rejected the cert:
#   powershell -ExecutionPolicy Bypass -File scripts\Test-EidAfterPin1.ps1
#
# Optional:
#   -EnableCapi2Log     turn on CAPI2 Operational log (then reproduce PIN1 once more)
#   -Thumbprint ABC...  only verify that PIN1 cert

param(
    [string]$Thumbprint,
    [switch]$EnableCapi2Log
)

$ErrorActionPreference = "Continue"
$failed = 0

function Write-Head([string]$title) {
    Write-Host ""
    Write-Host "======== $title ========"
}

function Write-Fail([string]$msg) {
    $script:failed++
    Write-Host "FAIL  $msg"
}

function Write-Ok([string]$msg) { Write-Host "OK    $msg" }
function Write-Info([string]$msg) { Write-Host "INFO  $msg" }

function Get-StoreCerts([string]$path) {
    if (-not (Test-Path $path)) { return @() }
    @(Get-ChildItem $path -ErrorAction SilentlyContinue)
}

function Test-Name($certs, $pattern) {
    @($certs | Where-Object { $_.Subject -match $pattern -or $_.Issuer -match $pattern }).Count
}

Write-Host "PIN1 / client-cert failure checklist"
Write-Host "Run this ON THE IIS BOX that received the handshake (not only on the PC with the card)."
Write-Host "PIN1 dialog means Windows on the CLIENT accepted the card. Failure after that is SERVER chain/OCSP/IIS."
Write-Host ""

# --- stores ---
Write-Head "1. Certificate stores (LocalMachine)"
$roots = Get-StoreCerts Cert:\LocalMachine\Root
$inter = Get-StoreCerts Cert:\LocalMachine\CA
$issuers = Get-StoreCerts Cert:\LocalMachine\ClientAuthIssuer
$nRoot = Test-Name $roots 'EE-GovCA2018|EEGovCA2025'
$nCa = Test-Name $inter 'ESTEID2018|ESTEID2025'
$nIss = Test-Name $issuers 'ESTEID2018|ESTEID2025'
Write-Host "Root EE-GovCA2018/EEGovCA2025:     $nRoot   (need 2)"
Write-Host "CA ESTEID2018/ESTEID2025:          $nCa   (need 2)"
Write-Host "ClientAuthIssuer ESTEID2018/2025:  $nIss   (need 2; empty store => IIS 8+ 403.16)"
if ($nRoot -lt 2) { Write-Fail "Missing government roots. Install-EsteidIisProduction.ps1 or lab.ps1 eid-ca" }
else { Write-Ok "Roots present" }
if ($nCa -lt 2) { Write-Fail "Missing ESTEID intermediates. 403.16 even if roots exist." }
else { Write-Ok "Intermediates present" }
if ($issuers.Count -eq 0) { Write-Fail "ClientAuthIssuer is EMPTY. All client certs can become 403.16." }
elseif ($nIss -lt 2) { Write-Fail "ClientAuthIssuer missing ESTEID2018/2025." }
else { Write-Ok "ClientAuthIssuer has ESTEID intermediates" }

$mode = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -ErrorAction SilentlyContinue).ClientAuthTrustMode
$send = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -ErrorAction SilentlyContinue).SendTrustedIssuerList
Write-Host "SCHANNEL ClientAuthTrustMode  = $mode   (lab=2; production often unset + CTL)"
Write-Host "SCHANNEL SendTrustedIssuerList = $send   (1 = send issuer list to client)"

# --- HTTP.sys ---
Write-Head "2. HTTP.sys SSL bindings"
$ssl = netsh http show sslcert 2>$null | Out-String
$ssl | Select-String -Pattern "IP:port|Certificate Hash|Negotiate Client Certificate|Verify Client Certificate Revocation|Verify Revocation with Cached Client Certificate Only|Ctl Store Name|Usage Check" |
    ForEach-Object { Write-Host "  $_" }
if ($ssl -notmatch "Negotiate Client Certificate\s*:\s*Enabled") {
    Write-Fail "Negotiate Client Certificate is not Enabled. TLS 1.3 in-handshake will fail / cert not requested."
} else { Write-Ok "clientcertnegotiation=enable" }
if ($ssl -match "Ctl Store Name\s*:\s*ClientAuthIssuer" -and $issuers.Count -eq 0) {
    Write-Fail "Ctl Store = ClientAuthIssuer but the store is empty => 403.16"
}
if ($ssl -match "Verify Client Certificate Revocation\s*:\s*Enabled") {
    Write-Info "Revocation ENABLED. If SK OCSP is blocked => 403.13 (not 403.16)."
}

# --- WinHTTP (Local System / HTTP.sys) ---
Write-Head "3. WinHTTP proxy (HTTP.sys and CAPI2 use this, NOT IE proxy)"
netsh winhttp show proxy
Write-Info "If IIS VMs have no direct internet, set machine WinHTTP proxy and allow SK hosts."
Write-Info "  netsh winhttp set proxy proxy-server=`"http://proxy:8080`" bypass-list=`"*.corp.local`""
Write-Info "IE / WinINET holes do not apply to Local System."

# --- URL reachability ---
Write-Head "4. URLs that THIS machine must reach (AIA / OCSP / CRL)"
Write-Info "Chain can be built OFFLINE if intermediates are in LocalMachine\CA."
Write-Info "OCSP/CRL still need the network when verifyclientcertrevocation=enable."

$urls = @(
    @{ Url = "https://c.sk.ee/EE-GovCA2018.der.crt"; Why = "EE-GovCA2018 root download / AIA" }
    @{ Url = "https://c.sk.ee/esteid2018.der.crt";   Why = "ESTEID2018 intermediate download / AIA" }
    @{ Url = "https://crt.eidpki.ee/EEGovCA2025.crt"; Why = "EEGovCA2025 root" }
    @{ Url = "https://crt.eidpki.ee/ESTEID2025.crt"; Why = "ESTEID2025 intermediate" }
    @{ Url = "http://aia.sk.ee/esteid2018";         Why = "ESTEID2018 OCSP AIA (HTTP.sys uses this)" }
    @{ Url = "http://aia.sk.ee/EE-GovCA2018";       Why = "EE-GovCA2018 OCSP AIA" }
    @{ Url = "http://ocsp.eidpki.ee";               Why = "ESTEID2025 OCSP" }
    @{ Url = "http://ocsp.sk.ee";                   Why = "legacy SK OCSP" }
    @{ Url = "http://c.sk.ee/crls/esteid/esteid2018.crl"; Why = "ESTEID2018 CRL fallback" }
    @{ Url = "http://www.sk.ee/crls/esteid/esteid2018.crl"; Why = "ESTEID2018 CRL alt" }
)

foreach ($item in $urls) {
    $u = [Uri]$item.Url
    $port = $u.Port
    if ($port -le 0) { $port = $(if ($u.Scheme -eq "https") { 443 } else { 80 }) }
    $tcpOk = $false
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($u.Host, $port, $null, $null)
        $tcpOk = $iar.AsyncWaitHandle.WaitOne(4000, $false) -and $client.Connected
        $client.Close()
    } catch { $tcpOk = $false }

    $http = "n/a"
    try {
        $r = Invoke-WebRequest -Uri $item.Url -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 3 -ErrorAction Stop
        $http = [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { $http = [int]$_.Exception.Response.StatusCode }
        else { $http = $_.Exception.Message }
    }

    $tag = "OK  "
    if (-not $tcpOk) {
        $tag = "FAIL"
        $script:failed++
    }
    Write-Host ("{0}  TCP {1,-22} :{2,-3}  HTTP={3}  {4}" -f $tag, $u.Host, $port, $http, $item.Why)
}

Write-Info "OCSP HTTP 400/405 without a signed request is still REACHABLE. TCP fail = firewall/proxy."

# --- PIN1 cert verify (if present on this box) ---
Write-Head "5. certutil -verify -urlfetch (PIN1 in CurrentUser\My, if any)"
Write-Info "On a dedicated IIS VM there is often NO card. Run this on a jump host with the card, or export the leaf .cer from the client."
$personal = Get-StoreCerts Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
if ($Thumbprint) { $personal = $personal | Where-Object { $_.Thumbprint -eq $Thumbprint } }
$auth = $personal | Where-Object {
    $_.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" -and $_.Format($false) -match "1.3.6.1.5.5.7.3.2|Client Authentication" }
}
if ($auth.Count -eq 0) {
    Write-Info "No PIN1 cert in this user store. Export the leaf from the client and: certutil -verify -urlfetch leaf.cer"
} else {
    foreach ($cert in $auth) {
        Write-Host "--- $($cert.Subject)"
        Write-Host "    Issuer $($cert.Issuer)"
        Write-Host "    Thumb  $($cert.Thumbprint)"
        $tmp = Join-Path $env:TEMP ("eid-" + $cert.Thumbprint + ".cer")
        Export-Certificate -Cert $cert -FilePath $tmp | Out-Null
        $out = & certutil -verify -urlfetch $tmp 2>&1 | Out-String
        $out -split "`r?`n" | Select-String -Pattern "ERROR|FAILED|Chain|Leaf|AIA|OCSP|CRL|Verified|CERT_|Revocation" |
            ForEach-Object { Write-Host "    $_" }
        if ($out -match "CERT_E_UNTRUSTEDROOT|CERT_E_CHAINING") { Write-Fail "Chain/untrusted root for $($cert.Thumbprint) => 403.16" }
        if ($out -match "CERT_E_REVOKED|REVOCATION_OFFLINE|CERT_E_REVOCATION_FAILURE") { Write-Fail "Revocation problem for $($cert.Thumbprint) => 403.13" }
    }
}

# --- CAPI2 ---
Write-Head "6. CAPI2 Operational log (chain/OCSP on the IIS box)"
$capi = "Microsoft-Windows-CAPI2/Operational"
if ($EnableCapi2Log) {
    wevtutil sl $capi /e:true | Out-Null
    Write-Ok "Enabled $capi . Reproduce PIN1 once, then re-run this script."
}
try {
    $events = @(Get-WinEvent -LogName $capi -MaxEvents 25 -ErrorAction Stop)
    foreach ($e in $events) {
        $line = "[{0:HH:mm:ss}] id={1} {2}" -f $e.TimeCreated, $e.Id, ($e.Message -replace '\s+', ' ')
        if ($line.Length -gt 220) { $line = $line.Substring(0, 220) + "..." }
        Write-Host "  $line"
    }
} catch {
    Write-Info "CAPI2 log empty/disabled. Enable: wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true"
    Write-Info "Then reproduce PIN1 and look for result=800B0109 (untrusted) or revocation errors."
}

# --- HTTP.sys error log ---
Write-Head "7. HTTPERR (HTTP.sys dropped the request before IIS)"
$httpErrDir = Join-Path $env:SystemRoot "System32\LogFiles\HTTPERR"
if (Test-Path $httpErrDir) {
    $latest = Get-ChildItem $httpErrDir -Filter "httperr*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host "File $($latest.FullName)"
        Get-Content $latest.FullName -Tail 15
    }
} else { Write-Info "No HTTPERR folder." }

# --- IIS W3C logs ---
Write-Head "8. IIS W3C logs (sc-status + sc-substatus)"
$inet = @(
    (Join-Path $env:SystemDrive "inetpub\logs\LogFiles"),
    (Join-Path $env:USERPROFILE "Documents\IISExpress\Logs")
)
$foundLog = $false
foreach ($dir in $inet) {
    if (-not (Test-Path $dir)) { continue }
    $logs = Get-ChildItem $dir -Recurse -Filter "*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
    foreach ($log in $logs) {
        $foundLog = $true
        Write-Host "File $($log.FullName)"
        Get-Content $log.FullName -Tail 40 | Where-Object { $_ -match " 403 | 500 |Demo.svc" } | Select-Object -Last 12
    }
}
if (-not $foundLog) { Write-Info "No IIS/IIS Express logs found. Enable site logging / Failed Request Tracing for 403." }

Write-Head "9. How to read the codes"
Write-Host "403.7   Client cert required but none sent (Negotiate Client Certificate off, or LB terminated TLS)."
Write-Host "403.16  Cert arrived, chain NOT trusted (missing ESTEID intermediate / empty ClientAuthIssuer)."
Write-Host "403.13  Cert arrived, revocation/OCSP/CRL failed (WinHTTP/proxy/SK URL blocked)."
Write-Host "WCF 'Anonymous' / MessageSecurityException  = usually 403.16 or 403.13 rewritten."
Write-Host "PIN1 prompt + then fail  = client crypto OK; fix THIS server's stores/OCSP, not the card PIN."
Write-Host ""
if ($failed -gt 0) { Write-Host "Summary: $failed check(s) failed." } else { Write-Host "Summary: store/TCP checks did not flag a hard FAIL (still read CAPI2 + IIS 403.xx)." }
