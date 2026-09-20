# One report for "PIN1 was entered but login still failed".
# ASCII-only: Windows PowerShell 5.1.
#
# Collects, from ONE machine, everything that decides a client-certificate login:
#   IIS/IIS Express W3C 403.x rows, HTTPERR, CAPI2, Schannel, cert stores,
#   HTTP.sys binding flags, WinHTTP proxy, CertProbe log, client log, LB log.
#
# Usage (run on the machine that received the TLS handshake):
#   powershell -ExecutionPolicy Bypass -File scripts\Get-EidReport.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\Get-EidReport.ps1 -Minutes 60 -ClientIp 10.0.0.5
#   powershell -ExecutionPolicy Bypass -File scripts\Get-EidReport.ps1 -EnableLogs   (then reproduce PIN1 and run again)
#   powershell -ExecutionPolicy Bypass -File scripts\Get-EidReport.ps1 -CertFile card.cer
#     ^ runs certutil -verify -urlfetch on that certificate: the only check that proves
#       whether THIS machine can actually fetch AIA/OCSP/CRL (proxy 407, MITM, timeouts).
#       Defaults to .lab\lastclient.cer, which Demo.CertProbe writes on every handshake.

param(
    [int]$Minutes = 30,
    [string]$OutDir,
    [string]$ClientIp,
    [string]$CertFile,
    [switch]$EnableLogs,
    [switch]$NoNetwork,
    [switch]$Open
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$since = (Get-Date).AddMinutes(-$Minutes)
$sinceUtc = $since.ToUniversalTime()

$script:lines = @()
$script:findings = @()

function Add-Line([string]$text = "") { $script:lines += $text }

function Add-Section([string]$title) {
    Add-Line ""
    Add-Line ("-" * 78)
    Add-Line $title
    Add-Line ("-" * 78)
}

function Add-Finding([string]$level, [string]$text, [string]$fix = "") {
    $script:findings += [pscustomobject]@{ Level = $level; Text = $text; Fix = $fix }
}

function Get-StoreCount([string]$location, [string]$name, [string]$pattern) {
    $path = "Cert:\$location\$name"
    if (-not (Test-Path $path)) { return -1 }
    $certs = @(Get-ChildItem $path -ErrorAction SilentlyContinue)
    if (-not $pattern) { return $certs.Count }
    return @($certs | Where-Object { $_.Subject -match $pattern }).Count
}

# ---------------------------------------------------------------- stores
function Collect-Stores {
    Add-Section "1. CERT STORES (LocalMachine) - decides 403.16"
    $rootGov = Get-StoreCount "LocalMachine" "Root" 'EE-GovCA2018|EEGovCA2025'
    $caEsteid = Get-StoreCount "LocalMachine" "CA" 'ESTEID2018|ESTEID2025'
    $issuerAll = Get-StoreCount "LocalMachine" "ClientAuthIssuer" $null
    $issuerEsteid = Get-StoreCount "LocalMachine" "ClientAuthIssuer" 'ESTEID2018|ESTEID2025'

    Add-Line ("Root   EE-GovCA2018/EEGovCA2025 : {0}" -f $rootGov)
    Add-Line ("CA     ESTEID2018/ESTEID2025    : {0}" -f $caEsteid)
    Add-Line ("ClientAuthIssuer total / ESTEID : {0} / {1}" -f $issuerAll, $issuerEsteid)

    if ($rootGov -le 0) { Add-Finding "FAIL" "LocalMachine\Root has no EE-GovCA root => 403.16" "certutil -addstore -f Root EE-GovCA2018.der.crt" }
    if ($caEsteid -le 0) { Add-Finding "FAIL" "LocalMachine\CA has no ESTEID intermediate => 403.16" "certutil -addstore -f CA esteid2018.der.crt" }
    if ($issuerAll -le 0) { Add-Finding "FAIL" "LocalMachine\ClientAuthIssuer is EMPTY => IIS 8+ can reject every card with 403.16" "certutil -addstore -f ClientAuthIssuer esteid2018.der.crt" }
    elseif ($issuerEsteid -le 0) { Add-Finding "WARN" "ClientAuthIssuer has certs but no ESTEID issuer" "" }

    $schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    $trustMode = (Get-ItemProperty $schannel -ErrorAction SilentlyContinue).ClientAuthTrustMode
    $sendList = (Get-ItemProperty $schannel -ErrorAction SilentlyContinue).SendTrustedIssuerList
    Add-Line ("SCHANNEL ClientAuthTrustMode    : {0}" -f $(if ($null -ne $trustMode) { $trustMode } else { "(unset = 0)" }))
    Add-Line ("SCHANNEL SendTrustedIssuerList  : {0}" -f $(if ($null -ne $sendList) { $sendList } else { "(unset)" }))
}

# ---------------------------------------------------------------- HTTP.sys
function Get-SslBindings {
    $ssl = netsh http show sslcert 2>$null | Out-String
    if (-not $ssl) { return @() }

    $bindings = @()
    $current = $null
    foreach ($line in ($ssl -split "`r?`n")) {
        # netsh pads keys into a column; the key itself can contain a colon ("IP:port").
        if ($line -notmatch '^\s*(\S.*?)\s+:\s*(.*)$') { continue }
        $key = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        if ($key -eq "IP:port" -or $key -eq "Hostname:port") {
            if ($current) { $bindings += $current }
            $current = [pscustomobject]@{
                Binding = $value; Hash = ""; Negotiate = ""; Revocation = ""
                CachedOnly = ""; CtlStore = ""; UsageCheck = ""
            }
            continue
        }
        if (-not $current) { continue }
        switch -Regex ($key) {
            '^Certificate Hash' { $current.Hash = $value }
            '^Negotiate Client Certificate' { $current.Negotiate = $value }
            '^Verify Client Certificate Revocation' { $current.Revocation = $value }
            '^Verify Revocation with Cached' { $current.CachedOnly = $value }
            '^Ctl Store Name' { $current.CtlStore = $value }
            '^Usage Check' { $current.UsageCheck = $value }
        }
    }
    if ($current) { $bindings += $current }
    return @($bindings)
}

function Collect-HttpSys {
    Add-Section "2. HTTP.sys SSL BINDINGS (netsh http show sslcert)"
    $bindings = Get-SslBindings
    if ($bindings.Count -eq 0) {
        Add-Line "(no output - run as Administrator)"
        Add-Finding "WARN" "netsh http show sslcert returned nothing (not admin?)" "Re-run elevated"
        return
    }

    # A dev box has dozens of Visual Studio bindings (44300+). Show only mTLS-relevant ones.
    $interesting = @($bindings | Where-Object {
            $_.Negotiate -eq "Enabled" -or $_.Binding -match ':(443|8443|8444|9443|9444)$'
        })
    $hidden = $bindings.Count - $interesting.Count

    Add-Line ("bindings total: {0}   shown: {1}   hidden (no client-cert negotiation): {2}" -f $bindings.Count, $interesting.Count, $hidden)
    Add-Line ""
    Add-Line ("  {0,-24} {1,-10} {2,-11} {3,-11} {4}" -f "binding", "negotiate", "revocation", "usagecheck", "ctl store")
    foreach ($b in $interesting) {
        Add-Line ("  {0,-24} {1,-10} {2,-11} {3,-11} {4}" -f $b.Binding, $b.Negotiate, $b.Revocation, $b.UsageCheck, $b.CtlStore)
        Add-Line ("  {0,-24} hash {1}" -f "", $b.Hash)
    }

    if ($interesting.Count -eq 0) {
        Add-Finding "FAIL" "No binding has Negotiate Client Certificate = Enabled => client cert is never requested (403.7)" "netsh http update sslcert ipport=0.0.0.0:443 certhash=... appid={...} clientcertnegotiation=enable"
        return
    }
    if (@($interesting | Where-Object { $_.Negotiate -ne "Enabled" }).Count -gt 0) {
        Add-Finding "WARN" "One of the mTLS ports has Negotiate Client Certificate disabled" "Fix that exact ipport - the setting is per IP:port, not global"
    }

    $emptyIssuerStore = (Get-StoreCount "LocalMachine" "ClientAuthIssuer" $null) -le 0
    if (@($interesting | Where-Object { $_.CtlStore -match "ClientAuthIssuer" }).Count -gt 0 -and $emptyIssuerStore) {
        Add-Finding "FAIL" "Ctl Store Name = ClientAuthIssuer but that store is empty => every card gets 403.16" "Install ESTEID intermediates into ClientAuthIssuer"
    }
    if (@($interesting | Where-Object { $_.Revocation -eq "Enabled" }).Count -gt 0) {
        Add-Line ""
        Add-Line "  NOTE revocation is ENABLED on an mTLS port: blocked OCSP shows up as 403.13, not 403.16"
    }
    if (@($interesting | Where-Object { $_.CachedOnly -eq "Enabled" }).Count -gt 0) {
        Add-Finding "WARN" "Verify Revocation with Cached Client Certificate Only is Enabled" "Set verifyrevocationwithcachedclientcertonly=disable"
    }
}

function Collect-WinHttp {
    Add-Section "3. WinHTTP PROXY (used by HTTP.sys / CAPI2, NOT web.config, NOT IE)"
    $proxy = netsh winhttp show proxy 2>$null | Out-String
    Add-Line ($proxy.Trim())
    if ($proxy -match "Direct access") {
        Add-Line "Direct access = no machine proxy. Fine if this box can reach SK/eidpki directly on port 80."
    }
}

# ---------------------------------------------------------------- outbound urls
function Collect-Urls {
    Add-Section "3b. OUTBOUND AIA / OCSP / CRL (needed only when revocation is enabled)"
    if ($NoNetwork) { Add-Line "(skipped: -NoNetwork)"; return }

    $urls = @(
        @{ Url = "http://aia.sk.ee/esteid2018"; Why = "ESTEID2018 OCSP" }
        @{ Url = "http://ocsp.eidpki.ee"; Why = "ESTEID2025 OCSP" }
        @{ Url = "http://crl.eidpki.ee/EEGovCA2025.crl"; Why = "EEGovCA2025 CRL" }
        @{ Url = "http://ocsp.sk.ee"; Why = "legacy SK OCSP" }
        @{ Url = "http://c.sk.ee/crls/esteid/esteid2018.crl"; Why = "ESTEID2018 CRL" }
        @{ Url = "https://c.sk.ee/esteid2018.der.crt"; Why = "ESTEID2018 cert download" }
        @{ Url = "https://crt.eidpki.ee/ESTEID2025.crt"; Why = "ESTEID2025 cert download" }
    )

    $failed = 0
    foreach ($item in $urls) {
        $u = [Uri]$item.Url
        $port = $u.Port
        if ($port -le 0) { $port = $(if ($u.Scheme -eq "https") { 443 } else { 80 }) }
        $ok = $false
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($u.Host, $port, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(3000, $false) -and $client.Connected
            $client.Close()
        } catch { $ok = $false }
        if (-not $ok) { $failed++ }
        Add-Line ("  {0}  TCP {1,-22}:{2,-4} {3}" -f $(if ($ok) { "OK  " } else { "FAIL" }), $u.Host, $port, $item.Why)
    }

    Add-Line "  (OCSP answering 400/405 to a plain GET is still reachable - only TCP matters here)"
    if ($failed -gt 0) {
        Add-Finding "WARN" "$failed SK/eidpki endpoint(s) unreachable from this machine" "Only fatal when verifyclientcertrevocation=enable (403.13). Open outbound 80/443 or set WinHTTP proxy."
    }
}

# ------------------------------------------------- client cert chain (certutil)
# TCP test (3b) says only "the port answers". This says whether the chain really
# validates on THIS machine, per URL: proxy 407, MITM, slow CRL, clock skew.
function Collect-CertVerify {
    Add-Section "3c. CLIENT CERT CHAIN (certutil -verify -urlfetch)"

    $file = $CertFile
    if (-not $file) {
        $fallback = Join-Path $Root ".lab\lastclient.cer"
        if (Test-Path $fallback) { $file = $fallback }
    }
    if (-not $file) {
        Add-Line "(no certificate given. Use -CertFile card.cer, or run '.\lab.ps1 probe' with the card:"
        Add-Line " CertProbe writes the last client cert to .lab\lastclient.cer and this section runs by itself.)"
        return
    }
    if (-not (Test-Path $file)) {
        Add-Line ("(certificate not found: " + $file + ")")
        Add-Finding "WARN" "-CertFile path does not exist" $file
        return
    }

    Add-Line ("FILE " + (Resolve-Path $file).Path)
    if ($NoNetwork) { Add-Line "(skipped: -NoNetwork - certutil -urlfetch goes to the network)"; return }

    $raw = ""
    try { $raw = (& certutil -verify -urlfetch $file 2>&1 | Out-String) } catch { $raw = "certutil failed: $_" }
    if (-not $raw) { Add-Line "(certutil returned nothing)"; return }

    $lines = @($raw -split "`r?`n")
    $current = $null
    foreach ($line in $lines) {
        $trim = $line.Trim()
        if (-not $trim) { continue }

        # "Verified "Certificate (0)" Time: 0" / "Failed "OCSP(1)" Time: 15"
        $m = [regex]::Match($trim, '^(Verified|Failed|Expired)\s+"?([^"]+?)"?\s+Time:\s*(\d+)')
        if ($m.Success) {
            $current = [pscustomobject]@{ State = $m.Groups[1].Value; What = $m.Groups[2].Value; Seconds = $m.Groups[3].Value }
            continue
        }
        $u = [regex]::Match($trim, '^\[[\d\.]+\]\s+(\S+)$')
        if ($u.Success -and $current) {
            Add-Line ("  {0,-8} {1,3}s  {2,-16} {3}" -f $current.State, $current.Seconds, $current.What, $u.Groups[1].Value)
            if ($current.State -ne "Verified") {
                Add-Finding "FAIL" ("certutil could not fetch " + $current.What + ": " + $u.Groups[1].Value) `
                    "This is the 403.13 path: outbound 80/443, WinHTTP proxy (407?), or the proxy rewrites the response"
            }
            $current = $null
            continue
        }
        if ($trim -match '^Error retrieving URL:') { Add-Line ("  " + $trim); continue }
        if ($trim -match '^(ERROR|CertUtil: )') { Add-Line ("  " + $trim); continue }
        if ($trim -match 'revocation check (passed|skipped)') { Add-Line ("  " + $trim); continue }
    }

    # Codes worth naming: they map 1:1 to the IIS substatus.
    $codes = @(
        @{ Code = '800B0109'; Level = "FAIL"; Text = "chain untrusted (CERT_E_UNTRUSTEDROOT) - this is 403.16"; Fix = "Root: EE-GovCA; CA + ClientAuthIssuer: ESTEID2018/2025" }
        @{ Code = '800B010A'; Level = "FAIL"; Text = "chain incomplete (CERT_E_CHAINING) - intermediate CA missing"; Fix = "Install ESTEID2018/ESTEID2025 into LocalMachine\CA" }
        @{ Code = '80092013'; Level = "FAIL"; Text = "revocation server offline (CRYPT_E_REVOCATION_OFFLINE) - this is 403.13"; Fix = "Outbound 80 to aia.sk.ee / ocsp.eidpki.ee, or WinHTTP proxy without 407" }
        @{ Code = '800B0101'; Level = "FAIL"; Text = "certificate expired or clock skew (CERT_E_EXPIRED)"; Fix = "w32tm /query /status; check the card validity" }
        @{ Code = '800B010C'; Level = "FAIL"; Text = "certificate REVOKED (CERT_E_REVOKED)"; Fix = "Nothing to fix on the server: the card certificate is revoked" }
    )
    foreach ($c in $codes) {
        if ($raw -match $c.Code) { Add-Finding $c.Level ("certutil: " + $c.Text) $c.Fix }
    }

    # The two proxy signatures that look identical in IIS logs (both end as 403.13).
    if ($raw -match '12016' -or $raw -match 'requires user authentication') {
        Add-Finding "FAIL" "certutil: the proxy demands authentication (407) for OCSP/CRL" `
            "CAPI2 cannot authenticate: let *.sk.ee / *.eidpki.ee through without auth, or bypass the proxy for them"
    }
    if ($raw -match '12002' -or $raw -match 'operation timed out') {
        Add-Finding "WARN" "certutil: an AIA/OCSP/CRL fetch timed out" `
            "Large SK CRL or a slow proxy: prefer OCSP and check netsh http urlretrievaltimeout"
    }
    if ($raw -match 'Leaf certificate revocation check passed') {
        Add-Line "  VERDICT certutil: chain + revocation OK on this machine"
    }
}

# ---------------------------------------------------------------- IIS logs
function Read-W3c([string]$path) {
    $fields = @()
    $rows = @()
    try {
        $head = @(Get-Content $path -TotalCount 12 -ErrorAction Stop)
        $tail = @(Get-Content $path -Tail 4000 -ErrorAction Stop)
    } catch {
        return [pscustomobject]@{ Rows = @(); Fields = @() }
    }

    foreach ($line in (@($head) + @($tail))) {
        if (-not $line) { continue }
        if ($line.StartsWith("#Fields:")) { $fields = ($line.Substring(8).Trim() -split '\s+'); continue }
        if ($line.StartsWith("#")) { continue }
        if ($fields.Count -eq 0) { continue }
        $parts = $line -split '\s+'
        if ($parts.Count -lt $fields.Count) { continue }
        $row = @{}
        for ($i = 0; $i -lt $fields.Count; $i++) { $row[$fields[$i]] = $parts[$i] }
        $rows += , $row
    }
    return [pscustomobject]@{ Rows = @($rows); Fields = @($fields) }
}

function Collect-IisLogs {
    Add-Section "4. IIS / IIS Express W3C - sc-status + sc-substatus (the real error code)"
    Add-Line "(timestamps are UTC; IIS buffers up to ~60s, so a failure from seconds ago may not be here yet - rerun)"
    Add-Line ""
    $dirs = @(
        (Join-Path $env:SystemDrive "inetpub\logs\LogFiles"),
        (Join-Path $Root ".lab\iislogs"),
        (Join-Path $env:APPDATA "Microsoft\IISExpressLogs"),
        (Join-Path $env:USERPROFILE "Documents\IISExpress\Logs")
    )

    $any = $false
    $missingSubstatus = $false
    $hit403 = @{}

    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) { continue }
        $logs = Get-ChildItem $dir -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 4
        foreach ($log in $logs) {
            $parsed = Read-W3c $log.FullName
            $rows = @($parsed.Rows)
            $fields = @($parsed.Fields)
            if ($rows.Count -eq 0) { continue }
            $any = $true
            if ($fields -notcontains "sc-substatus") { $missingSubstatus = $true }

            $interesting = @()
            foreach ($row in $rows) {
                $stamp = $null
                if ($row['date'] -and $row['time']) {
                    try { $stamp = [datetime]::ParseExact(($row['date'] + " " + $row['time']), 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
                }
                if ($stamp -and $stamp -lt $sinceUtc) { continue }
                if ($ClientIp -and $row['c-ip'] -ne $ClientIp) { continue }
                $status = "$($row['sc-status'])"
                if ($status -notmatch '^(4|5)') { continue }

                $sub = "$($row['sc-substatus'])"
                $key = "$status.$sub"
                if ($status -eq "403") {
                    if ($hit403.ContainsKey($key)) { $hit403[$key] = $hit403[$key] + 1 }
                    else { $hit403[$key] = 1 }
                }
                $interesting += ("  {0} {1}  c-ip={2,-15} {3} -> {4}.{5}  win32={6}" -f `
                        $row['date'], $row['time'], $row['c-ip'], $row['cs-uri-stem'], $status, $sub, $row['sc-win32-status'])
            }

            if ($interesting.Count -gt 0) {
                Add-Line ("FILE " + $log.FullName)
                $interesting | Select-Object -Last 25 | ForEach-Object { Add-Line $_ }
                Add-Line ""
            }
        }
    }

    if (-not $any) {
        Add-Line "No IIS/IIS Express logs parsed."
        Add-Finding "WARN" "No IIS logs found. Without them 403.16 vs 403.13 cannot be separated." "Enable site logging (W3C) and include sc-substatus + sc-win32-status."
    }
    if ($missingSubstatus) {
        Add-Finding "WARN" "IIS log format has no sc-substatus field" "IIS Manager -> Logging -> Select Fields -> add sc-substatus, sc-win32-status"
    }
    if ($any -and $hit403.Count -eq 0) {
        Add-Finding "INFO" ("IIS logs readable, but no 403/4xx/5xx in the last " + $Minutes + " min") "Reproduce the PIN1 failure, wait ~60s for the log flush, then rerun this script"
    }

    foreach ($key in $hit403.Keys) {
        switch ($key) {
            "403.7" { Add-Finding "FAIL" "IIS logged 403.7: no client certificate arrived" "Negotiate Client Certificate on the binding; load balancer must not terminate TLS" }
            "403.16" { Add-Finding "FAIL" "IIS logged 403.16: cert arrived, chain NOT trusted on THIS machine" "Fix Root / CA / ClientAuthIssuer stores; verify with Demo.CertProbe" }
            "403.13" { Add-Finding "FAIL" "IIS logged 403.13: revocation check failed (OCSP/CRL)" "Allow outbound HTTP 80 to aia.sk.ee / ocsp.eidpki.ee or set WinHTTP proxy" }
            "403.0" { Add-Finding "WARN" "IIS logged 403.0" "Check SSL settings / authorization rules on the app" }
            default { Add-Finding "INFO" ("IIS logged " + $key) "" }
        }
    }
}

# ---------------------------------------------------------------- HTTPERR
function Collect-HttpErr {
    Add-Section "5. HTTPERR (HTTP.sys dropped it before IIS)"
    $dir = Join-Path $env:SystemRoot "System32\LogFiles\HTTPERR"
    if (-not (Test-Path $dir)) { Add-Line "(no HTTPERR folder)"; return }
    $latest = Get-ChildItem $dir -Filter "httperr*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { Add-Line "(no httperr log)"; return }
    Add-Line ("FILE " + $latest.FullName)
    $tail = @(Get-Content $latest.FullName -Tail 25 -ErrorAction SilentlyContinue)
    $tail | ForEach-Object { Add-Line ("  " + $_) }
    if (($tail -join " ") -match "Connection_Dropped|Timer_|BadRequest") {
        Add-Finding "INFO" "HTTPERR has dropped connections - can be idle keep-alive or a TLS level failure" "Compare timestamps with the client log"
    }
}

# ---------------------------------------------------------------- CAPI2
function Collect-Capi2 {
    Add-Section "6. CAPI2 Operational (chain building + OCSP, the source of 403.16/403.13)"
    $log = "Microsoft-Windows-CAPI2/Operational"
    if ($EnableLogs) {
        wevtutil sl $log /e:true 2>$null | Out-Null
        Add-Line "Enabled $log. Reproduce PIN1 once, then run this script again."
    }

    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } -ErrorAction Stop)
    } catch {
        Add-Line "CAPI2 log is empty or disabled."
        Add-Finding "WARN" "CAPI2 Operational log is off - the actual chain error is invisible" "wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true (or run this script with -EnableLogs)"
        return
    }

    Add-Line ("events in window: " + $events.Count)
    $bad = 0
    foreach ($e in ($events | Select-Object -First 60)) {
        $msg = ($e.Message -replace '\s+', ' ')
        $flag = ""
        if ($msg -match '800B0109') { $flag = "  <== CERT_E_UNTRUSTEDROOT => 403.16"; $bad++ }
        elseif ($msg -match '800B010A') { $flag = "  <== CERT_E_CHAINING => 403.16"; $bad++ }
        elseif ($msg -match '80092013|80092012') { $flag = "  <== revocation offline/unavailable => 403.13"; $bad++ }
        elseif ($msg -match '800B0101') { $flag = "  <== CERT_E_EXPIRED"; $bad++ }
        elseif ($msg -match '800B010C') { $flag = "  <== CERT_E_REVOKED (card revoked)"; $bad++ }
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + "..." }
        if ($flag -or $e.LevelDisplayName -eq "Error") {
            Add-Line ("  [{0:HH:mm:ss}] id={1} {2}{3}" -f $e.TimeCreated, $e.Id, $msg, $flag)
        }
    }

    if ($bad -gt 0) { Add-Finding "FAIL" "CAPI2 recorded $bad chain/revocation error(s) in the last $Minutes min" "Read the CAPI2 lines in section 6" }
    elseif ($events.Count -eq 0) { Add-Line "(no CAPI2 events in the window - reproduce PIN1 while the log is enabled)" }
}

# ---------------------------------------------------------------- Schannel
function Collect-Schannel {
    Add-Section "7. Schannel (System log) - TLS level, before IIS"
    $alerts = @{
        "40" = "handshake_failure"; "42" = "bad_certificate"; "43" = "unsupported_certificate"
        "44" = "certificate_revoked"; "45" = "certificate_expired"; "46" = "certificate_unknown"
        "48" = "unknown_ca (client cert issuer not trusted)"; "49" = "access_denied"
        "51" = "decrypt_error"; "70" = "protocol_version"; "116" = "certificate_required"
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Schannel"; StartTime = $since } -ErrorAction Stop)
    } catch {
        Add-Line "(no Schannel events in the window)"
        return
    }

    Add-Line ("events in window: " + $events.Count)
    foreach ($e in ($events | Select-Object -First 30)) {
        $msg = ($e.Message -replace '\s+', ' ')
        $note = ""
        if ($e.Id -eq 36887) {
            $code = ([regex]::Match($msg, 'alert.*?(\d+)')).Groups[1].Value
            if ($code -and $alerts.ContainsKey($code)) { $note = "  <== alert $code = " + $alerts[$code] }
        }
        if ($msg.Length -gt 180) { $msg = $msg.Substring(0, 180) + "..." }
        Add-Line ("  [{0:HH:mm:ss}] id={1} {2}{3}" -f $e.TimeCreated, $e.Id, $msg, $note)
        if ($e.Id -eq 36887 -and $note -match "unknown_ca|certificate_unknown") {
            Add-Finding "FAIL" "Schannel sent a TLS alert about the client certificate issuer" "Same fix as 403.16: install ESTEID intermediates into CA + ClientAuthIssuer"
        }
        if ($e.Id -eq 36874) {
            Add-Finding "WARN" "Schannel: client and server could not agree on a TLS version/cipher" "Do not disable TLS 1.2 while a .NET Framework 4.8 client is in use"
        }
    }
}

# ---------------------------------------------------------------- extra logs
function Add-Tail([string]$title, [string]$path, [int]$count = 30) {
    if (-not (Test-Path $path)) { return }
    Add-Line ""
    Add-Line ("### " + $title + "  (" + $path + ")")
    Get-Content $path -Tail $count -ErrorAction SilentlyContinue | ForEach-Object { Add-Line ("  " + $_) }
}

# CertProbe kirjutab iga katluse kohta pika raporti - siia korjame ainult verdiktid,
# muidu upub ulejaanud raport nende sisse. Taisraport on failis endas.
function Add-Verdicts([string]$title, [string]$path, [int]$count = 10) {
    if (-not (Test-Path $path)) { return }
    Add-Line ""
    Add-Line ("### " + $title + "  (" + $path + ")")
    # CertProbe kirjutab sona "VERDIKT" omale reale ja sisu jargmistele - votame need kaasa.
    $lines = @(Select-String -Path $path -Pattern "VERDIKT" -SimpleMatch -Context 0, 3 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $text = $_.Line.Trim()
            if ($text -notmatch '\S.*:\s*\S') {
                foreach ($after in $_.Context.PostContext) {
                    $trimmed = $after.Trim()
                    if ($trimmed -match '^[A-Z][A-Z ]{3,}$') { break }   # jargmine pealkiri, nt MIDA TEHA
                    if ($trimmed -and $trimmed -notmatch '^[=-]+$') { $text = $text + " " + $trimmed }
                }
            }
            $text
        })
    if ($lines.Count -eq 0) {
        Add-Line "  (no verdict lines yet - open https://demo.local:9444/ with the card)"
        return
    }
    $lines | Select-Object -Last $count | ForEach-Object { Add-Line ("  " + $_) }
    Add-Line ("  (full per-handshake report: " + $path + ")")
}

function Collect-AppLogs {
    Add-Section "8. APPLICATION SIDE (CertProbe, WCF service, client, load balancer)"
    Add-Verdicts "CertProbe (verdict per handshake)" (Join-Path $Root ".lab\certprobe.log") 10
    Add-Tail "WCF service log" (Join-Path $Root "src\Demo.Service\App_Data\service.log") 40
    Add-Verdicts "Client verdicts" (Join-Path $env:LOCALAPPDATA "IIS-ID\client.log") 6
    Add-Tail "Client log (detail)" (Join-Path $env:LOCALAPPDATA "IIS-ID\client.log") 30
    Add-Tail "Load balancer" (Join-Path $Root ".lab\lb.out.log") 20
    Add-Tail "Backend1" (Join-Path $Root ".lab\backend1.out.log") 10
    Add-Tail "Backend2" (Join-Path $Root ".lab\backend2.out.log") 10
}

# ---------------------------------------------------------------- run
Add-Line "IIS-ID single report: why did the client certificate login fail?"
Add-Line ("machine    : " + $env:COMPUTERNAME)
Add-Line ("user       : " + $env:USERNAME)
Add-Line ("generated  : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Add-Line ("window     : last $Minutes min (since " + $since.ToString("HH:mm:ss") + " local / " + $sinceUtc.ToString("HH:mm:ss") + " UTC)")
if ($ClientIp) { Add-Line ("client ip  : " + $ClientIp) }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
Add-Line ("elevated   : " + $admin)
if (-not $admin) { Add-Finding "WARN" "Not running as Administrator - netsh and some event logs stay hidden" "Re-run in an elevated PowerShell" }

Collect-Stores
Collect-HttpSys
Collect-WinHttp
Collect-Urls
Collect-CertVerify
Collect-IisLogs
Collect-HttpErr
Collect-Capi2
Collect-Schannel
Collect-AppLogs

Add-Section "9. HOW TO READ THE CODES"
Add-Line "403.7   cert never arrived    -> Negotiate Client Certificate off, or the LB terminated TLS"
Add-Line "403.16  cert arrived, chain untrusted on THIS machine -> Root / CA / ClientAuthIssuer"
Add-Line "403.13  chain fine, revocation failed -> OCSP/CRL network or WinHTTP proxy"
Add-Line "WCF 'client authentication scheme Anonymous' is a rewritten 403.x - always read sc-substatus"
Add-Line "PIN1 prompt appeared = the CLIENT crypto worked. Everything after that is this server."

# verdict on top
$verdict = @()
$verdict += ("=" * 78)
$verdict += "VERDICT"
$verdict += ("=" * 78)
$fails = @($script:findings | Where-Object { $_.Level -eq "FAIL" })
$warns = @($script:findings | Where-Object { $_.Level -eq "WARN" })
if ($fails.Count -eq 0 -and $warns.Count -eq 0) {
    $verdict += "No blocking problem found in the last $Minutes min on this machine."
    $verdict += "If the client still fails: reproduce PIN1 now, then run again with -Minutes 5,"
    $verdict += "and run Demo.CertProbe to test the actual card against this machine's stores."
}
foreach ($f in $fails) {
    $verdict += ("FAIL  " + $f.Text)
    if ($f.Fix) { $verdict += ("      fix: " + $f.Fix) }
}
foreach ($f in $warns) {
    $verdict += ("WARN  " + $f.Text)
    if ($f.Fix) { $verdict += ("      fix: " + $f.Fix) }
}
$verdict += ""
$verdict += "Sections below: 1 stores, 2 HTTP.sys, 3 WinHTTP, 3b outbound OCSP/CRL,"
$verdict += "3c certutil chain check, 4 IIS 403.x, 5 HTTPERR, 6 CAPI2, 7 Schannel,"
$verdict += "8 application logs, 9 code reference."
$verdict += ""

if (-not $OutDir) { $OutDir = Join-Path $Root ".lab" }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$file = Join-Path $OutDir ("eid-report-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".txt")
($verdict + $script:lines) | Set-Content -Path $file -Encoding UTF8

$verdict | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host ("Full report: " + $file)
Write-Host "Client-side proof (run on the IIS box, open with the card): Demo.CertProbe.exe --port 9444"
if ($Open) { Start-Process notepad.exe $file }
