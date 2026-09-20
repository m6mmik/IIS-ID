# Get-IdCardMatrix.ps1 - answers the README "Vordlusmaatriks" rows that only the
# RUNNING machine can answer. Read-only: no netsh add/update, no certutil -addstore.
# ASCII-only, Windows PowerShell 5.1, single file (safe to copy to a work VM).
#
# Split of work:
#   prompt 1 (repo)  Terraform / Ansible / .NET source     -> rows marked REPO
#   prompt 2 (VM)    THIS script output                    -> rows marked PASS/FAIL/WARN
#
# Usage (Administrator, on the IIS VM that received the handshake):
#   powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1
#   powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1 -NoNetwork
#   powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1 -Minutes 120 -OutDir C:\temp
#   powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1 -Compare \\share\idcard-matrix-APP11.txt
#
# Run it on EVERY app server, including the healthy ones: row 18 is the diff
# between two FINGERPRINT lines, and that diff is usually the whole answer.

param(
    [int]$Minutes = 120,
    [string]$OutDir,
    [int[]]$MtlsPorts = @(443, 8443, 8444),
    [switch]$NoNetwork,
    # Row 18/20: an earlier output file (healthy host, or this host before gpupdate).
    # Only its FINGERPRINT line is read; the diff is printed at the end.
    [string]$Compare
)

$ErrorActionPreference = "Continue"

$script:lines = @()
$script:rows = @()
$script:facts = @()

function Add-Line([string]$text = "") { $script:lines += $text }

function Add-Section([string]$title) {
    Add-Line ""
    Add-Line ("-" * 78)
    Add-Line $title
    Add-Line ("-" * 78)
}

# Verdict values:
#   PASS  this machine is fine on that row
#   FAIL  blocking: this alone explains a failed login
#   WARN  suspicious / depends on another layer
#   REPO  cannot be seen from a VM - belongs to prompt 1 (source code review)
#   DATA  needs a second host, or a reproduced login, to decide
function Add-Row([int]$id, [string]$question, [string]$verdict, [string]$answer, [string]$note = "") {
    # Last writer wins: a later, better-informed check replaces an early placeholder.
    $script:rows = @($script:rows | Where-Object { $_.Id -ne $id })
    $script:rows += [pscustomobject]@{
        Id = $id; Question = $question; Verdict = $verdict; Answer = $answer; Note = $note
    }
}

# Short key=value facts that make two machines comparable at a glance (row 18).
function Add-Fact([string]$key, [string]$value) {
    $script:facts += ($key + "=" + $value)
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

$script:IsAdmin = Test-Admin
$script:Appcmd = Join-Path $env:windir "system32\inetsrv\appcmd.exe"
$script:HasAppcmd = Test-Path $script:Appcmd

function Invoke-Appcmd([string[]]$appcmdArgs) {
    if (-not $script:HasAppcmd) { return "" }
    try { return (& $script:Appcmd @appcmdArgs 2>&1 | Out-String) } catch { return "" }
}

function Get-StoreSubjects([string]$name, [string]$pattern) {
    $path = "Cert:\LocalMachine\$name"
    if (-not (Test-Path $path)) { return @() }
    $certs = @(Get-ChildItem $path -ErrorAction SilentlyContinue)
    if ($pattern) { $certs = @($certs | Where-Object { $_.Subject -match $pattern }) }
    return $certs
}

# --------------------------------------------------------------- HTTP.sys parse
function Get-SslBindings {
    if (-not $script:IsAdmin) { return @() }
    $raw = netsh http show sslcert 2>$null | Out-String
    if (-not $raw) { return @() }

    $bindings = @()
    $current = $null
    foreach ($line in ($raw -split "`r?`n")) {
        # netsh pads keys into a column and the key itself may contain a colon.
        if ($line -notmatch '^\s*(\S.*?)\s+:\s*(.*)$') { continue }
        $key = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        if ($key -eq "IP:port" -or $key -eq "Hostname:port") {
            if ($current) { $bindings += $current }
            $current = [pscustomobject]@{
                Binding = $value; Hash = ""; Negotiate = ""; Revocation = ""
                CachedOnly = ""; CtlStore = ""; UsageCheck = ""; DisableAia = ""
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
            '^Disable Authority Info Access' { $current.DisableAia = $value }
        }
    }
    if ($current) { $bindings += $current }

    # Only mTLS-relevant rows: a dev box has dozens of Visual Studio bindings.
    $portPattern = ":(" + (($MtlsPorts | ForEach-Object { [string]$_ }) -join "|") + ")$"
    return @($bindings | Where-Object { $_.Negotiate -eq "Enabled" -or $_.Binding -match $portPattern })
}

# ------------------------------------------------------- deployed WCF Web.config
# The deployed file is the truth; the repo may be ahead of what is on this box.
function Get-WcfSites {
    $result = @()
    if (-not $script:HasAppcmd) { return $result }
    $raw = Invoke-Appcmd @("list", "vdir", "/text:*")
    $path = ""
    $phys = ""
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^\s*VDIR\.NAME:\s*(.+?)\s*$') { $path = $Matches[1] }
        if ($line -match '^\s*physicalPath:\s*"?(.+?)"?\s*$') {
            $phys = $Matches[1]
            if ($path -and $phys -and (Test-Path $phys)) {
                $cfg = Join-Path $phys "Web.config"
                $svc = @(Get-ChildItem $phys -Filter *.svc -ErrorAction SilentlyContinue)
                if ((Test-Path $cfg) -and $svc.Count -gt 0) {
                    $result += [pscustomobject]@{ VDir = $path; Path = $phys; Config = $cfg }
                }
            }
            $path = ""; $phys = ""
        }
    }
    return $result
}

function Read-WcfConfig([string]$file) {
    $info = [pscustomobject]@{
        File = $file; SecurityMode = ""; ClientCredential = ""
        EstablishSecurityContext = ""; ReliableSession = ""
        ValidationMode = ""; RevocationMode = ""; AllowLab = ""
        DefaultProxy = ""; ServiceLogPath = ""
    }
    if (-not (Test-Path $file)) { return $info }
    $text = ""
    try { $text = Get-Content $file -Raw -ErrorAction Stop } catch { return $info }

    if ($text -match '<security\s+mode\s*=\s*"([^"]+)"') { $info.SecurityMode = $Matches[1] }
    if ($text -match 'clientCredentialType\s*=\s*"([^"]+)"') { $info.ClientCredential = $Matches[1] }
    if ($text -match 'establishSecurityContext\s*=\s*"([^"]+)"') { $info.EstablishSecurityContext = $Matches[1] }
    elseif ($text -match '<secureConversation|<message\s') { $info.EstablishSecurityContext = "(default true)" }
    if ($text -match '<reliableSession[^>]*enabled\s*=\s*"([^"]+)"') { $info.ReliableSession = $Matches[1] }
    elseif ($text -match '<reliableSession') { $info.ReliableSession = "present" }
    if ($text -match 'certificateValidationMode\s*=\s*"([^"]+)"') { $info.ValidationMode = $Matches[1] }
    if ($text -match 'revocationMode\s*=\s*"([^"]+)"') { $info.RevocationMode = $Matches[1] }
    if ($text -match 'key\s*=\s*"AllowLabCertificates"\s+value\s*=\s*"([^"]+)"') { $info.AllowLab = $Matches[1] }
    if ($text -match 'key\s*=\s*"RevocationMode"\s+value\s*=\s*"([^"]+)"') {
        if (-not $info.RevocationMode) { $info.RevocationMode = $Matches[1] }
    }
    if ($text -match 'proxyaddress\s*=\s*"([^"]+)"') { $info.DefaultProxy = $Matches[1] }
    if ($text -match 'key\s*=\s*"serviceLogPath"\s+value\s*=\s*"([^"]+)"') { $info.ServiceLogPath = $Matches[1] }
    return $info
}

# ------------------------------------------------------------------- IIS W3C log
function Get-Iis403Rows([int]$minutes) {
    $result = [pscustomobject]@{ Rows = @(); Dirs = 0; Checked = 0 }
    $dirs = @()
    $inetpub = Join-Path $env:SystemDrive "inetpub\logs\LogFiles"
    if (Test-Path $inetpub) { $dirs += @(Get-ChildItem $inetpub -Directory -ErrorAction SilentlyContinue) }
    $express = Join-Path $env:USERPROFILE "Documents\IISExpress\Logs"
    if (Test-Path $express) { $dirs += @(Get-ChildItem $express -Directory -ErrorAction SilentlyContinue) }
    $result.Dirs = $dirs.Count

    $sinceUtc = (Get-Date).ToUniversalTime().AddMinutes(-$minutes)
    $rows = @()
    foreach ($dir in $dirs) {
        $files = @(Get-ChildItem (Join-Path $dir.FullName "*.log") -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-$minutes - 120) } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 2)
        foreach ($f in $files) {
            $result.Checked++
            $fields = @()
            foreach ($line in (Get-Content $f.FullName -ErrorAction SilentlyContinue)) {
                if ($line.StartsWith("#Fields:")) {
                    $fields = @(($line.Substring(8)).Trim() -split '\s+')
                    continue
                }
                if ($line.StartsWith("#")) { continue }
                if ($line -notmatch '\s403\s') { continue }
                $parts = @($line -split '\s+')
                $get = {
                    param($name)
                    $i = [array]::IndexOf($fields, $name)
                    if ($i -ge 0 -and $i -lt $parts.Count) { return $parts[$i] }
                    return ""
                }
                $d = & $get "date"
                $t = & $get "time"
                $stamp = $null
                if ($d -and $t) {
                    try { $stamp = [datetime]::Parse($d + " " + $t) } catch { $stamp = $null }
                }
                if ($stamp -and $stamp -lt $sinceUtc) { continue }
                $rows += [pscustomobject]@{
                    When      = ($d + " " + $t + " UTC")
                    Uri       = (& $get "cs-uri-stem")
                    Status    = (& $get "sc-status")
                    SubStatus = (& $get "sc-substatus")
                    Win32     = (& $get "sc-win32-status")
                    Site      = (& $get "s-sitename")
                    HasFields = ($fields -contains "sc-substatus" -and $fields -contains "sc-win32-status")
                    File      = $f.FullName
                }
            }
        }
    }
    $result.Rows = @($rows | Sort-Object When -Descending | Select-Object -First 15)
    return $result
}

function Get-Win32Meaning([string]$code) {
    switch ($code) {
        "2148204809" { return "0x800B0109 CERT_E_UNTRUSTEDROOT - trust (chain end not trusted HERE)" }
        "2148081683" { return "0x80092013 CRYPT_E_REVOCATION_OFFLINE - revocation could not be reached" }
        "2148204810" { return "0x800B010A CERT_E_CHAINING - intermediate missing, chain did not build" }
        "2148204801" { return "0x800B0101 CERT_E_EXPIRED - expired cert or machine clock" }
        "2148204812" { return "0x800B010C CERT_E_REVOKED - the card is revoked" }
        "0" { return "no win32 error" }
    }
    return ""
}

# =============================================================== rows 1,7 (config)
function Check-DeployedConfig {
    Add-Section "DEPLOYED WCF CONFIG (rows 1, 7, 6b) - the file on THIS box"
    $sites = Get-WcfSites
    if ($sites.Count -eq 0) {
        Add-Line "(no IIS application with both *.svc and Web.config found)"
        Add-Row 1 "Is the service stateless?" "REPO" "no deployed .svc app found on this host" "Answer from source: SessionMode, reliableSession, establishSecurityContext"
        Add-Row 7 "Trust strictness" "REPO" "no deployed Web.config found" ""
        Add-Fact "wcfsites" "0"
        return
    }
    Add-Fact "wcfsites" ([string]$sites.Count)

    $worst1 = "PASS"; $ans1 = @()
    $worst7 = "PASS"; $ans7 = @()
    foreach ($s in $sites) {
        $c = Read-WcfConfig $s.Config
        Add-Line ("vdir " + $s.VDir + "  ->  " + $s.Config)
        Add-Line ("  security mode          : " + $c.SecurityMode)
        Add-Line ("  clientCredentialType   : " + $c.ClientCredential)
        Add-Line ("  establishSecurityContext: " + $c.EstablishSecurityContext)
        Add-Line ("  reliableSession        : " + $c.ReliableSession)
        Add-Line ("  certificateValidationMode: " + $c.ValidationMode)
        Add-Line ("  revocationMode (app)   : " + $c.RevocationMode)
        Add-Line ("  AllowLabCertificates   : " + $c.AllowLab)
        Add-Line ("  defaultProxy proxyaddress: " + $c.DefaultProxy)
        Add-Line ("  serviceLogPath         : " + $c.ServiceLogPath)
        Add-Line ""

        # row 1: stateful WCF breaks failover
        $stateful = @()
        if ($c.SecurityMode -and $c.SecurityMode -ne "Transport") { $stateful += ("security mode=" + $c.SecurityMode) }
        if ($c.EstablishSecurityContext -match 'true|default') { $stateful += ("establishSecurityContext=" + $c.EstablishSecurityContext) }
        if ($c.ReliableSession -and $c.ReliableSession -ne "false") { $stateful += ("reliableSession=" + $c.ReliableSession) }
        if ($stateful.Count -gt 0) {
            $worst1 = "WARN"
            $ans1 += ($s.VDir + ": " + ($stateful -join ", "))
        } else {
            $ans1 += ($s.VDir + ": Transport, no session")
        }

        # row 7: lab shortcuts left in production
        $loose = @()
        if ($c.ValidationMode -eq "PeerOrChainTrust" -or $c.ValidationMode -eq "PeerTrust") { $loose += ("certificateValidationMode=" + $c.ValidationMode) }
        if ($c.AllowLab -eq "true") { $loose += "AllowLabCertificates=true" }
        if ($loose.Count -gt 0) {
            $worst7 = "WARN"
            $ans7 += ($s.VDir + ": " + ($loose -join ", "))
        } else {
            $ans7 += ($s.VDir + ": " + $c.ValidationMode + " / lab=" + $c.AllowLab)
        }

        $script:WcfProxy = $c.DefaultProxy
        $script:WcfAppRevocation = $c.RevocationMode
    }

    Add-Row 1 "Is the service stateless (failover possible)?" $worst1 ($ans1 -join " | ") "WARN here = failover is not possible without sticky sessions"
    Add-Row 7 "Trust strictness in the deployed config" $worst7 ($ans7 -join " | ") "Lab shortcuts in production are a finding, not a fix"
}

# ============================================================ rows 4, 15, 16
function Check-Trust {
    Add-Section "CERT STORES + SCHANNEL (rows 4, 15, 16) - decides 403.16"

    $rootGov = Get-StoreSubjects "Root" 'EE-GovCA2018|EEGovCA2025'
    $caEsteid = Get-StoreSubjects "CA" 'ESTEID2018|ESTEID2025|EID-SK'
    $issuerAll = Get-StoreSubjects "ClientAuthIssuer" $null
    $issuerEsteid = Get-StoreSubjects "ClientAuthIssuer" 'ESTEID2018|ESTEID2025|EID-SK'

    Add-Line ("Root  EE-GovCA2018/EEGovCA2025 : " + $rootGov.Count)
    foreach ($c in $rootGov) { Add-Line ("    " + $c.Subject) }
    Add-Line ("CA    ESTEID/EID-SK            : " + $caEsteid.Count)
    foreach ($c in $caEsteid) { Add-Line ("    " + $c.Subject) }
    Add-Line ("ClientAuthIssuer total/ESTEID  : " + $issuerAll.Count + " / " + $issuerEsteid.Count)
    foreach ($c in $issuerEsteid) { Add-Line ("    " + $c.Subject) }

    Add-Fact "rootGov" ([string]$rootGov.Count)
    Add-Fact "caEsteid" ([string]$caEsteid.Count)
    Add-Fact "issuerAll" ([string]$issuerAll.Count)
    Add-Fact "issuerEsteid" ([string]$issuerEsteid.Count)

    $v4 = "PASS"
    $miss = @()
    if ($rootGov.Count -le 0) { $v4 = "FAIL"; $miss += "Root has no EE-GovCA" }
    if ($caEsteid.Count -le 0) { $v4 = "FAIL"; $miss += "CA has no ESTEID" }
    if ($issuerEsteid.Count -le 0) { $miss += "ClientAuthIssuer has no ESTEID" ; if ($v4 -ne "FAIL") { $v4 = "WARN" } }
    $ans4 = ("Root=" + $rootGov.Count + " CA=" + $caEsteid.Count + " Issuer=" + $issuerAll.Count + "/" + $issuerEsteid.Count)
    if ($miss.Count -gt 0) { $ans4 = $ans4 + "  (" + ($miss -join "; ") + ")" }
    Add-Row 4 "Is the chain present on THIS host?" $v4 $ans4 "Compare with a healthy host (row 18) before changing anything"

    $schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    $props = Get-ItemProperty $schannel -ErrorAction SilentlyContinue
    $trustMode = $props.ClientAuthTrustMode
    $sendList = $props.SendTrustedIssuerList
    $trustText = "(unset = 0 Machine Trust)"
    if ($null -ne $trustMode) { $trustText = [string]$trustMode }
    $sendText = "(unset = 0)"
    if ($null -ne $sendList) { $sendText = [string]$sendList }
    Add-Line ""
    Add-Line ("SCHANNEL ClientAuthTrustMode   : " + $trustText)
    Add-Line ("SCHANNEL SendTrustedIssuerList : " + $sendText)
    Add-Fact "trustMode" $trustText
    Add-Fact "sendIssuerList" $sendText

    $v16 = "PASS"
    $note16 = ""
    if ($trustMode -eq 1) {
        $note16 = "Exclusive Root: the chain must END IN A ROOT in ClientAuthIssuer - an intermediate there is not enough"
        if (Get-StoreSubjects "ClientAuthIssuer" 'EE-GovCA2018|EEGovCA2025') { $v16 = "WARN" } else { $v16 = "FAIL" }
    } elseif ($trustMode -eq 2) {
        if ($issuerEsteid.Count -le 0) {
            $v16 = "WARN"
            $note16 = "Exclusive CA with no ESTEID in ClientAuthIssuer: 403.16 as soon as a CTL is also set"
        }
    }
    Add-Row 16 "ClientAuthTrustMode 0/1/2 vs issuer store" $v16 ("mode=" + $trustText + " issuerEsteid=" + $issuerEsteid.Count) $note16

    # row 15 needs the bindings, done in Check-HttpSys
    $script:IssuerEsteidCount = $issuerEsteid.Count
    $script:IssuerAllCount = $issuerAll.Count
}

# ==================================================== rows 5, 15, 17a, 13
function Check-HttpSys {
    Add-Section "HTTP.sys BINDINGS (rows 5, 13, 15, 17) - netsh http show sslcert"
    if (-not $script:IsAdmin) {
        Add-Line "(needs Administrator)"
        Add-Row 5 "Negotiate Client Certificate" "DATA" "not elevated" "Re-run in an elevated PowerShell"
        Add-Row 15 "CTL / Ctl Store Name" "DATA" "not elevated" ""
        Add-Row 17 "Revocation vs egress" "DATA" "not elevated" ""
        Add-Row 13 "Server cert name" "DATA" "not elevated" ""
        return
    }

    $bindings = Get-SslBindings
    if ($bindings.Count -eq 0) {
        Add-Line ("(no mTLS binding found on ports " + ($MtlsPorts -join ", ") + ")")
        Add-Row 5 "Negotiate Client Certificate" "FAIL" "no binding with client-cert negotiation" "Without this the card is never requested -> 403.7"
        Add-Row 15 "CTL / Ctl Store Name" "DATA" "no binding" ""
        Add-Row 17 "Revocation vs egress" "DATA" "no binding" ""
        Add-Row 13 "Server cert name" "DATA" "no binding" ""
        return
    }

    Add-Line ("{0,-22} {1,-10} {2,-11} {3,-11} {4,-11} {5}" -f "binding", "negotiate", "revocation", "usagecheck", "disableaia", "ctl store")
    foreach ($b in $bindings) {
        Add-Line ("{0,-22} {1,-10} {2,-11} {3,-11} {4,-11} {5}" -f $b.Binding, $b.Negotiate, $b.Revocation, $b.UsageCheck, $b.DisableAia, $b.CtlStore)
    }

    # ---- row 5
    $noNeg = @($bindings | Where-Object { $_.Negotiate -ne "Enabled" })
    $v5 = "PASS"
    if ($noNeg.Count -eq $bindings.Count) { $v5 = "FAIL" } elseif ($noNeg.Count -gt 0) { $v5 = "WARN" }
    Add-Row 5 "Negotiate Client Certificate" $v5 (($bindings | ForEach-Object { $_.Binding + "=" + $_.Negotiate }) -join " ") "Per IP:port. 0.0.0.0:443 and 10.x.x.x:443 are different rows"
    Add-Fact "negotiate" (($bindings | ForEach-Object { $_.Binding + ":" + $_.Negotiate }) -join ",")

    # ---- row 15 (CTL) - the APP12 symptom
    $withCtl = @($bindings | Where-Object { $_.CtlStore -and $_.CtlStore -ne "(null)" })
    $v15 = "PASS"
    $ans15 = "Ctl Store Name=(null) on all mTLS bindings"
    $note15 = ""
    if ($withCtl.Count -gt 0) {
        $ans15 = (($withCtl | ForEach-Object { $_.Binding + " ctl=" + $_.CtlStore }) -join " ")
        if ($script:IssuerEsteidCount -le 0) {
            $v15 = "FAIL"
            $note15 = "CTL is active but the store has no ESTEID issuer: every card gets 403.16 while Root/CA look perfect (lab experiment A)"
        } else {
            $v15 = "WARN"
            $note15 = "CTL is active; it currently contains ESTEID. Any GPO/baseline that rewrites that store turns every login into 403.16"
        }
    }
    Add-Row 15 "CTL: does Ctl Store Name filter the issuers?" $v15 $ans15 $note15
    Add-Fact "ctl" (($bindings | ForEach-Object { $_.Binding + ":" + $_.CtlStore }) -join ",")

    # ---- row 17a (revocation flag; network part in Check-Egress)
    $revOn = @($bindings | Where-Object { $_.Revocation -eq "Enabled" })
    $script:RevocationEnabled = ($revOn.Count -gt 0)
    $script:RevocationKnown = $true
    Add-Fact "revocation" (($bindings | ForEach-Object { $_.Binding + ":" + $_.Revocation }) -join ",")
    Add-Fact "disableaia" (($bindings | ForEach-Object { $_.Binding + ":" + $_.DisableAia }) -join ",")

    $cachedOnly = @($bindings | Where-Object { $_.CachedOnly -eq "Enabled" })
    if ($cachedOnly.Count -gt 0) {
        Add-Line ""
        Add-Line "NOTE verifyrevocationwithcachedclientcertonly=Enabled: a test can 'pass' from cache while real users get 403.13"
    }

    $aiaOff = @($bindings | Where-Object { $_.DisableAia -eq "Enabled" })
    if ($aiaOff.Count -gt 0 -and $script:IssuerEsteidCount -ge 0) {
        Add-Line "NOTE Disable Authority Info Access=Enabled: the local CA store must contain EVERY card generation in use"
    }

    # ---- row 13 server certificate identity (compare across hosts)
    $certInfo = @()
    foreach ($b in $bindings) {
        if (-not $b.Hash) { continue }
        $c = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $b.Hash.ToUpper() } | Select-Object -First 1
        if ($c) {
            $san = ""
            $ext = $c.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" } | Select-Object -First 1
            if ($ext) { $san = (($ext.Format($false)) -replace 'DNS Name=', '' -replace '\s+', '') }
            $certInfo += ($b.Binding + " CN=" + $c.GetNameInfo("SimpleName", $false) + " san=" + $san + " notAfter=" + $c.NotAfter.ToString("yyyy-MM-dd") + " thumb=" + $c.Thumbprint.Substring(0, 8))
        } else {
            $certInfo += ($b.Binding + " thumb=" + $b.Hash.Substring(0, 8) + " (not found in LocalMachine\My)")
        }
    }
    foreach ($line in $certInfo) { Add-Line ("  " + $line) }
    $v13 = "DATA"
    if ($certInfo.Count -gt 0) { $v13 = "PASS" }
    Add-Row 13 "Server cert name (passthrough: same CN/SAN everywhere)" $v13 ($certInfo -join " | ") "All app servers must present the SAME VIP name; compare this line between hosts"
    Add-Fact "serverCert" (($certInfo | ForEach-Object { ($_ -split ' ')[1] }) -join ",")
}

# ================================================================ rows 6, 17b, 12
function Check-Proxy {
    Add-Section "WinHTTP vs Web.config (rows 6, 17) - HTTP.sys uses WinHTTP only"
    $proxy = ""
    if ($script:IsAdmin) { $proxy = (netsh winhttp show proxy 2>$null | Out-String).Trim() }
    else { $proxy = "(needs Administrator)" }
    Add-Line $proxy
    $direct = ($proxy -match "Direct access")
    $winProxy = ""
    if ($proxy -match 'Proxy Server\(s\)\s*:\s*(\S+)') { $winProxy = $Matches[1] }
    Add-Fact "winhttp" $(if ($winProxy) { $winProxy } else { "direct" })

    Add-Line ""
    Add-Line ("Web.config defaultProxy : " + $(if ($script:WcfProxy) { $script:WcfProxy } else { "(none)" }))
    Add-Line "Reminder: Web.config <defaultProxy> does NOT affect the PIN1 handshake, chain or OCSP."

    $v6 = "PASS"
    $note6 = ""
    if ($script:WcfProxy -and $direct) {
        $v6 = "WARN"
        $note6 = "Web.config has a proxy but WinHTTP is Direct access: classic 'proxy is configured' that HTTP.sys never sees"
        if ($script:RevocationEnabled) {
            $v6 = "FAIL"
            $note6 = "Revocation is ENABLED, WinHTTP is Direct access and only Web.config has a proxy -> 403.13"
        }
    }
    Add-Row 6 "Is the proxy in BOTH places (WinHTTP + app)?" $v6 ("winhttp=" + $(if ($winProxy) { $winProxy } else { "direct" }) + " webconfig=" + $(if ($script:WcfProxy) { $script:WcfProxy } else { "none" })) $note6
}

function Check-Egress {
    Add-Section "OUTBOUND AIA / OCSP / CRL (rows 12, 17) - only matters when revocation is on"
    $urls = @(
        @{ Host = "aia.sk.ee"; Port = 80; Why = "ESTEID2018 / EE-GovCA2018 OCSP" }
        @{ Host = "c.sk.ee"; Port = 80; Why = "EE-GovCA2018 CRL" }
        @{ Host = "ocsp.eidpki.ee"; Port = 80; Why = "ESTEID2025 OCSP" }
        @{ Host = "crl.eidpki.ee"; Port = 80; Why = "EEGovCA2025 CRL" }
        @{ Host = "ocsp.sk.ee"; Port = 80; Why = "legacy SK OCSP" }
        @{ Host = "crt.eidpki.ee"; Port = 443; Why = "2025 CA files" }
    )
    if ($NoNetwork) {
        Add-Line "(skipped: -NoNetwork)"
        Add-Row 12 "Outbound OCSP/CRL reachable?" "DATA" "skipped (-NoNetwork)" ""
        if (-not $script:RevocationKnown) {
            Add-Row 17 "Revocation vs egress" "DATA" "binding flags unknown (not elevated / no binding)" "Re-run elevated: the revocation flag decides whether SK access matters at all"
        } elseif ($script:RevocationEnabled) {
            Add-Row 17 "Revocation vs egress" "DATA" "revocation=Enabled, network not tested" "Test before trusting this row"
        } else {
            Add-Row 17 "Revocation vs egress" "PASS" "revocation=Disabled on all mTLS bindings" "OCSP errors in the event log are NOISE on this box - they cannot cause 403.16"
        }
        return
    }

    $failed = 0
    foreach ($u in $urls) {
        $ok = $false
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($u.Host, $u.Port, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(3000, $false) -and $client.Connected
            $client.Close()
        } catch { $ok = $false }
        if (-not $ok) { $failed++ }
        $mark = "FAIL"
        if ($ok) { $mark = "OK  " }
        Add-Line ("  " + $mark + "  TCP " + $u.Host + ":" + $u.Port + "  " + $u.Why)
    }
    Add-Line "  (direct TCP test. Behind a proxy-only network these FAIL while revocation still works:"
    Add-Line "   the deciding test is 'certutil -verify -urlfetch <card.cer>', which uses WinHTTP.)"
    Add-Fact "egressFail" ([string]$failed)

    $v12 = "PASS"
    if ($failed -gt 0) { $v12 = "WARN" }
    Add-Row 12 "Outbound OCSP/CRL reachable (direct)?" $v12 ($failed.ToString() + " of " + $urls.Count + " hosts unreachable") "Chain/403.16 does NOT need these. Only revocation does."

    if (-not $script:RevocationKnown) {
        Add-Row 17 "Revocation vs egress" "DATA" ("binding flags unknown; " + $failed + " SK hosts unreachable directly") "Re-run elevated to read verifyclientcertrevocation"
        return
    }

    $v17 = "PASS"
    $ans17 = "revocation=Disabled"
    $note17 = "OCSP errors in the event log cannot cause 403.16 on this box"
    if ($script:RevocationEnabled) {
        $ans17 = "revocation=Enabled, unreachable=" + $failed
        if ($failed -gt 0) {
            $v17 = "FAIL"
            $note17 = "Revocation on + SK unreachable = 403.13 for every card. Either order egress/proxy, or turn revocation off until it exists"
        } else {
            $note17 = "Revocation on and SK reachable directly - confirm with certutil -verify -urlfetch too"
        }
    }
    Add-Row 17 "Revocation flag vs actual network" $v17 $ans17 $note17
}

# ==================================================================== rows 3, 19
function Check-IisConfig {
    Add-Section "IIS SITES / APP POOLS / MAPPING (rows 3, 19)"
    if (-not $script:HasAppcmd) {
        Add-Line "(appcmd.exe not found - not a full IIS box)"
        Add-Row 3 "Does health tell the truth (same app pool)?" "REPO" "no appcmd on this host" ""
        Add-Row 19 "Client certificate mapping off?" "REPO" "no appcmd on this host" ""
        return
    }

    $apps = Invoke-Appcmd @("list", "app")
    Add-Line "APPS"
    foreach ($line in ($apps -split "`r?`n")) { if ($line.Trim()) { Add-Line ("  " + $line.Trim()) } }

    # row 3: health endpoint and the .svc must share one app pool
    $pools = @{}
    foreach ($line in ($apps -split "`r?`n")) {
        if ($line -match 'APP\s+"([^"]+)"\s+\(applicationPool:([^)]+)\)') {
            $pools[$Matches[1]] = $Matches[2]
        }
    }
    $distinct = @($pools.Values | Sort-Object -Unique)
    $v3 = "DATA"
    $note3 = "Which URL does the load balancer check? If health runs in another app pool, a dead WCF pool still reports UP"
    $ans3 = (($pools.Keys | ForEach-Object { $_ + "->" + $pools[$_] }) -join " ")
    if ($pools.Count -eq 0) {
        $ans3 = "no IIS applications on this host"
    } elseif ($distinct.Count -eq 1) {
        $v3 = "PASS"
        $note3 = "One app pool serves everything on this host"
    } else {
        $v3 = "WARN"
    }
    Add-Row 3 "Does health tell the truth (same app pool)?" $v3 $ans3 $note3
    Add-Fact "appPools" (($distinct) -join ",")

    # row 19: certificate mapping must be off when identity comes from app code
    $map1 = Invoke-Appcmd @("list", "config", "/section:clientCertificateMappingAuthentication")
    $map2 = Invoke-Appcmd @("list", "config", "/section:iisClientCertificateMappingAuthentication")
    Add-Line ""
    Add-Line "clientCertificateMappingAuthentication:"
    foreach ($line in ($map1 -split "`r?`n")) { if ($line.Trim()) { Add-Line ("  " + $line.Trim()) } }
    Add-Line "iisClientCertificateMappingAuthentication:"
    foreach ($line in ($map2 -split "`r?`n")) { if ($line.Trim()) { Add-Line ("  " + $line.Trim()) } }

    $on1 = ($map1 -match 'enabled\s*=\s*"true"')
    $on2 = ($map2 -match 'enabled\s*=\s*"true"')
    $v19 = "PASS"
    $ans19 = "both disabled"
    if ($on1 -or $on2) {
        $v19 = "WARN"
        $ans19 = "clientCertMapping=" + $on1 + " iisClientCertMapping=" + $on2
    }
    Add-Row 19 "Client certificate mapping / NTAuth off?" $v19 $ans19 "Mapping enabled without a rule returns 403 even when the chain is fine"
    Add-Fact "certMapping" ($ans19 -replace '\s+', '')

    # sslFlags per app (403.7 vs 403.16 boundary, and ClickOnce install path)
    Add-Line ""
    Add-Line "SSL FLAGS per application path:"
    foreach ($app in ($pools.Keys | Sort-Object)) {
        $cfg = Invoke-Appcmd @("list", "config", $app.TrimStart("/"), "/section:access")
        $flags = ""
        if ($cfg -match 'sslFlags\s*=\s*"([^"]*)"') { $flags = $Matches[1] }
        Add-Line ("  " + $app + " sslFlags=" + $flags)
    }
}

# ======================================================================= row 10
function Check-Tls {
    Add-Section "TLS PROTOCOLS (row 10) - Schannel registry"
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    $names = @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
    $state = @()
    foreach ($n in $names) {
        foreach ($side in @("Server", "Client")) {
            $p = Join-Path (Join-Path $base $n) $side
            if (-not (Test-Path $p)) { continue }
            $pp = Get-ItemProperty $p -ErrorAction SilentlyContinue
            $enabled = $pp.Enabled
            $disabled = $pp.DisabledByDefault
            $txt = $n + "/" + $side + " Enabled=" + $(if ($null -ne $enabled) { $enabled } else { "unset" }) +
                   " DisabledByDefault=" + $(if ($null -ne $disabled) { $disabled } else { "unset" })
            Add-Line ("  " + $txt)
            $state += $txt
        }
    }
    if ($state.Count -eq 0) { Add-Line "  (no explicit protocol keys - Windows defaults apply)" }

    $tls12Server = Join-Path (Join-Path $base "TLS 1.2") "Server"
    $v10 = "PASS"
    $ans10 = "TLS 1.2 not explicitly disabled"
    $note10 = ".NET Framework 4.8 WCF clients speak TLS 1.2 in practice"
    if (Test-Path $tls12Server) {
        $pp = Get-ItemProperty $tls12Server -ErrorAction SilentlyContinue
        if ($pp.Enabled -eq 0) {
            $v10 = "FAIL"
            $ans10 = "TLS 1.2 Server Enabled=0"
            $note10 = "A .NET 4.8 client cannot connect at all - this is a handshake failure, not a 403"
        }
    }
    Add-Row 10 "TLS versions allow the .NET 4.8 client?" $v10 $ans10 $note10
    $tlsFact = "default"
    if ($v10 -eq "FAIL") { $tlsFact = "server-disabled" }
    Add-Fact "tls12" $tlsFact
}

# ======================================================================= row 14
function Check-Evidence {
    Add-Section ("IIS 403 EVIDENCE (row 14) - last " + $Minutes + " min, timestamps are UTC")
    $res = Get-Iis403Rows $Minutes
    Add-Line ("log dirs: " + $res.Dirs + "   files parsed: " + $res.Checked)

    if ($res.Rows.Count -eq 0) {
        Add-Line "(no 403 rows in the window. IIS buffers up to ~60 s; reproduce one login and re-run.)"
        Add-Row 14 "What is the real substatus + win32?" "DATA" "no 403 rows in the last $Minutes min" "Reproduce ONE failed login, then re-run. Without this number every next step is a guess"
        Add-Fact "last403" "none"
        return
    }

    $missingFields = @($res.Rows | Where-Object { -not $_.HasFields })
    Add-Line ""
    Add-Line ("{0,-24} {1,-28} {2,-5} {3,-4} {4}" -f "when(UTC)", "uri", "stat", "sub", "win32")
    foreach ($r in $res.Rows) {
        Add-Line ("{0,-24} {1,-28} {2,-5} {3,-4} {4}" -f $r.When, $r.Uri, $r.Status, $r.SubStatus, $r.Win32)
    }
    Add-Line ""
    foreach ($code in (@($res.Rows | ForEach-Object { $_.Win32 }) | Sort-Object -Unique)) {
        $meaning = Get-Win32Meaning $code
        if ($meaning) { Add-Line ("  " + $code + " = " + $meaning) }
    }
    Add-Line ("  log file: " + $res.Rows[0].File)

    if ($missingFields.Count -gt 0) {
        Add-Row 14 "What is the real substatus + win32?" "FAIL" "W3C fields sc-substatus / sc-win32-status are NOT logged" "You are blind on purpose: add both fields to the site logging, reproduce, re-run"
        Add-Fact "last403" "no-substatus-field"
        return
    }

    # 403.4 (HTTPS required) and 403.14 are noise here; the mTLS story is 7/13/16.
    $newest = @($res.Rows | Where-Object { @("7", "13", "16") -contains $_.SubStatus }) | Select-Object -First 1
    if (-not $newest) {
        $other = $res.Rows[0]
        Add-Row 14 "What is the real substatus + win32?" "DATA" ("newest 403 is 403." + $other.SubStatus + " win32=" + $other.Win32 + " uri=" + $other.Uri) "No 403.7/13/16 in the window: this host has not rejected a client certificate lately. Reproduce the failing login on THIS host (LB may have sent it elsewhere)"
        Add-Fact "last403" ("403." + $other.SubStatus + "/nonmtls")
        return
    }

    $verdict = "WARN"
    $note = ""
    if ($newest.SubStatus -eq "16") {
        $note = "TRUST layer. Go to rows 15, 16, 4 (CTL / TrustMode / stores) and compare with a healthy host (18)"
    } elseif ($newest.SubStatus -eq "13") {
        $note = "REVOCATION layer. Go to rows 17, 6, 12 (revocation flag / WinHTTP / egress)"
    } elseif ($newest.SubStatus -eq "7") {
        $note = "The cert never arrived. Rows 5 (Negotiate) and 2 (LB terminating TLS)"
    } else {
        $note = "Not a client-certificate substatus"
    }
    Add-Row 14 "What is the real substatus + win32?" $verdict ("403." + $newest.SubStatus + " win32=" + $newest.Win32 + " uri=" + $newest.Uri) $note
    Add-Fact "last403" ("403." + $newest.SubStatus + "/" + $newest.Win32)
}

# =================================================================== rows 18, 20
function Check-Fingerprint {
    Add-Section "FINGERPRINT (rows 18, 20) - diff this line between hosts and after gpupdate"
    Add-Line "Row 18: run this script on a HEALTHY app server too and diff the line below."
    Add-Line "Row 20: save it, run 'gpupdate /force', run this script again and diff."
    Add-Line ""
    Add-Line ("HOST " + $env:COMPUTERNAME)
    Add-Line ("FINGERPRINT " + ($script:facts -join " "))
    Add-Row 18 "Are the app servers identical to each other?" "DATA" "fingerprint written" "One machine failing = that machine's knob. Diff fingerprints, do not compare against the lab"
    Add-Row 20 "Does GPO / CIS baseline revert the settings?" "DATA" "fingerprint written" "Re-run after gpupdate /force; Schannel keys and ClientAuthIssuer must not change"

    if (-not $Compare) { return }
    Add-Line ""
    if (-not (Test-Path $Compare)) {
        Add-Line ("(-Compare file not found: " + $Compare + ")")
        return
    }

    $otherHost = "(unknown)"
    $otherFacts = @{}
    foreach ($line in (Get-Content $Compare -ErrorAction SilentlyContinue)) {
        if ($line -match '^HOST\s+(\S+)') { $otherHost = $Matches[1] }
        if ($line -match '^FINGERPRINT\s+(.+)$') {
            foreach ($pair in ($Matches[1] -split ' (?=[A-Za-z0-9]+=)')) {
                $i = $pair.IndexOf("=")
                if ($i -gt 0) { $otherFacts[$pair.Substring(0, $i)] = $pair.Substring($i + 1) }
            }
        }
    }
    if ($otherFacts.Count -eq 0) {
        Add-Line ("(no FINGERPRINT line in " + $Compare + ")")
        return
    }

    $mine = @{}
    foreach ($f in $script:facts) {
        $i = $f.IndexOf("=")
        if ($i -gt 0) { $mine[$f.Substring(0, $i)] = $f.Substring($i + 1) }
    }

    Add-Line ("DIFF against " + $otherHost + "  (" + $Compare + ")")
    $keys = @(($mine.Keys + $otherFacts.Keys) | Sort-Object -Unique)
    $diffs = @()
    foreach ($k in $keys) {
        $a = "(absent)"
        $b = "(absent)"
        if ($mine.ContainsKey($k)) { $a = $mine[$k] }
        if ($otherFacts.ContainsKey($k)) { $b = $otherFacts[$k] }
        if ($a -eq $b) { continue }
        if ($k -eq "last403") { continue }   # differs by definition: one host is the broken one
        $diffs += ($k + ":  this=" + $a + "   " + $otherHost + "=" + $b)
    }
    if ($diffs.Count -eq 0) {
        Add-Line "  identical (except last403). The difference is then NOT in these knobs:"
        Add-Line "  look at the load balancer, the card itself, or which host the LB actually used."
        Add-Row 18 "Are the app servers identical to each other?" "PASS" ("identical to " + $otherHost) "Same knobs on both: stop tuning Windows, the difference is elsewhere"
        return
    }

    foreach ($d in $diffs) { Add-Line ("  " + $d) }
    $keysChanged = @($diffs | ForEach-Object { ($_ -split ':')[0] })
    Add-Row 18 "Are the app servers identical to each other?" "WARN" ($diffs.Count.ToString() + " difference(s) vs " + $otherHost + ": " + ($keysChanged -join ", ")) "Each one is a candidate cause - see the DIFF block. Fix ONE, re-run, diff again"
}

# ================================================================== repo-only rows
function Add-RepoRows {
    Add-Row 2  "Is HAProxy really passthrough?" "REPO" "not visible from the VM" "haproxy.cfg BOTH layers: mode tcp, no 'ssl' on server lines. Hint: if this box ever logged 403.16 or 200 with a client cert, passthrough already works"
    Add-Row 8  "Policy OID check" "REPO" "application source" "X509ChainPolicy.CertificatePolicy, not text parsing of the extension"
    Add-Row 9  "Does the client rebuild the channel?" "REPO" "client source" "Retry + drop pooled connections, or users see random errors on healthy servers"
    Add-Row 11 "What is 'signature'?" "REPO" "application source" "Nonce, chain, timestamp, container - or it is only proof of possession"
}

# ============================================================================ run
Add-Line "IIS-ID matrix collector (read-only). Answers the VM-side rows of the README comparison matrix."
Add-Line ("machine   : " + $env:COMPUTERNAME)
Add-Line ("user      : " + $env:USERNAME)
Add-Line ("generated : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Add-Line ("elevated  : " + $script:IsAdmin)
Add-Line ("full IIS  : " + $script:HasAppcmd)
Add-Line ("window    : last " + $Minutes + " min   mTLS ports: " + ($MtlsPorts -join ", "))
if (-not $script:IsAdmin) { Add-Line "WARNING not elevated: netsh and parts of the event log stay hidden" }

$script:WcfProxy = ""
$script:WcfAppRevocation = ""
$script:RevocationEnabled = $false
$script:RevocationKnown = $false
$script:CompareResult = ""
$script:IssuerEsteidCount = 0
$script:IssuerAllCount = 0

Check-DeployedConfig
Check-Trust
Check-HttpSys
Check-Proxy
Check-Egress
Check-IisConfig
Check-Tls
Check-Evidence
Check-Fingerprint
Add-RepoRows

# ---------------------------------------------------------------- summary on top
$summary = @()
$summary += ("=" * 78)
$summary += ("MATRIX ANSWERS - " + $env:COMPUTERNAME + " - " + (Get-Date).ToString("yyyy-MM-dd HH:mm"))
$summary += ("=" * 78)
$summary += "PASS ok here | FAIL blocking | WARN depends | DATA need more input | REPO source review"
$summary += ""
$summary += ("{0,-4} {1,-6} {2}" -f "row", "state", "answer")
foreach ($r in ($script:rows | Sort-Object Id)) {
    $summary += ("{0,-4} {1,-6} {2}" -f $r.Id, $r.Verdict, $r.Answer)
    if ($r.Note) { $summary += ("          note: " + $r.Note) }
}
$summary += ""

$fails = @($script:rows | Where-Object { $_.Verdict -eq "FAIL" })
$warns = @($script:rows | Where-Object { $_.Verdict -eq "WARN" })
if ($fails.Count -gt 0) {
    $summary += "BLOCKING ON THIS HOST:"
    foreach ($r in $fails) { $summary += ("  row " + $r.Id + "  " + $r.Question + " -> " + $r.Answer) }
} else {
    $summary += "No blocking row found on this host. Next: diff the FINGERPRINT against a healthy server (row 18),"
    $summary += "and make sure row 14 has a real 403 line (reproduce one login if it says DATA)."
}
if ($warns.Count -gt 0) {
    $summary += ""
    $summary += "WORTH A LOOK:"
    foreach ($r in $warns) { $summary += ("  row " + $r.Id + "  " + $r.Answer) }
}

# Cross-checks: two rows that contradict each other say more than either row alone.
$cross = @()
$last403 = [string](@($script:facts | Where-Object { $_ -like "last403=*" }) | Select-Object -First 1)
$sub = ""
if ($last403 -match '^last403=403\.(\d+)') { $sub = $Matches[1] }

if ($sub -eq "13" -and -not $script:RevocationEnabled) {
    $cross += "Log says 403.13 but revocation is currently Disabled on every mTLS binding. Either someone"
    $cross += "already changed the binding after that request, or that row came from a different config."
    $cross += "Reproduce ONE login now and re-run before touching anything else."
}
if ($sub -eq "13" -and $script:RevocationEnabled) {
    $cross += "403.13 + revocation Enabled: this is the revocation layer, not trust. Do NOT add certificates."
    $cross += "Either give this host OCSP/CRL access (WinHTTP proxy or direct 80), or turn revocation off."
}
if ($sub -eq "16") {
    $cross += "403.16 is the TRUST layer: stores, CTL and ClientAuthTrustMode on THIS host - never the network."
    if ($script:IssuerEsteidCount -le 0) {
        $cross += "ClientAuthIssuer has no ESTEID here, which is enough to explain it."
    } else {
        $cross += "Stores look sane, so compare the FINGERPRINT with a healthy host (row 18) and check the CTL (row 15)."
    }
}
if ($sub -eq "7") {
    $cross += "403.7: no certificate arrived. Check Negotiate (row 5) on the exact IP:port, and whether the"
    $cross += "load balancer terminated TLS instead of passing it through (row 2, repo prompt)."
}
if ($cross.Count -gt 0) {
    $summary += ""
    $summary += "CROSS-CHECKS:"
    foreach ($c in $cross) { $summary += ("  " + $c) }
}
$summary += ""
$summary += "Change ONE thing at a time, then re-run this script and diff. Rows marked REPO go to the"
$summary += "source-code prompt (Terraform / Ansible / .NET), not to this machine."
$summary += ""

if (-not $OutDir) { $OutDir = $env:TEMP }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$file = Join-Path $OutDir ("idcard-matrix-" + $env:COMPUTERNAME + "-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".txt")
($summary + $script:lines) | Set-Content -Path $file -Encoding UTF8

$summary | ForEach-Object { Write-Host $_ }
Write-Host ("Full output: " + $file)
Write-Host "Mask personal identification codes before sharing this file."
