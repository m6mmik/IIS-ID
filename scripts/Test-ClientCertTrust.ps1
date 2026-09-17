# Diagnoses IIS 403.16 (client certificate untrusted).
# ASCII-only on purpose: Windows PowerShell 5.1 breaks UTF-8 scripts without BOM.
# Usage:  powershell -File scripts\Test-ClientCertTrust.ps1

param(
    [string]$Thumbprint
)

$ErrorActionPreference = "Continue"

function Get-StoreCerts([string]$path) {
    if (-not (Test-Path $path)) { return @() }
    @(Get-ChildItem $path -ErrorAction SilentlyContinue)
}

function Test-Name($certs, $pattern) {
    @($certs | Where-Object { $_.Subject -match $pattern -or $_.Issuer -match $pattern }).Count
}

Write-Host "=== 403.16 diagnostika (HTTP.sys ei usalda kliendisertifikaati) ==="
Write-Host "403.16 ei ole PIN ega WCF jarjekorra viga. Handshake joudab kohale, ahel ei ole serveri jaoks usaldusvaarne."
Write-Host ""

$roots = Get-StoreCerts Cert:\LocalMachine\Root
$inter = Get-StoreCerts Cert:\LocalMachine\CA
$issuers = Get-StoreCerts Cert:\LocalMachine\ClientAuthIssuer

Write-Host "LocalMachine\Root ESTEID/EE-Gov:    $(Test-Name $roots 'EE-Gov|EEGov|ESTEID|IIS-ID Home Lab')"
Write-Host "LocalMachine\CA ESTEID/EE-Gov:      $(Test-Name $inter 'EE-Gov|EEGov|ESTEID|IIS-ID Home Lab')"
Write-Host "ClientAuthIssuer ESTEID/EE-Gov/lab: $(Test-Name $issuers 'EE-Gov|EEGov|ESTEID|IIS-ID Home Lab')"
Write-Host ""

if ($issuers.Count -eq 0) {
    Write-Host "PROBLEEM: Client Authentication Issuers hoidla on TYHI."
    Write-Host "IIS 8+ / Windows 10/11/Server: tyhi hoidla -> KOIK kliendisertifikaadid = 403.16."
    Write-Host "Tootmine: pane siia ESTEID2018 ja ESTEID2025 (vahepealsed, mitte ainult juur)."
    Write-Host "  certutil -addstore -f ClientAuthIssuer esteid2018.der.crt"
    Write-Host "  certutil -addstore -f ClientAuthIssuer ESTEID2025.crt"
    Write-Host ""
}

$mode = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -ErrorAction SilentlyContinue).ClientAuthTrustMode
$send = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -ErrorAction SilentlyContinue).SendTrustedIssuerList
Write-Host "SCHANNEL ClientAuthTrustMode  = $mode   (kodu lab soovitus: 2; toodangus pigem CTL + taidetud ClientAuthIssuer)"
Write-Host "SCHANNEL SendTrustedIssuerList = $send"
Write-Host ""

Write-Host "HTTP.sys SSL (443/8443/8444):"
netsh http show sslcert | Select-String -Pattern "IP:port|Certificate Hash|Negotiate Client Certificate|Verify Client Certificate Revocation|Ctl Store Name"
Write-Host ""

$personal = Get-StoreCerts Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
if ($Thumbprint) {
    $personal = $personal | Where-Object { $_.Thumbprint -eq $Thumbprint }
}

$auth = $personal | Where-Object {
    $_.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" -and $_.Format($false) -match "1.3.6.1.5.5.7.3.2|Client Authentication" }
}

Write-Host "Praeguse kasutaja PIN1 (clientAuth) sertifikaadid: $($auth.Count)"
foreach ($cert in $auth) {
    Write-Host ""
    Write-Host "--- $($cert.Subject)"
    Write-Host "    Issuer      $($cert.Issuer)"
    Write-Host "    Thumbprint  $($cert.Thumbprint)"
    Write-Host "    NotAfter    $($cert.NotAfter)"

    $issuerCn = ($cert.Issuer -split ",")[0]
    $inRoot = $roots | Where-Object { $_.Subject -eq $cert.Issuer -or $_.Subject -match [regex]::Escape($issuerCn) }
    $inCa = $inter | Where-Object { $_.Subject -eq $cert.Issuer -or $_.Subject -match [regex]::Escape($issuerCn) }
    $inIssuers = $issuers | Where-Object { $_.Subject -eq $cert.Issuer -or $_.Subject -match [regex]::Escape($issuerCn) }

    if ($inCa -or $inRoot) { Write-Host "    Issuer masina CA/Root hoidlas: JAH" }
    else { Write-Host "    Issuer masina CA/Root hoidlas: EI  <- 403.16 toenaoline pohjus" }
    if ($inIssuers) { Write-Host "    Issuer ClientAuthIssuer hoidlas: JAH" }
    else { Write-Host "    Issuer ClientAuthIssuer hoidlas: EI  <- IIS 8+ 403.16, kui CTL on kasutusel voi hoidla tyhi" }

    $tmp = Join-Path $env:TEMP ("eid-" + $cert.Thumbprint + ".cer")
    Export-Certificate -Cert $cert -FilePath $tmp | Out-Null
    Write-Host "    certutil -verify (chain + AIA):"
    certutil -verify -urlfetch $tmp | Select-String -Pattern "ERROR|FAILED|Chain|Leaf|AIA|OCSP|CRL|Verified|CERT_" | ForEach-Object { Write-Host "      $_" }
}

Write-Host ""
Write-Host "Toodangu 4 IIS serverit: need kontrollid peavad olema identsed KOIGIL."
Write-Host "Yks server Root-iga ja teine ilma = vahel 403.16."
Write-Host "Ara aja 403.16 sassi 403.13-ga (403.13 = tyhistus/OCSP). 403.16 = usaldus/ahel."
