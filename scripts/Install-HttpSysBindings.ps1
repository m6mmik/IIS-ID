# Trust lab CA, install server cert into LocalMachine\My, bind HTTP.sys, hosts, urlacl.
# Must run as Administrator:  powershell -File scripts\Install-HttpSysBindings.ps1
#
# 403.16 = HTTP.sys ei usalda kliendisertifikaati. IIS 8+ kasutab vaikimisi
# "Client Authentication Issuers" hoidlat; kui see on tühi, lükatakse kõik
# kliendisertifikaadid tagasi.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root "certs"
$ThumbFile = Join-Path $Out "server.thumbprint"
$Pfx = Join-Path $Out "lab-server.pfx"
$Ca = Join-Path $Out "lab-root.cer"
$AppId = "{a7c1d0e5-4b8f-4a2e-9c31-11e1d0000001}"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "See skript vajab Administrator PowerShelli."
}

if (-not (Test-Path $Pfx) -or -not (Test-Path $Ca) -or -not (Test-Path $ThumbFile)) {
    throw "Sertifikaate pole. Käivita esmalt: .\lab.ps1 certs"
}

function Import-CertToStores([string]$file) {
    if (-not (Test-Path $file)) { return }
    foreach ($store in @("Root", "CA", "ClientAuthIssuer")) {
        & certutil -f -addstore $store $file | Out-Null
    }
    Write-Host "Trusted: $file"
}

Import-CertToStores $Ca
Get-ChildItem (Join-Path $Out "eid-ca") -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '\.(crt|cer)$' } |
    ForEach-Object { Import-CertToStores $_.FullName }

$password = ConvertTo-SecureString "lab" -AsPlainText -Force
Import-Certificate -FilePath $Ca -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
Import-PfxCertificate -FilePath $Pfx -CertStoreLocation Cert:\LocalMachine\My -Password $password | Out-Null

$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
if (-not (Test-Path $schannel)) { New-Item -Path $schannel -Force | Out-Null }
New-ItemProperty -Path $schannel -Name ClientAuthTrustMode -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $schannel -Name SendTrustedIssuerList -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "SCHANNEL ClientAuthTrustMode=2 (usalda LocalMachine\Root ahelaid)"

$thumb = (Get-Content $ThumbFile -Raw).Trim()
Write-Host "Server thumbprint $thumb"

function Remove-SslCert([string]$ipPort) {
    & netsh http delete sslcert ipport=$ipPort | Out-Null
}

function Add-SslCert([string]$ipPort) {
    Remove-SslCert $ipPort
    # Lab: ära nõua OCSP-d. ID-kaardi tühistuseks muuda verifyclientcertrevocation=enable.
    $out = & netsh http add sslcert ipport=$ipPort certhash=$thumb appid=$AppId certstorename=MY clientcertnegotiation=enable verifyclientcertrevocation=disable
    Write-Host $out
}

Add-SslCert "127.0.0.1:8443"
Add-SslCert "127.0.0.1:8444"

function Add-UrlAcl([string]$url) {
    & netsh http delete urlacl url=$url 2>$null | Out-Null
    $user = "$env:USERDOMAIN\$env:USERNAME"
    if ([string]::IsNullOrWhiteSpace($env:USERDOMAIN)) { $user = $env:USERNAME }
    $out = & netsh http add urlacl url=$url user=$user
    Write-Host $out
}

Add-UrlAcl "https://127.0.0.1:8443/"
Add-UrlAcl "https://127.0.0.1:8444/"
Add-UrlAcl "http://127.0.0.1:8080/"
Add-UrlAcl "http://127.0.0.1:8081/"
Add-UrlAcl "http://127.0.0.1:8404/"
Add-UrlAcl "http://127.0.0.1:9443/"

$hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$line = "127.0.0.1 demo.local"
$existing = Get-Content $hosts -ErrorAction Stop
if ($existing -notcontains $line) {
    Add-Content -Path $hosts -Value "`r`n$line"
    Write-Host "Lisatud hosts: $line"
} else {
    Write-Host "hosts juba sisaldab demo.local"
}

Write-Host ""
Write-Host "HTTP.sys clientcertnegotiation=enable, revocation=disable."
Write-Host "Kui tegid .\lab.ps1 certs UUESTI, peab bind olema samuti uuesti (uus CA)."
Write-Host "ID-kaart: .\lab.ps1 eid-ca  ja siis uuesti  .\lab.ps1 bind"
Write-Host "Kontroll: netsh http show sslcert 127.0.0.1:8443"
