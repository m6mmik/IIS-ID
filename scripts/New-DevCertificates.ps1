# Lab CA, server TLS cert, PIN1 auth cert, PIN2 signing cert.
# Run from repo root:  powershell -File scripts\New-DevCertificates.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root "certs"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Get-BySubject([string]$store, [string]$subject) {
    Get-ChildItem $store | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
}

function Remove-BySubject([string]$store, [string]$subject) {
    Get-ChildItem $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $subject } |
        ForEach-Object { Remove-Item $_.PSPath -DeleteKey -ErrorAction SilentlyContinue }
}

$caSubject = "CN=IIS-ID Home Lab Root, O=IIS-ID Home Lab, C=EE"
$serverSubject = "CN=demo.local, O=IIS-ID Home Lab, C=EE"
$authSubject = "CN=LAB USER AUTH, SERIALNUMBER=PNOEE-39001010000, O=IIS-ID Home Lab, C=EE"
$signSubject = "CN=LAB USER SIGN, SERIALNUMBER=PNOEE-39001010000, O=IIS-ID Home Lab, C=EE"

Remove-BySubject Cert:\CurrentUser\My $caSubject
Remove-BySubject Cert:\CurrentUser\My $serverSubject
Remove-BySubject Cert:\CurrentUser\My $authSubject
Remove-BySubject Cert:\CurrentUser\My $signSubject

Write-Host "Creating lab CA..."
$ca = New-SelfSignedCertificate `
    -Subject $caSubject `
    -FriendlyName "IIS-ID Home Lab Root" `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -KeyExportPolicy Exportable `
    -KeyLength 384 `
    -KeyAlgorithm ECDSA_nistP384 `
    -HashAlgorithm SHA384 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type Custom `
    -TextExtension @("2.5.29.19={critical}{text}ca=1&pathlength=1") `
    -NotAfter (Get-Date).AddYears(10)

Write-Host "Creating server certificate..."
$server = New-SelfSignedCertificate `
    -Subject $serverSubject `
    -FriendlyName "IIS-ID demo.local" `
    -Signer $ca `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -KeyLength 384 `
    -KeyAlgorithm ECDSA_nistP384 `
    -HashAlgorithm SHA384 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type Custom `
    -TextExtension @(
        "2.5.29.37={text}1.3.6.1.5.5.7.3.1",
        "2.5.29.17={text}DNS=demo.local&DNS=localhost&IPAddress=127.0.0.1"
    ) `
    -NotAfter (Get-Date).AddYears(3)

Write-Host "Creating PIN1 (client auth) certificate..."
$auth = New-SelfSignedCertificate `
    -Subject $authSubject `
    -FriendlyName "IIS-ID lab PIN1 auth" `
    -Signer $ca `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -KeyLength 384 `
    -KeyAlgorithm ECDSA_nistP384 `
    -HashAlgorithm SHA384 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type Custom `
    -TextExtension @(
        "2.5.29.37={text}1.3.6.1.5.5.7.3.2",
        "2.5.29.32={text}OID=0.4.0.2042.1.2"
    ) `
    -NotAfter (Get-Date).AddYears(3)

Write-Host "Creating PIN2 (non-repudiation) certificate..."
$sign = New-SelfSignedCertificate `
    -Subject $signSubject `
    -FriendlyName "IIS-ID lab PIN2 sign" `
    -Signer $ca `
    -KeyUsage NonRepudiation, DigitalSignature `
    -KeyExportPolicy Exportable `
    -KeyLength 384 `
    -KeyAlgorithm ECDSA_nistP384 `
    -HashAlgorithm SHA384 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type Custom `
    -TextExtension @(
        "2.5.29.32={text}OID=0.4.0.2042.1.2"
    ) `
    -NotAfter (Get-Date).AddYears(3)

$password = ConvertTo-SecureString "lab" -AsPlainText -Force
Export-Certificate -Cert $ca -FilePath (Join-Path $Out "lab-root.cer") | Out-Null
Export-PfxCertificate -Cert $server -FilePath (Join-Path $Out "lab-server.pfx") -Password $password | Out-Null
Export-Certificate -Cert $server -FilePath (Join-Path $Out "lab-server.cer") | Out-Null
Export-PfxCertificate -Cert $auth -FilePath (Join-Path $Out "lab-auth.pfx") -Password $password | Out-Null
Export-PfxCertificate -Cert $sign -FilePath (Join-Path $Out "lab-sign.pfx") -Password $password | Out-Null
Set-Content -Path (Join-Path $Out "server.thumbprint") -Value $server.Thumbprint -Encoding ASCII
try {
    Import-Certificate -FilePath (Join-Path $Out "lab-root.cer") -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
} catch {
    Write-Host "CurrentUser\\Root import skipped: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "OK. CA thumbprint     $($ca.Thumbprint)"
Write-Host "    Server thumbprint $($server.Thumbprint)"
Write-Host "    PIN1 thumbprint   $($auth.Thumbprint)"
Write-Host "    PIN2 thumbprint   $($sign.Thumbprint)"
Write-Host "PFX password: lab"
Write-Host ""
Write-Host "TAHTIS: kui bind on juba korra tehtud, kaivita see UUVESTI Administratoris."
Write-Host "Uus CA ei ole HTTP.sys-is usaldatud enne uut bind-i (tagajarg: 403.16)."
Write-Host "Next (Administrator):  .\lab.ps1 bind"
