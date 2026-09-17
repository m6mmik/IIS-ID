# Production-style ESTEID chain on a Windows IIS machine.
# ASCII-only: Windows PowerShell 5.1.
#
# Run as Administrator, ON EACH IIS server:
#   powershell -ExecutionPolicy Bypass -File scripts\Install-EsteidIisProduction.ps1
#
# Correct stores (open-eid IIS guide):
#   Root:              EE-GovCA2018, EEGovCA2025
#   CA (Intermediate): ESTEID2018, ESTEID2025
#   ClientAuthIssuer:  ESTEID2018, ESTEID2025   (intermediates, not only roots)
#
# This script does NOT bind sslcert (certhash is unique per server).
# After this, follow README: IIS SSL, netsh clientcertnegotiation, OCSP, health site.

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator PowerShell required."
}

$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root "certs\eid-ca"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$files = @(
    @{ Url = "https://c.sk.ee/EE-GovCA2018.der.crt"; Name = "EE-GovCA2018.crt"; Stores = @("Root") }
    @{ Url = "https://crt.eidpki.ee/EEGovCA2025.crt"; Name = "EEGovCA2025.crt"; Stores = @("Root") }
    @{ Url = "https://c.sk.ee/esteid2018.der.crt";   Name = "ESTEID2018.crt";  Stores = @("CA", "ClientAuthIssuer") }
    @{ Url = "https://crt.eidpki.ee/ESTEID2025.crt"; Name = "ESTEID2025.crt";  Stores = @("CA", "ClientAuthIssuer") }
)

foreach ($item in $files) {
    $path = Join-Path $Out $item.Name
    if (-not (Test-Path $path)) {
        Write-Host "Download $($item.Url)"
        Invoke-WebRequest -Uri $item.Url -OutFile $path -UseBasicParsing
    } else {
        Write-Host "Use existing $path"
    }
    foreach ($store in $item.Stores) {
        Write-Host "  certutil -addstore $store $($item.Name)"
        & certutil -f -addstore $store $path | Out-Null
    }
}

Write-Host ""
Write-Host "Stores updated. Next (THIS machine):"
Write-Host "  1. netsh http show sslcert"
Write-Host "  2. Recreate HTTPS binding with clientcertnegotiation=enable"
Write-Host "  3. Production: verifyclientcertrevocation=enable"
Write-Host "  4. Optional CTL: sslctlstorename=ClientAuthIssuer  (store must not be empty)"
Write-Host "  5. .\lab.ps1 diagnose    or    powershell -File scripts\Test-EidAfterPin1.ps1"
Write-Host "  6. Repeat on EVERY IIS VM."
