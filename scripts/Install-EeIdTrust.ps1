# Downloads EE-GovCA / ESTEID intermediates from the official IIS eID guide.
# Admin recommended so LocalMachine stores are updated.
# https://open-eid.github.io/iis/index.et.html

$ErrorActionPreference = "Stop"

$files = @(
    @{ Url = "https://c.sk.ee/EE-GovCA2018.der.crt"; Store = "Cert:\LocalMachine\Root"; Name = "EE-GovCA2018.crt" }
    @{ Url = "https://crt.eidpki.ee/EEGovCA2025.crt"; Store = "Cert:\LocalMachine\Root"; Name = "EEGovCA2025.crt" }
    @{ Url = "https://c.sk.ee/esteid2018.der.crt"; Store = "Cert:\LocalMachine\CA"; Name = "ESTEID2018.crt" }
    @{ Url = "https://crt.eidpki.ee/ESTEID2025.crt"; Store = "Cert:\LocalMachine\CA"; Name = "ESTEID2025.crt" }
)

$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root "certs\eid-ca"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

foreach ($item in $files) {
    $path = Join-Path $Out $item.Name
    Write-Host "Download $($item.Url)"
    Invoke-WebRequest -Uri $item.Url -OutFile $path -UseBasicParsing
    if ($admin) {
        Import-Certificate -FilePath $path -CertStoreLocation $item.Store | Out-Null
        & certutil -f -addstore ClientAuthIssuer $path | Out-Null
        Write-Host "  installed $($item.Store) + ClientAuthIssuer"
    } else {
        Write-Host "  saved $path (run as Administrator to install)"
    }
}

if ($admin) {
    $schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    New-ItemProperty -Path $schannel -Name ClientAuthTrustMode -Value 2 -PropertyType DWord -Force | Out-Null
    Write-Host "SCHANNEL ClientAuthTrustMode=2"
}
