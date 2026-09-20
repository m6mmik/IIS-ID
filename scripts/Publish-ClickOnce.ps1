# Builds Demo.Client as a ClickOnce deployment under publish\clickonce.
# The install URL must NOT require a client certificate (work rule).
#
#   .\lab.ps1 publish
#   then ansible copies it to the IIS /install virtual directory.

param(
    [string]$ProviderUrl = "http://demo.local:8080/install/",
    [string]$Version
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root "publish\clickonce"
$Bin = Join-Path $Root "src\Demo.Client\bin\Debug\net48"
$Pfx = Join-Path $Root "certs\lab-codesign.pfx"
$AppName = "Demo.Client"

if (-not $Version) {
    $now = Get-Date
    $Version = "1.0.{0}.{1}" -f $now.ToString("yyM"), [int]$now.ToString("HHmm")
}

function Get-Mage {
    $cmd = Get-Command mage.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $roots = @(
        "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows",
        "${env:ProgramFiles}\Microsoft SDKs\Windows"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem $root -Recurse -Filter mage.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "NETFX 4" } |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

Write-Host "Building client..."
# ClickOnce reads the embedded Win32 manifest first. If it disagrees with the
# deployment identity (typical with ApplicationManifest), install fails with
# "Reference in the manifest does not match the identity of the downloaded assembly".
dotnet build (Join-Path $Root "src\Demo.Client\Demo.Client.csproj") -c Debug -t:Rebuild `
    -p:Version=$Version -p:AssemblyVersion=$Version -p:FileVersion=$Version `
    -p:InformationalVersion=$Version `
    -p:ApplicationManifest= -p:NoWin32Manifest=true | Out-Host
if (-not (Test-Path (Join-Path $Bin "$AppName.exe"))) {
    throw "Client exe missing at $Bin. Build failed?"
}

if (-not (Test-Path $Pfx)) {
    $ca = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq "CN=IIS-ID Home Lab Root, O=IIS-ID Home Lab, C=EE" } |
        Select-Object -First 1
    if (-not $ca) { throw "lab-codesign.pfx missing and lab CA is not in CurrentUser\\My. Run .\\lab.ps1 certs once, then publish (do not re-run certs if Firefox already trusts the root)." }
    Write-Host "Creating ClickOnce signing cert from the existing lab CA..."
    $cs = New-SelfSignedCertificate -Subject "CN=IIS-ID Lab Code Signing, O=IIS-ID Home Lab, C=EE" `
        -FriendlyName "IIS-ID lab ClickOnce" -Signer $ca -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable -KeyLength 2048 -HashAlgorithm SHA256 `
        -CertStoreLocation Cert:\CurrentUser\My -Type Custom `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3") -NotAfter (Get-Date).AddYears(3)
    $pw = ConvertTo-SecureString "lab" -AsPlainText -Force
    Export-PfxCertificate -Cert $cs -FilePath $Pfx -Password $pw | Out-Null
    Export-Certificate -Cert $cs -FilePath (Join-Path $Root "certs\lab-codesign.cer") | Out-Null
}

$cer = Join-Path $Root "certs\lab-codesign.cer"
if (-not (Test-Path $cer)) {
    $tmp = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, "lab")
    Export-Certificate -Cert $tmp -FilePath $cer | Out-Null
}
try {
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
} catch {
    Write-Host "TrustedPublisher import skipped: $($_.Exception.Message)"
}

$mage = Get-Mage
if (-not $mage) {
    throw "mage.exe not found. Install the .NET Framework 4.8 Developer Pack / Windows SDK (NETFX 4.8 Tools)."
}

if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
$appDir = Join-Path $Out "Application Files\${AppName}_$($Version.Replace('.', '_'))"
New-Item -ItemType Directory -Force -Path $appDir | Out-Null

Get-ChildItem $Bin -File | Where-Object {
    $_.Extension -in ".exe", ".dll" -or $_.Name -eq "$AppName.exe.config"
} | ForEach-Object { Copy-Item $_.FullName $appDir -Force }

$manifest = Join-Path $appDir "$AppName.exe.manifest"
$application = Join-Path $Out "$AppName.application"
$pfxPass = "lab"

& $mage -New Application -ToFile $manifest -Name $AppName -Version $Version `
    -Processor amd64 -FromDirectory $appDir -TrustLevel FullTrust | Out-Host
& $mage -Sign $manifest -CertFile $Pfx -Password $pfxPass | Out-Host

Get-ChildItem $appDir -File | Where-Object { $_.Name -notmatch '\.manifest$' } | ForEach-Object {
    Rename-Item $_.FullName ($_.Name + ".deploy")
}

& $mage -New Deployment -ToFile $application -Name $AppName -Version $Version `
    -Processor amd64 -AppManifest $manifest -Install true `
    -providerUrl ($ProviderUrl + "$AppName.application") | Out-Host
& $mage -Update $application -ProviderUrl ($ProviderUrl + "$AppName.application") | Out-Host

[xml]$dep = Get-Content $application
$dep.assembly.deployment.SetAttribute("mapFileExtensions", "true")
$dep.Save($application)

& $mage -Sign $application -CertFile $Pfx -Password $pfxPass | Out-Host

$html = @"
<!DOCTYPE html>
<html lang="et">
<head>
  <meta charset="utf-8" />
  <title>IIS-ID Demo — paigaldus</title>
  <style>
    body { font-family: Segoe UI, sans-serif; max-width: 40rem; margin: 3rem auto; line-height: 1.45; }
    a.btn { display: inline-block; background: #1b4f9c; color: #fff; padding: 0.7rem 1.2rem; text-decoration: none; border-radius: 4px; }
    .note { color: #444; background: #f4f4f4; padding: 0.8rem 1rem; }
    code { background: #eee; padding: 0.1rem 0.3rem; }
  </style>
</head>
<body>
  <h1>IIS-ID Demo klient</h1>
  <p>ClickOnce paigaldus. <strong>See leht ei kusi ID-kaarti</strong> — PIN1 küsitakse alles siis, kui rakendus läheb <code>Demo.svc</code> poole.</p>
  <p><a class="btn" href="Demo.Client.application">Paigalda / käivita</a></p>
  <p class="note">Ava Edge’is otse see leht. Firefox salvestab <code>.application</code> Downloads’i — see fail vananeb. Versioon $Version.</p>
  <p>Teenus pärast paigaldust: <code>https://demo.local:9443/Demo.svc</code> (läbi balanceri; PIN1).</p>
</body>
</html>
"@
Set-Content -Path (Join-Path $Out "index.html") -Value $html -Encoding UTF8

$webConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <defaultDocument><files><clear /><add value="index.html" /></files></defaultDocument>
    <staticContent>
      <remove fileExtension=".application" />
      <remove fileExtension=".manifest" />
      <remove fileExtension=".deploy" />
      <mimeMap fileExtension=".application" mimeType="application/x-ms-application" />
      <mimeMap fileExtension=".manifest" mimeType="application/x-ms-manifest" />
      <mimeMap fileExtension=".deploy" mimeType="application/octet-stream" />
    </staticContent>
  </system.webServer>
</configuration>
"@
Set-Content -Path (Join-Path $Out "web.config") -Value $webConfig -Encoding UTF8

Write-Host ""
Write-Host "ClickOnce -> $Out"
Write-Host "Install: ${ProviderUrl}   or  http://demo.local:8080/install/"
Write-Host "Version $Version"
