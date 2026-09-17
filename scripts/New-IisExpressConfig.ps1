# Builds an IIS Express applicationhost.config with two sites / two app pools.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$SitePath = Join-Path $Root "src\Demo.Service"
$IisDir = Join-Path $Root "iis"
$Dest = Join-Path $IisDir "applicationhost.config"
$Source = Join-Path $env:USERPROFILE "Documents\IISExpress\config\applicationhost.config"

if (-not (Test-Path $Source)) {
    throw "IIS Express config puudub: $Source"
}

New-Item -ItemType Directory -Force -Path $IisDir | Out-Null
Copy-Item $Source $Dest -Force

[xml]$xml = Get-Content $Dest
$pools = $xml.configuration.'system.applicationHost'.applicationPools
$sites = $xml.configuration.'system.applicationHost'.sites

function Remove-Named($parent, $localName, $name) {
    $nodes = @($parent.ChildNodes | Where-Object { $_.Name -eq $localName -and $_.GetAttribute("name") -eq $name })
    foreach ($n in $nodes) { [void]$parent.RemoveChild($n) }
}

Remove-Named $pools "add" "Backend1Pool"
Remove-Named $pools "add" "Backend2Pool"
Remove-Named $sites "site" "Backend1"
Remove-Named $sites "site" "Backend2"

function Add-Pool($name) {
    $add = $xml.CreateElement("add")
    $add.SetAttribute("name", $name)
    $add.SetAttribute("managedRuntimeVersion", "v4.0")
    $add.SetAttribute("managedPipelineMode", "Integrated")
    $add.SetAttribute("CLRConfigFile", "%IIS_USER_HOME%\config\aspnet.config")
    $add.SetAttribute("autoStart", "true")
    [void]$pools.AppendChild($add)
}

Add-Pool "Backend1Pool"
Add-Pool "Backend2Pool"

function Add-Site($name, $id, $pool, $httpsPort, $httpPort) {
    $site = $xml.CreateElement("site")
    $site.SetAttribute("name", $name)
    $site.SetAttribute("id", "$id")
    $site.SetAttribute("serverAutoStart", "true")

    $app = $xml.CreateElement("application")
    $app.SetAttribute("path", "/")
    $app.SetAttribute("applicationPool", $pool)

    $vdir = $xml.CreateElement("virtualDirectory")
    $vdir.SetAttribute("path", "/")
    $vdir.SetAttribute("physicalPath", $SitePath)
    [void]$app.AppendChild($vdir)
    [void]$site.AppendChild($app)

    $bindings = $xml.CreateElement("bindings")
    $https = $xml.CreateElement("binding")
    $https.SetAttribute("protocol", "https")
    $https.SetAttribute("bindingInformation", "127.0.0.1:${httpsPort}:")
    $http = $xml.CreateElement("binding")
    $http.SetAttribute("protocol", "http")
    $http.SetAttribute("bindingInformation", "127.0.0.1:${httpPort}:")
    [void]$bindings.AppendChild($https)
    [void]$bindings.AppendChild($http)
    [void]$site.AppendChild($bindings)
    [void]$sites.AppendChild($site)
}

Add-Site "Backend1" "11" "Backend1Pool" 8443 8080
Add-Site "Backend2" "12" "Backend2Pool" 8444 8081

# W3C logimine sisse koos sc-substatus'ega: ilma selleta ei erista 403.16 ja 403.13.
$LogDir = Join-Path $Root ".lab\iislogs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$siteDefaults = $sites.siteDefaults
$logFile = $siteDefaults.logFile
$logFile.SetAttribute("enabled", "true")
$logFile.SetAttribute("logFormat", "W3C")
$logFile.SetAttribute("directory", $LogDir)
$logFile.SetAttribute("logExtFileFlags",
    "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,ServerPort,Method,UriStem,UriQuery,HttpStatus,HttpSubStatus,Win32Status,TimeTaken,ProtocolVersion,Host,UserAgent")

function Add-Location($path, $sslFlags) {
    $existing = @($xml.configuration.location | Where-Object { $_.path -eq $path })
    foreach ($n in $existing) { [void]$xml.configuration.RemoveChild($n) }

    $location = $xml.CreateElement("location")
    $location.SetAttribute("path", $path)
    $web = $xml.CreateElement("system.webServer")
    $security = $xml.CreateElement("security")
    $access = $xml.CreateElement("access")
    $access.SetAttribute("sslFlags", $sslFlags)
    [void]$security.AppendChild($access)

    $auth = $xml.CreateElement("authentication")
    $anon = $xml.CreateElement("anonymousAuthentication")
    $anon.SetAttribute("enabled", "true")
    $win = $xml.CreateElement("windowsAuthentication")
    $win.SetAttribute("enabled", "false")
    [void]$auth.AppendChild($anon)
    [void]$auth.AppendChild($win)
    [void]$security.AppendChild($auth)
    [void]$web.AppendChild($security)
    [void]$location.AppendChild($web)
    [void]$xml.configuration.AppendChild($location)
}

Add-Location "Backend1" "None"
Add-Location "Backend2" "None"
Add-Location "Backend1/Demo.svc" "Ssl,SslNegotiateCert,SslRequireCert"
Add-Location "Backend2/Demo.svc" "Ssl,SslNegotiateCert,SslRequireCert"

$xml.Save($Dest)
Write-Host "IIS Express config: $Dest"
Write-Host "  Backend1Pool  https://127.0.0.1:8443/Demo.svc  health :8080"
Write-Host "  Backend2Pool  https://127.0.0.1:8444/Demo.svc  health :8081"
Write-Host "  W3C logid (sc-substatus): $LogDir"
