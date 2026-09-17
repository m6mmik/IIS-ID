param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "build", "certs", "bind", "eid-ca", "start", "start-selfhost", "start-lb", "stop", "down", "up", "client", "haproxy", "haproxy-stop", "status", "diagnose", "report", "probe", "probe-stop")]
    [string]$Command = "help",
    [Parameter(Position = 1)]
    [string]$Target
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Lab = Join-Path $Root ".lab"
$PidFile = Join-Path $Lab "pids.txt"
$IisExpress = Join-Path ${env:ProgramFiles} "IIS Express\iisexpress.exe"
$Config = Join-Path $Root "iis\applicationhost.config"

function Ensure-LabDir { New-Item -ItemType Directory -Force -Path $Lab | Out-Null }

function Invoke-Build {
    Get-Process Demo.Client -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Stop Demo.Client pid=$($_.Id) (lukustas buildi)"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Building .NET 4.8 solution..."
    dotnet build (Join-Path $Root "IIS-ID.slnx") -c Debug
}

function Get-PidMap {
    $map = @{}
    if (-not (Test-Path $PidFile)) { return $map }
    foreach ($line in Get-Content $PidFile) {
        if ($line -match '^(lb|backend1|backend2|mode)=(.+)$') {
            $map[$Matches[1]] = $Matches[2]
        }
        elseif ($line -match '^\d+$') {
            $map["legacy_$line"] = $line
        }
    }
    return $map
}

function Set-PidMap($map) {
    Ensure-LabDir
    $lines = @()
    foreach ($key in @("mode", "lb", "backend1", "backend2")) {
        if ($map.ContainsKey($key) -and $map[$key]) {
            $lines += "$key=$($map[$key])"
        }
    }
    if ($lines.Count -eq 0) { if (Test-Path $PidFile) { Remove-Item $PidFile -Force }; return }
    $lines | Set-Content $PidFile
}

function Get-RunningPids {
    $map = Get-PidMap
    foreach ($key in $map.Keys) {
        if ($key -eq "mode") { continue }
        $procId = 0
        if ([int]::TryParse($map[$key], [ref]$procId)) { $procId }
    }
}

function Resolve-BackendName([string]$name) {
    if (-not $name) { throw "Kasuta: .\lab.ps1 down Backend1  voi  .\lab.ps1 down Backend2" }
    switch ($name.ToLowerInvariant()) {
        { $_ -in @("1", "b1", "backend1") } { "backend1"; break }
        { $_ -in @("2", "b2", "backend2") } { "backend2"; break }
        default { throw "Kasuta: .\lab.ps1 down Backend1  voi  .\lab.ps1 down Backend2" }
    }
}

function Get-BackendPorts([string]$name) {
    if ($name -eq "backend1") { return @{ Https = 8443; Http = 8080; Site = "Backend1"; Display = "Backend1" } }
    return @{ Https = 8444; Http = 8081; Site = "Backend2"; Display = "Backend2" }
}

function Wait-ProcessGone([int]$procId, [int]$seconds = 8) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 200
    }
}

function Stop-ProcessId([int]$procId, [string]$label) {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p) { return }
    Write-Host "Stop $($p.ProcessName) pid=$procId ($label)"
    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    Wait-ProcessGone $procId
}

function Stop-NamedProcess([string]$name) {
    $map = Get-PidMap
    $procId = 0
    if ($map.ContainsKey($name)) { [void][int]::TryParse($map[$name], [ref]$procId) }
    if ($procId -gt 0) { Stop-ProcessId $procId $name }

    if ($name -eq "backend1" -or $name -eq "backend2") {
        $ports = Get-BackendPorts $name
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '^(iisexpress|Demo.Host)\.exe$' -and
                $_.CommandLine -and
                ($_.CommandLine -like "*site:$($ports.Site)*" -or $_.CommandLine -like "*--name $($ports.Display)*")
            } |
            ForEach-Object { Stop-ProcessId ([int]$_.ProcessId) $name }
    }

    $map = Get-PidMap
    $map.Remove($name)
    Set-PidMap $map
    Start-Sleep -Milliseconds 400
}

function Stop-Lab {
    $pids = @(Get-RunningPids)
    foreach ($procId in $pids) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host "Stop $($p.ProcessName) pid=$procId"
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
    Get-Process Demo.LoadBalancer, Demo.Host, Demo.CertProbe -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Stop $($_.ProcessName) pid=$($_.Id)"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $PidFile) { Remove-Item $PidFile -Force }
}

function Start-CertProbe([string]$port) {
    if (-not $port) { $port = "9444" }
    $exe = Join-Path $Root "src\Demo.CertProbe\bin\Debug\net48\Demo.CertProbe.exe"
    if (-not (Test-Path $exe)) { Invoke-Build }
    if (-not (Test-Path $exe)) { throw "Demo.CertProbe puudub. Käivita .\lab.ps1 build" }

    Get-Process Demo.CertProbe -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-ProcessId $_.Id "probe"
    }

    Start-LoggedProcess $exe @("--port", $port) "probe" | Out-Null
    Start-Sleep -Milliseconds 800
    Write-Host ""
    Write-Host "CertProbe kuulab: https://demo.local:$port/"
    Write-Host "Ava see aadress ID-kaardiga (brauser voi klient) ning saad taisraporti:"
    Write-Host "  kas serti kusiti, kas ahel ehitub, millisest hoidlast iga luli tuleb,"
    Write-Host "  kas OCSP vastab ja mida IIS teeks (403.7 / 403.13 / 403.16)."
    Write-Host "Logi: .lab\certprobe.log      Peata: .\lab.ps1 probe-stop"
}

function Add-Pid([int]$procId, [string]$name) {
    $map = Get-PidMap
    $map[$name] = "$procId"
    Set-PidMap $map
}

function Set-LabMode([string]$mode) {
    $map = Get-PidMap
    $map["mode"] = $mode
    Set-PidMap $map
}

function New-LabLog([string]$logName, [string]$kind) {
    $preferred = Join-Path $Lab "$logName.$kind.log"
    try {
        if (Test-Path $preferred) {
            Remove-Item $preferred -Force -ErrorAction Stop
        }
        return $preferred
    } catch {
        $fallback = Join-Path $Lab ("{0}.{1}.{2}.log" -f $logName, $kind, (Get-Date -Format "HHmmss"))
        Write-Host "Log $preferred lukus, kasutan $fallback"
        return $fallback
    }
}

function Start-LoggedProcess([string]$file, [string[]]$procArgs, [string]$logName) {
    Ensure-LabDir
    $out = New-LabLog $logName "out"
    $err = New-LabLog $logName "err"

    $start = @{
        FilePath               = $file
        PassThru               = $true
        NoNewWindow            = $true
        RedirectStandardOutput = $out
        RedirectStandardError  = $err
    }
    if ($procArgs -and $procArgs.Count -gt 0) {
        $start.ArgumentList = $procArgs
    }

    $p = Start-Process @start
    Add-Pid $p.Id $logName
    Write-Host "Started $file pid=$($p.Id) log=$out"
    return $p
}

function Start-Backend([string]$name) {
    $map = Get-PidMap
    if ($map.ContainsKey($name)) {
        $existing = 0
        if ([int]::TryParse($map[$name], [ref]$existing)) {
            $p = Get-Process -Id $existing -ErrorAction SilentlyContinue
            if ($p) {
                Write-Host "$name juba jookseb pid=$existing"
                return
            }
        }
    }

    $ports = Get-BackendPorts $name
    $mode = $map["mode"]
    if (-not $mode) { $mode = "iis" }

    if ($mode -eq "selfhost") {
        $exe = Join-Path $Root "src\Demo.Host\bin\Debug\net48\Demo.Host.exe"
        if (-not (Test-Path $exe)) { $exe = Join-Path $Root "src\Demo.Host\bin\Demo.Host.exe" }
        if (-not (Test-Path $exe)) { throw "Demo.Host.exe puudub. Käivita .\lab.ps1 start-selfhost" }
        Start-LoggedProcess $exe @("--name", $ports.Display, "--https", "$($ports.Https)", "--http", "$($ports.Http)") $name | Out-Null
    }
    else {
        if (-not (Test-Path $IisExpress)) { throw "IIS Express puudub: $IisExpress" }
        if (-not (Test-Path $Config)) { & (Join-Path $Root "scripts\New-IisExpressConfig.ps1") }
        Start-LoggedProcess $IisExpress @("/config:`"$Config`"", "/site:$($ports.Site)", "/systray:false") $name | Out-Null
    }

    Start-Sleep -Seconds 2
    Wait-Health $ports.Http
}

function Wait-Health([int]$port, [int]$seconds = 20) {
    $url = "http://127.0.0.1:$port/health.json"
    for ($i = 0; $i -lt $seconds; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) {
                Write-Host "Health OK $url  $($r.Content)"
                return
            }
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode } catch { }
            Write-Host "health retry $url  $code"
            Start-Sleep -Seconds 1
        }
        Start-Sleep -Milliseconds 400
    }
    throw "Health check failed: $url  (vaata .lab\backend*.out.log)"
}

function Start-LoadBalancer([string]$bind) {
    $exe = Join-Path $Root "src\Demo.LoadBalancer\bin\Debug\net48\Demo.LoadBalancer.exe"
    if (-not (Test-Path $exe)) { $exe = Join-Path $Root "src\Demo.LoadBalancer\bin\Demo.LoadBalancer.exe" }
    if (-not (Test-Path $exe)) { throw "Load balancer puudub. Käivita .\lab.ps1 build" }
    $backends = Join-Path $Root "backends.txt"
    $lbArgs = @("--lab", (Join-Path $Root "lab.ps1"))
    if (Test-Path $backends) { $lbArgs += @("--backends", $backends) }
    if ($bind) { $lbArgs += @("--bind", $bind) }
    Start-LoggedProcess $exe $lbArgs "lb" | Out-Null
}

switch ($Command) {
    "help" {
        @"
IIS-ID kodune lab (.NET 4.8, IIS Express app poolid, PIN1/PIN2, TCP load balancing)

  .\lab.ps1 certs            Loo lab CA + server + PIN1/PIN2 sertifikaadid
  .\lab.ps1 bind             ADMIN: HTTP.sys mTLS, urlacl, hosts demo.local
  .\lab.ps1 eid-ca           Lae EE-GovCA / ESTEID ahelad (ID-kaardi test)
  .\lab.ps1 build            Kompileeri lahendus
  .\lab.ps1 start            2 x IIS Express app pool + TCP passthrough LB
  .\lab.ps1 start-selfhost   Sama pordid ilma IIS Expressita (WCF ServiceHost)
  .\lab.ps1 start-lb         Ainult balancer (backends.txt; valikuline: 0.0.0.0)
  .\lab.ps1 diagnose         UKS raport: hoidlad, HTTP.sys, WinHTTP, OCSP, IIS 403.x, CAPI2, Schannel
  .\lab.ps1 report 15        Sama raport viimase 15 min kohta ja avab selle
  .\lab.ps1 probe            CertProbe: ava kaardiga https://demo.local:9444/ ja naed miks ahel ei ehitu
  .\lab.ps1 probe-stop       Peata CertProbe
  .\lab.ps1 client           Ava desktop klient (PIN1, siis PIN2)
  .\lab.ps1 down Backend1    Tapab ühe IIS-i (failover test)
  .\lab.ps1 up Backend1      Toob sama backend'i tagasi
  .\lab.ps1 stop             Peata lab
  .\lab.ps1 haproxy          Docker HAProxy TCP passthrough (peata enne .NET LB)
  .\lab.ps1 haproxy-stop
  .\lab.ps1 status

Failover: logi sisse, tee tavaline päring, siis .\lab.ps1 down Backend1 (või 2)
ja vajuta päring uuesti — klient avab uue TLS-kanali elus masinasse.

PIN1 sisestatud, aga ikka ei toimi? Jarjekord:
  1) .\lab.ps1 probe        -> ava kaardiga https://demo.local:9444/  (utleb 403.7 / 13 / 16)
  2) .\lab.ps1 report 15    -> uks fail: IIS alamstaatus, CAPI2, Schannel, hoidlad, OCSP
  3) kliendis nupp "Diagnostika" -> paris HTTP staatus, mitte "Anonymous"

Klient: https://demo.local:9443/Demo.svc
Stats:  http://127.0.0.1:8404/
Logid:  .lab\certprobe.log, .lab\eid-report-*.txt, %LOCALAPPDATA%\IIS-ID\client.log,
        src\Demo.Service\App_Data\service.log
"@
    }
    "build" { Invoke-Build }
    "certs" { & (Join-Path $Root "scripts\New-DevCertificates.ps1") }
    "bind" { & (Join-Path $Root "scripts\Install-HttpSysBindings.ps1") }
    "eid-ca" { & (Join-Path $Root "scripts\Install-EeIdTrust.ps1") }
    "start" {
        Stop-Lab
        Invoke-Build
        & (Join-Path $Root "scripts\New-IisExpressConfig.ps1")
        if (-not (Test-Path $IisExpress)) { throw "IIS Express puudub: $IisExpress" }
        Start-LoadBalancer
        Set-LabMode "iis"
        Start-LoggedProcess $IisExpress @("/config:`"$Config`"", "/site:Backend1", "/systray:false") "backend1" | Out-Null
        Start-LoggedProcess $IisExpress @("/config:`"$Config`"", "/site:Backend2", "/systray:false") "backend2" | Out-Null
        Start-Sleep -Seconds 2
        Wait-Health 8080
        Wait-Health 8081
        Write-Host ""
        Write-Host "Lab over. Klient: .\lab.ps1 client"
        Write-Host "Stats: http://127.0.0.1:8404/"
        Write-Host "Otse Backend1: https://127.0.0.1:8443/Demo.svc"
        Write-Host "Failover: .\lab.ps1 down Backend1   /   .\lab.ps1 up Backend1"
    }
    "start-selfhost" {
        Stop-Lab
        Invoke-Build
        $exe = Join-Path $Root "src\Demo.Host\bin\Debug\net48\Demo.Host.exe"
        if (-not (Test-Path $exe)) { $exe = Join-Path $Root "src\Demo.Host\bin\Demo.Host.exe" }
        Start-LoadBalancer
        Set-LabMode "selfhost"
        Start-LoggedProcess $exe @("--name", "Backend1", "--https", "8443", "--http", "8080") "backend1" | Out-Null
        Start-LoggedProcess $exe @("--name", "Backend2", "--https", "8444", "--http", "8081") "backend2" | Out-Null
        Start-Sleep -Seconds 2
        Wait-Health 8080
        Wait-Health 8081
        Write-Host "Self-host lab over. .\lab.ps1 client"
    }
    "start-lb" {
        Stop-NamedProcess "lb"
        Get-Process Demo.LoadBalancer -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Stop Demo.LoadBalancer pid=$($_.Id)"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        Start-LoadBalancer $Target
        Write-Host "LB backends.txt pealt. Stats: http://127.0.0.1:8404/"
        if ($Target) { Write-Host "listen $Target" }
    }
    "stop" { Stop-Lab; Write-Host "Stopped." }
    "down" {
        $name = Resolve-BackendName $Target
        Stop-NamedProcess $name
        Write-Host "$name maas. Stats: http://127.0.0.1:8404/  (health ~2s DOWN). Klient hüppab järgmisel päringul."
    }
    "up" {
        $name = Resolve-BackendName $Target
        Start-Backend $name
        Write-Host "$name uuesti üleval."
    }
    "client" {
        $exe = Join-Path $Root "src\Demo.Client\bin\Debug\net48\Demo.Client.exe"
        if (-not (Test-Path $exe)) { Invoke-Build; $exe = Join-Path $Root "src\Demo.Client\bin\Debug\net48\Demo.Client.exe" }
        Start-Process $exe
    }
    "haproxy" {
        Stop-Lab
        Invoke-Build
        & (Join-Path $Root "scripts\New-IisExpressConfig.ps1")
        Set-LabMode "iis"
        Start-LoggedProcess $IisExpress @("/config:`"$Config`"", "/site:Backend1", "/systray:false") "backend1" | Out-Null
        Start-LoggedProcess $IisExpress @("/config:`"$Config`"", "/site:Backend2", "/systray:false") "backend2" | Out-Null
        Wait-Health 8080
        Wait-Health 8081
        Push-Location $Root
        try { docker compose up -d }
        finally { Pop-Location }
        Write-Host "HAProxy kuulab hostiporti 9443. Stats http://127.0.0.1:8404/"
    }
    "haproxy-stop" {
        Push-Location $Root
        try { docker compose down }
        finally { Pop-Location }
        Stop-Lab
    }
    "diagnose" {
        # Uks raport: hoidlad, HTTP.sys, WinHTTP, OCSP URL-id, IIS 403.x alamstaatus, CAPI2, Schannel, rakenduse logid.
        $minutes = 30
        if ($Target -and [int]::TryParse($Target, [ref]$minutes)) { }
        & (Join-Path $Root "scripts\Get-EidReport.ps1") -Minutes $minutes
        Write-Host ""
        Write-Host "Kaardi enda kontroll sellel masinal: .\lab.ps1 probe"
        Write-Host "Kui probe on kaardiga labi tehtud, kontrollib raport ise ka ahelat ja OCSP-d"
        Write-Host "  (certutil -verify -urlfetch .lab\lastclient.cer). Oma failiga: -CertFile kaart.cer"
        Write-Host "Vanemad uksiktestid: scripts\Test-ClientCertTrust.ps1 ja scripts\Test-EidAfterPin1.ps1"
    }
    "report" {
        $minutes = 30
        if ($Target -and [int]::TryParse($Target, [ref]$minutes)) { }
        & (Join-Path $Root "scripts\Get-EidReport.ps1") -Minutes $minutes -Open
    }
    "probe" { Start-CertProbe $Target }
    "probe-stop" {
        Stop-NamedProcess "probe"
        Get-Process Demo.CertProbe -ErrorAction SilentlyContinue | ForEach-Object { Stop-ProcessId $_.Id "probe" }
        Write-Host "CertProbe peatatud."
    }
    "status" {
        $map = Get-PidMap
        if ($map.Count -eq 0) { Write-Host "Lab pids: (puudub)" }
        else {
            foreach ($key in @("mode", "lb", "backend1", "backend2")) {
                if ($map.ContainsKey($key)) { Write-Host "$key=$($map[$key])" }
            }
        }
        foreach ($port in 8080, 8081, 8404, 9443, 8443, 8444) {
            $c = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($c) { Write-Host "LISTEN $port  pid=$($c.OwningProcess)" }
            else { Write-Host "free  $port" }
        }
    }
}
