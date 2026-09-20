param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "build", "certs", "bind", "eid-ca", "start", "start-selfhost", "start-lb", "stop", "down", "up", "client", "haproxy", "haproxy-stop", "status", "diagnose", "report", "probe", "probe-stop", "lockdown", "unlock", "proxy", "proxy-stop", "hyperv", "vm", "vm-fix", "vm-check", "vm-start", "vm-pass", "bootstrap", "iac", "ansible", "ansible-ping", "tf", "publish")]
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

function Get-TerraformExe {
    $cmd = Get-Command terraform -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @(
            (Join-Path $Root "terraform.exe"),
            "C:\terraform\terraform.exe",
            (Join-Path $env:LOCALAPPDATA "terraform\terraform.exe")
        )) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Get-LabWslDistro {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $null }
    $raw = & wsl.exe -l -q 2>$null
    foreach ($n in @($raw | ForEach-Object { ($_ -replace "`0", "").Trim() } | Where-Object { $_ })) {
        if ($n -notmatch "docker-desktop") { return $n }
    }
    return $null
}

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ComposeArgs)
    $args = @("compose") + @($ComposeArgs)
    if (Get-Command podman -ErrorAction SilentlyContinue) {
        Write-Host "compose: podman"
        & podman @args
        return
    }
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Write-Host "compose: docker"
        & docker @args
        return
    }
    throw "Neither podman nor docker is on PATH. Install Podman Desktop (or Docker) then .\lab.ps1 haproxy"
}

function ConvertTo-WslPath([string]$winPath) {
    $full = [System.IO.Path]::GetFullPath($winPath)
    if ($full -notmatch '^([A-Za-z]):\\') { throw "Not a drive path: $full" }
    $drive = $Matches[1].ToLowerInvariant()
    $rest = $full.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$rest"
}

function Invoke-LabAnsible {
    param(
        [Parameter(Mandatory = $true)][string[]]$AnsibleArgs,
        [switch]$NeedPassword
    )
    if ($NeedPassword -and -not $env:LAB_WINRM_PASSWORD) {
        $passFile = Join-Path $Root ".lab\lab-admin.pass"
        if (Test-Path $passFile) { $env:LAB_WINRM_PASSWORD = (Get-Content $passFile -Raw).Trim() }
        if (-not $env:LAB_WINRM_PASSWORD) {
            throw "Set the guest Administrator password: `$env:LAB_WINRM_PASSWORD = 'IisId2026!'"
        }
    }
    $ansibleDir = Join-Path $Root "ansible"
    if (Get-Command ansible-playbook -ErrorAction SilentlyContinue) {
        Push-Location $ansibleDir
        try { & ansible-playbook @AnsibleArgs; return $LASTEXITCODE } finally { Pop-Location }
    }
    $distro = Get-LabWslDistro
    if ($distro) {
        $wslDir = ConvertTo-WslPath $ansibleDir
        $quoted = ($AnsibleArgs | ForEach-Object { if ($_ -match '\s') { "'" + $_ + "'" } else { $_ } }) -join ' '
        $env:WSLENV = "LAB_WINRM_PASSWORD/u:LAB_WINRM_USER/u"
        $inner = "export PATH=/opt/iis-id-ansible/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export ANSIBLE_CONFIG=/tmp/iis-id-ansible.cfg; cp -f '$wslDir/ansible.cfg' /tmp/iis-id-ansible.cfg; cd '$wslDir'; ansible-playbook $quoted"
        cmd.exe /c "wsl.exe -d $distro -u root -- bash -lc `"$inner`"" | Out-Host
        return [int]$LASTEXITCODE
    }
    throw "Ansible not found. WSL has no Linux distro (docker-desktop does not count). Run .\lab.ps1 iac"
}

function Invoke-LabAnsibleAdhoc {
    param([string[]]$ModuleArgs)
    if (-not $env:LAB_WINRM_PASSWORD) {
        $passFile = Join-Path $Root ".lab\lab-admin.pass"
        if (Test-Path $passFile) { $env:LAB_WINRM_PASSWORD = (Get-Content $passFile -Raw).Trim() }
        if (-not $env:LAB_WINRM_PASSWORD) {
            throw "Set the guest Administrator password: `$env:LAB_WINRM_PASSWORD = 'IisId2026!'"
        }
    }
    $ansibleDir = Join-Path $Root "ansible"
    if (Get-Command ansible -ErrorAction SilentlyContinue) {
        Push-Location $ansibleDir
        try { & ansible @ModuleArgs; return $LASTEXITCODE } finally { Pop-Location }
    }
    $distro = Get-LabWslDistro
    if ($distro) {
        $wslDir = ConvertTo-WslPath $ansibleDir
        $quoted = ($ModuleArgs | ForEach-Object { if ($_ -match '\s') { "'" + $_ + "'" } else { $_ } }) -join ' '
        $env:WSLENV = "LAB_WINRM_PASSWORD/u:LAB_WINRM_USER/u"
        $inner = "export PATH=/opt/iis-id-ansible/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export ANSIBLE_CONFIG=/tmp/iis-id-ansible.cfg; cp -f '$wslDir/ansible.cfg' /tmp/iis-id-ansible.cfg; cd '$wslDir'; ansible $quoted"
        cmd.exe /c "wsl.exe -d $distro -u root -- bash -lc `"$inner`"" | Out-Host
        return [int]$LASTEXITCODE
    }
    throw "Ansible not found. WSL has no Linux distro (docker-desktop does not count). Run .\lab.ps1 iac"
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

function Start-LabProxy([string]$mode) {
    if (-not $mode) { $mode = "allow" }
    $script = Join-Path $Root "scripts\Start-LabProxy.ps1"
    Stop-LabProxy
    Start-LoggedProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $script, $mode, "-Bind", "any") "proxy" | Out-Null
    Start-Sleep -Milliseconds 800
    Write-Host ""
    Write-Host "Lab proxy: 0.0.0.0:3128 (loopback + 192.168.56.2)  mode=$mode"
    Write-Host "Logi: .lab\proxy.log  (iga URL, mida Windows ise kusib: AIA / CRL / OCSP)"
    Write-Host "VM WinHTTP: http://192.168.56.2:3128   Host: .\lab.ps1 lockdown proxy-only   (ADMIN)"
    Write-Host "Peata: .\lab.ps1 proxy-stop"
}

function Stop-LabProxy {
    Stop-NamedProcess "proxy"
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "powershell.exe" -and $_.CommandLine -like "*Start-LabProxy.ps1*" } |
        ForEach-Object { Stop-ProcessId ([int]$_.ProcessId) "proxy" }
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
  .\lab.ps1 proxy [mode]     Logiv lab-proxy: naitab, MIS URL-e Windows ise kusib
                             mode: allow (vaikimisi) | allowlist | auth407 | deny | timeout
  .\lab.ps1 proxy-stop       Peata lab-proxy
  .\lab.ps1 lockdown [nimi]  ADMIN: tee masinast suletud vorgu server (vaikimisi: status)
                             hosts-blackhole | system-no-net | proxy-only | dead-proxy
                             no-aia | no-issuer
  .\lab.ps1 unlock           ADMIN: votab koik lockdown-muudatused tagasi
                             Eelvaade ilma muutmata:
                             scripts\Set-LabLockdown.ps1 proxy-only -Preview
  .\lab.ps1 hyperv           Windows Home: eelvaade Hyper-V lubamisest
  .\lab.ps1 vm [iso]         Loo suletud vorgu Windows Server VM (ilma ISO-ta = eelvaade)
  .\lab.ps1 vm-start         Kaivita VM ja vajuta ise SPACE (CD/DVD viip on ~2 s)
  .\lab.ps1 vm-pass          Setupi Administrator parool (IisId2026!) WMI klaviatuuriga
  .\lab.ps1 bootstrap        Ootab guest valmis (PS Direct) + WinRM + Ansible — ilma konsoolita
  .\lab.ps1 vm-check [iso]   Miks VM ei buudi: VM seaded + kas ISO on x64 UEFI Windows
  .\lab.ps1 vm-fix [iso]     "No operating system was loaded": DVD esimeseks + juhend
  .\lab.ps1 iac              Ansible kontrollsõlm (WSL: ansible-core + Windows collectionid)
  .\lab.ps1 ansible-ping     WinRM test 192.168.56.10 vastu (LAB_WINRM_PASSWORD)
  .\lab.ps1 ansible          IIS + ESTEID + WinHTTP guestis (sama roll mis Nutanixis)
  .\lab.ps1 publish          ClickOnce paigalduskaust (siis ansible kopeerib /install peale)
  .\lab.ps1 tf [plan|apply]  Terraform Hyper-V juur (switch + VM; destroy ei kustuta Windowsit)
  .\lab.ps1 client           Ava desktop klient (PIN1, siis PIN2)
  .\lab.ps1 down Backend1    Tapab ühe IIS-i (failover test)
  .\lab.ps1 up Backend1      Toob sama backend'i tagasi
  .\lab.ps1 stop             Peata lab
  .\lab.ps1 haproxy          HAProxy TCP passthrough (Podman, muidu Docker; peata enne .NET LB)
  .\lab.ps1 haproxy-stop
  .\lab.ps1 status

Failover: logi sisse, tee tavaline päring, siis .\lab.ps1 down Backend1 (või 2)
ja vajuta päring uuesti — klient avab uue TLS-kanali elus masinasse.

PIN1 sisestatud, aga ikka ei toimi? Jarjekord:
  1) .\lab.ps1 probe        -> ava kaardiga https://demo.local:9444/  (utleb 403.7 / 13 / 16)
  2) .\lab.ps1 report 15    -> uks fail: IIS alamstaatus, CAPI2, Schannel, hoidlad, OCSP
  3) kliendis nupp "Diagnostika" -> paris HTTP staatus, mitte "Anonymous"

Kodus internet, tool keelatud? Tekita sama olukord siin:
  .\lab.ps1 proxy                    -> naed logist, MIS URL-e Windows kusib
  .\lab.ps1 lockdown proxy-only      -> otse suletud, ainult proxy (ADMIN)
  .\lab.ps1 lockdown system-no-net   -> ainult lsass/IIS kaotavad vorgu; PS testid ikka PASS
  .\lab.ps1 lockdown no-issuer       -> 403.16, kuigi rakendus utleb "sert kehtiv"
  .\lab.ps1 unlock                   -> koik tagasi

Klient: https://demo.local:9443/Demo.svc
Stats:  http://127.0.0.1:8404/
Logid:  .lab\certprobe.log, .lab\proxy.log, .lab\eid-report-*.txt,
        %LOCALAPPDATA%\IIS-ID\client.log, src\Demo.Service\App_Data\service.log
"@
    }
    "build" { Invoke-Build }
    "certs" { & (Join-Path $Root "scripts\New-DevCertificates.ps1") }
    "bind" { & (Join-Path $Root "scripts\Install-HttpSysBindings.ps1") }
    "eid-ca" { & (Join-Path $Root "scripts\Install-EeIdTrust.ps1") }
    "start" {
        Stop-Lab
        Invoke-Build
        & (Join-Path $Root "scripts\Publish-ClickOnce.ps1")
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
        Write-Host "Paigalda: http://demo.local:8080/install/  (ilma PIN1-ta)"
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
        try { Invoke-Compose up -d }
        finally { Pop-Location }
        Write-Host "HAProxy kuulab hostiporti 9443. Stats http://127.0.0.1:8404/"
    }
    "haproxy-stop" {
        Push-Location $Root
        try { Invoke-Compose down }
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
    "lockdown" {
        # Teeb sellest masinast "suletud vorgu" serveri: vaikimisi keelatud valjapoole.
        $scenario = $Target
        if (-not $scenario) { $scenario = "status" }
        & (Join-Path $Root "scripts\Set-LabLockdown.ps1") $scenario
    }
    "unlock" { & (Join-Path $Root "scripts\Set-LabLockdown.ps1") restore }
    "hyperv" {
        # Windows Home: Hyper-V ei ole vaikimisi olemas. Eelvaade enne muutmist.
        & (Join-Path $Root "scripts\Enable-HyperVHome.ps1") -Preview
        Write-Host ""
        Write-Host "Paigaldamiseks (ADMIN): scripts\Enable-HyperVHome.ps1"
    }
    "vm" {
        if (-not $Target) {
            & (Join-Path $Root "scripts\New-LabVm.ps1") -Preview
            Write-Host ""
            Write-Host "Anna ISO kaasa: .\lab.ps1 vm D:\iso\WindowsServer.iso"
            return
        }
        & (Join-Path $Root "scripts\New-LabVm.ps1") -IsoPath $Target
    }
    "bootstrap" {
        & (Join-Path $Root "scripts\Bootstrap-LabGuest.ps1")
    }
    "vm-pass" {
        & (Join-Path $Root "scripts\Send-LabVmText.ps1")
    }
    "vm-start" {
        # Kaivitab VM-i ja vajutab ise SPACE-i, et "Press any key to boot from CD/DVD"
        # aken (~2 s) kindlasti tabatud saaks.
        & (Join-Path $Root "scripts\New-LabVm.ps1") -StartWithKey
    }
    "vm-check" {
        # Miks VM utleb "No operating system was loaded": VM seaded + ISO sisu.
        if ($Target) { & (Join-Path $Root "scripts\Test-LabVm.ps1") -IsoPath $Target }
        else { & (Join-Path $Root "scripts\Test-LabVm.ps1") }
    }
    "iac" { & (Join-Path $Root "scripts\Install-LabIac.ps1") }
    "ansible-ping" {
        $code = Invoke-LabAnsibleAdhoc @("-i", "inventories/lab.yml", "iis", "-m", "ansible.windows.win_ping")
        if ($code -ne 0) { throw "ansible-ping failed (exit $code). Guest: scripts\Enable-LabWinRm.ps1" }
    }
    "publish" { & (Join-Path $Root "scripts\Publish-ClickOnce.ps1") }
    "ansible" {
        Invoke-Build
        & (Join-Path $Root "scripts\Publish-ClickOnce.ps1")
        $code = Invoke-LabAnsible -NeedPassword -AnsibleArgs @("-i", "inventories/lab.yml", "iis.yml")
        if ($code -ne 0) { throw "ansible-playbook failed (exit $code)." }
    }
    "tf" {
        $tf = Get-TerraformExe
        if (-not $tf) {
            throw "terraform.exe not found. Expected C:\terraform\terraform.exe or PATH. Then .\lab.ps1 tf init"
        }
        $action = if ($Target) { $Target } else { "plan" }
        if ($action -notin @("init", "plan", "apply", "output", "validate", "show")) {
            throw "Kasuta: .\lab.ps1 tf  voi  .\lab.ps1 tf init|plan|apply|output"
        }
        $tfDir = Join-Path $Root "terraform\hyperv"
        Write-Host "terraform: $tf"
        if ($action -eq "apply") { & $tf -chdir="$tfDir" apply }
        else { & $tf -chdir="$tfDir" $action }
    }
    "vm-fix" {
        # "No operating system was loaded": DVD boot order / ISO / kaotatud klahvivajutus.
        if ($Target) { & (Join-Path $Root "scripts\New-LabVm.ps1") -FixBoot -IsoPath $Target }
        else { & (Join-Path $Root "scripts\New-LabVm.ps1") -FixBoot }
    }
    "proxy" { Start-LabProxy $Target }
    "proxy-stop" {
        Stop-LabProxy
        Write-Host "Lab proxy peatatud."
    }
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
