# Start-LabProxy.ps1
#
# A tiny forward proxy for the lab, whose real job is VISIBILITY: it writes down
# every URL that Windows itself asks for during a TLS handshake (AIA, CRL, OCSP).
# In a locked down production network you never get to see that list - you only
# get "ordered access to what we guessed". Here you get the exact list.
#
# It also reproduces the ways a corporate proxy says no:
#   allow      forward everything, log it          (what does the OS actually fetch?)
#   allowlist  forward only -Allow hosts, 403 rest (only part of the URLs ordered)
#   auth407    always 407 Proxy Authentication     (machine account cannot authenticate)
#   deny       always 403 Forbidden                (proxy policy blocks the category)
#   timeout    accept and never answer             (silent drop: the worst case, 15s stalls)
#
# Point WinHTTP at it (this is what HTTP.sys/Schannel/lsass use):
#   netsh winhttp set proxy proxy-server="127.0.0.1:3128" bypass-list="<local>"
# or let the lockdown script do it:  .\lab.ps1 lockdown proxy-only
#
# VM setup (host = proxy, guest = closed network server):
#   run this on the HOST with -Bind any, then inside the VM point WinHTTP at the
#   host address of the host-only network, e.g.
#   netsh winhttp set proxy proxy-server="192.168.56.1:3128" bypass-list="<local>"
#   That way the guest has no route of its own and this log is the full list of
#   URLs Windows needs - the list you normally have to guess when ordering access.
#
# Stop with Ctrl+C, or .\lab.ps1 proxy-stop

param(
    [Parameter(Position = 0)]
    [ValidateSet("allow", "allowlist", "auth407", "deny", "timeout")]
    [string]$Mode = "allow",
    [int]$Port = 3128,
    [string[]]$Allow = @("c.sk.ee", "crt.eidpki.ee"),
    [int]$DelaySeconds = 30,
    [ValidateSet("loopback", "any")]
    [string]$Bind = "loopback",
    [string]$LogPath
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Lab = Join-Path $Root ".lab"
New-Item -ItemType Directory -Force -Path $Lab | Out-Null
if (-not $LogPath) { $LogPath = Join-Path $Lab "proxy.log" }

function Write-Log([string]$text) {
    $line = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "  " + $text
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch { }
}

function Read-Line([IO.Stream]$stream) {
    $bytes = New-Object Collections.Generic.List[byte]
    while ($true) {
        $b = $stream.ReadByte()
        if ($b -lt 0) { break }
        if ($b -eq 10) { break }
        if ($b -ne 13) { $bytes.Add([byte]$b) }
    }
    if ($bytes.Count -eq 0) { return "" }
    return [Text.Encoding]::ASCII.GetString($bytes.ToArray())
}

function Read-Exact([IO.Stream]$stream, [int]$count) {
    $buffer = New-Object byte[] $count
    $read = 0
    while ($read -lt $count) {
        $n = $stream.Read($buffer, $read, $count - $read)
        if ($n -le 0) { break }
        $read += $n
    }
    return $buffer
}

function Send-Text([IO.Stream]$stream, [string]$text) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($text)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

function Send-Status([IO.Stream]$stream, [int]$code, [string]$reason, [string]$extraHeader, [string]$body) {
    if (-not $body) { $body = "$code $reason (IIS-ID lab proxy, mode=$Mode)" }
    $bytes = [Text.Encoding]::ASCII.GetBytes($body)
    $head = "HTTP/1.1 $code $reason`r`n"
    if ($extraHeader) { $head += "$extraHeader`r`n" }
    $head += "Content-Type: text/plain`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
    Send-Text $stream $head
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

function Get-TargetHost([string]$target) {
    if ($target -match '^[a-zA-Z]+://([^/:]+)') { return $Matches[1] }
    if ($target -match '^([^/:]+):\d+$') { return $Matches[1] }
    return $target
}

function Test-Allowed([string]$hostName) {
    foreach ($pattern in $Allow) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        if ($hostName -eq $pattern) { return $true }
        if ($pattern.StartsWith("*") -and $hostName.EndsWith($pattern.TrimStart("*"))) { return $true }
    }
    return $false
}

function Invoke-Forward([IO.Stream]$stream, [string]$method, [string]$target, [hashtable]$headers, [byte[]]$body) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $req = [Net.HttpWebRequest]::Create($target)
        $req.Method = $method
        $req.Proxy = $null                  # never chain into ourselves
        $req.Timeout = 15000
        $req.ReadWriteTimeout = 15000
        $req.AllowAutoRedirect = $false
        $req.UserAgent = "IIS-ID-lab-proxy"
        if ($headers.ContainsKey("content-type")) { $req.ContentType = $headers["content-type"] }
        if ($headers.ContainsKey("accept")) { $req.Accept = $headers["accept"] }
        if ($body -and $body.Length -gt 0) {
            $req.ContentLength = $body.Length
            $out = $req.GetRequestStream()
            $out.Write($body, 0, $body.Length)
            $out.Close()
        }

        $resp = $null
        try { $resp = $req.GetResponse() }
        catch [Net.WebException] {
            if ($_.Exception.Response) { $resp = $_.Exception.Response }
            else { throw }
        }

        $ms = New-Object IO.MemoryStream
        $resp.GetResponseStream().CopyTo($ms)
        $bytes = $ms.ToArray()
        $code = [int]$resp.StatusCode
        $ctype = $resp.ContentType
        if (-not $ctype) { $ctype = "application/octet-stream" }

        $reason = $resp.StatusDescription
        if (-not $reason) { $reason = "OK" }
        $head = "HTTP/1.1 $code $reason`r`nContent-Type: $ctype`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
        Send-Text $stream $head
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $resp.Close()

        Write-Log ("  -> $code  $($bytes.Length) bytes  $($sw.ElapsedMilliseconds) ms")
    }
    catch {
        Write-Log ("  -> UPSTREAM FAILED after $($sw.ElapsedMilliseconds) ms: " + $_.Exception.Message)
        Send-Status $stream 502 "Bad Gateway" $null ("upstream failed: " + $_.Exception.Message)
    }
}

function Invoke-Connect([Net.Sockets.TcpClient]$client, [IO.Stream]$stream, [string]$target) {
    $parts = $target.Split(":")
    if ($parts.Count -ne 2) {
        Send-Status $stream 400 "Bad Request" $null $null
        return
    }
    try {
        $remote = New-Object Net.Sockets.TcpClient($parts[0], [int]$parts[1])
    }
    catch {
        Write-Log ("  -> CONNECT failed: " + $_.Exception.Message)
        Send-Status $stream 502 "Bad Gateway" $null $null
        return
    }
    Send-Text $stream "HTTP/1.1 200 Connection Established`r`n`r`n"
    Write-Log "  -> 200 tunnel established"
    $remoteStream = $remote.GetStream()
    $t1 = $stream.CopyToAsync($remoteStream)
    $t2 = $remoteStream.CopyToAsync($stream)
    [Threading.Tasks.Task]::WaitAny(@($t1, $t2), 120000) | Out-Null
    $remote.Close()
}

function Handle-Client([Net.Sockets.TcpClient]$client) {
    $client.ReceiveTimeout = 20000
    $client.SendTimeout = 20000
    $stream = $client.GetStream()
    $peer = $client.Client.RemoteEndPoint.ToString()

    $requestLine = Read-Line $stream
    if (-not $requestLine) { return }
    $parts = $requestLine.Split(" ")
    if ($parts.Count -lt 2) {
        Write-Log "$peer  BAD REQUEST: $requestLine"
        return
    }
    $method = $parts[0]
    $target = $parts[1]

    $headers = @{}
    while ($true) {
        $line = Read-Line $stream
        if (-not $line) { break }
        $idx = $line.IndexOf(":")
        if ($idx -gt 0) {
            $headers[$line.Substring(0, $idx).Trim().ToLowerInvariant()] = $line.Substring($idx + 1).Trim()
        }
    }

    $body = $null
    if ($headers.ContainsKey("content-length")) {
        $len = 0
        if ([int]::TryParse($headers["content-length"], [ref]$len) -and $len -gt 0) {
            $body = Read-Exact $stream $len
        }
    }

    $hostName = Get-TargetHost $target
    $bodyNote = ""
    if ($body) { $bodyNote = " body=$($body.Length)B" }
    Write-Log "$peer  $method $target$bodyNote"

    switch ($Mode) {
        "auth407" {
            Write-Log "  -> 407 (machine accounts usually cannot answer this)"
            Send-Status $stream 407 "Proxy Authentication Required" 'Proxy-Authenticate: Basic realm="iis-id-lab"' $null
        }
        "deny" {
            Write-Log "  -> 403 (proxy policy)"
            Send-Status $stream 403 "Forbidden" $null $null
        }
        "timeout" {
            Write-Log "  -> silent drop, sleeping $DelaySeconds s (this is what a firewall DROP feels like)"
            Start-Sleep -Seconds $DelaySeconds
        }
        "allowlist" {
            if (Test-Allowed $hostName) {
                if ($method -eq "CONNECT") { Invoke-Connect $client $stream $target }
                else { Invoke-Forward $stream $method $target $headers $body }
            }
            else {
                Write-Log "  -> 403 NOT ORDERED ($hostName is not in -Allow)"
                Send-Status $stream 403 "Forbidden" $null "host $hostName is not on the proxy allowlist"
            }
        }
        default {
            if ($method -eq "CONNECT") { Invoke-Connect $client $stream $target }
            else { Invoke-Forward $stream $method $target $headers $body }
        }
    }
}

$address = [Net.IPAddress]::Loopback
if ($Bind -eq "any") { $address = [Net.IPAddress]::Any }
$listener = New-Object Net.Sockets.TcpListener($address, $Port)
$listener.Start()

Write-Log "lab proxy listening on $($address):$Port  mode=$Mode"
if ($Mode -eq "allowlist") { Write-Log "allowlist: $($Allow -join ', ')" }
Write-Log "log file: $LogPath"
Write-Log "point Windows at it: netsh winhttp set proxy proxy-server=`"127.0.0.1:$Port`" bypass-list=`"<local>`""
if ($Bind -eq "any") {
    Write-Log "guests must be allowed in on the host firewall, e.g.:"
    Write-Log "  New-NetFirewallRule -DisplayName 'IIS-ID lab proxy' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -RemoteAddress 192.168.56.0/24"
}

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try { Handle-Client $client }
        catch { Write-Log ("  !! handler error: " + $_.Exception.Message) }
        finally { try { $client.Close() } catch { } }
    }
}
finally {
    $listener.Stop()
    Write-Log "lab proxy stopped"
}
