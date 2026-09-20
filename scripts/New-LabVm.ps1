# New-LabVm.ps1
#
# Creates the Hyper-V VM for the closed-network lab: a Windows Server guest whose
# ONLY network is an internal switch shared with the host. There is no NAT, no
# DHCP and no route to the internet - which is the entire point. Everything the
# guest needs (files, AIA/OCSP access) has to come from the host, exactly like a
# production server where access is ordered one URL at a time.
#
#   host   192.168.56.1   runs the logging proxy (.\lab.ps1 proxy -Bind any)
#   guest  192.168.56.10  IIS + Demo.Service, WinHTTP proxy -> host
#
# Usage (Administrator, after Hyper-V is available):
#   scripts\New-LabVm.ps1 -IsoPath D:\iso\WindowsServer2025.iso -Preview
#   scripts\New-LabVm.ps1 -IsoPath D:\iso\WindowsServer2025.iso
#
# Guest Services are enabled, so you can push the built repository into the VM
# without any network at all:
#   Copy-VMFile -Name IIS-ID-Server -SourcePath C:\Users\...\IIS-ID -DestinationPath C:\IIS-ID -FileSource Host -CreateFullPath -Recurse

param(
    [string]$Name = "IIS-ID-Server",
    [string]$IsoPath,
    [int]$MemoryGB = 4,
    [int]$CpuCount = 2,
    [int]$DiskGB = 60,
    [string]$SwitchName = "IIS-ID-Closed",
    [string]$HostIp = "192.168.56.1",
    [int]$PrefixLength = 24,
    [string]$VmPath,
    [ValidateSet(1, 2)]
    [int]$Generation = 2,
    [switch]$WithInternet,
    [switch]$FixBoot,
    [switch]$NoSecureBoot,
    [switch]$StartWithKey,
    [int]$KeySeconds = 12,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"
if (-not $VmPath) { $VmPath = Join-Path $env:PUBLIC "Documents\Hyper-V\IIS-ID" }
$vhdPath = Join-Path $VmPath "$Name.vhdx"
$adapterAlias = "vEthernet ($SwitchName)"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script needs an Administrator PowerShell."
    }
}

function Step([string]$text) {
    Write-Host ""
    Write-Host "== $text"
}

if ($Preview) {
    Write-Host ""
    Write-Host "PREVIEW (nothing is changed)"
    Write-Host "vm name        : $Name"
    Write-Host "vm files       : $VmPath"
    Write-Host "disk           : $vhdPath  ($DiskGB GB dynamic)"
    Write-Host "memory / cpu   : $MemoryGB GB dynamic / $CpuCount vCPU"
    Write-Host "generation     : $Generation $(if ($Generation -eq 2) { '(UEFI; needs \efi\boot\bootx64.efi on the ISO)' } else { '(BIOS fallback)' })"
    Write-Host "switch         : $SwitchName (Internal - host and guest only, no internet)"
    Write-Host "host address   : $HostIp/$PrefixLength on '$adapterAlias'"
    Write-Host "guest address  : set by hand inside the VM, e.g. 192.168.56.10/$PrefixLength, no gateway"
    Write-Host "second adapter : $(if ($WithInternet) { 'Default Switch (temporary internet)' } else { 'none - closed network from the start' })"
    Write-Host "installation   : $(if ($IsoPath) { $IsoPath } else { '(no -IsoPath given)' })"
    Write-Host "guest services : enabled, so Copy-VMFile works without network"
    return
}

Assert-Admin

if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    throw "Hyper-V cmdlets are missing. On Windows Home run scripts\Enable-HyperVHome.ps1 first (and reboot)."
}

# The "Press any key to boot from CD/DVD" prompt lives for about two seconds and
# a Generation 2 VM has no second chance: it falls through to the empty disk and
# prints "No operating system was loaded". Instead of racing it by hand, type the
# key into the VM's synthetic keyboard over WMI, which works whether or not the
# console window has focus.
if ($StartWithKey) {
    Assert-Admin
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$Name' does not exist." }

    Step "Starting $Name and holding the CD/DVD prompt open"
    if ($vm.State -ne "Off") {
        Stop-VM -Name $Name -TurnOff -Force
        Start-Sleep -Seconds 2
    }
    Start-Process vmconnect.exe -ArgumentList @("localhost", $Name) -ErrorAction SilentlyContinue | Out-Null
    Start-VM -Name $Name | Out-Null

    $system = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem `
        -Filter "ElementName='$Name'" -ErrorAction SilentlyContinue
    $keyboard = $null
    if ($system) {
        $keyboard = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_Keyboard -ErrorAction SilentlyContinue
    }
    if (-not $keyboard) {
        Write-Host "Could not reach the virtual keyboard over WMI."
        Write-Host "Press SPACE in the console window yourself, now."
        return
    }

    $deadline = (Get-Date).AddSeconds($KeySeconds)
    $presses = 0
    while ((Get-Date) -lt $deadline) {
        Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = [uint16]0x20 } | Out-Null
        $presses++
        Start-Sleep -Milliseconds 250
    }
    Write-Host "sent SPACE $presses times over $KeySeconds s"
    Write-Host "Windows Setup should now be loading files. If it still says"
    Write-Host "'No operating system was loaded', run .\lab.ps1 vm-check."
    return
}

# "No operating system was loaded" on a Generation 2 VM is almost always one of
# three things: the DVD is not first in the boot order, the ISO fell off the
# drive, or nobody pressed a key at "Press any key to boot from CD/DVD" in the
# two seconds it is offered. This fixes the first two and warns about the third.
if ($FixBoot) {
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM '$Name' does not exist yet. Create it first (without -FixBoot)." }

    Step "Fixing boot configuration of $Name"
    if ($vm.State -ne "Off") {
        Stop-VM -Name $Name -TurnOff -Force
        Write-Host "VM turned off"
    }

    $dvd = Get-VMDvdDrive -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $dvd) {
        if (-not $IsoPath) { throw "No DVD drive on the VM and no -IsoPath given." }
        Add-VMDvdDrive -VMName $Name -Path $IsoPath
        $dvd = Get-VMDvdDrive -VMName $Name | Select-Object -First 1
        Write-Host "DVD drive added with $IsoPath"
    }
    elseif ($IsoPath) {
        Set-VMDvdDrive -VMName $Name -Path $IsoPath
        Write-Host "ISO re-attached: $IsoPath"
    }
    elseif (-not $dvd.Path) {
        throw "The DVD drive is empty. Pass -IsoPath as well."
    }
    else {
        Write-Host "ISO already attached: $($dvd.Path)"
    }

    $dvd = Get-VMDvdDrive -VMName $Name | Select-Object -First 1
    # Drop the network adapter from the boot order: a PXE attempt on an internal
    # switch only adds a timeout to every retry.
    $order = @($dvd)
    $hdd = Get-VMHardDiskDrive -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hdd) { $order += $hdd }
    if ($NoSecureBoot) {
        Set-VMFirmware -VMName $Name -BootOrder $order -EnableSecureBoot Off
        Write-Host "boot order: DVD, then disk. Secure Boot OFF"
    }
    else {
        Set-VMFirmware -VMName $Name -BootOrder $order -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
        Write-Host "boot order: DVD, then disk. Secure Boot ON (MicrosoftWindows template)"
    }

    Write-Host ""
    Write-Host "Now start it WITHOUT racing the prompt by hand:"
    Write-Host "  .\lab.ps1 vm-start        (sends SPACE into the VM keyboard over WMI)"
    Write-Host ""
    Write-Host "By hand it would be: open vmconnect FIRST, click inside it, Start-VM, then"
    Write-Host "hammer SPACE - the prompt lasts about two seconds."
    Write-Host ""
    Write-Host "If it still fails, retry with -NoSecureBoot (some rebuilt or non-MS ISOs"
    Write-Host "are not signed for the MicrosoftWindows template)."
    return
}
if (-not $IsoPath -or -not (Test-Path $IsoPath)) {
    Write-Host ""
    Write-Host "ISO not found."
    if ($IsoPath) {
        Write-Host "  looked for : '$IsoPath'"
        $folder = Split-Path -Parent $IsoPath
        if (-not $folder) { $folder = (Get-Location).Path }
        $candidates = @(Get-ChildItem -LiteralPath $folder -Filter "*.iso" -File -ErrorAction SilentlyContinue)
        if ($candidates.Count -gt 0) {
            Write-Host "  found in $folder :"
            foreach ($c in $candidates) { Write-Host "    '$($c.Name)'  ($([math]::Round($c.Length / 1GB, 1)) GB)" }
            Write-Host "  NB: a name with a space needs quotes, e.g. .\lab.ps1 vm ""$folder\$($candidates[0].Name)"""
        }
    }
    throw "Give a Windows Server ISO: .\lab.ps1 vm D:\iso\WindowsServer.iso  (evaluation ISO is fine, 180 days)"
}
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    throw "VM '$Name' already exists. Remove it first or pass another -Name."
}

Step "Internal switch: host and guest only"
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Host "created switch $SwitchName (Internal: no NAT, no DHCP, no internet)"
}
else {
    Write-Host "switch $SwitchName already exists"
}

# The internal switch gives the host a virtual adapter. Without a static address
# on it the host is unreachable from the guest, and the proxy trick cannot work.
Start-Sleep -Seconds 2
$existing = Get-NetIPAddress -InterfaceAlias $adapterAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $HostIp }
if (-not $existing) {
    Get-NetIPAddress -InterfaceAlias $adapterAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -eq "WellKnown" -or $_.PrefixOrigin -eq "Manual" } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $adapterAlias -IPAddress $HostIp -PrefixLength $PrefixLength | Out-Null
    Write-Host "host address $HostIp/$PrefixLength on '$adapterAlias'"
}
else {
    Write-Host "host already has $HostIp on '$adapterAlias'"
}

Step "Virtual machine (generation $Generation)"
New-Item -ItemType Directory -Force -Path $VmPath | Out-Null
New-VM -Name $Name -MemoryStartupBytes ($MemoryGB * 1GB) -Generation $Generation `
    -NewVHDPath $vhdPath -NewVHDSizeBytes ($DiskGB * 1GB) -SwitchName $SwitchName -Path $VmPath | Out-Null
Set-VMProcessor -VMName $Name -Count $CpuCount
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $true -MinimumBytes 1GB -MaximumBytes ($MemoryGB * 1GB)
Set-VM -VMName $Name -AutomaticCheckpointsEnabled $false -CheckpointType Production
Write-Host "$Name : $CpuCount vCPU, up to $MemoryGB GB, $DiskGB GB dynamic disk"

Step "Installation media and boot order"
if ($Generation -eq 2) {
    Add-VMDvdDrive -VMName $Name -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $Name | Select-Object -First 1
    if ($NoSecureBoot) {
        Set-VMFirmware -VMName $Name -FirstBootDevice $dvd -EnableSecureBoot Off
        Write-Host "UEFI boot from $IsoPath, Secure Boot OFF"
    }
    else {
        Set-VMFirmware -VMName $Name -FirstBootDevice $dvd -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
        Write-Host "UEFI boot from $IsoPath, Secure Boot ON"
    }
}
else {
    # Generation 1 is the fallback for images without \efi\boot\bootx64.efi.
    $dvd = Get-VMDvdDrive -VMName $Name | Select-Object -First 1
    if ($dvd) { Set-VMDvdDrive -VMName $Name -Path $IsoPath }
    else { Add-VMDvdDrive -VMName $Name -Path $IsoPath }
    Set-VMBios -VMName $Name -StartupOrder @("CD", "IDE", "LegacyNetworkAdapter", "Floppy")
    Write-Host "BIOS boot from $IsoPath (no Secure Boot on generation 1)"
}

Step "Unattend ISO (silent Setup + Administrator IisId2026! + WinRM)"
$unattendIso = Join-Path (Split-Path -Parent $PSScriptRoot) ".lab\unattend.iso"
try {
    & (Join-Path $PSScriptRoot "New-UnattendIso.ps1") -IsoPath $unattendIso
    $already = Get-VMDvdDrive -VMName $Name | Where-Object { $_.Path -eq $unattendIso }
    if (-not $already) {
        Add-VMDvdDrive -VMName $Name -Path $unattendIso
        Write-Host "second DVD: $unattendIso (not first in boot order)"
    }
}
catch {
    Write-Host "unattend ISO skipped: $($_.Exception.Message)"
}

Step "Guest services (file copy without network)"
Enable-VMIntegrationService -VMName $Name -Name "Guest Service Interface"
Write-Host "Copy-VMFile is now usable from the host"

if ($WithInternet) {
    Step "Temporary second adapter with internet"
    $default = Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue
    if ($default) {
        Add-VMNetworkAdapter -VMName $Name -SwitchName "Default Switch" -Name "Temporary internet"
        Write-Host "added 'Temporary internet' adapter. REMOVE IT before testing closed-network behaviour:"
        Write-Host "  Remove-VMNetworkAdapter -VMName $Name -Name 'Temporary internet'"
    }
    else {
        Write-Host "Default Switch not found - continuing without internet (which is the goal anyway)"
    }
}

Write-Host ""
Write-Host "DONE. Next steps:"
Write-Host "  1. vmconnect.exe localhost $Name   THEN   Start-VM -Name $Name"
Write-Host "     Click inside the console and press SPACE at once: 'Press any key to boot"
Write-Host "     from CD/DVD' lasts ~2 s, and if you miss it a Generation 2 VM says"
Write-Host "     'No operating system was loaded'. Fix + retry: scripts\New-LabVm.ps1 -FixBoot"
Write-Host "  2. Install Windows Server (Desktop Experience is easier for the first round)"
Write-Host "  3. In the guest set a static address, there is no DHCP on an internal switch:"
Write-Host "       New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 192.168.56.10 -PrefixLength $PrefixLength"
Write-Host "  4. On the host build and push the repo (no network needed):"
Write-Host "       .\lab.ps1 build"
Write-Host "       Copy-VMFile -Name $Name -SourcePath <repo> -DestinationPath C:\IIS-ID -FileSource Host -CreateFullPath -Recurse"
Write-Host "  5. In the guest: powershell -ExecutionPolicy Bypass -File C:\IIS-ID\scripts\Install-LabServer.ps1"
Write-Host "  6. On the host: .\lab.ps1 proxy   (add -Bind any and allow inbound 3128 from 192.168.56.0/24)"
Write-Host "     In the guest: netsh winhttp set proxy proxy-server=`"$($HostIp):3128`" bypass-list=`"<local>`""
Write-Host "  7. Checkpoint-VM -Name $Name -SnapshotName 'clean lab'   <- do this before breaking things"
