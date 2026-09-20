# Test-LabVm.ps1
#
# Answers "why does this VM say 'No operating system was loaded'" with facts
# instead of guesses. Three things can cause it and they look identical on screen:
#   1. nobody pressed a key at "Press any key to boot from CD/DVD" (~2 s window)
#   2. the DVD is not first in the boot order / the ISO is not attached
#   3. the ISO cannot boot this machine type: wrong architecture (ARM64 image on
#      an x64 VM has no \efi\boot\bootx64.efi), not a Windows installation image,
#      or a truncated download
#
# Read-only apart from temporarily mounting the ISO on the host.
# Run as Administrator:  powershell -ExecutionPolicy Bypass -File scripts\Test-LabVm.ps1

param(
    [string]$Name = "IIS-ID-Server",
    [string]$IsoPath
)

$ErrorActionPreference = "Continue"

function Section([string]$text) {
    Write-Host ""
    Write-Host "== $text"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT ADMIN - Hyper-V cmdlets will return nothing. Reopen PowerShell as Administrator."
}

Section "Virtual machine"
$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
if (-not $vm) {
    Write-Host "VM '$Name' not found. Existing VMs:"
    Get-VM -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $($_.Name)  state=$($_.State)  gen=$($_.Generation)" }
}
else {
    Write-Host "name        : $($vm.Name)"
    Write-Host "state       : $($vm.State)"
    Write-Host "generation  : $($vm.Generation)   (Gen2 = UEFI only, Gen1 = BIOS)"
    Write-Host "memory      : $([math]::Round($vm.MemoryAssigned / 1GB, 2)) GB assigned, startup $([math]::Round($vm.MemoryStartup / 1GB, 2)) GB"
    Write-Host "cpu         : $($vm.ProcessorCount)"

    Section "DVD drive"
    $dvds = @(Get-VMDvdDrive -VMName $Name -ErrorAction SilentlyContinue)
    if ($dvds.Count -eq 0) {
        Write-Host "NO DVD DRIVE -> this alone explains the message."
        Write-Host "Fix: .\lab.ps1 vm-fix <iso path>"
    }
    foreach ($dvd in $dvds) {
        Write-Host "controller $($dvd.ControllerNumber):$($dvd.ControllerLocation)  path=$($dvd.Path)"
        if (-not $dvd.Path) { Write-Host "  EMPTY drive -> attach the ISO: .\lab.ps1 vm-fix <iso path>" }
        elseif (-not (Test-Path $dvd.Path)) { Write-Host "  FILE MISSING on the host: $($dvd.Path)" }
        else {
            $size = (Get-Item $dvd.Path).Length
            Write-Host "  file exists, $([math]::Round($size / 1GB, 2)) GB"
            if (-not $IsoPath) { $IsoPath = $dvd.Path }
        }
    }

    Section "Firmware / boot order"
    $fw = Get-VMFirmware -VMName $Name -ErrorAction SilentlyContinue
    if ($fw) {
        Write-Host "secure boot : $($fw.SecureBoot)  template=$($fw.SecureBootTemplate)"
        $index = 1
        foreach ($entry in $fw.BootOrder) {
            $desc = $entry.BootType
            if ($entry.Device) { $desc = "$desc  $($entry.Device)" }
            Write-Host "  $index. $desc"
            $index++
        }
        if ($fw.BootOrder.Count -gt 0 -and $fw.BootOrder[0].BootType -ne "Drive") {
            Write-Host "  NB: first entry is not a drive. Fix: .\lab.ps1 vm-fix"
        }
    }

    Section "Disk"
    foreach ($drive in @(Get-VMHardDiskDrive -VMName $Name -ErrorAction SilentlyContinue)) {
        Write-Host "vhd: $($drive.Path)"
        $vhd = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
        if ($vhd) {
            Write-Host "  size $([math]::Round($vhd.Size / 1GB, 1)) GB, used $([math]::Round($vhd.FileSize / 1GB, 2)) GB"
            if ($vhd.FileSize -lt 200MB) {
                Write-Host "  practically empty -> nothing installed yet, so booting from DVD is mandatory"
            }
        }
    }
}

Section "ISO contents (the check that usually finds the real problem)"
if (-not $IsoPath) {
    Write-Host "No ISO path known. Pass -IsoPath <file>."
    return
}
if (-not (Test-Path $IsoPath)) {
    Write-Host "ISO not found: $IsoPath"
    return
}

Write-Host "file: $IsoPath"
Write-Host "size: $([math]::Round((Get-Item $IsoPath).Length / 1GB, 2)) GB"

$mounted = $null
try {
    $mounted = Mount-DiskImage -ImagePath $IsoPath -PassThru -ErrorAction Stop
    $letter = ($mounted | Get-Volume).DriveLetter
    if (-not $letter) { throw "mounted but no drive letter" }
    $root = "$letter`:\"
    Write-Host "mounted at $root"

    $bootFiles = @(Get-ChildItem (Join-Path $root "efi\boot") -Filter *.efi -ErrorAction SilentlyContinue)
    if ($bootFiles.Count -eq 0) {
        Write-Host "VERDICT: no \efi\boot\*.efi -> this image cannot boot a Generation 2 (UEFI) VM."
        Write-Host "  Either it is not a Windows installation ISO, or the download is truncated."
        Write-Host "  A Generation 1 VM (BIOS) could still boot it if \bootmgr exists:"
        Write-Host "    bootmgr present: $([bool](Test-Path (Join-Path $root 'bootmgr')))"
    }
    else {
        foreach ($file in $bootFiles) { Write-Host "  efi\boot\$($file.Name)" }
        $hasX64 = @($bootFiles | Where-Object { $_.Name -ieq "bootx64.efi" }).Count -gt 0
        $hasArm = @($bootFiles | Where-Object { $_.Name -ieq "bootaa64.efi" }).Count -gt 0
        if (-not $hasX64 -and $hasArm) {
            Write-Host "VERDICT: this is an ARM64 image. An x64 Hyper-V VM cannot boot it."
            Write-Host "  Download the x64 (AMD64) Windows Server evaluation ISO."
        }
        elseif ($hasX64) {
            Write-Host "VERDICT: x64 UEFI boot files present - the image is bootable on Gen2."
        }
    }

    $install = @(Get-ChildItem (Join-Path $root "sources") -Filter "install.*" -ErrorAction SilentlyContinue)
    if ($install.Count -eq 0) {
        Write-Host "WARNING: \sources\install.wim / install.esd missing -> not a Windows setup image."
    }
    else {
        foreach ($file in $install) {
            Write-Host "  sources\$($file.Name)  $([math]::Round($file.Length / 1GB, 2)) GB"
        }
    }

    $setup = Test-Path (Join-Path $root "setup.exe")
    Write-Host "  setup.exe present: $setup"
}
catch {
    Write-Host "Could not mount the ISO: $($_.Exception.Message)"
    Write-Host "A file that cannot be mounted is usually a broken or partial download."
}
finally {
    if ($mounted) {
        Dismount-DiskImage -ImagePath $IsoPath | Out-Null
        Write-Host "dismounted"
    }
}

Write-Host ""
Write-Host "If the ISO is fine and the boot order is fine, the remaining cause is timing:"
Write-Host "  vmconnect.exe localhost $Name    (open console first)"
Write-Host "  Start-VM -Name $Name             (then start)"
Write-Host "  press SPACE repeatedly at once - the CD/DVD prompt lasts about two seconds"
