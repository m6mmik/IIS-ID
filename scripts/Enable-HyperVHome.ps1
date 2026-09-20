# Enable-HyperVHome.ps1
#
# Enables Hyper-V on Windows 10/11 HOME, where it is not offered by default.
# Method: the Hyper-V servicing packages are present on disk even on Home, so
# they are added with DISM first and only then is the feature switched on.
# Based on the widely used community recipe:
#   https://gist.github.com/HimDek/6edde284203a620745fad3f762be603b
#
# READ BEFORE RUNNING:
#   - This is NOT a Microsoft supported configuration on Home. A future Windows
#     update can remove it again; then just run this script once more.
#   - A reboot is required, twice in some builds.
#   - Enabling Hyper-V puts Windows itself on top of the hypervisor. VirtualBox
#     and some Android emulators become slower afterwards. WSL2 and VBS keep
#     working (they already use the same hypervisor).
#   - "systeminfo" saying "A hypervisor has been detected" does NOT mean Hyper-V
#     is available: it usually means VBS or WSL2 is running. The real test is
#     whether Get-Command New-VM and Get-VMSwitch exist, which is what this
#     script checks at the end.
#
# Usage (Administrator):
#   powershell -ExecutionPolicy Bypass -File scripts\Enable-HyperVHome.ps1 -Preview
#   powershell -ExecutionPolicy Bypass -File scripts\Enable-HyperVHome.ps1

param(
    [switch]$Preview,
    [switch]$Restart
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script needs an Administrator PowerShell."
    }
}

$edition = (Get-CimInstance Win32_OperatingSystem).Caption
$packages = @(Get-ChildItem (Join-Path $env:SystemRoot "servicing\Packages\*Hyper-V*.mum") -ErrorAction SilentlyContinue)

Write-Host ""
Write-Host "edition           : $edition"
Write-Host "Hyper-V packages  : $($packages.Count) found on disk"
Write-Host "New-VM available  : $([bool](Get-Command New-VM -ErrorAction SilentlyContinue))"

if ($edition -notmatch "Home") {
    Write-Host ""
    Write-Host "This edition supports Hyper-V directly - no package trick needed:"
    Write-Host "  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All"
}

if ($packages.Count -eq 0) {
    throw "No Hyper-V servicing packages found. This build cannot be converted this way."
}

if ($Preview) {
    Write-Host ""
    Write-Host "PREVIEW (nothing is changed)"
    Write-Host "would add $($packages.Count) packages with DISM (/norestart); grouped:"
    $packages |
        Group-Object { ($_.Name -split '~')[0] } |
        Sort-Object Name |
        ForEach-Object { Write-Host ("    {0}  x{1}" -f $_.Name, $_.Count) }
    Write-Host "(several are language variants of the same package; most of the time is spent here)"
    Write-Host "would then enable features: Microsoft-Hyper-V-All, VirtualMachinePlatform, HypervisorPlatform"
    Write-Host "would then require a reboot"
    return
}

Assert-Admin

Write-Host ""
Write-Host "== Adding Hyper-V servicing packages (this takes a few minutes)"
$failed = 0
foreach ($package in $packages) {
    $out = & dism.exe /online /norestart "/add-package:$($package.FullName)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $failed++
        Write-Host "  WARN $($package.Name) -> exit $LASTEXITCODE"
    }
    else {
        Write-Host "  ok   $($package.Name)"
    }
}
if ($failed -gt 0) {
    Write-Host "$failed package(s) reported an error. That is common (already installed / not applicable)."
}

Write-Host ""
Write-Host "== Enabling features"
foreach ($feature in @("Microsoft-Hyper-V-All", "VirtualMachinePlatform", "HypervisorPlatform")) {
    try {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
        Write-Host "  $feature -> RestartNeeded=$($result.RestartNeeded)"
    }
    catch {
        Write-Host "  $feature -> FAILED: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "REBOOT NOW, then verify with:"
Write-Host "  Get-Command New-VM ; Get-VMSwitch"
Write-Host "If New-VM still does not exist after the reboot, open 'Turn Windows features"
Write-Host "on or off' and tick Hyper-V + Virtual Machine Platform + Windows Hypervisor"
Write-Host "Platform by hand - the packages are installed now, so they will be listed."
Write-Host ""
Write-Host "After that, create the lab VM:"
Write-Host "  scripts\New-LabVm.ps1 -IsoPath D:\iso\WindowsServer.iso -Preview"

if ($Restart) {
    Write-Host ""
    Write-Host "Restarting in 10 seconds (Ctrl+C to cancel)..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
