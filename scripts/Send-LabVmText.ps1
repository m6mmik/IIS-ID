# Types into the Hyper-V synthetic keyboard (Msvm_Keyboard). No console focus needed.
# Used so Windows Setup's Administrator password page does not need a human.
#
#   scripts\Send-LabVmText.ps1                  # password + confirm + Enter
#   scripts\Send-LabVmText.ps1 -Text "hello"
#
# Lab password is IisId2026! (also written to .lab\lab-admin.pass).

param(
    [string]$Name = "IIS-ID-Server",
    [string]$Password = "IisId2026!",
    [string]$Text,
    [switch]$AdminPasswordForm
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator PowerShell required (Hyper-V WMI)."
}

$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
if (-not $vm) { throw "VM '$Name' does not exist." }
if ($vm.State -ne "Running") { throw "VM '$Name' is $($vm.State). Start it first." }

$system = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem `
    -Filter "ElementName='$Name'"
$keyboard = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_Keyboard
if (-not $keyboard) { throw "No Msvm_Keyboard on $Name." }

function Send-Text([string]$value) {
    Invoke-CimMethod -InputObject $keyboard -MethodName TypeText -Arguments @{ asciiText = $value } | Out-Null
}

function Send-Key([uint16]$code) {
    Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = $code } | Out-Null
}

if ($Text) {
    Send-Text $Text
    Write-Host "typed $($Text.Length) chars into $Name"
    return
}

# Default: the Setup "Administrator password" form (password, re-enter, Next).
$lab = Join-Path (Split-Path -Parent $PSScriptRoot) ".lab"
New-Item -ItemType Directory -Force -Path $lab | Out-Null
Set-Content -Path (Join-Path $lab "lab-admin.pass") -Value $Password -NoNewline

Write-Host "Typing Administrator password into $Name (IisId2026!)"
Start-Sleep -Seconds 1
Send-Text $Password
Start-Sleep -Milliseconds 400
Send-Key 0x09
Start-Sleep -Milliseconds 400
Send-Text $Password
Start-Sleep -Milliseconds 400
Send-Key 0x0D
Write-Host "sent password, Tab, password, Enter"
Write-Host "WinRM later: `$env:LAB_WINRM_PASSWORD = 'IisId2026!'"
