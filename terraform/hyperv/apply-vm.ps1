# Called by terraform/hyperv (local-exec). Idempotent: existing VM is success.
# Environment is set by Terraform (TF_*). ASCII-only for Windows PowerShell 5.1.

$ErrorActionPreference = "Stop"
$Name = $env:TF_VM_NAME
if (-not $Name) { throw "TF_VM_NAME is empty. Run this only via terraform apply." }

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$NewLabVm = Join-Path $Root "scripts\New-LabVm.ps1"
if (-not (Test-Path $NewLabVm)) { throw "New-LabVm.ps1 not found at $NewLabVm" }

if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw "Hyper-V cmdlets missing. On Windows Home run scripts\Enable-HyperVHome.ps1 first."
}

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    Write-Host "VM '$Name' already exists - terraform apply is a no-op."
    exit 0
}

$iso = $env:TF_ISO_PATH
if (-not $iso) {
    throw "VM '$Name' does not exist. Set iso_path in terraform.tfvars and apply again."
}

& $NewLabVm `
    -Name $Name `
    -IsoPath $iso `
    -MemoryGB ([int]$env:TF_MEMORY_GB) `
    -CpuCount ([int]$env:TF_CPU_COUNT) `
    -DiskGB ([int]$env:TF_DISK_GB) `
    -SwitchName $env:TF_SWITCH_NAME `
    -HostIp $env:TF_HOST_IP `
    -PrefixLength ([int]$env:TF_PREFIX_LENGTH)
