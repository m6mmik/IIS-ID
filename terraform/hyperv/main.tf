# Lab Hyper-V is created by the existing PowerShell (New-LabVm.ps1), not by the
# community Hyper-V provider. That provider talks WinRM to the hypervisor host,
# which on Windows 11 Home is more ceremony than the VM itself. Work Nutanix
# uses a real provider — see ../nutanix.
#
# This root still has state and outputs so the rest of the workflow matches work:
#   terraform apply  ->  VM + switch exist
#   ansible-playbook ->  IIS / ESTEID / netsh / WinHTTP
# Destroy does not Remove-VM: the guest already has Windows on the disk.

resource "terraform_data" "lab_vm" {
  input = {
    vm_name       = var.vm_name
    switch_name   = var.switch_name
    host_ip       = var.host_ip
    prefix_length = var.prefix_length
    memory_gb     = var.memory_gb
    cpu_count     = var.cpu_count
    disk_gb       = var.disk_gb
  }

  provisioner "local-exec" {
    interpreter = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
    command     = "${path.module}/apply-vm.ps1"
    environment = {
      TF_VM_NAME       = var.vm_name
      TF_ISO_PATH      = var.iso_path
      TF_MEMORY_GB     = tostring(var.memory_gb)
      TF_CPU_COUNT     = tostring(var.cpu_count)
      TF_DISK_GB       = tostring(var.disk_gb)
      TF_SWITCH_NAME   = var.switch_name
      TF_HOST_IP       = var.host_ip
      TF_PREFIX_LENGTH = tostring(var.prefix_length)
    }
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["powershell.exe", "-NoProfile", "-Command"]
    command     = "Write-Host 'terraform destroy will not Remove-VM. The guest disk has Windows on it. Delete by hand: Remove-VM -Name ${self.input.vm_name} -Force'"
  }
}
