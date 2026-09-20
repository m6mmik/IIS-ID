output "guest_ip" {
  value       = var.guest_ip
  description = "Expected static address inside the guest. Terraform does not assign it."
}

output "host_ip" {
  value = var.host_ip
}

output "vm_name" {
  value = var.vm_name
}

output "ansible_inventory" {
  description = "Paste into ansible/inventories/lab.yml if the address ever changes."
  value       = <<-EOT
    iis:
      hosts:
        ${var.vm_name}:
          ansible_host: ${var.guest_ip}
    EOT
}

output "next" {
  value = "In the guest: powershell -File C:\\IIS-ID\\scripts\\Enable-LabWinRm.ps1 -StaticIp ${var.guest_ip}  then on the host: .\\lab.ps1 ansible"
}
