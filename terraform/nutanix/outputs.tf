output "iis_ips" {
  value = [
    for vm in nutanix_virtual_machine.iis :
    try(vm.nic_list_status[0].ip_endpoint_list[0].ip, "")
  ]
}

output "haproxy_ip" {
  value = try(nutanix_virtual_machine.haproxy.nic_list_status[0].ip_endpoint_list[0].ip, "")
}

output "eid_https_port" {
  value = var.eid_https_port
}

output "eid_health_port" {
  value = var.eid_health_port
}

output "ocsp_proxy_cidr" {
  value = var.ocsp_proxy_cidr
}

output "ansible_inventory" {
  description = "Write this to ansible/inventories/work.yml (or generate it in CI). The roles stay in ansible/roles/."
  value       = <<-EOT
    all:
      children:
        iis:
          hosts:
    %{for i, vm in nutanix_virtual_machine.iis~}
            ${var.name_prefix}-iis-${i + 1}:
              ansible_host: ${try(vm.nic_list_status[0].ip_endpoint_list[0].ip, "SET_ME")}
              eid_https_port: ${var.eid_https_port}
              eid_health_port: ${var.eid_health_port}
    %{endfor~}
        haproxy:
          hosts:
            ${var.name_prefix}-haproxy:
              ansible_host: ${try(nutanix_virtual_machine.haproxy.nic_list_status[0].ip_endpoint_list[0].ip, "SET_ME")}
    EOT
}
