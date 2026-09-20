resource "nutanix_virtual_machine" "haproxy" {
  name                 = "${var.name_prefix}-haproxy"
  cluster_uuid         = data.nutanix_cluster.this.id
  num_vcpus_per_socket = var.haproxy_vcpu
  num_sockets          = 1
  memory_size_mib      = var.haproxy_memory_mib

  nic_list {
    subnet_uuid = data.nutanix_subnet.this.id
  }

  disk_list {
    data_source_reference {
      kind = "image"
      uuid = var.linux_image_uuid
    }
    disk_size_mib = var.haproxy_disk_mib
  }

  categories = {
    Role = "haproxy"
    App  = var.name_prefix
  }
}

# Terraform stops at "a Linux VM with an IP". haproxy.cfg (mode tcp, check
# port 8080, no ssl on server lines) is ansible/roles/haproxy_passthrough.
# Two HAProxy layers + balance source need send-proxy-v2 — also Ansible, not TF.
