resource "nutanix_virtual_machine" "iis" {
  count = var.iis_count

  name                 = "${var.name_prefix}-iis-${count.index + 1}"
  cluster_uuid         = data.nutanix_cluster.this.id
  num_vcpus_per_socket = var.iis_vcpu
  num_sockets          = 1
  memory_size_mib      = var.iis_memory_mib

  nic_list {
    subnet_uuid = data.nutanix_subnet.this.id
  }

  disk_list {
    data_source_reference {
      kind = "image"
      uuid = var.windows_image_uuid
    }
    disk_size_mib = var.iis_disk_mib
  }

  # Nutanix 1.x map form. 2.x may want a categories { name = ... } block.
  categories = {
    Role = "iis"
    App  = var.name_prefix
  }

  # Do not bake ESTEID into the image only. Ansible must run on every scale-out.
}

# Egress is only the revocation foot-gun. PIN1 trust (403.16) needs the four
# CA files in stores — Ansible copies them; no SK hole required.
# verifyclientcertrevocation=enable without egress => 403.13 (not 16).
# Schannel uses WinHTTP, not IE and not Web.config.
#
# Required from EVERY IIS VM:
#   HAProxy -> :443 (mTLS) and :8080 (health, no client cert)
#   If revocation is on: corporate proxy 80/443  OR
#     aia.sk.ee / ocsp.eidpki.ee / ocsp.sk.ee / c.sk.ee / crt.eidpki.ee / crl.eidpki.ee
#
# Put that in the work Flow / NSG module. The resource name differs per Nutanix
# version, so it is not hard-coded here — only the ports and destinations matter.
