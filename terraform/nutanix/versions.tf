terraform {
  required_version = ">= 1.4.0"

  required_providers {
    nutanix = {
      source  = "nutanix/nutanix"
      version = "~> 1.9"
    }
  }
}

# Pin this to the same version the work repo already uses. The VM resource
# schema moved between 1.x and 2.x (categories, disk_list, nic_list).
# After copy: terraform init && terraform validate against Prism, not against
# this lab machine.
