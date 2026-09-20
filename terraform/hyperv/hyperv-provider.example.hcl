# NOT applied. This is what the same lab would look like with the community
# Hyper-V provider (taliesins/hyperv). That provider requires WinRM *to the
# hypervisor host*, which is extra work on Windows 11 Home. The live root uses
# apply-vm.ps1 instead. Work Nutanix uses a real provider (see ../nutanix).

terraform {
  required_providers {
    hyperv = {
      source  = "taliesins/hyperv"
      version = "~> 1.2"
    }
  }
}

provider "hyperv" {
  host     = "127.0.0.1"
  user     = var.hyperv_user
  password = var.hyperv_password
  https    = true
  insecure = true
  use_ntlm = true
}

resource "hyperv_network_switch" "closed" {
  name                = "IIS-ID-Closed"
  switch_type         = "Internal"
  allow_management_os = true
}

resource "hyperv_vhd" "iis" {
  path = "C:/Users/Public/Documents/Hyper-V/IIS-ID/IIS-ID-Server.vhdx"
  size = 64424509440
}

resource "hyperv_machine_instance" "iis" {
  name           = "IIS-ID-Server"
  generation     = 2
  processor_count = 2
  dynamic_memory = true
  memory_startup_bytes = 4294967296
  memory_minimum_bytes = 1073741824
  memory_maximum_bytes = 4294967296

  network_adaptors {
    name        = "internal"
    switch_name = hyperv_network_switch.closed.name
  }

  hard_disk_drives {
    path                = hyperv_vhd.iis.path
    controller_number   = 0
    controller_location = 0
  }

  dvd_drives {
    controller_number   = 0
    controller_location = 1
    path                = var.iso_path
  }
}
