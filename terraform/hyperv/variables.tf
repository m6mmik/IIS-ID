variable "vm_name" {
  type        = string
  default     = "IIS-ID-Server"
  description = "Generation 2 Hyper-V VM. Windows Setup is still interactive."
}

variable "iso_path" {
  type        = string
  default     = ""
  description = "Windows Server ISO. Required only when the VM does not exist yet."
}

variable "memory_gb" {
  type    = number
  default = 4
}

variable "cpu_count" {
  type    = number
  default = 2
}

variable "disk_gb" {
  type    = number
  default = 60
}

variable "switch_name" {
  type    = string
  default = "IIS-ID-Closed"
}

variable "host_ip" {
  type        = string
  default     = "192.168.56.1"
  description = "Address on the host vEthernet adapter. Guest uses host_ip as WinHTTP proxy."
}

variable "guest_ip" {
  type        = string
  default     = "192.168.56.10"
  description = "Set inside the guest by Enable-LabWinRm.ps1 / Ansible. Terraform only records it."
}

variable "prefix_length" {
  type    = number
  default = 24
}
