variable "prism_endpoint" {
  type        = string
  description = "Prism Central or Prism Element FQDN/IP. Do not commit the real value here."
}

variable "prism_username" {
  type = string
}

variable "prism_password" {
  type      = string
  sensitive = true
}

variable "prism_port" {
  type    = number
  default = 9440
}

variable "prism_insecure" {
  type    = bool
  default = true
}

variable "cluster_name" {
  type = string
}

variable "subnet_name" {
  type        = string
  description = "VLAN the IIS and HAProxy VMs share. HAProxy must reach IIS :443 and :8080."
}

variable "name_prefix" {
  type    = string
  default = "iis-id"
}

variable "windows_image_uuid" {
  type        = string
  description = "Sysprep'd Windows Server image in the Nutanix image service. ISO-at-boot is a lab thing."
}

variable "linux_image_uuid" {
  type        = string
  description = "HAProxy guest (Debian/RHEL). Ansible installs the package and writes haproxy.cfg."
}

variable "iis_count" {
  type        = number
  default     = 2
  description = "Every instance must get the Ansible iis role. A new VM without the role is intermittent 403.16."
}

variable "iis_vcpu" {
  type    = number
  default = 2
}

variable "iis_memory_mib" {
  type    = number
  default = 8192
}

variable "iis_disk_mib" {
  type    = number
  default = 81920
}

variable "haproxy_vcpu" {
  type    = number
  default = 2
}

variable "haproxy_memory_mib" {
  type    = number
  default = 2048
}

variable "haproxy_disk_mib" {
  type    = number
  default = 20480
}

variable "eid_https_port" {
  type    = number
  default = 443
}

variable "eid_health_port" {
  type    = number
  default = 8080
}

variable "ocsp_proxy_cidr" {
  type        = string
  default     = ""
  description = "If set, document that Flow/NSG must allow IIS -> this proxy on 80/443. Empty = allow SK/eidpki directly."
}
