provider "nutanix" {
  username = var.prism_username
  password = var.prism_password
  endpoint = var.prism_endpoint
  port     = var.prism_port
  insecure = var.prism_insecure
}
