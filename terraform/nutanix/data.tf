data "nutanix_cluster" "this" {
  name = var.cluster_name
}

data "nutanix_subnet" "this" {
  subnet_name = var.subnet_name
}
