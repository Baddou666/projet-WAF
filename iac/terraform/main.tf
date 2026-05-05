data "local_file" "ssh_pubkey"{
    filename = var.ssh_public_key_path
}
resource "proxmox_virtual_environment_file" "cloud_config" {
    content_type = "snippets"
    datastore_id = "local"
    node_name    = var.node_name
    source_raw{
      data = templatefile("${path.module}/cloud_config.yml.tpl", {
      ts-auth-key = var.ts-auth-key,
      hostname = var.vm_name,
      devbox_ssh_pubkey = data.local_file.ssh_pubkey.content})
      file_name = "vm-waf-cloud-init.yaml"
    }
}
resource "proxmox_virtual_environment_vm" "dvwa_vm" {
  name      = var.vm_name
  node_name = var.node_name

  cpu {
    cores = var.cpu_cores
  }

  memory {
    dedicated = var.memory
  }

  disk {
    datastore_id = var.storage
    size         = var.disk_size
    interface    = "scsi0"
    file_id      = var.ubuntu_image_file_id
  }

  network_device {
    bridge = var.bridge
  }

  operating_system {
    type = "l26"
  }

  initialization {
    dns{
        servers = ["1.1.1.1","8.8.8.8","8.8.4.4"]
      }
    ip_config {
      ipv4 {
        address = var.ip_address
        gateway = var.gateway
      }
    }
    user_data_file_id = proxmox_virtual_environment_file.cloud_config.id
  }
}