terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.60.0"
    }
  }
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  username = var.proxmox_username
  password = var.proxmox_password
  insecure = true
  ssh {
    username = "root"
    password = var.proxmox_password
    agent = true
    node {
      name    = "fanida"
      address = "fanida"
    }
  }
}