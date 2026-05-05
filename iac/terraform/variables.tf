variable "proxmox_endpoint" {
    type = string
}
variable "proxmox_username" {
    type = string
}
variable "proxmox_password" {
    type = string
    sensitive = true
}

variable "node_name" {
    type = string
}
variable "vm_name" {
    type = string
}

variable "cpu_cores" {
    type = number
}
variable "memory" {
    type = number
}

variable "disk_size" {
    type = string
}
variable "storage" {
    type = string
}

variable "bridge" {
    type = string
}

variable "ip_address" {
    type = string
}
variable "gateway" {
    type = string
}

variable "ssh_public_key_path" {
    type = string
    sensitive = true
}
variable "ci_user" {
    type = string
}

variable "ts-auth-key"{
    type = string
    sensitive = true
}
variable "ubuntu_image_file_id" {
    type = string
}