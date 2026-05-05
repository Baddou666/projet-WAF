#cloud-config
hostname: ${hostname}
users:
  - default
  - name: ${hostname}
    groups:
      - sudo
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${devbox_ssh_pubkey}
    sudo: ALL=(ALL) NOPASSWD:ALL
package_update: true
package_upgrade: false          # ← Très important
package_reboot_if_required: false
packages:
  - python3
  - curl

runcmd:
  - curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up --auth-key=${ts-auth-key}