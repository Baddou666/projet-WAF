# Deploiement

## 1. Deploiement Local

Le moyen le plus simple de tester le projet est la stack locale. Elle build les
deux WAF depuis le code du depot et expose les memes ports que la VM.

Depuis la racine du projet:

```bash
docker compose -f docker-compose.local.yml up -d --build
```

Services exposes:

| URL | Service |
|---|---|
| `http://localhost:8080` | DVWA direct |
| `http://localhost:8081` | Open WAF local |
| `http://localhost:8082` | Custom WAF local |

Pour lancer les scans locaux:

```bash
sh scripts/attack.sh http://localhost:8080 scripts/reports/local-dvwa-direct
sh scripts/attack.sh http://localhost:8081 scripts/reports/local-openwaf
sh scripts/attack.sh http://localhost:8082 scripts/reports/local-custom-waf
```

Sous PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://localhost:8080 -OutDir scripts\reports\local-dvwa-direct
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://localhost:8081 -OutDir scripts\reports\local-openwaf
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://localhost:8082 -OutDir scripts\reports\local-custom-waf
```

Pour arreter la stack locale:

```bash
docker compose -f docker-compose.local.yml down
```

## 2. Deploiement Sur Proxmox

Terraform et Ansible sont executes depuis une devbox Docker fournie par le
projet. La machine hote n'a donc pas besoin d'installer directement Terraform ou
Ansible.

La machine hote doit disposer de:

- Docker, pour lancer la devbox;
- un acces reseau vers Proxmox;
- un acces reseau/SSH vers `dvwa-vm`.

Les images WAF utilisees par la VM sont des packages GHCR publics deja
disponibles. Le deploiement Proxmox ne build pas les images.

## 3. Devbox IaC

La devbox est definie par:

- `iac/Dockerfile`
- `iac/docker-compose.yml`

Elle installe notamment:

- Python 3;
- Ansible via `pip3`;
- Terraform via le depot HashiCorp;
- SSH, Git, curl, vim, nano et unzip.

Depuis `iac/`, lancer:

```bash
docker compose up -d --build
docker exec -it waf-devbox bash
```

Dans le conteneur, le dossier `iac/` est monte sous:

```text
/root/host
```

Les commandes Terraform et Ansible doivent etre lancees depuis ce montage.

## 4. Provisionnement Terraform

Les fichiers Terraform se trouvent dans:

```text
iac/terraform/
```

Variables importantes:

| Variable | Role |
|---|---|
| `proxmox_endpoint` | URL de l'API Proxmox |
| `proxmox_username` | utilisateur API Proxmox |
| `proxmox_password` | mot de passe Proxmox |
| `node_name` | noeud Proxmox |
| `vm_name` | nom de la VM, aussi utilise par cloud-init |
| `ubuntu_image_file_id` | image cloud Ubuntu |
| `ssh_public_key_path` | cle publique injectee dans la VM |
| `ts-auth-key` | cle d'authentification Tailscale |

Commandes depuis la devbox:

```bash
cd /root/host/terraform
terraform init
terraform plan
terraform apply
```

## 5. Installation Docker Sur La VM

Depuis la devbox:

```bash
cd /root/host/ansible
ansible-playbook -i inventory.ini playbook-docker-setup.yml
```

Ce playbook:

- installe les paquets prerequis;
- ajoute le depot officiel Docker;
- installe Docker Engine et le plugin Compose;
- active le service Docker;
- ajoute `ansible_user` au groupe `docker`;
- remet la connexion SSH a zero.

Si Docker reste inaccessible sans sudo, reconnecter la session SSH ou relancer
le playbook apres quelques secondes.

## 6. Deploiement DVWA Avec WAF Sur La VM

Depuis la devbox:

```bash
cd /root/host/ansible
ansible-playbook -i inventory.ini dvwa-with-waf-deploy.yml
```

Le playbook:

- verifie que Docker est utilisable par l'utilisateur Ansible;
- cree `~/dvwa-with-waf` sur la VM;
- copie `dvwa-with-waf/docker-compose.yml`;
- lance `docker compose pull`;
- lance `docker compose up -d`.

Services exposes sur la VM:

| URL | Service |
|---|---|
| `http://dvwa-vm:8080` | DVWA direct |
| `http://dvwa-vm:8081` | Open WAF |
| `http://dvwa-vm:8082` | Custom WAF |

## 7. Arret Des Stacks Compose Sur La VM

Pour arreter les projets Docker Compose trouves dans les dossiers directs du
home de l'utilisateur Ansible:

```bash
cd /root/host/ansible
ansible-playbook -i inventory.ini playbook-compose-down-home.yml
```
