# Deploiement

## Principe

Terraform et Ansible sont executes depuis une devbox Docker fournie par le
projet. La machine hote n'a donc pas besoin d'installer directement Terraform ou
Ansible.

La machine hote doit surtout disposer de:

- Docker, pour lancer la devbox et construire les images WAF;
- un acces reseau vers Proxmox;
- un acces reseau/SSH vers `dvwa-vm`;
- un acces GHCR seulement si les images doivent etre publiees.

## Devbox IaC

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

Les commandes Terraform et Ansible doivent donc etre lancees depuis ce montage.

## Provisionnement Terraform

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

Commandes usuelles depuis la devbox:

```bash
cd /root/host/terraform
terraform init
terraform plan
terraform apply
```

## Installation Docker Sur La VM

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

## Deploiement DVWA Avec WAF

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

## Services Exposes

Apres deploiement:

| URL | Service |
|---|---|
| `http://dvwa-vm:8080` | DVWA direct |
| `http://dvwa-vm:8081` | Open WAF |
| `http://dvwa-vm:8082` | Custom WAF |

## Arret Des Stacks Compose

Pour arreter les projets Docker Compose trouves dans les dossiers directs du
home de l'utilisateur Ansible:

```bash
cd /root/host/ansible
ansible-playbook -i inventory.ini playbook-compose-down-home.yml
```

## Build Et Push Des Images WAF

Les scripts de build/push sont lances depuis la machine hote Windows, pas
depuis la devbox IaC.

Open WAF:

```powershell
cd openwaf
.\script-waf-opensrc.bat buildpush final latest
```

Custom WAF:

```powershell
cd custom-waf
.\script-waf-custom.bat buildpush final latest
```

Les packages GHCR sont supposes publics pour le deploiement. Aucun `docker
login` n'est execute par Ansible.

Pour publier une nouvelle image avec les scripts `buildpush`, Docker doit deja
etre authentifie sur la machine hote si le registre le demande. Les scripts ne
declenchent aucune authentification Docker.
