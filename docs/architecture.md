# Architecture

## Objectif

Le laboratoire compare trois chemins d'acces vers DVWA:

1. acces direct a DVWA;
2. acces via l'image `waf-open-source` construite dans `openwaf/`;
3. acces via un WAF custom developpe en Node.js.

Cette organisation permet de mesurer le comportement des protections face a des
payloads SQLi, XSS et a du trafic benin.

## Flux Reseau

Sur la VM, le nom cible est `dvwa-vm`. En local, le meme mapping de ports est
disponible sur `localhost` via `docker-compose.local.yml`.

```text
Client de test
    |
    |-- http://dvwa-vm:8080 --> DVWA direct
    |
    |-- http://dvwa-vm:8081 --> Open WAF --> DVWA
    |
    `-- http://dvwa-vm:8082 --> Custom WAF --> DVWA
```

`dvwa-vm` est le nom MagicDNS Tailscale de la VM de laboratoire.

## Composants

### DVWA

DVWA est l'application volontairement vulnerable utilisee comme cible. Elle est
deployee avec une base de donnees MariaDB ou MySQL selon le compose utilise.

Fichiers principaux:

- `iac/ansible/dvwa/docker-compose.yml`
- `iac/ansible/dvwa-with-waf/docker-compose.yml`

### Open WAF

L'Open WAF est l'image `waf-open-source` construite depuis le dossier
`openwaf/`. Ce dossier contient une configuration Nginx/ModSecurity locale:

- `openwaf/nginx.conf`
- `openwaf/modsecurity.conf`
- `openwaf/crs-setup.conf`
- `openwaf/rules/custom-exclusions.conf`

Dans l'etat actuel du Dockerfile, l'image part de
`owasp/modsecurity-crs:nginx-alpine` et copie seulement le fichier d'exclusions
CRS:

```text
openwaf/rules/custom-exclusions.conf
```

La configuration runtime active est fournie par variables d'environnement dans
`iac/ansible/dvwa-with-waf/docker-compose.yml`:

- `BACKEND=http://dvwa:80`
- `BLOCKING_PARANOIA=1`
- `ANOMALY_INBOUND=5`
- `ANOMALY_OUTBOUND=4`
- `MODSEC_RULE_ENGINE=On`

L'image finale attendue est:

```text
ghcr.io/dazinenoamane/projet-waf/waf-open-source:latest
```

### Custom WAF

Le Custom WAF est un reverse proxy HTTP en Node.js. Il inspecte:

- la methode HTTP;
- l'URI;
- les query parameters;
- les headers;
- le body brut;
- les champs JSON;
- les champs `application/x-www-form-urlencoded`.

Les regles sont definies dans:

```text
custom-waf/src/rules.js
```

Le serveur proxy est dans:

```text
custom-waf/src/server.js
```

Lorsqu'une requete est bloquee, un log JSON est ajoute dans:

```text
/var/log/custom-waf/waf.log
```

L'image finale attendue est:

```text
ghcr.io/dazinenoamane/projet-waf/waf-custom:latest
```

## Devbox IaC

Terraform et Ansible sont fournis par une devbox Docker:

- `iac/Dockerfile`
- `iac/docker-compose.yml`

Le conteneur s'appelle `waf-devbox`. Il monte le dossier `iac/` dans
`/root/host` et contient deja Terraform, Ansible, SSH et les outils de base.

## Infrastructure

### Terraform

Terraform cree une VM Proxmox et injecte un cloud-init. Les fichiers sont dans:

```text
iac/terraform/
```

Le template cloud-init installe Python et curl, ajoute la cle SSH, puis installe
Tailscale.

### Ansible

Ansible installe Docker, copie les fichiers Docker Compose et demarre les
services sur la VM.

Fichiers principaux:

- `iac/ansible/inventory.ini`
- `iac/ansible/playbook-docker-setup.yml`
- `iac/ansible/dvwa-with-waf-deploy.yml`
- `iac/ansible/playbook-compose-down-home.yml`

Le deploiement applicatif est execute sans `become`; l'utilisateur Ansible doit
donc etre membre du groupe `docker`.

## Scripts De Test

Les scripts de scan sont fournis en Bash et PowerShell:

- `scripts/attack.sh`
- `scripts/attack.ps1`

Ils produisent des fichiers CSV et Markdown dans `scripts/reports/`.
