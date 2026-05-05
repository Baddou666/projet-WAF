# Carte Du Projet

## Racine

| Chemin | Role |
|---|---|
| `README.md` | point d'entree du projet |
| `docker-compose.local.yml` | stack locale DVWA + Open WAF + Custom WAF avec build local |
| `docs/` | documentation lisible du laboratoire |
| `iac/` | infrastructure et automatisation |
| `openwaf/` | image Open WAF et fichiers Nginx/ModSecurity |
| `custom-waf/` | WAF custom en Node.js |
| `scripts/` | scripts de test et rapports generes |

## `iac/`

| Chemin | Role |
|---|---|
| `iac/Dockerfile` | image devbox Ubuntu avec Terraform et Ansible deja installes |
| `iac/docker-compose.yml` | lancement du conteneur `waf-devbox` |
| `iac/terraform/` | provisionnement de la VM Proxmox |
| `iac/ansible/` | installation Docker et deploiement applicatif |

## `iac/ansible/`

| Chemin | Role |
|---|---|
| `inventory.ini` | inventaire Ansible, cible `dvwa-vm` |
| `playbook-docker-setup.yml` | installation de Docker sur la VM |
| `dvwa-with-waf-deploy.yml` | deploiement DVWA + Open WAF + Custom WAF |
| `playbook-compose-down-home.yml` | arret des projets Compose trouves dans le home |
| `dvwa/docker-compose.yml` | stack DVWA directe |
| `dvwa-with-waf/docker-compose.yml` | stack complete exposee sur `8080`, `8081`, `8082` |

## `iac/terraform/`

| Chemin | Role |
|---|---|
| `providers.tf` | configuration du provider Proxmox |
| `variables.tf` | variables Terraform attendues |
| `main.tf` | definition de la VM et du cloud-init |
| `cloud_config.yml.tpl` | template cloud-init avec SSH et Tailscale |

## `openwaf/`

| Chemin | Role |
|---|---|
| `Dockerfile` | definition de l'image `waf-open-source` |
| `rules/custom-exclusions.conf` | exclusions WAF personnalisees |
| `script-waf-opensrc.bat` | build/push Windows vers GHCR |
| `nginx.conf` | configuration Nginx locale du reverse proxy |
| `modsecurity.conf` | configuration ModSecurity locale |
| `crs-setup.conf` | configuration CRS locale |

Dans l'etat actuel du Dockerfile, seule l'exclusion personnalisee est copiee
dans l'image. Le compose fournit aussi la configuration runtime par variables
d'environnement.

## `custom-waf/`

| Chemin | Role |
|---|---|
| `Dockerfile` | image Node.js du WAF custom |
| `package.json` | metadata et script `npm start` |
| `src/server.js` | reverse proxy HTTP et blocage |
| `src/rules.js` | regles SQLi/XSS et normalisation |
| `src/logger.js` | ecriture des logs JSON |
| `script-waf-custom.bat` | build/push Windows vers GHCR |

## `scripts/`

| Chemin | Role |
|---|---|
| `attack.sh` | scanner Bash |
| `attack.ps1` | scanner PowerShell |
| `attack-script-report.md` | description statique des scripts |
| `reports/` | resultats CSV et Markdown generes par les scans |
