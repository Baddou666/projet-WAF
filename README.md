# Projet WAF

Projet academique de laboratoire pour deployer DVWA, comparer plusieurs WAF et
generer des resultats de tests SQL injection, XSS et faux positifs.

Terraform et Ansible ne sont pas supposes etre installes directement sur la
machine hote. Le dossier `iac/` fournit une devbox Docker (`waf-devbox`) qui
contient deja les outils necessaires.

## Vue D'ensemble

Le projet contient trois chemins de test autour de DVWA:

| Port | Service | Description |
|---:|---|---|
| `8080` | DVWA direct | Application vulnerable sans WAF |
| `8081` | Open WAF | DVWA protegee par OWASP ModSecurity CRS |
| `8082` | Custom WAF | DVWA protegee par le WAF Node.js du projet |

La VM cible est appelee `dvwa-vm` et doit etre resolue par Tailscale MagicDNS.

## Structure

```text
.
|-- iac/                 Infrastructure, Terraform, Ansible et devbox
|-- openwaf/             Image OWASP ModSecurity CRS personnalisee
|-- custom-waf/          Reverse proxy WAF en Node.js
|-- scripts/             Scripts de scan et rapports generes
`-- docs/                Documentation du projet
```

## Documentation

- [Architecture](docs/architecture.md)
- [Carte du projet](docs/project-map.md)
- [Deploiement](docs/deployment.md)
- [Tests et resultats](docs/testing.md)
- [Notes de securite](docs/security-notes.md)
- [Description des scripts d'attaque](scripts/attack-script-report.md)

## Workflow Rapide

### Test Local

Pour builder les deux WAF localement et tester DVWA sans passer par la VM:

```bash
docker compose -f docker-compose.local.yml up -d --build
```

Services locaux:

| URL | Service |
|---|---|
| `http://localhost:8080` | DVWA direct |
| `http://localhost:8081` | Open WAF local |
| `http://localhost:8082` | Custom WAF local |

Les scripts peuvent ensuite etre lances avec `localhost`:

```bash
sh scripts/attack.sh http://localhost:8080 scripts/reports/local-dvwa-direct
sh scripts/attack.sh http://localhost:8081 scripts/reports/local-openwaf
sh scripts/attack.sh http://localhost:8082 scripts/reports/local-custom-waf
```

### Deploiement VM

Lancer d'abord la devbox IaC:

```bash
cd iac
docker compose up -d --build
docker exec -it waf-devbox bash
cd /root/host/ansible
```

Depuis cette devbox:

```bash
ansible-playbook -i inventory.ini playbook-docker-setup.yml
ansible-playbook -i inventory.ini dvwa-with-waf-deploy.yml
```

Pour arreter les stacks Docker Compose presentes dans le home de l'utilisateur
Ansible:

```bash
ansible-playbook -i inventory.ini playbook-compose-down-home.yml
```

Pour lancer les tests depuis la racine du projet:

```bash
sh scripts/attack.sh http://dvwa-vm:8080 scripts/reports/dvwa-direct
sh scripts/attack.sh http://dvwa-vm:8081 scripts/reports/openwaf
sh scripts/attack.sh http://dvwa-vm:8082 scripts/reports/custom-waf
```

Sous Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8080 -OutDir scripts\reports\dvwa-direct
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8081 -OutDir scripts\reports\openwaf
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8082 -OutDir scripts\reports\custom-waf
```

## Images Docker

Les images utilisees par le deploiement WAF sont publiees publiquement sur GHCR:

- `ghcr.io/dazinenoamane/projet-waf/waf-open-source:latest`
- `ghcr.io/dazinenoamane/projet-waf/waf-custom:latest`

Les scripts Windows dans `openwaf/` et `custom-waf/` permettent de construire
et pousser ces images.

## Important

DVWA est volontairement vulnerable. Ce projet doit rester limite a un
environnement de laboratoire controle. Ne pas exposer ces services sur Internet.
