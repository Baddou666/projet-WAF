# Tests Et Resultats

## Objectif Des Tests

Les scripts de test comparent le comportement des trois chemins d'acces:

| Port | Chemin | Attendu |
|---:|---|---|
| `8080` | DVWA direct | les attaques passent souvent |
| `8081` | Open WAF | les attaques doivent etre bloquees |
| `8082` | Custom WAF | les attaques couvertes par les regles doivent etre bloquees |

Le but n'est pas de prouver une securite complete, mais de produire une base de
comparaison reproductible.

## Scripts Disponibles

Deux versions equivalent fonctionnellement:

- `scripts/attack.sh`
- `scripts/attack.ps1`

La cible par defaut est:

```text
http://dvwa-vm:8080
```

## Lancer Les Scans

### Test Local Avec Images Buildees

Le fichier `docker-compose.local.yml` lance une stack locale complete:

- DVWA direct exposee sur `http://localhost:8080`;
- Open WAF builde depuis `openwaf/` et expose sur `http://localhost:8081`;
- Custom WAF builde depuis `custom-waf/` et expose sur `http://localhost:8082`.

Depuis la racine du projet:

```bash
docker compose -f docker-compose.local.yml up -d --build
```

Scans locaux:

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

### Test Sur La VM

Bash:

```bash
sh scripts/attack.sh http://dvwa-vm:8080 scripts/reports/dvwa-direct
sh scripts/attack.sh http://dvwa-vm:8081 scripts/reports/openwaf
sh scripts/attack.sh http://dvwa-vm:8082 scripts/reports/custom-waf
```

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8080 -OutDir scripts\reports\dvwa-direct
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8081 -OutDir scripts\reports\openwaf
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8082 -OutDir scripts\reports\custom-waf
```

## Corpus De Test

### SQL Injection

Le corpus SQLi contient notamment:

- `UNION SELECT`;
- tautologies booleennes;
- tests temporels MySQL et PostgreSQL;
- acces a `information_schema`;
- statements empiles;
- obfuscation par commentaires;
- payload double encode.

### XSS

Le corpus XSS contient notamment:

- balises `<script>`;
- `img onerror`;
- `svg onload`;
- liens `javascript:`;
- `iframe srcdoc`;
- payloads encodes;
- entites HTML.

### Trafic Benin

Le trafic benin sert a mesurer les faux positifs:

- ID numerique simple;
- texte contenant des mots comme `union` et `select`;
- apostrophe dans un nom;
- message normal de guestbook;
- texte HTML/CSS;
- expression mathematique.

## Classification

Une reponse est consideree comme bloquee si:

- le statut HTTP est `403`;
- le body contient un marqueur comme `request blocked`, `custom waf`,
  `modsecurity`, `owasp`, `forbidden` ou `access denied`.

Chaque ligne de resultat contient un champ `attack_result`:

| Valeur | Signification |
|---|---|
| `reussi` | attaque non bloquee |
| `failed` | attaque bloquee |
| `faux_positif` | requete benigne bloquee |
| `normal` | requete benigne autorisee |

## Fichiers Generes

Chaque scan cree:

- un CSV detaille: `waf-scan-<timestamp>.csv`;
- un resume Markdown: `waf-scan-<timestamp>.md`.

Les sorties sont rangees dans le dossier donne en argument, par exemple:

```text
scripts/reports/dvwa-direct/
scripts/reports/openwaf/
scripts/reports/custom-waf/
```

## Logs Du Custom WAF

Le Custom WAF ecrit ses blocages au format JSON Lines: chaque ligne est un
objet JSON independant.

Exemple de structure:

```json
{
  "timestamp": "2026-05-05T20:34:22.398Z",
  "attackerIp": "100.118.186.33",
  "requestLine": "GET /vulnerabilities/sqli/?id=...",
  "triggeredRules": ["SQLI-002"],
  "maliciousPayload": "/vulnerabilities/sqli/?id=..."
}
```

Champs:

| Champ | Description |
|---|---|
| `timestamp` | date UTC ISO-8601 du blocage |
| `attackerIp` | adresse IP vue par le WAF |
| `requestLine` | methode HTTP et chemin demande |
| `triggeredRules` | liste des IDs de regles declenchees |
| `maliciousPayload` | valeur ou URI consideree comme malveillante |

Dans le conteneur, le chemin configure par defaut est:

```text
/var/log/custom-waf/waf.log
```

Dans les stacks Compose, ce chemin peut etre monte dans un volume Docker afin
de conserver les logs du Custom WAF. Les fichiers de logs locaux generes pendant
les tests ne font pas partie des livrables du projet.

## Interpretation Rapide

Sur `dvwa-direct`, les attaques non bloquees sont normales: le service n'a pas
de WAF.

Sur `openwaf` et `custom-waf`, les lignes `reussi` indiquent des payloads qui
ont traverse la protection. Les lignes `faux_positif` indiquent des requetes
normales bloquees a tort.
