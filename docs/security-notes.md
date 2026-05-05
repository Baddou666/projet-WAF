# Notes De Securite

## Perimetre

Ce projet est un laboratoire academique. Il contient volontairement une
application vulnerable et des scripts qui envoient des payloads SQLi et XSS.

Ne pas exposer les services sur Internet.

## Secrets

Les elements sensibles doivent rester hors Git:

- mot de passe Proxmox;
- cle Tailscale;
- fichiers Terraform state;
- fichiers `.tfvars`.

Aucun secret GHCR n'est necessaire pour tirer les images WAF, car les packages
sont supposes publics.

## Images Docker

Les images WAF publiques sont tirees depuis GHCR:

- `ghcr.io/dazinenoamane/projet-waf/waf-open-source:latest`
- `ghcr.io/dazinenoamane/projet-waf/waf-custom:latest`

Pour un environnement reproductible, preferer des tags versionnes a `latest`.

## DVWA

DVWA utilise des identifiants faibles et une base de donnees locale. C'est
normal pour un lab, mais ce service ne doit jamais etre publie hors reseau de
test.

## Terraform

Terraform est execute depuis la devbox `waf-devbox`, pas directement depuis
l'hote.

Le provider Proxmox utilise actuellement `insecure = true`. C'est acceptable
pour un lab local, mais a eviter dans un environnement de production.

Le bloc SSH du provider utilise encore `root`. Si possible, creer un utilisateur
Proxmox dedie avec le minimum de privileges necessaires.

## Cloud-Init

Le template cloud-init lance Tailscale avec une auth key. Eviter de journaliser
ou partager les sorties cloud-init contenant cette valeur.

## Custom WAF

Le WAF custom est volontairement simple. Il sert a demontrer:

- inspection de requetes;
- normalisation de payloads;
- scoring par regles;
- journalisation des blocages.

Il ne remplace pas un WAF complet en production.

## Open WAF

L'Open WAF est maintenu dans `openwaf/`. Les faux positifs doivent etre traites
par des exclusions documentees dans:

```text
openwaf/rules/custom-exclusions.conf
```

Chaque exclusion devrait expliquer quelle page ou requete legitime elle
debloque.
