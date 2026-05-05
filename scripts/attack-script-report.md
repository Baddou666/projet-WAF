# Attack Script Description

This document describes the purpose and behavior of `attack.sh` and
`attack.ps1`. It is not an execution report and does not contain measured test
results.

## Purpose

The scripts send a fixed set of HTTP requests to the DVWA lab through a target
URL. The default target is:

```text
http://dvwa-vm:8080
```

`dvwa-vm` is expected to resolve through Tailscale MagicDNS. The scripts can
also receive another target URL when testing a different exposed port or WAF
deployment.

The lab port mapping is:

| Target | Purpose |
|---|---|
| `http://dvwa-vm:8080` | DVWA direct |
| `http://dvwa-vm:8081` | Open WAF |
| `http://dvwa-vm:8082` | Custom WAF |

## Test Inputs

The request set is split into three groups:

- SQL injection payloads
- XSS payloads
- benign requests

The malicious payloads are expected to be blocked by the WAF. The benign
requests are expected to pass without being blocked.

## Result Logic

Each response is considered blocked when:

- the HTTP status code is `403`, or
- the response body contains a common block marker such as `request blocked`,
  `custom waf`, `modsecurity`, `owasp`, `forbidden`, or `access denied`.

The scripts then assign an `attack_result` value:

| Value | Meaning |
|---|---|
| `reussi` | a malicious request was not blocked |
| `failed` | a malicious request was blocked |
| `faux_positif` | a benign request was blocked |
| `normal` | a benign request was allowed |

The older technical `verdict` field is still written for detail:

- `blocked`
- `bypass_candidate`
- `false_positive`
- `allowed`

## Generated Files

Each run creates output files in the selected output directory:

- `waf-scan-<timestamp>.csv`
- `waf-scan-<timestamp>.md`

The CSV contains one row per request. The Markdown file summarizes the same run
and lists successful attacks and false positives.

## Usage

Shell:

```sh
sh scripts/attack.sh
sh scripts/attack.sh http://dvwa-vm:8080 reports/dvwa-direct
sh scripts/attack.sh http://dvwa-vm:8081 reports/openwaf
sh scripts/attack.sh http://dvwa-vm:8082 reports/custom-waf
```

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8080 -OutDir reports\dvwa-direct
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8081 -OutDir reports\openwaf
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8082 -OutDir reports\custom-waf
```

## Scope

These scripts are intended only for the controlled DVWA/WAF lab environment.
They are documentation and test helpers for comparing WAF behavior, not a
general-purpose attack tool.
