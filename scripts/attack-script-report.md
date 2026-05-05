# Attack Scanner Report

## Objective

The scanner tests the local DVWA/WAF lab and gathers hard data for comparison:

- SQL injection block rate
- XSS block rate
- bypass candidates
- false positives on benign traffic
- response status, response size, and request duration

The script is intended for the local lab endpoints only:

- DVWA direct: `http://localhost:8081`
- Open-source WAF: `http://localhost:8080`
- Custom WAF: `http://localhost:8082`

## Test Corpus

### SQLi

The SQLi corpus contains classic and lightly obfuscated payloads:

- `UNION SELECT`
- boolean tautologies
- MySQL and PostgreSQL time-based probes
- metadata probing through `information_schema`
- stacked statements
- inline comment obfuscation
- double-encoded SQLi input

### XSS

The XSS corpus contains reflected/stored XSS style payloads:

- `<script>` tags
- image `onerror`
- SVG `onload`
- `javascript:` links
- `iframe srcdoc`
- double-encoded script tags
- HTML entity encoded script tags

### Benign Traffic

The benign corpus is used to estimate false positives:

- normal numeric IDs
- harmless text containing words like `union` and `select`
- apostrophes in names
- normal guestbook messages
- plain HTML/CSS text
- mathematical comparison text

## Classification Logic

Each request is classified as blocked when:

- HTTP status is `403`, or
- the response body contains common WAF block markers such as `request blocked`,
  `custom waf`, `modsecurity`, `owasp`, `forbidden`, or `access denied`.

Expected malicious requests that are not blocked are marked as:

- `bypass_candidate`

Expected benign requests that are blocked are marked as:

- `false_positive`

## Outputs

Each run writes two files under the chosen output directory:

- `waf-scan-<timestamp>.csv`
- `waf-scan-<timestamp>.md`

The CSV contains one row per request. The Markdown file contains the summary
table plus lists of bypass candidates and false positives.

## Usage

Shell:

```sh
sh scripts/attack.sh http://localhost:8082
sh scripts/attack.sh http://localhost:8080 reports/openwaf
sh scripts/attack.sh http://localhost:8081 reports/dvwa-direct
```

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://localhost:8082
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://localhost:8080 -OutDir reports\openwaf
powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://localhost:8081 -OutDir reports\dvwa-direct
```

## Current Execution Note

At the time of this update, the local ports `8080`, `8081`, and `8082` did not
respond from the Codex terminal, so no live block-rate numbers were generated.
Start the Docker lab stack, then run either script to produce the live reports.
