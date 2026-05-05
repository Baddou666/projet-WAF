#!/usr/bin/env sh
set -eu

# DVWA/WAF lab scanner.
# It sends a fixed, transparent test corpus to a local DVWA lab endpoint and
# reports block rates, bypass candidates, and false positives.

TARGET="${1:-http://localhost:8082}"
OUT_DIR="${2:-scan-results}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
CSV_FILE="${OUT_DIR}/waf-scan-${RUN_ID}.csv"
MD_FILE="${OUT_DIR}/waf-scan-${RUN_ID}.md"
TMP_DIR="$(mktemp -d)"

SQLI_ENDPOINT="/vulnerabilities/sqli/"
XSS_ENDPOINT="/vulnerabilities/xss_r/"

SQLI_TOTAL=0
SQLI_BLOCKED=0
SQLI_BYPASS=0
XSS_TOTAL=0
XSS_BLOCKED=0
XSS_BYPASS=0
BENIGN_TOTAL=0
BENIGN_BLOCKED=0

mkdir -p "$OUT_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

usage() {
  cat <<EOF
Usage:
  $0 [target_url] [output_dir]

Examples:
  $0 http://localhost:8082
  $0 http://localhost:8080 reports/openwaf
  $0 http://localhost:8081 reports/dvwa-direct

Default target: http://localhost:8082

The scanner is intended for your local DVWA/WAF lab only.
It classifies a request as blocked when the response status is 403, or when
the body contains common WAF block-page markers.
EOF
}

urlencode() {
  # POSIX-ish percent encoder for query-string values.
  # Uses od, which is available in normal Linux shells used for Docker/VM labs.
  printf '%s' "$1" | od -An -tx1 | tr ' ' '\n' | sed '/^$/d; s/^/%/' | tr -d '\n'
}

csv_escape() {
  printf '%s' "$1" | sed 's/"/""/g'
}

write_csv_row() {
  label="$1"
  category="$2"
  method="$3"
  path="$4"
  payload="$5"
  status="$6"
  blocked="$7"
  verdict="$8"
  duration="$9"
  bytes="${10}"

  printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
    "$(csv_escape "$label")" \
    "$(csv_escape "$category")" \
    "$(csv_escape "$method")" \
    "$(csv_escape "$path")" \
    "$(csv_escape "$payload")" \
    "$(csv_escape "$status")" \
    "$(csv_escape "$blocked")" \
    "$(csv_escape "$verdict")" \
    "$(csv_escape "$duration")" \
    "$(csv_escape "$bytes")" >> "$CSV_FILE"
}

is_blocked_response() {
  status="$1"
  body_file="$2"

  if [ "$status" = "403" ]; then
    return 0
  fi

  if grep -Eiq 'request blocked|custom waf|forbidden|mod_security|modsecurity|owasp|access denied' "$body_file"; then
    return 0
  fi

  return 1
}

record_count() {
  category="$1"
  expected="$2"
  blocked="$3"

  case "$category" in
    sqli)
      SQLI_TOTAL=$((SQLI_TOTAL + 1))
      if [ "$blocked" = "yes" ]; then
        SQLI_BLOCKED=$((SQLI_BLOCKED + 1))
      elif [ "$expected" = "block" ]; then
        SQLI_BYPASS=$((SQLI_BYPASS + 1))
      fi
      ;;
    xss)
      XSS_TOTAL=$((XSS_TOTAL + 1))
      if [ "$blocked" = "yes" ]; then
        XSS_BLOCKED=$((XSS_BLOCKED + 1))
      elif [ "$expected" = "block" ]; then
        XSS_BYPASS=$((XSS_BYPASS + 1))
      fi
      ;;
    benign)
      BENIGN_TOTAL=$((BENIGN_TOTAL + 1))
      if [ "$blocked" = "yes" ]; then
        BENIGN_BLOCKED=$((BENIGN_BLOCKED + 1))
      fi
      ;;
  esac
}

send_get() {
  label="$1"
  category="$2"
  expected="$3"
  path="$4"
  payload="$5"

  encoded_payload="$(urlencode "$payload")"
  url="${TARGET}${path}?id=${encoded_payload}&Submit=Submit"
  body_file="${TMP_DIR}/${label}.body"
  meta_file="${TMP_DIR}/${label}.meta"

  curl -ksS -o "$body_file" \
    -w '%{http_code} %{time_total} %{size_download}' \
    "$url" > "$meta_file" || true

  set -- $(cat "$meta_file")
  status="${1:-000}"
  duration="${2:-0}"
  bytes="${3:-0}"

  if is_blocked_response "$status" "$body_file"; then
    blocked="yes"
  else
    blocked="no"
  fi

  if [ "$expected" = "block" ] && [ "$blocked" = "yes" ]; then
    verdict="blocked"
  elif [ "$expected" = "block" ] && [ "$blocked" = "no" ]; then
    verdict="bypass_candidate"
  elif [ "$expected" = "allow" ] && [ "$blocked" = "yes" ]; then
    verdict="false_positive"
  else
    verdict="allowed"
  fi

  record_count "$category" "$expected" "$blocked"
  write_csv_row "$label" "$category" "GET" "$path" "$payload" "$status" "$blocked" "$verdict" "$duration" "$bytes"
  printf '%-24s %-8s status=%s blocked=%s verdict=%s\n' "$label" "$category" "$status" "$blocked" "$verdict"
}

send_get_encoded() {
  label="$1"
  category="$2"
  expected="$3"
  path="$4"
  encoded_payload="$5"
  payload_label="$6"

  url="${TARGET}${path}?id=${encoded_payload}&Submit=Submit"
  body_file="${TMP_DIR}/${label}.body"
  meta_file="${TMP_DIR}/${label}.meta"

  curl -ksS -o "$body_file" \
    -w '%{http_code} %{time_total} %{size_download}' \
    "$url" > "$meta_file" || true

  set -- $(cat "$meta_file")
  status="${1:-000}"
  duration="${2:-0}"
  bytes="${3:-0}"

  if is_blocked_response "$status" "$body_file"; then
    blocked="yes"
  else
    blocked="no"
  fi

  if [ "$expected" = "block" ] && [ "$blocked" = "yes" ]; then
    verdict="blocked"
  elif [ "$expected" = "block" ] && [ "$blocked" = "no" ]; then
    verdict="bypass_candidate"
  elif [ "$expected" = "allow" ] && [ "$blocked" = "yes" ]; then
    verdict="false_positive"
  else
    verdict="allowed"
  fi

  record_count "$category" "$expected" "$blocked"
  write_csv_row "$label" "$category" "GET" "$path" "$payload_label" "$status" "$blocked" "$verdict" "$duration" "$bytes"
  printf '%-24s %-8s status=%s blocked=%s verdict=%s\n' "$label" "$category" "$status" "$blocked" "$verdict"
}

send_post() {
  label="$1"
  category="$2"
  expected="$3"
  path="$4"
  payload="$5"

  body_file="${TMP_DIR}/${label}.body"
  meta_file="${TMP_DIR}/${label}.meta"

  curl -ksS -X POST -o "$body_file" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "txtName=${payload}" \
    --data-urlencode "mtxMessage=hello from scanner" \
    --data 'btnSign=Sign+Guestbook' \
    -w '%{http_code} %{time_total} %{size_download}' \
    "${TARGET}${path}" > "$meta_file" || true

  set -- $(cat "$meta_file")
  status="${1:-000}"
  duration="${2:-0}"
  bytes="${3:-0}"

  if is_blocked_response "$status" "$body_file"; then
    blocked="yes"
  else
    blocked="no"
  fi

  if [ "$expected" = "block" ] && [ "$blocked" = "yes" ]; then
    verdict="blocked"
  elif [ "$expected" = "block" ] && [ "$blocked" = "no" ]; then
    verdict="bypass_candidate"
  elif [ "$expected" = "allow" ] && [ "$blocked" = "yes" ]; then
    verdict="false_positive"
  else
    verdict="allowed"
  fi

  record_count "$category" "$expected" "$blocked"
  write_csv_row "$label" "$category" "POST" "$path" "$payload" "$status" "$blocked" "$verdict" "$duration" "$bytes"
  printf '%-24s %-8s status=%s blocked=%s verdict=%s\n' "$label" "$category" "$status" "$blocked" "$verdict"
}

send_post_encoded() {
  label="$1"
  category="$2"
  expected="$3"
  path="$4"
  encoded_payload="$5"
  payload_label="$6"

  body_file="${TMP_DIR}/${label}.body"
  meta_file="${TMP_DIR}/${label}.meta"

  curl -ksS -X POST -o "$body_file" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "txtName=${encoded_payload}&mtxMessage=hello+from+scanner&btnSign=Sign+Guestbook" \
    -w '%{http_code} %{time_total} %{size_download}' \
    "${TARGET}${path}" > "$meta_file" || true

  set -- $(cat "$meta_file")
  status="${1:-000}"
  duration="${2:-0}"
  bytes="${3:-0}"

  if is_blocked_response "$status" "$body_file"; then
    blocked="yes"
  else
    blocked="no"
  fi

  if [ "$expected" = "block" ] && [ "$blocked" = "yes" ]; then
    verdict="blocked"
  elif [ "$expected" = "block" ] && [ "$blocked" = "no" ]; then
    verdict="bypass_candidate"
  elif [ "$expected" = "allow" ] && [ "$blocked" = "yes" ]; then
    verdict="false_positive"
  else
    verdict="allowed"
  fi

  record_count "$category" "$expected" "$blocked"
  write_csv_row "$label" "$category" "POST" "$path" "$payload_label" "$status" "$blocked" "$verdict" "$duration" "$bytes"
  printf '%-24s %-8s status=%s blocked=%s verdict=%s\n' "$label" "$category" "$status" "$blocked" "$verdict"
}

pct() {
  numerator="$1"
  denominator="$2"
  if [ "$denominator" -eq 0 ]; then
    printf '0.0'
    return
  fi
  awk "BEGIN { printf \"%.1f\", (${numerator} * 100) / ${denominator} }"
}

write_report() {
  SQLI_RATE="$(pct "$SQLI_BLOCKED" "$SQLI_TOTAL")"
  XSS_RATE="$(pct "$XSS_BLOCKED" "$XSS_TOTAL")"
  FP_RATE="$(pct "$BENIGN_BLOCKED" "$BENIGN_TOTAL")"

  {
    printf '# WAF Scan Report\n\n'
    printf '- Target: `%s`\n' "$TARGET"
    printf '- Run ID: `%s`\n' "$RUN_ID"
    printf '- CSV: `%s`\n\n' "$CSV_FILE"
    printf '## Summary\n\n'
    printf '| Category | Total | Blocked | Bypass candidates | False positives | Rate |\n'
    printf '|---|---:|---:|---:|---:|---:|\n'
    printf '| SQLi | %s | %s | %s | - | %s%% |\n' "$SQLI_TOTAL" "$SQLI_BLOCKED" "$SQLI_BYPASS" "$SQLI_RATE"
    printf '| XSS | %s | %s | %s | - | %s%% |\n' "$XSS_TOTAL" "$XSS_BLOCKED" "$XSS_BYPASS" "$XSS_RATE"
    printf '| Benign | %s | %s | - | %s | %s%% |\n\n' "$BENIGN_TOTAL" "$BENIGN_BLOCKED" "$BENIGN_BLOCKED" "$FP_RATE"
    printf '## Bypass Candidates\n\n'
    awk -F '","' 'NR > 1 && $8 ~ /bypass_candidate/ { gsub(/^"|"$/, "", $1); gsub(/^"|"$/, "", $2); gsub(/^"|"$/, "", $5); printf "- `%s` [%s]: `%s`\n", $1, $2, $5 }' "$CSV_FILE"
    printf '\n## False Positives\n\n'
    awk -F '","' 'NR > 1 && $8 ~ /false_positive/ { gsub(/^"|"$/, "", $1); gsub(/^"|"$/, "", $2); gsub(/^"|"$/, "", $5); printf "- `%s` [%s]: `%s`\n", $1, $2, $5 }' "$CSV_FILE"
  } > "$MD_FILE"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

printf '"label","category","method","path","payload","status","blocked","verdict","duration_seconds","bytes"\n' > "$CSV_FILE"

printf '\n== Target: %s ==\n' "$TARGET"
printf '== Writing: %s ==\n\n' "$CSV_FILE"

printf '== SQLi corpus ==\n'
send_get "sqli_union_select" "sqli" "block" "$SQLI_ENDPOINT" "1' UNION SELECT user,password FROM users-- "
send_get "sqli_tautology_or" "sqli" "block" "$SQLI_ENDPOINT" "1' OR '1'='1'-- "
send_get "sqli_tautology_and" "sqli" "block" "$SQLI_ENDPOINT" "1 AND 2=2"
send_get "sqli_time_mysql" "sqli" "block" "$SQLI_ENDPOINT" "1' AND SLEEP(2)-- "
send_get "sqli_time_pg" "sqli" "block" "$SQLI_ENDPOINT" "1'; SELECT pg_sleep(2)--"
send_get "sqli_metadata" "sqli" "block" "$SQLI_ENDPOINT" "1' UNION SELECT table_name,2 FROM information_schema.tables-- "
send_get "sqli_stacked_drop" "sqli" "block" "$SQLI_ENDPOINT" "1; DROP TABLE users"
send_get "sqli_comment_obfusc" "sqli" "block" "$SQLI_ENDPOINT" "1'/**/OR/**/'a'='a"
send_get_encoded "sqli_encoded_union" "sqli" "block" "$SQLI_ENDPOINT" "1%2527%2520UNION%2520SELECT%25201%2C2--" "1%2527%2520UNION%2520SELECT%25201%2C2--"

printf '\n== XSS corpus ==\n'
send_post "xss_script_tag" "xss" "block" "$XSS_ENDPOINT" "<script>alert(1)</script>"
send_post "xss_img_onerror" "xss" "block" "$XSS_ENDPOINT" "<img src=x onerror=alert(1)>"
send_post "xss_svg_onload" "xss" "block" "$XSS_ENDPOINT" "<svg onload=alert(1)>"
send_post "xss_js_href" "xss" "block" "$XSS_ENDPOINT" "<a href=javascript:alert(1)>click</a>"
send_post "xss_srcdoc" "xss" "block" "$XSS_ENDPOINT" "<iframe srcdoc='<script>alert(1)</script>'></iframe>"
send_post_encoded "xss_encoded_script" "xss" "block" "$XSS_ENDPOINT" "%253Cscript%253Ealert%281%29%253C%252Fscript%253E" "%253Cscript%253Ealert(1)%253C%252Fscript%253E"
send_post "xss_entity_script" "xss" "block" "$XSS_ENDPOINT" "&lt;script&gt;alert(1)&lt;/script&gt;"

printf '\n== Benign corpus ==\n'
send_get "benign_numeric_id" "benign" "allow" "$SQLI_ENDPOINT" "1"
send_get "benign_search_words" "benign" "allow" "$SQLI_ENDPOINT" "union station select menu"
send_get "benign_apostrophe" "benign" "allow" "$SQLI_ENDPOINT" "O'Reilly"
send_post "benign_guestbook" "benign" "allow" "$XSS_ENDPOINT" "hello dvwa team"
send_post "benign_html_text" "benign" "allow" "$XSS_ENDPOINT" "I like HTML and CSS"
send_post "benign_math" "benign" "allow" "$XSS_ENDPOINT" "2 < 3 and 5 > 4"

write_report

printf '\n== Summary ==\n'
printf 'SQLi blocked:   %s/%s (%s%%), bypass candidates: %s\n' "$SQLI_BLOCKED" "$SQLI_TOTAL" "$(pct "$SQLI_BLOCKED" "$SQLI_TOTAL")" "$SQLI_BYPASS"
printf 'XSS blocked:    %s/%s (%s%%), bypass candidates: %s\n' "$XSS_BLOCKED" "$XSS_TOTAL" "$(pct "$XSS_BLOCKED" "$XSS_TOTAL")" "$XSS_BYPASS"
printf 'False positive: %s/%s (%s%%)\n' "$BENIGN_BLOCKED" "$BENIGN_TOTAL" "$(pct "$BENIGN_BLOCKED" "$BENIGN_TOTAL")"
printf '\nCSV report:      %s\n' "$CSV_FILE"
printf 'Markdown report: %s\n' "$MD_FILE"
