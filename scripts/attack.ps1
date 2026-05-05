param(
  [string]$Target = "http://dvwa-vm:8080",
  [string]$OutDir = "scan-results",
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# DVWA/WAF lab scanner.
# It sends a fixed, transparent test corpus to a DVWA lab endpoint and reports
# block rates, successful attacks, failed attacks, and false positives.

$SqliEndpoint = "/vulnerabilities/sqli/"
$XssEndpoint = "/vulnerabilities/xss_r/"
$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$CsvFile = Join-Path $OutDir "waf-scan-$RunId.csv"
$MdFile = Join-Path $OutDir "waf-scan-$RunId.md"
$Results = New-Object System.Collections.Generic.List[object]

function Show-Usage {
  Write-Host @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 [-Target <url>] [-OutDir <dir>]

Examples:
  powershell -ExecutionPolicy Bypass -File scripts\attack.ps1
  powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8080 -OutDir reports\dvwa-direct
  powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8081 -OutDir reports\openwaf
  powershell -ExecutionPolicy Bypass -File scripts\attack.ps1 -Target http://dvwa-vm:8082 -OutDir reports\custom-waf

Default target: http://dvwa-vm:8080

The scanner is intended for your DVWA/WAF lab only.
It classifies a request as blocked when the response status is 403, or when
the body contains common WAF block-page markers.

Attack result values:
  reussi       malicious request was not blocked
  failed       malicious request was blocked
  faux_positif benign request was blocked
  normal       benign request was allowed
"@
}

function ConvertTo-UrlEncoded {
  param([string]$Value)
  return [Uri]::EscapeDataString($Value)
}

function Test-BlockedResponse {
  param(
    [int]$StatusCode,
    [string]$Body
  )

  if ($StatusCode -eq 403) {
    return $true
  }

  return $Body -match "(?i)request blocked|custom waf|forbidden|mod_security|modsecurity|owasp|access denied"
}

function Get-Verdict {
  param(
    [string]$Expected,
    [bool]$Blocked
  )

  if ($Expected -eq "block" -and $Blocked) {
    return "blocked"
  }
  if ($Expected -eq "block" -and -not $Blocked) {
    return "bypass_candidate"
  }
  if ($Expected -eq "allow" -and $Blocked) {
    return "false_positive"
  }
  return "allowed"
}

function Get-AttackResult {
  param(
    [string]$Expected,
    [bool]$Blocked
  )

  if ($Expected -eq "block" -and $Blocked) {
    return "failed"
  }
  if ($Expected -eq "block" -and -not $Blocked) {
    return "reussi"
  }
  if ($Expected -eq "allow" -and $Blocked) {
    return "faux_positif"
  }
  return "normal"
}

function Invoke-ScannerRequest {
  param(
    [string]$Method,
    [string]$Url,
    [hashtable]$Headers = @{},
    [string]$Body = $null
  )

  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  $statusCode = 0
  $responseBody = ""

  try {
    if ($Method -eq "POST") {
      $response = Invoke-WebRequest -Uri $Url -Method Post -Headers $Headers -Body $Body -UseBasicParsing -TimeoutSec 20
    } else {
      $response = Invoke-WebRequest -Uri $Url -Method Get -Headers $Headers -UseBasicParsing -TimeoutSec 20
    }

    $statusCode = [int]$response.StatusCode
    $responseBody = [string]$response.Content
  } catch {
    if ($_.Exception.Response) {
      $statusCode = [int]$_.Exception.Response.StatusCode
      try {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
        $reader.Dispose()
      } catch {
        $responseBody = $_.Exception.Message
      }
    } else {
      $statusCode = 0
      $responseBody = $_.Exception.Message
    }
  } finally {
    $watch.Stop()
  }

  $bytes = [System.Text.Encoding]::UTF8.GetByteCount($responseBody)
  return [pscustomobject]@{
    StatusCode = $statusCode
    DurationSeconds = [Math]::Round($watch.Elapsed.TotalSeconds, 4)
    Bytes = $bytes
    Body = $responseBody
  }
}

function Add-ScanResult {
  param(
    [string]$Label,
    [string]$Category,
    [string]$Method,
    [string]$Path,
    [string]$Payload,
    [string]$Expected,
    [object]$Response
  )

  $blocked = Test-BlockedResponse -StatusCode $Response.StatusCode -Body $Response.Body
  $verdict = Get-Verdict -Expected $Expected -Blocked $blocked
  $attackResult = Get-AttackResult -Expected $Expected -Blocked $blocked

  $row = [pscustomobject]@{
    label = $Label
    category = $Category
    method = $Method
    path = $Path
    payload = $Payload
    status = $Response.StatusCode
    blocked = $(if ($blocked) { "yes" } else { "no" })
    verdict = $verdict
    attack_result = $attackResult
    duration_seconds = $Response.DurationSeconds
    bytes = $Response.Bytes
  }

  $Results.Add($row) | Out-Null
  Write-Host ("{0,-24} {1,-8} status={2} blocked={3} verdict={4} result={5}" -f $Label, $Category, $Response.StatusCode, $row.blocked, $verdict, $attackResult)
}

function Send-GetTest {
  param(
    [string]$Label,
    [string]$Category,
    [string]$Expected,
    [string]$Path,
    [string]$Payload
  )

  $encodedPayload = ConvertTo-UrlEncoded $Payload
  $url = "$Target$Path`?id=$encodedPayload&Submit=Submit"
  $response = Invoke-ScannerRequest -Method "GET" -Url $url
  Add-ScanResult -Label $Label -Category $Category -Method "GET" -Path $Path -Payload $Payload -Expected $Expected -Response $response
}

function Send-GetEncodedTest {
  param(
    [string]$Label,
    [string]$Category,
    [string]$Expected,
    [string]$Path,
    [string]$EncodedPayload,
    [string]$PayloadLabel
  )

  $url = "$Target$Path`?id=$EncodedPayload&Submit=Submit"
  $response = Invoke-ScannerRequest -Method "GET" -Url $url
  Add-ScanResult -Label $Label -Category $Category -Method "GET" -Path $Path -Payload $PayloadLabel -Expected $Expected -Response $response
}

function Send-PostTest {
  param(
    [string]$Label,
    [string]$Category,
    [string]$Expected,
    [string]$Path,
    [string]$Payload
  )

  $body = "txtName=$(ConvertTo-UrlEncoded $Payload)&mtxMessage=$(ConvertTo-UrlEncoded 'hello from scanner')&btnSign=Sign+Guestbook"
  $headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
  $response = Invoke-ScannerRequest -Method "POST" -Url "$Target$Path" -Headers $headers -Body $body
  Add-ScanResult -Label $Label -Category $Category -Method "POST" -Path $Path -Payload $Payload -Expected $Expected -Response $response
}

function Send-PostEncodedTest {
  param(
    [string]$Label,
    [string]$Category,
    [string]$Expected,
    [string]$Path,
    [string]$EncodedPayload,
    [string]$PayloadLabel
  )

  $body = "txtName=$EncodedPayload&mtxMessage=hello+from+scanner&btnSign=Sign+Guestbook"
  $headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
  $response = Invoke-ScannerRequest -Method "POST" -Url "$Target$Path" -Headers $headers -Body $body
  Add-ScanResult -Label $Label -Category $Category -Method "POST" -Path $Path -Payload $PayloadLabel -Expected $Expected -Response $response
}

function Get-Percent {
  param(
    [int]$Numerator,
    [int]$Denominator
  )

  if ($Denominator -eq 0) {
    return "0.0"
  }
  return "{0:N1}" -f (($Numerator * 100.0) / $Denominator)
}

function Write-MarkdownReport {
  $sqli = @($Results | Where-Object { $_.category -eq "sqli" })
  $xss = @($Results | Where-Object { $_.category -eq "xss" })
  $benign = @($Results | Where-Object { $_.category -eq "benign" })

  $sqliBlocked = @($sqli | Where-Object { $_.blocked -eq "yes" }).Count
  $xssBlocked = @($xss | Where-Object { $_.blocked -eq "yes" }).Count
  $benignBlocked = @($benign | Where-Object { $_.blocked -eq "yes" }).Count
  $sqliSuccess = @($sqli | Where-Object { $_.attack_result -eq "reussi" }).Count
  $xssSuccess = @($xss | Where-Object { $_.attack_result -eq "reussi" }).Count

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("# WAF Scan Report")
  $lines.Add("")
  $lines.Add("- Target: ``$Target``")
  $lines.Add("- Run ID: ``$RunId``")
  $lines.Add("- CSV: ``$CsvFile``")
  $lines.Add("")
  $lines.Add("## Summary")
  $lines.Add("")
  $lines.Add("| Category | Total | Blocked | Successful attacks | False positives | Rate |")
  $lines.Add("|---|---:|---:|---:|---:|---:|")
  $lines.Add("| SQLi | $($sqli.Count) | $sqliBlocked | $sqliSuccess | - | $(Get-Percent $sqliBlocked $sqli.Count)% |")
  $lines.Add("| XSS | $($xss.Count) | $xssBlocked | $xssSuccess | - | $(Get-Percent $xssBlocked $xss.Count)% |")
  $lines.Add("| Benign | $($benign.Count) | $benignBlocked | - | $benignBlocked | $(Get-Percent $benignBlocked $benign.Count)% |")
  $lines.Add("")
  $lines.Add("## Successful Attacks")
  $lines.Add("")

  foreach ($row in @($Results | Where-Object { $_.attack_result -eq "reussi" })) {
    $lines.Add("- ``$($row.label)`` [$($row.category)]: ``$($row.payload)``")
  }

  $lines.Add("")
  $lines.Add("## False Positives")
  $lines.Add("")

  foreach ($row in @($Results | Where-Object { $_.attack_result -eq "faux_positif" })) {
    $lines.Add("- ``$($row.label)`` [$($row.category)]: ``$($row.payload)``")
  }

  Set-Content -LiteralPath $MdFile -Value $lines -Encoding UTF8
}

if ($Help) {
  Show-Usage
  exit 0
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host ""
Write-Host "== Target: $Target =="
Write-Host "== Writing: $CsvFile =="
Write-Host ""

Write-Host "== SQLi corpus =="
Send-GetTest "sqli_union_select" "sqli" "block" $SqliEndpoint "1' UNION SELECT user,password FROM users-- "
Send-GetTest "sqli_tautology_or" "sqli" "block" $SqliEndpoint "1' OR '1'='1'-- "
Send-GetTest "sqli_tautology_and" "sqli" "block" $SqliEndpoint "1 AND 2=2"
Send-GetTest "sqli_time_mysql" "sqli" "block" $SqliEndpoint "1' AND SLEEP(2)-- "
Send-GetTest "sqli_time_pg" "sqli" "block" $SqliEndpoint "1'; SELECT pg_sleep(2)--"
Send-GetTest "sqli_metadata" "sqli" "block" $SqliEndpoint "1' UNION SELECT table_name,2 FROM information_schema.tables-- "
Send-GetTest "sqli_stacked_drop" "sqli" "block" $SqliEndpoint "1; DROP TABLE users"
Send-GetTest "sqli_comment_obfusc" "sqli" "block" $SqliEndpoint "1'/**/OR/**/'a'='a"
Send-GetEncodedTest "sqli_encoded_union" "sqli" "block" $SqliEndpoint "1%2527%2520UNION%2520SELECT%25201%2C2--" "1%2527%2520UNION%2520SELECT%25201%2C2--"

Write-Host ""
Write-Host "== XSS corpus =="
Send-PostTest "xss_script_tag" "xss" "block" $XssEndpoint "<script>alert(1)</script>"
Send-PostTest "xss_img_onerror" "xss" "block" $XssEndpoint "<img src=x onerror=alert(1)>"
Send-PostTest "xss_svg_onload" "xss" "block" $XssEndpoint "<svg onload=alert(1)>"
Send-PostTest "xss_js_href" "xss" "block" $XssEndpoint "<a href=javascript:alert(1)>click</a>"
Send-PostTest "xss_srcdoc" "xss" "block" $XssEndpoint "<iframe srcdoc='<script>alert(1)</script>'></iframe>"
Send-PostEncodedTest "xss_encoded_script" "xss" "block" $XssEndpoint "%253Cscript%253Ealert%281%29%253C%252Fscript%253E" "%253Cscript%253Ealert(1)%253C%252Fscript%253E"
Send-PostTest "xss_entity_script" "xss" "block" $XssEndpoint "&lt;script&gt;alert(1)&lt;/script&gt;"

Write-Host ""
Write-Host "== Benign corpus =="
Send-GetTest "benign_numeric_id" "benign" "allow" $SqliEndpoint "1"
Send-GetTest "benign_search_words" "benign" "allow" $SqliEndpoint "union station select menu"
Send-GetTest "benign_apostrophe" "benign" "allow" $SqliEndpoint "O'Reilly"
Send-PostTest "benign_guestbook" "benign" "allow" $XssEndpoint "hello dvwa team"
Send-PostTest "benign_html_text" "benign" "allow" $XssEndpoint "I like HTML and CSS"
Send-PostTest "benign_math" "benign" "allow" $XssEndpoint "2 < 3 and 5 > 4"

$Results | Export-Csv -LiteralPath $CsvFile -NoTypeInformation -Encoding UTF8
Write-MarkdownReport

$sqliRows = @($Results | Where-Object { $_.category -eq "sqli" })
$xssRows = @($Results | Where-Object { $_.category -eq "xss" })
$benignRows = @($Results | Where-Object { $_.category -eq "benign" })
$sqliBlockedRows = @($sqliRows | Where-Object { $_.blocked -eq "yes" })
$xssBlockedRows = @($xssRows | Where-Object { $_.blocked -eq "yes" })
$benignBlockedRows = @($benignRows | Where-Object { $_.blocked -eq "yes" })
$sqliSuccessRows = @($sqliRows | Where-Object { $_.attack_result -eq "reussi" })
$xssSuccessRows = @($xssRows | Where-Object { $_.attack_result -eq "reussi" })

Write-Host ""
Write-Host "== Summary =="
Write-Host ("SQLi failed:    {0}/{1} ({2}%), reussi: {3}" -f $sqliBlockedRows.Count, $sqliRows.Count, (Get-Percent $sqliBlockedRows.Count $sqliRows.Count), $sqliSuccessRows.Count)
Write-Host ("XSS failed:     {0}/{1} ({2}%), reussi: {3}" -f $xssBlockedRows.Count, $xssRows.Count, (Get-Percent $xssBlockedRows.Count $xssRows.Count), $xssSuccessRows.Count)
Write-Host ("Faux positif:   {0}/{1} ({2}%)" -f $benignBlockedRows.Count, $benignRows.Count, (Get-Percent $benignBlockedRows.Count $benignRows.Count))
Write-Host ""
Write-Host "CSV report:      $CsvFile"
Write-Host "Markdown report: $MdFile"
