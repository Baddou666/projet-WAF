const http = require("http");
const https = require("https");
const { URL } = require("url");
const { inspectRequest } = require("./rules");
const { writeBlockedRequest } = require("./logger");

const listenPort = Number.parseInt(process.env.LISTEN_PORT || "8082", 10);
const upstreamUrl = new URL(process.env.UPSTREAM_URL || "http://dvwa:80");
const logFile = process.env.LOG_FILE || "/var/log/custom-waf/waf.log";
const bodyLimitBytes = 2 * 1024 * 1024;

function getClientIp(request) {
  const forwardedFor = request.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim();
  }
  return request.socket.remoteAddress || "unknown";
}

function collectBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    request.on("data", (chunk) => {
      total += chunk.length;
      if (total > bodyLimitBytes) {
        reject(new Error("Request body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });

    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function buildProxyHeaders(requestHeaders, targetHost) {
  const blockedHeaders = new Set([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
  ]);

  const headers = {};
  for (const [name, value] of Object.entries(requestHeaders)) {
    if (!blockedHeaders.has(name.toLowerCase())) {
      headers[name] = value;
    }
  }

  headers.host = targetHost;
  return headers;
}

function renderBlockPage(result, clientIp) {
  const rulesList = result.matches
    .map((match) => `<li><strong>${match.id}</strong> - ${match.name} (${match.source})</li>`)
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request Blocked</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: #0f172a; color: #e2e8f0; }
    .wrap { max-width: 760px; margin: 10vh auto; padding: 32px; }
    .card { background: linear-gradient(180deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 18px; padding: 28px; box-shadow: 0 20px 60px rgba(0,0,0,0.35); }
    h1 { margin-top: 0; color: #f87171; }
    code, pre { white-space: pre-wrap; word-break: break-word; background: #111827; border-radius: 12px; padding: 12px; display: block; }
    ul { line-height: 1.7; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>403 Forbidden</h1>
      <p>Your request was blocked by the custom WAF.</p>
      <p><strong>Client IP:</strong> ${escapeHtml(clientIp)}</p>
      <p><strong>Triggered rules:</strong></p>
      <ul>${rulesList}</ul>
      <p><strong>Detected payload:</strong></p>
      <pre>${escapeHtml(result.matches[0] ? result.matches[0].payload : "")}</pre>
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function proxyToUpstream(request, response, bodyBuffer) {
  const upstreamClient = upstreamUrl.protocol === "https:" ? https : http;
  const outboundHeaders = buildProxyHeaders(request.headers, upstreamUrl.host);
  const targetPath = `${upstreamUrl.pathname.replace(/\/$/, "")}${request.url}`;

  const proxyRequest = upstreamClient.request(
    {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port || undefined,
      method: request.method,
      path: targetPath,
      headers: outboundHeaders,
      timeout: 15000,
    },
    (proxyResponse) => {
      response.writeHead(proxyResponse.statusCode || 502, proxyResponse.headers);
      proxyResponse.pipe(response);
    },
  );

  proxyRequest.on("timeout", () => {
    proxyRequest.destroy(new Error("Upstream timeout"));
  });

  proxyRequest.on("error", (error) => {
    response.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    response.end(`Bad Gateway: ${error.message}`);
  });

  if (bodyBuffer.length > 0) {
    proxyRequest.write(bodyBuffer);
  }
  proxyRequest.end();
}

const server = http.createServer(async (request, response) => {
  try {
    const bodyBuffer = await collectBody(request);
    const bodyText = bodyBuffer.toString("utf8");
    const inspection = inspectRequest({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: bodyText,
    });

    if (inspection.blocked) {
      const clientIp = getClientIp(request);
      writeBlockedRequest(logFile, {
        timestamp: new Date().toISOString(),
        attackerIp: clientIp,
        requestLine: `${request.method} ${request.url}`,
        triggeredRules: inspection.matches.map((match) => match.id),
        maliciousPayload: inspection.matches[0] ? inspection.matches[0].payload : bodyText,
      });

      response.writeHead(403, { "Content-Type": "text/html; charset=utf-8" });
      response.end(renderBlockPage(inspection, clientIp));
      return;
    }

    proxyToUpstream(request, response, bodyBuffer);
  } catch (error) {
    response.writeHead(413, { "Content-Type": "text/plain; charset=utf-8" });
    response.end(`Request rejected: ${error.message}`);
  }
});

server.listen(listenPort, "0.0.0.0", () => {
  console.log(`Custom WAF listening on port ${listenPort}, upstream ${upstreamUrl.href}`);
});
