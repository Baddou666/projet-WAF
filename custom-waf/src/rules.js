const htmlEntities = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  colon: ":",
  sol: "/",
  tab: "\t",
  newline: "\n",
};

const rules = [
  {
    id: "SQLI-001",
    category: "sqli",
    severity: "critical",
    score: 7,
    name: "UNION query injection",
    pattern: /\bunion\b(?:[\s\S]|\/\*.*?\*\/){0,120}\bselect\b/i,
  },
  {
    id: "SQLI-002",
    category: "sqli",
    severity: "critical",
    score: 7,
    name: "Boolean tautology injection",
    pattern: /(?:'|"|`|\)|\b\d+\b)\s*(?:or|and)\s*(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*|"[^"]*"\s*=\s*"[^"]*"|\w+\s+like\s+\w+)/i,
  },
  {
    id: "SQLI-003",
    category: "sqli",
    severity: "medium",
    score: 3,
    name: "SQL comment with nearby SQL syntax",
    pattern: /(?:\b(select|union|insert|update|delete|drop|alter|create|truncate|or|and)\b[\s\S]{0,80}(--|#|\/\*)|(--|#|\/\*)[\s\S]{0,80}\b(select|union|insert|update|delete|drop|alter|create|truncate|or|and)\b)/i,
  },
  {
    id: "SQLI-004",
    category: "sqli",
    severity: "critical",
    score: 7,
    name: "Time based SQL injection",
    pattern: /\b(sleep|benchmark|pg_sleep|dbms_pipe\.receive_message|waitfor\s+delay)\b\s*(?:\(|'|\d)/i,
  },
  {
    id: "SQLI-005",
    category: "sqli",
    severity: "high",
    score: 5,
    name: "Database metadata probing",
    pattern: /\b(information_schema|sysobjects|syscolumns|sqlite_master|pg_catalog|all_tables|user_tables|mysql\.user)\b/i,
  },
  {
    id: "SQLI-006",
    category: "sqli",
    severity: "high",
    score: 5,
    name: "Stacked SQL statement",
    pattern: /;\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec|execute)\b/i,
  },
  {
    id: "SQLI-007",
    category: "sqli",
    severity: "high",
    score: 5,
    name: "SQL file or command function",
    pattern: /\b(load_file|into\s+outfile|xp_cmdshell|sp_executesql|utl_http|copy\s+.*\s+from)\b/i,
  },
  {
    id: "SQLI-008",
    category: "sqli",
    severity: "medium",
    score: 3,
    name: "Suspicious SQL function chain",
    pattern: /\b(concat|char|chr|ascii|substring|substr|mid|cast|convert)\s*\([^)]{0,120}\)/i,
  },
  {
    id: "XSS-001",
    category: "xss",
    severity: "critical",
    score: 7,
    name: "Executable HTML tag",
    pattern: /<\s*\/?\s*(?:script|iframe|object|embed|applet|meta|link|base)\b[^>]*>/i,
  },
  {
    id: "XSS-002",
    category: "xss",
    severity: "critical",
    score: 7,
    name: "HTML event handler",
    pattern: /<[^>]+\s+on[a-z0-9_-]+\s*=\s*(?:["'][\s\S]*?["']|[^\s>]+)/i,
  },
  {
    id: "XSS-003",
    category: "xss",
    severity: "critical",
    score: 7,
    name: "Scriptable URI scheme",
    pattern: /(?:href|src|xlink:href|action|formaction)\s*=\s*(?:["']?\s*)?(?:(?:javascript|vbscript)\s*:|data\s*:\s*text\/html)/i,
  },
  {
    id: "XSS-004",
    category: "xss",
    severity: "critical",
    score: 7,
    name: "SVG or MathML script vector",
    pattern: /<\s*(?:svg|math)\b[\s\S]{0,300}(?:on[a-z0-9_-]+\s*=|<\s*script|href\s*=\s*["']?\s*javascript\s*:)/i,
  },
  {
    id: "XSS-005",
    category: "xss",
    severity: "high",
    score: 5,
    name: "Inline JavaScript execution sink",
    pattern: /\b(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function)\s*\(/i,
  },
  {
    id: "XSS-006",
    category: "xss",
    severity: "high",
    score: 5,
    name: "Dangerous HTML attribute",
    pattern: /\b(?:srcdoc|style)\s*=\s*(?:["'][\s\S]{0,300}(?:<\s*script|expression\s*\(|javascript\s*:|url\s*\()|[^\s>]*(?:expression\s*\(|javascript\s*:))/i,
  },
  {
    id: "XSS-007",
    category: "xss",
    severity: "medium",
    score: 3,
    name: "Encoded HTML tag marker",
    pattern: /(?:%3c|&lt;|&#x0*3c;|&#0*60;)\s*\/?\s*(?:script|img|svg|iframe|body|input|details|video|audio)/i,
  },
];

const blockThreshold = 5;
const maxValueLength = 20000;
const maxDecodePasses = 3;

function inspectRequest({ method, url, headers, body }) {
  const parts = buildInspectionParts({ method, url, headers, body });
  const matches = [];
  let score = 0;

  for (const rule of rules) {
    const hit = findRuleHit(rule, parts);
    if (!hit) {
      continue;
    }

    score += rule.score;
    matches.push({
      id: rule.id,
      category: rule.category,
      severity: rule.severity,
      score: rule.score,
      name: rule.name,
      payload: trimPayload(hit.value),
      source: hit.source,
      normalized: hit.normalized !== hit.value,
    });
  }

  return {
    blocked: score >= blockThreshold,
    score,
    matches,
  };
}

function buildInspectionParts({ method, url, headers, body }) {
  const parts = [
    { source: "method", value: stringify(method) },
    { source: "uri", value: stringify(url) },
    { source: "body", value: stringify(body) },
  ];

  for (const [headerName, headerValue] of Object.entries(headers || {})) {
    parts.push({
      source: `header:${headerName}`,
      value: Array.isArray(headerValue) ? headerValue.join(",") : stringify(headerValue),
    });
  }

  addUrlParts(parts, url);
  addBodyParts(parts, body, headers);
  return parts.filter((part) => part.value.length > 0);
}

function addUrlParts(parts, url) {
  const rawUrl = stringify(url);
  const baseUrl = rawUrl.startsWith("http") ? rawUrl : `http://waf.local${rawUrl.startsWith("/") ? "" : "/"}${rawUrl}`;

  try {
    const parsed = new URL(baseUrl);
    for (const [name, value] of parsed.searchParams.entries()) {
      parts.push({ source: `query:${name}`, value });
    }
  } catch (_error) {
    // Keep scanning the raw URI if URL parsing fails.
  }
}

function addBodyParts(parts, body, headers) {
  const rawBody = stringify(body);
  if (!rawBody) {
    return;
  }

  const contentType = stringify((headers || {})["content-type"] || (headers || {})["Content-Type"]).toLowerCase();

  if (contentType.includes("application/json")) {
    try {
      flattenJson(JSON.parse(rawBody), "json", parts);
    } catch (_error) {
      // Malformed JSON is still scanned as raw body.
    }
    return;
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    try {
      const params = new URLSearchParams(rawBody);
      for (const [name, value] of params.entries()) {
        parts.push({ source: `form:${name}`, value });
      }
    } catch (_error) {
      // Keep raw body scanning as fallback.
    }
  }
}

function flattenJson(value, path, parts) {
  if (value === null || value === undefined) {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => flattenJson(item, `${path}[${index}]`, parts));
    return;
  }

  if (typeof value === "object") {
    for (const [key, nestedValue] of Object.entries(value)) {
      flattenJson(nestedValue, `${path}.${key}`, parts);
    }
    return;
  }

  parts.push({ source: path, value: stringify(value) });
}

function findRuleHit(rule, parts) {
  for (const part of parts) {
    for (const variant of buildVariants(part.value)) {
      if (rule.pattern.test(variant)) {
        return {
          source: part.source,
          value: part.value,
          normalized: variant,
        };
      }
    }
  }
  return null;
}

function buildVariants(value) {
  const variants = new Set();
  const queue = [limitLength(stringify(value))];

  while (queue.length > 0) {
    const current = queue.shift();
    if (variants.has(current) || variants.size > 20) {
      continue;
    }

    variants.add(current);

    for (const decoded of decodeOnce(current)) {
      if (!variants.has(decoded)) {
        queue.push(decoded);
      }
    }
  }

  return variants;
}

function decodeOnce(value) {
  const decoded = new Set();
  const compacted = value.replace(/\u0000|\x00|\0/g, "");
  decoded.add(compacted);
  decoded.add(compacted.replace(/\+/g, " "));
  decoded.add(decodeHtmlEntities(compacted));
  decoded.add(decodeJavaScriptEscapes(compacted));

  tryDecodeURIComponent(compacted, decoded);
  tryDecodeURIComponent(compacted.replace(/\+/g, " "), decoded);

  return Array.from(decoded).filter((item) => item !== value).slice(0, maxDecodePasses + 2);
}

function tryDecodeURIComponent(value, decoded) {
  try {
    decoded.add(decodeURIComponent(value));
  } catch (_error) {
    // Invalid percent-encoding is common in hostile input; ignore it.
  }
}

function decodeHtmlEntities(value) {
  return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]+);?/gi, (entity, body) => {
    const key = body.toLowerCase();

    if (key.startsWith("#x")) {
      return codePointToString(Number.parseInt(key.slice(2), 16), entity);
    }

    if (key.startsWith("#")) {
      return codePointToString(Number.parseInt(key.slice(1), 10), entity);
    }

    return Object.prototype.hasOwnProperty.call(htmlEntities, key) ? htmlEntities[key] : entity;
  });
}

function decodeJavaScriptEscapes(value) {
  return value
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (_match, hex) => codePointToString(Number.parseInt(hex, 16), _match))
    .replace(/\\u([0-9a-f]{4})/gi, (_match, hex) => codePointToString(Number.parseInt(hex, 16), _match))
    .replace(/\\x([0-9a-f]{2})/gi, (_match, hex) => codePointToString(Number.parseInt(hex, 16), _match));
}

function codePointToString(codePoint, fallback) {
  if (!Number.isFinite(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
    return fallback;
  }
  return String.fromCodePoint(codePoint);
}

function trimPayload(value) {
  const text = stringify(value);
  return text.length > 500 ? `${text.slice(0, 500)}...` : text;
}

function limitLength(value) {
  return value.length > maxValueLength ? value.slice(0, maxValueLength) : value;
}

function stringify(value) {
  return value === null || value === undefined ? "" : String(value);
}

module.exports = {
  inspectRequest,
  rules,
};

