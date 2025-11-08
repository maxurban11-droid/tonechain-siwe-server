// helpers/cors.js

const DEFAULT_ORIGINS = [
  "https://concave-device-193297.framer.app",
  "https://*.framer.app",
  // ⬇️ Ergänzt: Framer Canvas / Website-Domains (werden in Previews oft genutzt)
  "https://framercanvas.com",
  "https://*.framercanvas.com",
  "https://*.framer.website",
  "https://tonechain.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
]

const envList = (
  process.env.CORS_ORIGINS ||
  process.env.CORS_ORIGIN ||
  process.env.ALLOWED_ORIGINS ||
  ""
)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)

const ALLOWLIST = Array.from(new Set([...envList, ...DEFAULT_ORIGINS]))

function normalizeOrigin(input) {
  if (!input || typeof input !== "string") return ""
  try {
    const u = new URL(input)
    return `${u.protocol}//${u.host}`.toLowerCase().replace(/\/+$/, "")
  } catch {
    return input.toLowerCase().replace(/\/+$/, "")
  }
}

export function matchOrigin(origin) {
  const o = normalizeOrigin(origin)
  if (!o) return null

  for (const patRaw of ALLOWLIST) {
    const pat = normalizeOrigin(patRaw)

    // Wildcard host, z.B. https://*.framer.app
    if (pat.startsWith("https://*.") || pat.startsWith("http://*.")) {
      const want = pat
        .replace("https://*.", "https://")
        .replace("http://*.", "http://")
      try {
        const uO = new URL(o)
        const uW = new URL(want)
        if (uO.protocol !== uW.protocol) continue
        if (uO.host === uW.host || uO.host.endsWith("." + uW.host)) return o
      } catch {}
      continue
    }

    if (o === pat) return o
  }
  return null
}

function unionRequestedHeaders(req) {
  const requested = String(
    req?.headers?.["access-control-request-headers"] ||
    req?.headers?.["Access-Control-Request-Headers"] ||
    ""
  ).trim()

  // ⬇️ WICHTIG: "Cache-Control" hinzufügen (Problem-Header aus deinem Log)
  const base = ["Content-Type", "Authorization", "X-TC-Intent", "X-TC-Nonce", "Cache-Control"]
  const extra = requested
    ? requested.split(",").map((h) => h.trim()).filter(Boolean)
    : []
  // Einzigartige, geordnete Liste
  return Array.from(new Set([...base, ...extra])).join(", ")
}

function setCorsHeaders(res, allowedOrigin, req) {
  res.setHeader("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
  if (allowedOrigin) {
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin)
    res.setHeader("Access-Control-Allow-Credentials", "true")
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
  // ⬇️ dynamisch inkl. Cache-Control spiegeln
  res.setHeader("Access-Control-Allow-Headers", unionRequestedHeaders(req))
  res.setHeader("Access-Control-Max-Age", "600")
}

export function corsHeadersForOrigin(origin) {
  const allowed = matchOrigin(origin)
  if (!allowed) return null
  return {
    "Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    // ⬇️ feste Variante ebenfalls um Cache-Control erweitert
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-TC-Intent, X-TC-Nonce, Cache-Control",
    "Access-Control-Max-Age": "600",
  }
}

// WICHTIG: OPTIONS **immer** direkt hier beantworten – ohne Redirects.
export function withCors(handler) {
  return async function corsWrapped(req, res) {
    const origin = req.headers.origin || ""

    // Erlaube Framer + Prod + localhost (bestehende Logik bleibt)
    const allowed =
      origin.endsWith(".framer.app") ||
      origin.endsWith(".framer.website") ||
      origin.endsWith(".framercanvas.com") || // ⬅️ ergänzt
      origin.includes("tonechain.app") ||
      origin.startsWith("http://localhost") ||
      origin.startsWith("http://127.0.0.1")

    res.setHeader("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    if (allowed) {
      res.setHeader("Access-Control-Allow-Origin", origin)
      res.setHeader("Access-Control-Allow-Credentials", "true")
    }
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    // ⬇️ HIER war vorher der feste String – jetzt dynamisch inkl. Cache-Control
    res.setHeader("Access-Control-Allow-Headers", unionRequestedHeaders(req))
    // debug/expose bleibt
    res.setHeader("Access-Control-Expose-Headers", "X-TC-Debug, X-TC-Error, X-TC-CT, X-TC-Nonce-Source")

    // Preflight sofort beenden
    if (req.method === "OPTIONS") {
      res.statusCode = 204
      return res.end()
    }

    // Andere Methoden an den eigentlichen Handler
    return handler(req, res)
  }
}

export function handleOptions(req, res) {
  const origin = req.headers.origin || ""
  const allowed = matchOrigin(origin)
  setCorsHeaders(res, allowed || origin || "*", req)
  return res.status(204).end()
}

export function getCorsAllowlist() {
  return [...ALLOWLIST]
}
