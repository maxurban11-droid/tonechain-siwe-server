// helpers/cors.js

/** Default erlaubte Origins (kannst du anpassen/erweitern) */
const DEFAULT_ORIGINS = [
  "https://concave-device-193297.framer.app",
  // optional: Wildcard für Framer-Preview-Domains aktivieren:
  "https://*.framer.app",
  "https://tonechain.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

/** ENV-Whitelist: CORS_ORIGINS=foo.com,https://bar.app,https://*.example.com */
const envList = (
  process.env.CORS_ORIGINS ||
  process.env.CORS_ORIGIN ||    // <- neu: Singular akzeptieren
  process.env.ALLOWED_ORIGINS ||
  "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/** endgültige Allowlist (duplikate entfernen) */
const ALLOWLIST = Array.from(new Set([...envList, ...DEFAULT_ORIGINS]));

/** Normalisiert eine Origin-String-Quelle für den Vergleich. */
function normalizeOrigin(input) {
  if (!input || typeof input !== "string") return "";
  try {
    const u = new URL(input);
    // explizit nur scheme + host (+port) zurückgeben
    const normalized = `${u.protocol}//${u.host}`;
    return normalized.toLowerCase().replace(/\/+$/, "");
  } catch {
    // Falls bereits eine Origin ohne Pfad übergeben wurde
    return input.toLowerCase().replace(/\/+$/, "");
  }
}

/** Prüft, ob eine Origin in der Allowlist ist, inkl. Wildcard-Matching. */
function matchOrigin(origin) {
  const o = normalizeOrigin(origin);
  if (!o) return null;

  for (const patRaw of ALLOWLIST) {
    const pat = normalizeOrigin(patRaw);

    // Wildcard: https://*.example.com
    if (pat.startsWith("https://*.") || pat.startsWith("http://*.")) {
      const want = pat.replace("https://*.", "https://").replace("http://*.", "http://");
      try {
        const uO = new URL(o);
        const uW = new URL(want);
        // gleiche Schemes?
        if (uO.protocol !== uW.protocol) continue;
        // host matcht exakt oder als Subdomain
        if (uO.host === uW.host || uO.host.endsWith("." + uW.host)) {
          return o;
        }
      } catch {
        // ignorieren
      }
      continue;
    }

    if (o === pat) return o;
  }
  return null;
}

/** Setzt CORS-Header auf Node/Express/Next (Pages-Router) Response */
function setCorsHeaders(res, allowedOrigin) {
  res.setHeader("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "600");
}

/** Liefert CORS-Header-Objekt (für App Router / Edge Runtimes) */
export function corsHeadersForOrigin(origin) {
  const allowed = matchOrigin(origin);
  if (!allowed) return null;
  return {
    "Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "600",
  };
}

/**
 * Wrapper für Next.js Pages-Router API-Routen.
 * Nutzt die Allowlist und beantwortet OPTIONS/HEAD korrekt.
 */
export function withCors(handler) {
  return async (req, res) => {
    const origin = req.headers.origin || "";
    const allowed = matchOrigin(origin);

    // Preflight: wenn Origin NICHT erlaubt ist, antworte neutral ohne Freigabe
    if (req.method === "OPTIONS") {
      if (allowed) setCorsHeaders(res, allowed);
      return res.status(204).end();
    }

    // HEAD behandeln wie GET, aber ohne Body
    if (req.method === "HEAD") {
      if (!allowed) return res.status(403).end();
      setCorsHeaders(res, allowed);
      return res.status(204).end();
    }

    if (!allowed) {
      return res.status(403).json({ ok: false, error: "Origin not allowed" });
    }

    setCorsHeaders(res, allowed);
    return handler(req, res);
  };
}

/** Separater OPTIONS-Handler (falls du ihn in einer Route direkt nutzen willst) */
export function handleOptions(req, res) {
  const origin = req.headers.origin || "";
  const allowed = matchOrigin(origin);
  if (allowed) setCorsHeaders(res, allowed);
  return res.status(204).end();
}

/** Für Debug/Logs hilfreich */
export function getCorsAllowlist() {
  return [...ALLOWLIST];
}

export { matchOrigin };
