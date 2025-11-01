// helpers/cors.js
const DEFAULT_ORIGINS = [
  "https://*.framer.app",
  // dein festes Projekt:
  "https://concave-device-193297.framer.app",
  // lokale Devs:
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

// optional: ENV-Whitelist, komma-getrennt
const envList = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const ALLOWLIST = [...envList, ...DEFAULT_ORIGINS];

function matchOrigin(origin) {
  if (!origin) return null;
  for (const pat of ALLOWLIST) {
    if (pat.startsWith("https://*.") && origin.startsWith("https://")) {
      const host = origin.replace(/^https?:\/\//, "");
      const want = pat.replace("https://*.", "");
      if (host === want || host.endsWith("." + want)) return origin;
    }
    if (origin === pat) return origin;
  }
  return null;
}

export function withCors(handler) {
  return async (req, res) => {
    const origin = req.headers.origin;
    const allowed = matchOrigin(origin) || origin || "*";

    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Origin", allowed);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization"
    );

    if (req.method === "OPTIONS") return res.status(204).end();
    return handler(req, res);
  };
}

// Hilfs-Export, falls du irgendwo nur das Preflight abfangen willst
export function handleOptions(req, res) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  return res.status(204).end();
}
