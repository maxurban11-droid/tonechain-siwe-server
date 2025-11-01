// helpers/cors.js
const DEFAULT_ORIGINS = [
  "https://concave-device-193297.framer.app",
  "https://*.framer.app",
  "https://tonechain.app",
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
    if (pat.startsWith("https://*.")) {
      const want = pat.slice("https://*.".length);
      try {
        const u = new URL(origin);
        const host = u.host; // z.B. foo.bar.framer.app
        if (host === want || host.endsWith("." + want)) return origin;
      } catch {}
    } else if (origin === pat) {
      return origin;
    }
  }
  return null;
}

export function withCors(handler) {
  return async (req, res) => {
    const origin = req.headers.origin || "";
    const allowed = matchOrigin(origin);

    // Wichtig: Nur eine *konkrete* Origin zurückgeben, nie "*" bei credentials:true
    if (!allowed) {
      // preflight gnädig beantworten (ohne freigabe)
      if (req.method === "OPTIONS") return res.status(204).end();
      return res.status(403).json({ ok: false, error: "Origin not allowed" });
    }

    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Origin", allowed);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") return res.status(204).end();
    return handler(req, res);
  };
}

export function handleOptions(req, res) {
  const origin = req.headers.origin || "";
  const allowed = matchOrigin(origin);
  if (!allowed) return res.status(204).end();
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", allowed);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return res.status(204).end();
}
