// helpers/cors.js
// Zentrale CORS-Helper für alle API-Routen (Vercel Serverless, Node/Express-Style)

const ALLOWED = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// Gibt die erlaubte Origin (oder leeren String) zurück
function pickOrigin(req) {
  const o = req.headers.origin || "";
  if (!o) return "";
  if (ALLOWED.length === 0) return "";               // nichts erlaubt
  if (ALLOWED.includes(o)) return o;                 // exakte Übereinstimmung
  return "";                                         // nicht erlaubt
}

// setzt CORS-Header (bei erlaubter Origin)
function applyCors(req, res) {
  const origin = pickOrigin(req);
  if (!origin) return;                               // keine ACAO Header setzen

  // wichtig für Cache-Vary & Cookies
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
}

// beantwortet Preflight
function handleOptions(req, res) {
  applyCors(req, res);
  res.status(204).end();
}

// Wrapper für deine Routen
function withCors(handler) {
  return async (req, res) => {
    if (req.method === "OPTIONS") return handleOptions(req, res);
    applyCors(req, res);
    return handler(req, res);
  };
}

module.exports = { withCors, handleOptions };
