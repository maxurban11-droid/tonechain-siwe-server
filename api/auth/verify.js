// /api/auth/verify.js — gehärtete SIWE-Verify-Route (JS)
import { withCors } from "../../helpers/cors.js";

// ⚙️ Anpassen (klein & revertierbar):
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;               // IssuedAt darf max. 10min her sein
const MAX_SKEW_MS = 5 * 60 * 1000;    // ±5min Clock Skew Toleranz
const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24; // 1 Tag

// 🔐 Optional: Cookie-Signatur via Secret (falls gesetzt)
const SESSION_SECRET = process.env.SESSION_SECRET || null;
import crypto from "node:crypto";
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  parts.push("Path=/");
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  parts.push("HttpOnly");
  parts.push("SameSite=None");
  parts.push("Secure");
  res.setHeader("Set-Cookie", [...(res.getHeader("Set-Cookie") || []), parts.join("; ")]);
}
function clearCookie(res, name) {
  res.setHeader("Set-Cookie", [...(res.getHeader("Set-Cookie") || []), `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`]);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}
function parseJSONSafe(s) { try { return JSON.parse(s); } catch { return null; } }
function now() { return new Date(); }

// 🔎 EIP-4361 Parsen (nur Felder, die wir brauchen)
function parseSiweMessage(msg) {
  // Erwartetes Format (vereinfacht):
  // <domain> wants you to sign in with your Ethereum account:
  // <address>
  //
  // <statement>
  //
  // URI: <uri>
  // Version: <version>
  // Chain ID: <chainId>
  // Nonce: <nonce>
  // Issued At: <iso>

  const lines = String(msg || "").split("\n").map(l => l.trim());
  if (lines.length < 8) return null;

  const domainLine = lines[0];
  const addressLine = lines[1];
  const statementLine = lines[3] || ""; // optional
  const fields = Object.fromEntries(
    lines.slice(5).map(l => {
      const idx = l.indexOf(":");
      if (idx === -1) return [];
      const k = l.slice(0, idx).trim().toLowerCase();
      const v = l.slice(idx + 1).trim();
      return [k, v];
    })
  );

  // Domain extrahieren
  const domain = domainLine.split(" ")[0] || "";

  const out = {
    domain,
    address: addressLine,
    statement: statementLine,
    uri: fields["uri"],
    version: fields["version"],
    chainId: Number(fields["chain id"]),
    nonce: fields["nonce"],
    issuedAt: fields["issued at"],
  };
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) {
    return null;
  }
  return out;
}

function originAllowed(req) {
  const origin = req.headers.origin || "";
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch { return false; }
}
function hostFromUri(u) { try { return new URL(u).hostname; } catch { return ""; } }
function uriAllowed(uri) {
  return ALLOWED_URI_PREFIXES.some(p => uri.startsWith(p));
}
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(now().getTime() - t);
  return age <= (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS);
}

export default withCors(async function handler(req, res) {
  // OPTIONS wird in withCors bereits korrekt behandelt
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // CSRF / Origin-Gate
  if (!originAllowed(req)) {
    return res.status(403).json({ ok: false, error: "Origin not allowed" });
  }

  // Body holen
  let body = {};
  try { body = req.body || {}; } catch {}
  const { message, signature } = body;
  if (!message || !signature) {
    return res.status(400).json({ ok: false, error: "Missing message or signature" });
  }

  // Nonce aus httpOnly Cookie muss vorhanden sein
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) {
    return res.status(400).json({ ok: false, error: "Missing server nonce" });
  }

  // SIWE parsen + Validierungen
  const siwe = parseSiweMessage(message);
  if (!siwe) return res.status(400).json({ ok: false, error: "Invalid SIWE format" });

  // Domain/URI/Chain prüfen
  if (!ALLOWED_DOMAINS.has(siwe.domain)) {
    return res.status(400).json({ ok: false, error: "Domain not allowed" });
  }
  if (!uriAllowed(siwe.uri)) {
    return res.status(400).json({ ok: false, error: "URI not allowed" });
  }
  if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) {
    return res.status(400).json({ ok: false, error: "ChainId not allowed" });
  }
  if (!withinAge(siwe.issuedAt)) {
    return res.status(400).json({ ok: false, error: "Message too old (IssuedAt)" });
  }
  if (siwe.nonce !== cookieNonce) {
    return res.status(401).json({ ok: false, error: "Nonce mismatch" });
  }

  // 🔏 Adresse aus Signatur rückgewinnen & vergleichen
  let recovered;
  try {
    const { verifyMessage } = await import("ethers");
    recovered = verifyMessage(message, signature);
  } catch (e) {
    return res.status(400).json({ ok: false, error: "Signature verification failed" });
  }
  const addrEq = (a,b) => String(a||"").toLowerCase() === String(b||"").toLowerCase();
  if (!addrEq(recovered, siwe.address)) {
    return res.status(401).json({ ok: false, error: "Address mismatch" });
  }

  // ✅ Erfolg → Session setzen, Nonce löschen
  try {
    // Minimaler Session-Blob (optional signiert)
    const payload = {
      v: 1,
      addr: siwe.address,
      ts: Date.now(),
      exp: Date.now() + SESSION_TTL_SEC * 1000,
    };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = sig ? Buffer.from(JSON.stringify({ raw, sig })).toString("base64") 
                             : Buffer.from(JSON.stringify({ raw })).toString("base64");

    // Nonce killen + Session setzen
    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    return res.status(200).json({ ok: true, address: siwe.address });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Session set failed" });
  }
});
