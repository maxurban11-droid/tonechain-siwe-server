// /api/auth/verify.js — gehärtete SIWE-Verify-Route (JS)
import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";

// ⚙️ Anpassbare, kleine Whitelists (leicht revertierbar)
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);

const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];

const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia

const MAX_AGE_MIN  = 10;              // IssuedAt max. 10 Min alt
const MAX_SKEW_MS  = 5 * 60 * 1000;   // ±5 Min Clock Skew
const COOKIE_NONCE   = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24; // 1 Tag

// 🔐 optional: Cookie-Signatur (wenn ENV gesetzt)
const SESSION_SECRET = process.env.SESSION_SECRET || null;

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
  const prev = res.getHeader("Set-Cookie") || [];
  res.setHeader("Set-Cookie", Array.isArray(prev) ? [...prev, parts.join("; ")] : [prev, parts.join("; ")]);
}
function clearCookie(res, name) {
  const prev = res.getHeader("Set-Cookie") || [];
  const killer = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  res.setHeader("Set-Cookie", Array.isArray(prev) ? [...prev, killer] : [prev, killer]);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}

function now() { return new Date(); }
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(now().getTime() - t);
  return age <= (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS);
}

function originAllowed(req) {
  const origin = req.headers.origin || "";
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch { return false; }
}
function uriAllowed(uri) {
  return ALLOWED_URI_PREFIXES.some(p => uri.startsWith(p));
}
function hostFromUri(u) { try { return new URL(u).hostname; } catch { return ""; } }

// 🧽 Nachricht robust normalisieren (unsichtbare Marks, CRLF etc.)
function normalizeMessage(raw) {
  return String(raw || "")
    .replace(/\r\n/g, "\n")
    .replace(/\u200e|\u200f|\u202a|\u202b|\u202c/g, "") // LTR/RTL marks
    .trim();
}

// 🔎 SIWE-Message tolerant parsen (nur Felder, die wir brauchen)
// akzeptiert Zeile 2 mit oder ohne "account:"
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n").map(l => l.trim());
  if (lines.length < 8) return null;

  // Zeile 0: "<domain> wants you to sign in with your Ethereum account:"
  const domain = (lines[0].split(" ")[0] || "").trim();

  // Zeile 1: "<address>" oder "account: <address>"
  let addressLine = (lines[1] || "").trim();
  addressLine = addressLine.replace(/^account\s*:?\s*/i, "").trim(); // tolerant

  // Optional: leerer Statement-Block ist erlaubt → Zeile 3
  const statement = (lines[3] || "").trim();

  // Key:Value Felder ab Zeile 5, tolerant bei Keys (Chain ID vs ChainID etc.)
  const kv = {};
  for (let i = 5; i < lines.length; i++) {
    const idx = lines[i].indexOf(":");
    if (idx === -1) continue;
    const k = lines[i].slice(0, idx).trim().toLowerCase().replace(/\s+/g, " ");
    const v = lines[i].slice(idx + 1).trim();
    kv[k] = v;
  }

  const chainIdStr = kv["chain id"] ?? kv["chainid"];
  const out = {
    domain,
    address: addressLine,
    statement,
    uri: kv["uri"],
    version: kv["version"],
    chainId: Number(chainIdStr),
    nonce: kv["nonce"],
    issuedAt: kv["issued at"] ?? kv["issuedat"],
  };

  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) {
    return null;
  }
  return out;
}

export default withCors(async function handler(req, res) {
  // OPTIONS wird durch withCors beantwortet
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // CSRF / Origin-Gate
  if (!originAllowed(req)) {
    return res.status(403).json({ ok: false, error: "Origin not allowed" });
  }

  // Body lesen
  const { message: rawMsg, signature: rawSig } = req.body || {};
  if (!rawMsg || !rawSig) {
    return res.status(400).json({ ok: false, error: "Missing message or signature" });
  }

  const message   = normalizeMessage(rawMsg);
  const signature = String(rawSig).trim();

  // Nonce muss als httpOnly Cookie gesetzt sein (vom /nonce)
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) {
    return res.status(400).json({ ok: false, error: "Missing server nonce" });
  }

  // SIWE tolerant parsen + Feld-Validierung
  const siwe = parseSiweMessage(message);
  if (!siwe) {
    return res.status(400).json({ ok: false, error: "Invalid SIWE format" });
  }

  // Domain / URI / Chain / Alter prüfen
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

  // 🔏 Signatur prüfen & Adresse vergleichen (case-insensitive)
  let recovered;
  try {
    const { verifyMessage } = await import("ethers");
    recovered = verifyMessage(message, signature);
  } catch {
    return res.status(400).json({ ok: false, error: "Signature verification failed" });
  }
  const sameAddr = (a, b) => String(a || "").toLowerCase() === String(b || "").toLowerCase();
  if (!sameAddr(recovered, siwe.address)) {
    return res.status(401).json({
      ok: false,
      error: "Address mismatch",
      // DEBUG-Hinweis: einmal testen, danach entfernen
      // detail: { recovered, addrFromMsg: siwe.address }
    });
  }

  // ✅ Erfolg → Nonce verwerfen & Session setzen
  try {
    const payload = {
      v: 1,
      addr: siwe.address,
      ts: Date.now(),
      exp: Date.now() + SESSION_TTL_SEC * 1000,
    };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    // Nonce killen + Session setzen
    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    return res.status(200).json({ ok: true, address: siwe.address });
  } catch {
    return res.status(500).json({ ok: false, error: "Session set failed" });
  }
});
