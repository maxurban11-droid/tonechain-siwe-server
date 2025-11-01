// /api/auth/verify.js — stabile SIWE-Verify-Route (Node runtime)
// Achtung: Datei-Endung .js lassen, kein TS nötig.

import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";

/* ============ Konfiguration (klein & schnell reversibel) ============ */
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]);   // mainnet + sepolia
const MAX_AGE_MIN   = 10;                        // IssuedAt max. 10 min alt
const MAX_SKEW_MS   = 5 * 60 * 1000;             // ±5 min Uhrtoleranz
const COOKIE_NONCE  = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24;            // 1 Tag

// Optional: Session-Signatur (wenn gesetzt)
const SESSION_SECRET = process.env.SESSION_SECRET || null;

/* ============ kleine Helfer ============ */
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
  const prev = /** @type {string[]|undefined} */(res.getHeader("Set-Cookie"));
  res.setHeader("Set-Cookie", [...(prev || []), parts.join("; ")]);
}

function clearCookie(res, name) {
  const prev = /** @type {string[]|undefined} */(res.getHeader("Set-Cookie"));
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  res.setHeader("Set-Cookie", [...(prev || []), del]);
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}

function now() { return new Date(); }

function originAllowed(req) {
  const origin = req.headers.origin || "";
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch { return false; }
}

function uriAllowed(uri) {
  try {
    const u = new URL(uri);
    return ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p));
  } catch { return false; }
}

function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(now().getTime() - t);
  return age <= (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS);
}

function addrEq(a, b) {
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}

/** Robust gegen kleine Layout-Varianten der Standard-SIWE Message */
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");

  if (lines.length < 8) return null;

  const domain = (lines[0] || "").split(" ")[0] || "";
  const address = (lines[1] || "").trim();

  // Felder block beginnt typischerweise nach einer Leerzeile + ggf. Statement
  // Wir suchen ab Zeile 2 die erste Zeile, die mit "<Key>: " beginnt.
  let i = 2;
  while (i < lines.length && !/^[A-Za-z ]+:\s/.test(lines[i])) i++;

  const fields = {};
  for (; i < lines.length; i++) {
    const row = lines[i];
    const idx = row.indexOf(":");
    if (idx === -1) continue;
    const k = row.slice(0, idx).trim().toLowerCase();
    const v = row.slice(idx + 1).trim();
    fields[k] = v;
  }

  const out = {
    domain,
    address,
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

/** Ethers v5/v6, ESM/CJS-robuster Zugriff auf verifyMessage */
async function verifyPersonalSign(message, signature) {
  const mod = await import("ethers");             // ESM-Only in v6
  const candidate =
    // v6: benannter Export
    mod.verifyMessage ||
    // v6: default-Export-Objekt
    (mod.default && mod.default.verifyMessage) ||
    // (Fallback v5: utils.verifyMessage)
    (mod.utils && mod.utils.verifyMessage);

  if (typeof candidate !== "function") {
    throw new Error("verifyMessage not available from ethers");
  }
  return candidate(message, signature);
}

/* ============ Handler (mit CORS-Wrapper) ============ */
export default withCors(async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // CSRF-Schutz: nur bekannte Origins
  if (!originAllowed(req)) {
    return res.status(403).json({ ok: false, error: "Origin not allowed" });
  }

  // Payload
  let body = {};
  try { body = req.body || {}; } catch {}
  const { message, signature } = body;
  if (!message || !signature) {
    return res.status(400).json({ ok: false, error: "Missing message or signature" });
  }

  // Server-Nonce muss aus httpOnly Cookie kommen
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) {
    return res.status(400).json({ ok: false, error: "Missing server nonce" });
  }

  // SIWE-Message parsen & validieren
  const siwe = parseSiweMessage(message);
  if (!siwe) {
    return res.status(400).json({ ok: false, error: "Invalid SIWE format" });
  }
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

  // Signatur prüfen (robuster ethers-Import)
  let recovered;
  try {
    recovered = await verifyPersonalSign(message, signature);
  } catch (e) {
    return res.status(400).json({ ok: false, error: "Signature verification failed" });
  }
  if (!addrEq(recovered, siwe.address)) {
    return res.status(401).json({ ok: false, error: "Address mismatch" });
  }

  // Erfolg → Session setzen, Nonce löschen
  try {
    const payload = {
      v: 1,
      addr: siwe.address,
      ts: Date.now(),
      exp: Date.now() + SESSION_TTL_SEC * 1000,
    };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer
      .from(JSON.stringify(sig ? { raw, sig } : { raw }))
      .toString("base64");

    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    return res.status(200).json({ ok: true, address: siwe.address });
  } catch {
    return res.status(500).json({ ok: false, error: "Session set failed" });
  }
});
