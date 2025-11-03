// /api/auth/verify.js — stabile SIWE-Verify-Route mit Registrierungscheck (Node runtime)
// Datei als .js belassen.

import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

/* ======== CORS (direkt im Handler, wie bei nonce/logout) ======== */
function setCors(req, res) {
  const origin = req.headers.origin || "";
  // Wir spiegeln den Origin zurück (notwendig bei credentials: 'include')
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

/* ============ Supabase Admin-Client (Service Role) ============ */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const sbAdmin = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false }})
  : null;

/* ============ Konfiguration ============ */
const ALLOWED_SIWE_URI_HOSTS = [
  "tonechain.app",
  ".framer.app",
  ".framerusercontent.com",
  ".framercanvas.com",
  "localhost",
  "127.0.0.1",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;
const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24;
const SESSION_SECRET = process.env.SESSION_SECRET || null;

/* ============ kleine Helfer ============ */
function sign(val){ if(!SESSION_SECRET) return null; return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex"); }
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`,"Path=/","HttpOnly","SameSite=None","Secure"];
  if (opts.maxAgeSec != null) parts.splice(1, 0, `Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [prev] : []), parts.join("; ")]);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [prev] : []), del]);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find(s => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(Date.now() - t);
  return age <= (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS);
}
function addrEq(a,b){ return String(a||"").toLowerCase() === String(b||"").toLowerCase(); }
function uriAllowedFlexible(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") return false;
    const host = u.host;
    return ALLOWED_SIWE_URI_HOSTS.some(p => {
      if (p === "localhost") return host.startsWith("localhost:");
      if (p === "127.0.0.1") return host.startsWith("127.0.0.1:");
      return p.startsWith(".") ? host.endsWith(p) : host === p;
    });
  } catch { return false; }
}
function parseSiweMessage(msg) {
  const lines = String(msg||"").split("\n");
  if (lines.length < 8) return null;
  const domain = (lines[0] || "").split(" ")[0] || "";
  const address = (lines[1] || "").trim();
  let i = 2; while (i < lines.length && !/^[A-Za-z ]+:\s/.test(lines[i])) i++;
  const fields = {};
  for (; i < lines.length; i++) {
    const row = lines[i]; const idx = row.indexOf(":");
    if (idx === -1) continue;
    fields[row.slice(0, idx).trim().toLowerCase()] = row.slice(idx+1).trim();
  }
  const out = {
    domain, address,
    uri: fields["uri"],
    version: fields["version"],
    chainId: Number(fields["chain id"]),
    nonce: fields["nonce"],
    issuedAt: fields["issued at"],
  };
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) return null;
  return out;
}
async function verifyPersonalSign(message, signature) {
  const mod = await import("ethers");
  const fn = mod.verifyMessage || (mod.default && mod.default.verifyMessage) || (mod.utils && mod.utils.verifyMessage);
  if (typeof fn !== "function") throw new Error("verifyMessage not available from ethers");
  return fn(message, signature);
}

/* ============ Handler ============ */
export default async function handler(req, res) {
  // Immer zuerst CORS setzen + OPTIONS beantworten
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" });

  // Payload
  const { message, signature } = (req.body || {});
  if (!message || !signature) return res.status(400).json({ ok:false, code:"INVALID_PAYLOAD" });

  // Server-Nonce (httpOnly)
  const cookieNonce = getCookie(req, COOKIE_NONCE);
  if (!cookieNonce) return res.status(400).json({ ok:false, code:"MISSING_SERVER_NONCE" });

  // SIWE parsen/prüfen
  const siwe = parseSiweMessage(message);
  if (!siwe) return res.status(400).json({ ok:false, code:"INVALID_SIWE_FORMAT" });
  if (!uriAllowedFlexible(siwe.uri)) return res.status(400).json({ ok:false, code:"URI_NOT_ALLOWED" });
  if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return res.status(400).json({ ok:false, code:"CHAIN_NOT_ALLOWED" });
  if (!withinAge(siwe.issuedAt)) return res.status(400).json({ ok:false, code:"MESSAGE_TOO_OLD" });
  // Domain-Zeile prüfen ist optional; viele Wallets variieren hier → weglassen oder flexibel prüfen.

  // Signatur prüfen
  let recovered;
  try { recovered = await verifyPersonalSign(message, signature); }
  catch { return res.status(400).json({ ok:false, code:"SIGNATURE_VERIFY_FAILED" }); }
  if (!addrEq(recovered, siwe.address)) return res.status(401).json({ ok:false, code:"ADDRESS_MISMATCH" });

  // Registrierungs-Check
  if (!sbAdmin) return res.status(500).json({ ok:false, code:"SERVER_CONFIG_MISSING" });
  const addressLower = String(siwe.address || "").toLowerCase();

  const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
  if (regErr) return res.status(500).json({ ok:false, code:"DB_ERROR" });
  if (!isRegistered) {
    clearCookie(res, COOKIE_NONCE);
    return res.status(403).json({ ok:false, code:"WALLET_NOT_REGISTERED", message:"No account found for this wallet. Please sign up first." });
  }

  // user_id zur Session
  let userId = null;
  const { data: row } = await sbAdmin.from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
  userId = row?.user_id ?? null;

  // Session setzen
  try {
    const payload = { v:1, addr: addressLower, userId, ts: Date.now(), exp: Date.now() + SESSION_TTL_SEC * 1000 };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({ ok:true, address: addressLower, userId });
  } catch (e) {
    return res.status(500).json({ ok:false, code:"SESSION_SET_FAILED" });
  }
}
