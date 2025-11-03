// /api/auth/verify.js — stabile SIWE-Verify-Route mit präziser Fehlerdiagnose
// Datei als .js belassen (Node runtime)

import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

/* ========= Konfiguration ========= */
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;

const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24;

const SESSION_SECRET = process.env.SESSION_SECRET || null;

/* ========= Supabase Admin ========= */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const sbAdmin = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;

/* ========= kleine Helfer ========= */
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "SameSite=None", "Secure"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
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
  try { if (!origin) return false; return ALLOWED_DOMAINS.has(new URL(origin).hostname); }
  catch { return false; }
}
function uriAllowed(uri) {
  try { const u = new URL(uri); return ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p)); }
  catch { return false; }
}
function withinAge(iso) {
  const t = Date.parse(iso); if (!Number.isFinite(t)) return false;
  const age = Math.abs(now().getTime() - t);
  return age <= (MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS);
}
function addrEq(a, b) { return String(a || "").toLowerCase() === String(b || "").toLowerCase(); }

// SIWE Message Parser (robust gegen Formatvarianten)
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");
  if (lines.length < 8) return null;
  const domain = (lines[0] || "").split(" ")[0] || "";
  const address = (lines[1] || "").trim();
  let i = 2; while (i < lines.length && !/^[A-Za-z ]+:\s/.test(lines[i])) i++;
  const fields = {};
  for (; i < lines.length; i++) {
    const row = lines[i]; const idx = row.indexOf(":"); if (idx === -1) continue;
    fields[row.slice(0, idx).trim().toLowerCase()] = row.slice(idx + 1).trim();
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
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) return null;
  return out;
}

// Ethers verifyMessage (v5/v6-kompatibel)
async function verifyPersonalSign(message, signature) {
  const mod = await import("ethers");
  const candidate = mod.verifyMessage || (mod.default && mod.default.verifyMessage) || (mod.utils && mod.utils.verifyMessage);
  if (typeof candidate !== "function") throw new Error("verifyMessage not available from ethers");
  return candidate(message, signature);
}

// Antworthelper mit Debug
function send(res, status, payload, dbg) {
  if (dbg) {
    // Nur für Debug-Phase – Header im Browser sichtbar
    res.setHeader("X-TC-Debug", dbg);
  }
  return res.status(status).json(payload);
}

/* ========= Handler ========= */
export default withCors(async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return send(res, 405, { ok: false, code: "METHOD_NOT_ALLOWED" });
    }
    if (!originAllowed(req)) {
      return send(res, 403, { ok: false, code: "ORIGIN_NOT_ALLOWED" }, "origin");
    }

    // Payload
    const body = req.body || {};
    const { message, signature } = body;
    if (!message || !signature) {
      return send(res, 400, { ok: false, code: "INVALID_PAYLOAD" }, "missing message/signature");
    }

    // Server-Nonce (httpOnly Cookie)
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) {
      return send(res, 400, { ok: false, code: "MISSING_SERVER_NONCE" }, "no tc_nonce");
    }

    // SIWE
    const siwe = parseSiweMessage(message);
    if (!siwe) return send(res, 400, { ok: false, code: "INVALID_SIWE_FORMAT" }, "parse");
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return send(res, 400, { ok: false, code: "DOMAIN_NOT_ALLOWED" }, siwe.domain);
    if (!uriAllowed(siwe.uri)) return send(res, 400, { ok: false, code: "URI_NOT_ALLOWED" }, siwe.uri);
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return send(res, 400, { ok: false, code: "CHAIN_NOT_ALLOWED" }, String(siwe.chainId));
    if (!withinAge(siwe.issuedAt)) return send(res, 400, { ok: false, code: "MESSAGE_TOO_OLD" }, siwe.issuedAt);
    if (siwe.nonce !== cookieNonce) return send(res, 401, { ok: false, code: "NONCE_MISMATCH" });

    // Signatur
    let recovered;
    try {
      recovered = await verifyPersonalSign(message, signature);
    } catch (e) {
      console.error("[SIWE] verifyMessage error:", e);
      return send(res, 400, { ok: false, code: "SIGNATURE_VERIFY_FAILED" }, "ethers");
    }
    if (!addrEq(recovered, siwe.address)) return send(res, 401, { ok: false, code: "ADDRESS_MISMATCH" });

    // Supabase vorhanden?
    if (!sbAdmin) {
      return send(res, 500, { ok: false, code: "SERVER_CONFIG_MISSING" }, "env");
    }

    const addressLower = String(siwe.address || "").toLowerCase();

    // 1) RPC wallet_registered
    let isRegistered = false;
    try {
      const { data, error } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
      if (error) throw error;
      isRegistered = !!data;
    } catch (e) {
      console.error("[SIWE] RPC wallet_registered failed:", e);
      return send(res, 500, { ok: false, code: "DB_ERROR" }, "rpc wallet_registered");
    }
    if (!isRegistered) {
      // keine Session setzen
      clearCookie(res, COOKIE_NONCE);
      return send(res, 403, {
        ok: false,
        code: "WALLET_NOT_REGISTERED",
        message: "No account found for this wallet. Please sign up first.",
      }, "not registered");
    }

    // 2) user_id zur Adresse (optional für Session)
    let userId = null;
    try {
      const { data, error } = await sbAdmin
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();
      if (error) throw error;
      userId = data?.user_id ?? null;
    } catch (e) {
      console.warn("[SIWE] wallets lookup failed:", e);
      // kein Hard-Fail – Session geht trotzdem weiter
    }

    // Session
    try {
      const payload = {
        v: 1,
        addr: addressLower,
        userId,
        ts: Date.now(),
        exp: Date.now() + SESSION_TTL_SEC * 1000,
      };
      const raw = JSON.stringify(payload);
      const sig = sign(raw);
      const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

      clearCookie(res, COOKIE_NONCE);
      setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

      return send(res, 200, { ok: true, address: addressLower, userId });
    } catch (e) {
      console.error("[SIWE] set session failed:", e);
      return send(res, 500, { ok: false, code: "SESSION_SET_FAILED" }, "cookie");
    }
  } catch (e) {
    console.error("[SIWE] INTERNAL_ERROR:", e);
    return send(res, 500, { ok: false, code: "INTERNAL_ERROR" }, "catch-all");
  }
});
