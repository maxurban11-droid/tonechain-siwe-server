// /api/auth/verify.js
// SIWE Verify (+ optional Link) mit robuster CORS-Antwort auch für OPTIONS/Fehler.

import crypto from "node:crypto";
import { withCors } from "../../helpers/cors.js";
import { readNonceFromReq } from "../../helpers/nonce.js";
import { SiweMessage } from "siwe";

/* ===== Policy ===== */
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
const SESSION_TTL_SEC = 60 * 60 * 24; // 1 Tag
const SESSION_SECRET = process.env.SESSION_SECRET || null;

/* ===== Utils ===== */
const originAllowed = (origin) => {
  try {
    if (!origin) return false;
    const { hostname } = new URL(origin);
    if (ALLOWED_DOMAINS.has(hostname)) return true;
    if (hostname.endsWith(".framer.app") || hostname.endsWith(".framer.website")) return true;
    if (hostname === "localhost" || hostname === "127.0.0.1") return true;
    return false;
  } catch { return false; }
};

const sign = (val) =>
  SESSION_SECRET ? crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex") : null;

function setCookie(res, name, value, opts = {}) {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=None",
    "Secure",
    "Partitioned",
  ];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]);
}
function deny(res, status, body, origin) {
  // >>> CORS auch bei Fehlern setzen <<<
  res.setHeader("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
  if (originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent, X-TC-Nonce");
  res.setHeader("Cache-Control", "public, max-age=0, s-maxage=0");
  try { clearCookie(res, COOKIE_SESSION); clearCookie(res, COOKIE_NONCE); } catch {}
  return res.status(status).json(body);
}
const withinAge = (iso) => {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  return Math.abs(Date.now() - t) <= MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS;
};
const addrEq = (a,b) => String(a||"").toLowerCase() === String(b||"").toLowerCase();
const readBearer = (req) => {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
};

async function handler(req, res) {
  const origin = req.headers.origin || "";

  // >>> CORS-Header IMMER zuerst setzen (auch für OPTIONS) <<<
  res.setHeader("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
  if (originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent, X-TC-Nonce");
  res.setHeader("Cache-Control", "public, max-age=0, s-maxage=0");

  if (req.method === "OPTIONS" || req.method === "HEAD") return res.status(204).end();
  if (req.method !== "POST") return deny(res, 405, { ok:false, code:"METHOD_NOT_ALLOWED" }, origin);
  if (!originAllowed(origin)) return deny(res, 403, { ok:false, code:"ORIGIN_NOT_ALLOWED" }, origin);

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const { message, signature } = body || {};
    if (!message || !signature) return deny(res, 400, { ok:false, code:"INVALID_PAYLOAD" }, origin);

    // Nonce bevorzugt aus Header (X-TC-Nonce)
    const providedNonce = readNonceFromReq(req);
    if (!providedNonce) return deny(res, 400, { ok:false, code:"MISSING_SERVER_NONCE" }, origin);

    // SIWE verifizieren + Policy-Checks
    const siweMsg = new SiweMessage(message);
    const { data: siwe } = await siweMsg.verify({ signature, nonce: String(providedNonce) });
    if (!siwe) return deny(res, 400, { ok:false, code:"SIWE_VERIFY_FAILED" }, origin);

    if (!ALLOWED_DOMAINS.has(siwe.domain)) return deny(res, 400, { ok:false, code:"DOMAIN_NOT_ALLOWED" }, origin);
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) {
        return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" }, origin);
      }
    } catch { return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" }, origin); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return deny(res, 400, { ok:false, code:"CHAIN_NOT_ALLOWED" }, origin);
    if (!withinAge(siwe.issuedAt)) return deny(res, 400, { ok:false, code:"MESSAGE_TOO_OLD" }, origin);

    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase();
    const bearer = readBearer(req);

    // Supabase Admin
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return deny(res, 500, { ok:false, code:"SERVER_CONFIG_MISSING" }, origin);
    }
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // Wallet-Status
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: walletRow, error: wErr } = await sbAdmin
      .from("wallets").select("address,user_id").eq("address", addressLower).maybeSingle();
    if (wErr) return deny(res, 500, { ok:false, code:"DB_SELECT_ERROR" }, origin);

    let isRegistered = !!walletRow;
    let walletUserId = walletRow?.user_id ?? null;

    // E-Mail-Profil (wenn Bearer)
    let emailProfileId = null;
    if (bearer) {
      const { data: authData, error: authErr } = await sbAdmin.auth.getUser(bearer);
      if (!authErr) {
        const authUserId = authData?.user?.id || null;
        if (authUserId) {
          const { data: prof } = await sbAdmin
            .from("profiles").select("id").eq("user_id", authUserId).maybeSingle();
          emailProfileId = prof?.id ?? null;
        }
      }
    }

    // Link-Modus
    if (intent === "link") {
      if (!bearer || !emailProfileId)
        return deny(res, 403, { ok:false, code:"LINK_REQUIRES_VALID_BEARER" }, origin);

      if (walletUserId && walletUserId !== emailProfileId)
        return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED" }, origin);

      // Fallback-Link (RPC optional)
      if (!isRegistered) {
        const { error: insErr } = await sbAdmin.from("wallets")
          .insert({ address: addressLower, user_id: emailProfileId });
        if (insErr) {
          const { data: again } = await sbAdmin.from("wallets")
            .select("address,user_id").eq("address", addressLower).maybeSingle();
          const uid = again?.user_id ?? null;
          if (uid && uid !== emailProfileId)
            return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED" }, origin);
          if (!uid) return deny(res, 500, { ok:false, code:"DB_UPSERT_ERROR" }, origin);
        }
        isRegistered = true; walletUserId = emailProfileId;
      } else if (!walletUserId) {
        const { data: upd, error: linkErr } = await sbAdmin.from("wallets")
          .update({ user_id: emailProfileId })
          .eq("address", addressLower).is("user_id", null).select("user_id");
        if (linkErr) return deny(res, 500, { ok:false, code:"LINK_ERROR" }, origin);
        if (!upd || upd.length === 0) {
          const { data: again } = await sbAdmin.from("wallets")
            .select("address,user_id").eq("address", addressLower).maybeSingle();
          const uid = again?.user_id ?? null;
          if (uid && uid !== emailProfileId)
            return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED" }, origin);
          if (!uid) return deny(res, 500, { ok:false, code:"LINK_ERROR" }, origin);
        }
        walletUserId = emailProfileId;
      }
    } else {
      // Normaler Verify (kein link)
      if (!isRegistered)
        return deny(res, 403, { ok:false, code:"WALLET_NOT_REGISTERED" }, origin);
      if (!walletUserId)
        return deny(res, 409, { ok:false, code:"WALLET_UNASSIGNED" }, origin);
      if (emailProfileId && walletUserId !== emailProfileId)
        return deny(res, 409, { ok:false, code:"OTHER_ACCOUNT_ACTIVE" }, origin);
    }

    // user_id final
    let userId = walletUserId ?? null;
    if (!userId && isRegistered) {
      const { data: row2 } = await sbAdmin.from("wallets")
        .select("user_id").eq("address", addressLower).maybeSingle();
      userId = row2?.user_id ?? null;
    }
    if (!userId) return deny(res, 403, { ok:false, code:"NO_USER_FOR_WALLET" }, origin);

    // Session setzen, Nonce verbrauchen
    const payload = { v:1, addr: addressLower, userId, ts: Date.now(), exp: Date.now() + SESSION_TTL_SEC*1000 };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    clearCookie(res, COOKIE_NONCE);
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    return res.status(200).json({ ok:true, address: addressLower, userId, linked: intent === "link" });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    return deny(res, 500, { ok:false, code:"INTERNAL_ERROR" }, req.headers.origin || "");
  }
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
