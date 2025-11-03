// /api/auth/verify.js — stabile SIWE-Verify-Route mit Registrierungscheck (Node runtime)

import crypto from "node:crypto";

// ===== Konfiguration =====
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN   = 10;
const MAX_SKEW_MS   = 5 * 60 * 1000;

const COOKIE_NONCE    = "tc_nonce";
const COOKIE_SESSION  = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24; // 1 Tag

const SESSION_SECRET = process.env.SESSION_SECRET || null;

// ===== kleine Helfer =====
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function pushCookie(res, cookie) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [cookie]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [String(prev), cookie]);
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  parts.push("Path=/");
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  parts.push("HttpOnly");
  parts.push("SameSite=None");
  parts.push("Secure");
  pushCookie(res, parts.join("; "));
}
function clearCookie(res, name) {
  pushCookie(res, `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`);
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
function addrEq(a, b) {
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");
  if (lines.length < 8) return null;
  const domain  = (lines[0] || "").split(" ")[0] || "";
  const address = (lines[1] || "").trim();
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

// ===== Haupt-Handler =====
export default async function handler(req, res) {
  // ---- CORS IMMER zuerst setzen (Preflight nie blockieren) ----
  const origin = req.headers.origin || "";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // kleine Debug-Header (helfen in der Browser-Konsole)
  const dbg = (stage, extra = {}) => {
    try { res.setHeader("x-tc-debug", `verify-v3|${stage}|${JSON.stringify(extra)}`); } catch {}
  };

  if (req.method === "OPTIONS") {
    dbg("preflight-ok");
    return res.status(204).end();
  }
  if (req.method !== "POST") {
    dbg("method-not-allowed");
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  try {
    // ---- Origin strikt prüfen (nachdem CORS gesetzt ist) ----
    let allowed = false;
    try { allowed = !!(origin && ALLOWED_DOMAINS.has(new URL(origin).hostname)); } catch {}
    if (!allowed) {
      dbg("origin-deny", { origin });
      return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
    }

    // ---- Payload + Nonce ----
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      dbg("bad-payload");
      return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD" });
    }
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) {
      dbg("no-server-nonce");
      return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });
    }

    // ---- SIWE parsen + statische Checks ----
    const siwe = parseSiweMessage(message);
    if (!siwe) { dbg("siwe-parse"); return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" }); }
    if (!ALLOWED_DOMAINS.has(siwe.domain)) { dbg("siwe-domain"); return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" }); }
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) {
        dbg("siwe-uri");
        return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
      }
    } catch {
      dbg("siwe-uri-parse");
      return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) { dbg("siwe-chain"); return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" }); }
    if (!withinAge(siwe.issuedAt)) { dbg("siwe-issued-at"); return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" }); }
    if (siwe.nonce !== cookieNonce) { dbg("nonce-mismatch"); return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" }); }

    // ---- Signatur prüfen (ethers) ----
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") {
      dbg("ethers-missing");
      return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });
    }
    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) {
      dbg("addr-mismatch");
      return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });
    }

    // ---- Supabase Admin initialisieren + schneller Selbsttest ----
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      dbg("env-missing", { hasUrl: !!SUPABASE_URL, hasKey: !!SUPABASE_SERVICE_ROLE_KEY });
      return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
    }
    if (!/^https:\/\/.+\.supabase\.co$/.test(SUPABASE_URL)) {
      dbg("url-format");
      return res.status(500).json({ ok: false, code: "BAD_SUPABASE_URL" });
    }
    const { createClient } = await import("@supabase/supabase-js");
    let sbAdmin;
    try {
      sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
      // kleiner Self-Test (liest nur 1 Feld, keine Secrets)
      await sbAdmin.from("profiles").select("user_id").limit(1);
    } catch (e) {
      console.error("[SIWE] Supabase init/test failed:", e);
      dbg("db-init-error");
      return res.status(500).json({ ok: false, code: "DB_INIT_ERROR" });
    }

    // ---- Registrierungscheck ----
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
    if (regErr) {
      console.error("[SIWE] wallet_registered rpc error:", regErr);
      dbg("rpc-error");
      return res.status(500).json({ ok: false, code: "DB_ERROR" });
    }
    if (!isRegistered) {
      clearCookie(res, COOKIE_NONCE);
      dbg("wallet-not-registered");
      return res.status(403).json({
        ok: false,
        code: "WALLET_NOT_REGISTERED",
        message: "No account found for this wallet. Please sign up first.",
      });
    }

    // user_id mitnehmen (optional)
    let userId = null;
    try {
      const { data: row } = await sbAdmin.from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
      userId = row?.user_id ?? null;
    } catch (e) {
      console.warn("[SIWE] wallets lookup warn:", e);
    }

    // ---- Session setzen ----
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
    dbg("ok");
    return res.status(200).json({ ok: true, address: addressLower, userId });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    dbg("internal-error");
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR" });
  }
}
