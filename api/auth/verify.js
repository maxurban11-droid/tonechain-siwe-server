// /api/auth/verify.js — stabile SIWE-Verify-Route mit Registrierungscheck
// Laufzeit: Node (kein Edge). Datei als .js belassen.

import crypto from "node:crypto";

/* ================= Konfiguration ================= */
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

/* ================= kleine Helfer ================= */
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function pushCookie(res, str) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [str]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, str]);
  else res.setHeader("Set-Cookie", [String(prev), str]);
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

/* ================= Haupt-Handler ================= */
export default async function handler(req, res) {
  // ---- CORS IMMER direkt setzen (auch bei Fehlern/OPTIONS) ----
  const origin = req.headers.origin || "";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // kleiner Debug-Header mit Stages
  const stages = [];
  const mark = (s) => { stages.push(s); res.setHeader("x-tc-debug", stages.join(" > ")); };

  if (req.method === "OPTIONS") { mark("preflight"); return res.status(204).end(); }
  if (req.method !== "POST")   { mark("bad-method"); return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" }); }

  try {
    mark("origin-check");
    let allowed = false;
    try { allowed = !!(origin && ALLOWED_DOMAINS.has(new URL(origin).hostname)); } catch {}
    if (!allowed) return res.status(403).json({ ok:false, code:"ORIGIN_NOT_ALLOWED" });

    mark("payload");
    const { message, signature } = req.body || {};
    if (!message || !signature) return res.status(400).json({ ok:false, code:"INVALID_PAYLOAD" });

    mark("nonce");
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) return res.status(400).json({ ok:false, code:"MISSING_SERVER_NONCE" });

    mark("siwe-parse");
    const siwe = parseSiweMessage(message);
    if (!siwe) return res.status(400).json({ ok:false, code:"INVALID_SIWE_FORMAT" });

    if (!ALLOWED_DOMAINS.has(siwe.domain)) return res.status(400).json({ ok:false, code:"DOMAIN_NOT_ALLOWED" });
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) {
        return res.status(400).json({ ok:false, code:"URI_NOT_ALLOWED" });
      }
    } catch { return res.status(400).json({ ok:false, code:"URI_NOT_ALLOWED" }); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return res.status(400).json({ ok:false, code:"CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return res.status(400).json({ ok:false, code:"MESSAGE_TOO_OLD" });
    if (siwe.nonce !== cookieNonce) return res.status(401).json({ ok:false, code:"NONCE_MISMATCH" });

    mark("ethers");
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") return res.status(500).json({ ok:false, code:"VERIFY_UNAVAILABLE" });

    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) return res.status(401).json({ ok:false, code:"ADDRESS_MISMATCH" });

    mark("db-init");
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ ok:false, code:"SERVER_CONFIG_MISSING" });
    }
    let sbAdmin;
    try {
      const { createClient } = await import("@supabase/supabase-js");
      sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
    } catch (e) {
      console.error("[DB_INIT_ERROR]", e);
      return res.status(500).json({ ok:false, code:"DB_INIT_ERROR" });
    }

    mark("db-check");
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
    if (regErr) {
      console.error("[DB_ERROR wallet_registered]", regErr);
      return res.status(500).json({ ok:false, code:"DB_ERROR" });
    }
    if (!isRegistered) {
      clearCookie(res, COOKIE_NONCE);
      return res.status(403).json({ ok:false, code:"WALLET_NOT_REGISTERED", message:"No account for this wallet yet." });
    }

    mark("db-lookup");
    let userId = null;
    const { data: row, error: rowErr } = await sbAdmin
      .from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
    if (rowErr) console.warn("[wallets lookup]", rowErr);
    else userId = row?.user_id ?? null;

    mark("session");
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
    mark("ok");
    return res.status(200).json({ ok:true, address: addressLower, userId });
  } catch (e) {
    console.error("[SIWE verify] unexpected", e);
    mark("catch");
    return res.status(500).json({ ok:false, code:"INTERNAL_ERROR" });
  }
}

// Optional – falls eure Plattform es verlangt
// export const config = { runtime: "nodejs" };
