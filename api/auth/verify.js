// /api/auth/verify.js — Final: stabile CORS + SIWE-Verify + Supabase-Check + Debug
// Wichtig: .js lassen (Node Runtime).

import crypto from "node:crypto";

/* ----------------------- Konfiguration ----------------------- */
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

/* ----------------------- Helpers ----------------------- */
const now = () => Date.now();
const lc = (s) => String(s || "").toLowerCase();

function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "SameSite=None", "Secure"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  return Math.abs(now() - t) <= MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS;
}
function addrEq(a, b) {
  return lc(a) === lc(b);
}
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");
  if (lines.length < 8) return null;

  const domain = (lines[0] || "").split(" ")[0] || "";
  const address = (lines[1] || "").trim();

  // ab Zeile 2 die Key:Value Felder suchen
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

/* ----------------------- Handler ----------------------- */
export default async function handler(req, res) {
  // ---- CORS IMMER zuerst (Preflight darf nie scheitern) ----
  const origin = req.headers.origin || "";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin || "*"); // Echo-Origin
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Debug-Header: zeigt Stage / feine Fehlerursachen im Network-Tab
  const dbg = (stage, detail) => {
    res.setHeader("x-tc-debug", stage);
    if (detail) res.setHeader("x-tc-detail", String(detail).slice(0, 512));
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
    // ---- Origin-Whitelist (nach Preflight) ----
    let originOk = false;
    try {
      originOk = !!(origin && ALLOWED_DOMAINS.has(new URL(origin).hostname));
    } catch {}
    if (!originOk) {
      dbg("origin-forbidden", origin);
      return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
    }

    // ---- Payload ----
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      dbg("payload-missing");
      return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD" });
    }

    // ---- Nonce (httpOnly Cookie) ----
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) {
      dbg("nonce-missing");
      return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });
    }

    // ---- SIWE parse & Checks ----
    const siwe = parseSiweMessage(message);
    if (!siwe) {
      dbg("siwe-parse-failed");
      return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });
    }
    if (!ALLOWED_DOMAINS.has(siwe.domain)) {
      dbg("siwe-domain-forbidden", siwe.domain);
      return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
    }
    try {
      const u = new URL(siwe.uri);
      const ok = ALLOWED_URI_PREFIXES.some((p) => u.href.startsWith(p));
      if (!ok) {
        dbg("siwe-uri-forbidden", siwe.uri);
        return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
      }
    } catch {
      dbg("siwe-uri-invalid", siwe.uri);
      return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) {
      dbg("siwe-chain-forbidden", siwe.chainId);
      return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
    }
    if (!withinAge(siwe.issuedAt)) {
      dbg("siwe-age-too-old", siwe.issuedAt);
      return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });
    }
    if (siwe.nonce !== cookieNonce) {
      dbg("siwe-nonce-mismatch");
      return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });
    }

    // ---- Signatur prüfen (ethers dyn. import) ----
    dbg("sig-verify-start");
    let recovered;
    try {
      const mod = await import("ethers");
      const verify =
        mod.verifyMessage || (mod.default && mod.default.verifyMessage) || (mod.utils && mod.utils.verifyMessage);
      if (typeof verify !== "function") {
        dbg("ethers-verify-missing");
        return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });
      }
      recovered = await verify(message, signature);
    } catch (e) {
      dbg("sig-verify-error", e?.message);
      return res.status(400).json({ ok: false, code: "SIGNATURE_VERIFY_FAILED" });
    }
    if (!addrEq(recovered, siwe.address)) {
      dbg("sig-address-mismatch");
      return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });
    }
    dbg("sig-verify-ok");

    // ---- Supabase Admin init (dyn. import, damit Preflight schlank bleibt) ----
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      dbg("db-env-missing");
      return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
    }

    let sbAdmin;
    try {
      const { createClient } = await import("@supabase/supabase-js");
      sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
    } catch (e) {
      dbg("db-init-error", e?.message);
      return res.status(500).json({ ok: false, code: "DB_INIT_ERROR" });
    }

    // ---- Registrierungscheck ----
    const addressLower = lc(siwe.address);
    dbg("db-rpc-wallet_registered");
    const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
    if (regErr) {
      dbg("db-rpc-error", regErr?.message || regErr);
      return res.status(500).json({ ok: false, code: "DB_RPC_ERROR" });
    }
    if (!isRegistered) {
      // Nonce invalidieren, aber KEIN Session-Cookie setzen
      clearCookie(res, COOKIE_NONCE);
      dbg("wallet-not-registered");
      return res.status(403).json({
        ok: false,
        code: "WALLET_NOT_REGISTERED",
        message: "No account found for this wallet. Please sign up first.",
      });
    }

    // ---- user_id zur Session (best effort) ----
    dbg("db-select-wallet-user");
    let userId = null;
    try {
      const { data: row } = await sbAdmin.from("wallets").select("user_id").eq("address", addressLower).maybeSingle();
      userId = row?.user_id ?? null;
    } catch (e) {
      // kein harter Fehler – Session geht auch ohne userId
      dbg("db-select-wallet-user-error", e?.message);
    }

    // ---- Session setzen ----
    dbg("session-set-start");
    try {
      const payload = { v: 1, addr: addressLower, userId, ts: now(), exp: now() + SESSION_TTL_SEC * 1000 };
      const raw = JSON.stringify(payload);
      const sig = sign(raw);
      const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

      clearCookie(res, COOKIE_NONCE);
      setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });
      dbg("session-set-ok");
      return res.status(200).json({ ok: true, address: addressLower, userId });
    } catch (e) {
      dbg("session-set-failed", e?.message);
      return res.status(500).json({ ok: false, code: "SESSION_SET_FAILED" });
    }
  } catch (e) {
    // Letzte Fangleine – Header bleiben erhalten
    dbg("internal-error", e?.message);
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR" });
  }
}
