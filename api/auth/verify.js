// /api/auth/verify.js — stabile SIWE-Verify-Route mit Registrierungscheck
// WICHTIG: .js belassen. Node-Runtime erzwingen.
export const config = { runtime: "nodejs" };

import crypto from "node:crypto";

/* ---------------- Konfiguration ---------------- */
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

/* ---------------- kleine Helfer ---------------- */
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "SameSite=None", "Secure"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  const out = [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")];
  res.setHeader("Set-Cookie", out);
}
function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  const prev = res.getHeader("Set-Cookie");
  const out = [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del];
  res.setHeader("Set-Cookie", out);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const m = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(Date.now() - t);
  return age <= MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS;
}
function addrEq(a, b) {
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}
function parseSiweMessage(msg) {
  const lines = String(msg || "").split("\n");
  if (lines.length < 8) return null;
  const domain = (lines[0] || "").split(" ")[0] || "";
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

/* ---------------- Handler ---------------- */
export default async function handler(req, res) {
  // 1) CORS IMMER zuerst: Echo-Origin + Credentials erlauben
  const origin = req.headers.origin || "";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // 2) Preflight sofort beenden (so crashen spätere Imports/Checks den Preflight nicht)
  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  try {
    // 3) Ab hier darf es strenger werden (Whitelist NACH dem Preflight)
    let allowed = false;
    try {
      allowed = !!(origin && ALLOWED_DOMAINS.has(new URL(origin).hostname));
    } catch {}
    if (!allowed) {
      return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
    }

    // 4) Payload
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD" });
    }

    // 5) Server-Nonce aus Cookie
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) {
      return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });
    }

    // 6) SIWE prüfen
    const siwe = parseSiweMessage(message);
    if (!siwe) return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some((p) => u.href.startsWith(p))) {
        return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
      }
    } catch {
      return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) {
      return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
    }
    if (!withinAge(siwe.issuedAt)) {
      return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });
    }
    if (siwe.nonce !== cookieNonce) {
      return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });
    }

    // 7) Signatur prüfen (dynamic import → kein Preflight-Problem)
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") {
      return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });
    }
    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) {
      return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });
    }

    // 8) Supabase Admin (dynamic import)
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
    }
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false },
    });

    // 9) Registrierungs-Check
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: isRegistered, error: regErr } = await sbAdmin.rpc("wallet_registered", { p_address: addressLower });
    if (regErr) {
      console.error("[SIWE] wallet_registered rpc error:", regErr);
      return res.status(500).json({ ok: false, code: "DB_ERROR" });
    }
    if (!isRegistered) {
      clearCookie(res, COOKIE_NONCE); // Nonce invalidieren
      return res.status(403).json({
        ok: false,
        code: "WALLET_NOT_REGISTERED",
        message: "No account found for this wallet. Please sign up first.",
      });
    }

    // 10) user_id (optional) für Session
    let userId = null;
    try {
      const { data: row, error: rowErr } = await sbAdmin
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();
      if (!rowErr) userId = row?.user_id ?? null;
    } catch (e) {
      console.warn("[SIWE] wallets lookup warning:", e);
    }

    // 11) Session-Cookie setzen
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

    return res.status(200).json({ ok: true, address: addressLower, userId });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR" });
  }
}
