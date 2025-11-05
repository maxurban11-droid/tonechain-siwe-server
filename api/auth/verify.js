// /api/auth/verify.js — SIWE-Verify mit Link-Option & Schutz vor Doppelkonten (Node runtime)
import crypto from "node:crypto";

/* ===== Konfiguration ===== */
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

function setDebug(res, msg) {
  try { res.setHeader("X-TC-Debug", msg); } catch {}
}

/* ===== Helpers ===== */
function originAllowed(origin) {
  try {
    if (!origin) return false;
    const { hostname } = new URL(origin);
    if (ALLOWED_DOMAINS.has(hostname)) return true;
    if (hostname.endsWith(".framer.app") || hostname.endsWith(".framer.website")) return true;
    if (hostname === "localhost" || hostname === "127.0.0.1") return true;
    return false;
  } catch { return false; }
}

function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "SameSite=None", "Secure", "Partitioned"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]);
}

function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]);
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

  // Key: Value-Zeilen
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
  if (!out.domain || !out.address || !out.uri || !out.version || !out.chainId || !out.nonce || !out.issuedAt) return null;
  return out;
}

function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

/* ===== Handler ===== */
export default async function handler(req, res) {
  const origin = req.headers.origin || "";
  const allowed = originAllowed(origin);

  // --- CORS ---
  res.setHeader("Vary", "Origin");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  // beide Schreibweisen von X-TC-Intent zulassen (einige Envs prüfen exakt)
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent, x-tc-intent");

  if (req.method === "OPTIONS") {
    setDebug(res, allowed ? "preflight-ok" : "preflight-denied");
    return res.status(204).end();
  }
  if (req.method !== "POST") return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  if (!allowed) return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });

  try {
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase(); // "link" | ""
    const bearer = readBearer(req);

    // 1) Payload
    const { message, signature } = req.body || {};
    if (!message || !signature) return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD" });

    // 2) Server-Nonce
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    if (!cookieNonce) return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });

    // 3) SIWE parse + Checks
    const siwe = parseSiweMessage(message);
    if (!siwe) return res.status(400).json({ ok: false, code: "INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    } catch { return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" }); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });
    if (siwe.nonce !== cookieNonce) return res.status(401).json({ ok: false, code: "NONCE_MISMATCH" });

    // 4) Signatur prüfen
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") return res.status(500).json({ ok: false, code: "VERIFY_UNAVAILABLE" });

    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) return res.status(401).json({ ok: false, code: "ADDRESS_MISMATCH" });

    // 5) Supabase Admin
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // 6) Wallet-Registrierung & Zuordnung
    const addressLower = String(siwe.address || "").toLowerCase();
    const { data: walletRow, error: wErr } = await sbAdmin
      .from("wallets")
      .select("user_id")
      .eq("address", addressLower)
      .maybeSingle();
    if (wErr) return res.status(500).json({ ok: false, code: "DB_SELECT_ERROR" });

    const isRegistered = !!walletRow;
    let walletUserId = walletRow?.user_id ?? null;

    // Aktives E-Mail-Profil bestimmen (falls Bearer vorhanden)
    let emailProfileId = null;
    if (bearer) {
      const { data: authData } = await sbAdmin.auth.getUser(bearer);
      const authUserId = authData?.user?.id || null;
      if (authUserId) {
        const { data: prof } = await sbAdmin
          .from("profiles")
          .select("id")
          .eq("user_id", authUserId)
          .maybeSingle();
        emailProfileId = prof?.id ?? null;
      }
    }

    /* ===== Link-Modus ===== */
    /* ===== Link-Modus (Wallet mit aktivem E-Mail-Profil verknüpfen) ===== */
if (intent === "link") {
  if (!bearer || !emailProfileId) {
    return res
      .status(403)
      .json({ ok: false, code: "LINK_REQUIRES_VALID_BEARER" });
  }

  // Wenn die Wallet schon einem ANDEREN Profil gehört → sofort blocken
  if (walletUserId && walletUserId !== emailProfileId) {
    return res.status(409).json({
      ok: false,
      code: "WALLET_ALREADY_LINKED",
      message: "This wallet is already linked to another profile.",
    });
  }

  // ✅ ATOMISCH in der DB verlinken (oder erstellen+verlinken):
  // - Unclaimed (user_id IS NULL)  → link to emailProfileId
  // - Bereits dem gleichen Profil  → idempotent OK
  // - Bereits anderem Profil       → RPC wirft 'WALLET_ALREADY_LINKED'
  const { error: rpcErr } = await sbAdmin.rpc("link_wallet_to_profile", {
    p_address: addressLower,
    p_profile_id: emailProfileId,
  });

  if (rpcErr) {
    const msg = (rpcErr.message || "").toLowerCase();
    if (msg.includes("wallet_already_linked")) {
      return res.status(409).json({
        ok: false,
        code: "WALLET_ALREADY_LINKED",
        message: "This wallet is already linked to another profile.",
      });
    }
    console.error("[verify:link] RPC failed:", rpcErr);
    return res
      .status(500)
      .json({ ok: false, code: "DB_LINK_RPC_ERROR" });
  }

  // Erfolgreich gelinkt → im laufenden Request die Zuordnung spiegeln
  walletUserId = emailProfileId;
  // (fällt unten in die Session-Setzung)
}

    // 7) user_id ggf. nachschlagen (wenn registriert; im Link-Fall oben gesetzt)
    let userId = walletUserId ?? null;
    if (!userId && isRegistered) {
      const { data: row2 } = await sbAdmin
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();
      userId = row2?.user_id ?? null;
    }

    // 8) SIWE-Session Cookie setzen
    const payload = {
      v: 1,
      addr: addressLower,
      userId: userId ?? null,
      ts: Date.now(),
      exp: Date.now() + SESSION_TTL_SEC * 1000,
    };
    const raw = JSON.stringify(payload);
    const sig = sign(raw);
    const sessionValue = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");

    clearCookie(res, COOKIE_NONCE); // Nonce verbraucht
    setCookie(res, COOKIE_SESSION, sessionValue, { maxAgeSec: SESSION_TTL_SEC });

    setDebug(res, "ok");
    return res.status(200).json({
      ok: true,
      address: addressLower,
      userId: userId ?? null,
      linked: intent === "link",
    });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    setDebug(res, "unexpected");
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR" });
  }
}

export const config = { runtime: "nodejs" };
