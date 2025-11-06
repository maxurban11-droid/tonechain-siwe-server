// /api/auth/verify.js — SIWE Verify + optional LINK-Flow (Node runtime)
import crypto from "node:crypto";
import { withCors } from "../../helpers/cors.js";

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

function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

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
  res.setHeader(
    "Set-Cookie",
    [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]
  );
}

function clearCookie(res, name) {
  const del = `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure; Partitioned`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), del]);
}

function deny(res, status, body) {
  try {
    clearCookie(res, COOKIE_SESSION);
    clearCookie(res, COOKIE_NONCE);
  } catch {}
  return res.status(status).json(body);
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

function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

export default withCors(async function handler(req, res) {
  if (req.method === "OPTIONS" || req.method === "HEAD") return res.status(204).end();
  if (req.method !== "POST") return deny(res, 405, { ok:false, code:"METHOD_NOT_ALLOWED" });

  try {
    const origin = req.headers.origin || "";
    // (Allowlist wird in withCors schon geprüft & Header gesetzt)

    // --- Intent & Bearer
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase(); // "link" | ""
    const bearer = readBearer(req);

    // --- Body
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const { message, signature } = body;
    if (!message || !signature) return deny(res, 400, { ok:false, code:"INVALID_PAYLOAD" });

    // --- Nonce aus Header ODER Cookie
    const headerNonce = req.headers["x-tc-nonce"] || req.headers["X-TC-Nonce"] || null;
    const cookieNonce = getCookie(req, COOKIE_NONCE);
    const providedNonce = String(headerNonce || cookieNonce || "");
    if (!providedNonce) return deny(res, 400, { ok:false, code:"MISSING_SERVER_NONCE" });

    // --- SIWE parse + Plausis
    const siwe = parseSiweMessage(message);
    if (!siwe) return deny(res, 400, { ok:false, code:"INVALID_SIWE_FORMAT" });
    if (!ALLOWED_DOMAINS.has(siwe.domain)) return deny(res, 400, { ok:false, code:"DOMAIN_NOT_ALLOWED" });
    try {
      const u = new URL(siwe.uri);
      if (!ALLOWED_URI_PREFIXES.some(p => u.href.startsWith(p))) return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" });
    } catch { return deny(res, 400, { ok:false, code:"URI_NOT_ALLOWED" }); }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return deny(res, 400, { ok:false, code:"CHAIN_NOT_ALLOWED" });
    if (!withinAge(siwe.issuedAt)) return deny(res, 400, { ok:false, code:"MESSAGE_TOO_OLD" });
    if (String(siwe.nonce) !== providedNonce) return deny(res, 401, { ok:false, code:"NONCE_MISMATCH" });

    // --- Signatur prüfen (ethers)
    const ethersMod = await import("ethers");
    const verify =
      ethersMod.verifyMessage ||
      (ethersMod.default && ethersMod.default.verifyMessage) ||
      (ethersMod.utils && ethersMod.utils.verifyMessage);
    if (typeof verify !== "function") return deny(res, 500, { ok:false, code:"VERIFY_UNAVAILABLE" });

    const recovered = await verify(message, signature);
    if (!addrEq(recovered, siwe.address)) return deny(res, 401, { ok:false, code:"ADDRESS_MISMATCH" });

    // --- Supabase Admin
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return deny(res, 500, { ok:false, code:"SERVER_CONFIG_MISSING" });

    const { createClient } = await import("@supabase/supabase-js");
    const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    const addressLower = String(siwe.address || "").toLowerCase();

    // Wallet-Status
    const { data: walletRow, error: wErr } = await sbAdmin
      .from("wallets")
      .select("address,user_id")
      .eq("address", addressLower)
      .maybeSingle();
    if (wErr) return deny(res, 500, { ok:false, code:"DB_SELECT_ERROR" });

    let isRegistered = !!walletRow;
    let walletUserId = walletRow?.user_id ?? null;

    // Aktive E-Mail-Session → Profil ermitteln
    let emailProfileId = null;
    if (bearer) {
      const { data: authData, error: authErr } = await sbAdmin.auth.getUser(bearer);
      if (!authErr) {
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
    }

    // LINK-Flow: Wallet ↔ aktives E-Mail-Profil verbinden
    if (intent === "link") {
      if (!bearer || !emailProfileId) {
        return deny(res, 403, { ok:false, code:"LINK_REQUIRES_VALID_BEARER" });
      }
      if (walletUserId && walletUserId !== emailProfileId) {
        return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED" });
      }
      if (!isRegistered) {
        const { error: insErr } = await sbAdmin.from("wallets").insert({ address: addressLower, user_id: emailProfileId });
        if (insErr) return deny(res, 500, { ok:false, code:"DB_UPSERT_ERROR" });
        isRegistered = true;
        walletUserId = emailProfileId;
      } else if (!walletUserId) {
        const { error: linkErr } = await sbAdmin
          .from("wallets")
          .update({ user_id: emailProfileId })
          .eq("address", addressLower)
          .is("user_id", null);
        if (linkErr) return deny(res, 500, { ok:false, code:"LINK_ERROR" });
        walletUserId = emailProfileId;
      }
      // danach ganz normal Session setzen
    }

    // Normaler Verify (kein link): nur zulassen, wenn Wallet bereits zugeordnet ist
    if (intent !== "link") {
      if (!isRegistered) {
        return deny(res, 403, { ok:false, code:"WALLET_NOT_REGISTERED" });
      }
      if (!walletUserId) {
        return deny(res, 409, { ok:false, code:"WALLET_UNASSIGNED" });
      }
      if (emailProfileId && walletUserId !== emailProfileId) {
        return deny(res, 409, { ok:false, code:"OTHER_ACCOUNT_ACTIVE" });
      }
    }

    // finale userId
    let userId = walletUserId ?? null;
    if (!userId && isRegistered) {
      const { data: again } = await sbAdmin
        .from("wallets")
        .select("user_id")
        .eq("address", addressLower)
        .maybeSingle();
      userId = again?.user_id ?? null;
    }
    if (!userId) return deny(res, 403, { ok:false, code:"NO_USER_FOR_WALLET" });

    // Session-Cookie setzen & Nonce verbrauchen
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

    return res.status(200).json({ ok:true, address: addressLower, userId, linked: intent === "link" });
  } catch (e) {
    console.error("[SIWE verify] unexpected error:", e);
    return deny(res, 500, { ok:false, code:"INTERNAL_ERROR" });
  }
});

export const config = { runtime: "nodejs" };
