// /api/auth/register.js
// SIWE Register / Link
// - robuste CORS-Header (auch bei OPTIONS/Fehlern)
// - Nonce aus Header "X-TC-Nonce" (Cookie nur Fallback)
// - Nonce wird NICHT gelöscht (direkt danach folgt /verify)

import { withCors } from "../../helpers/cors.js";
import { readNonceFromReq } from "../../helpers/nonce.js";
import { SiweMessage } from "siwe";

const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const ALLOWED_URI_PREFIXES = [
  "https://tonechain.app",
  "https://concave-device-193297.framer.app",
];
const ALLOWED_CHAINS = new Set([1, 11155111]);
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;
const COOKIE_NONCE = "tc_nonce";

/* helpers */
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
const withinAge = (iso) => {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  return Math.abs(Date.now() - t) <= MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS;
};
const readBearer = (req) => {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
};
function deny(res, status, body, origin) {
  res.setHeader("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
  if (originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent, X-TC-Nonce");
  res.setHeader("Cache-Control", "public, max-age=0, s-maxage=0");
  return res.status(status).json(body);
}

async function handler(req, res) {
  const origin = req.headers.origin || "";

  // >>> CORS-Header IMMER zuerst setzen <<<
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
    const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase();
    const bearer = readBearer(req);

    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const message = body?.message;
    const signature = body?.signature;
    const creatorName = (body?.creatorName ?? "").trim() || null;

    if (!message || !signature) {
      return deny(res, 400, { ok:false, code:"INVALID_PAYLOAD", message:"Missing message or signature" }, origin);
    }

    // Nonce bevorzugt aus Header, sonst Cookie
    const providedNonce = readNonceFromReq(req);
    if (!providedNonce) return deny(res, 400, { ok:false, code:"MISSING_SERVER_NONCE" }, origin);

    // SIWE prüfen (inkl. Nonce)
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

    // Supabase Admin
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return deny(res, 500, { ok:false, code:"SERVER_CONFIG_MISSING" }, origin);
    }
    const { createClient } = await import("@supabase/supabase-js");
    const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    const addressLower = String(siwe.address || "").toLowerCase();

    // 1) Wallet upsert
    {
      const { error: upErr } = await sb.from("wallets")
        .upsert({ address: addressLower }, { onConflict: "address" });
      if (upErr) {
        console.error("[register] upsert wallets failed:", upErr);
        return deny(res, 500, { ok:false, code:"DB_UPSERT_ERROR" }, origin);
      }
    }

    // 2) Wallet lesen
    let { data: walletRow, error: wErr } = await sb
      .from("wallets").select("address,user_id").eq("address", addressLower).maybeSingle();
    if (wErr) {
      console.error("[register] select wallets failed:", wErr);
      return deny(res, 500, { ok:false, code:"DB_SELECT_ERROR" }, origin);
    }
    let profileId = walletRow?.user_id ?? null;

    // 3) LINK-Fall (E-Mail-User aktiv)
    let linkProfileId = null;
    if (intent === "link" && bearer) {
      try {
        const { data: authData, error: authErr } = await sb.auth.getUser(bearer);
        if (!authErr) {
          const authUserId = authData?.user?.id || null;
          if (authUserId) {
            const { data: profExisting } = await sb
              .from("profiles").select("id").eq("user_id", authUserId).maybeSingle();
            if (profExisting?.id) {
              linkProfileId = profExisting.id;
            } else {
              const { data: profNew, error: pInsErr } = await sb
                .from("profiles")
                .insert({ user_id: authUserId, ...(creatorName ? { creator_name: creatorName } : {}) })
                .select("id").single();
              if (pInsErr) {
                console.error("[register] create profiles(user_id=auth) failed:", pInsErr);
                return deny(res, 500, { ok:false, code:"PROFILE_CREATE_ERROR" }, origin);
              }
              linkProfileId = profNew.id;
            }

            // Konflikt?
            if (walletRow?.user_id && walletRow.user_id !== linkProfileId) {
              return deny(res, 409, { ok:false, code:"WALLET_ALREADY_LINKED" }, origin);
            }
            if (!walletRow?.user_id) {
              const { error: linkErr } = await sb
                .from("wallets").update({ user_id: linkProfileId }).eq("address", addressLower);
              if (linkErr) {
                console.error("[register] link wallet->profile failed:", linkErr);
                return deny(res, 500, { ok:false, code:"LINK_ERROR" }, origin);
              }
              profileId = linkProfileId;
              walletRow = { ...walletRow, user_id: linkProfileId };
            } else {
              profileId = walletRow.user_id;
            }
          }
        }
      } catch (e) {
        console.warn("[register] getUser via bearer exception:", e?.message || e);
      }
    }

    // 4) Standard-Fall (kein Bearer/link)
    if (!profileId && !linkProfileId) {
      const insertPayload = creatorName ? { creator_name: creatorName } : {};
      const { data: prof, error: pErr } = await sb
        .from("profiles").insert(insertPayload).select("id").single();
      if (pErr) {
        console.error("[register] create profile failed:", pErr);
        return deny(res, 500, { ok:false, code:"PROFILE_UPSERT_ERROR" }, origin);
      }
      profileId = prof.id;

      const { error: linkErr } = await sb
        .from("wallets").update({ user_id: profileId }).eq("address", addressLower);
      if (linkErr) {
        console.error("[register] link wallet->profile failed:", linkErr);
        return deny(res, 500, { ok:false, code:"LINK_ERROR" }, origin);
      }
    } else if (creatorName && profileId) {
      await sb.from("profiles").update({ creator_name: creatorName }).eq("id", profileId);
    }

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      ok: true,
      registered: true,
      address: addressLower,
      userId: profileId ?? linkProfileId ?? null,
      keepNonce: true,
      linked: Boolean(linkProfileId),
    });
  } catch (e) {
    console.error("[SIWE register] unexpected error:", e);
    return deny(res, 500, { ok:false, code:"INTERNAL_ERROR" }, req.headers.origin || "");
  }
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
