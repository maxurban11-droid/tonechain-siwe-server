// /api/auth/register.js
// SIWE Register / Link
// - akzeptiert Nonce aus Header "X-TC-Nonce" (Fallback: Cookie)
// - upsert wallets(address)
// - optionales Linken zu aktivem E-Mail-Profil (Authorization: Bearer ... + X-TC-Intent: link)
// - Nonce wird NICHT gelöscht (direkt danach folgt /verify mit gleicher Signatur)

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
const ALLOWED_CHAINS = new Set([1, 11155111]); // mainnet + sepolia
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;
const COOKIE_NONCE = "tc_nonce";

/* ---------- Helpers ---------- */
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
function withinAge(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = Math.abs(Date.now() - t);
  return age <= MAX_AGE_MIN * 60 * 1000 + MAX_SKEW_MS;
}
function addrEq(a, b) {
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}
function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

/* ---------- Handler ---------- */
async function handler(req, res) {
  if (req.method === "OPTIONS" || req.method === "HEAD") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });

  // Origin-Whitelist (zusätzlich zu withCors)
  const origin = req.headers.origin || "";
  if (!originAllowed(origin)) {
    return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
  }

  // Intent + Bearer
  const intent = String(req.headers["x-tc-intent"] || req.headers["X-TC-Intent"] || "").toLowerCase(); // "link" | "signup" | "signin"
  const bearer = readBearer(req);

  // Body
  const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
  const message = body?.message;
  const signature = body?.signature;
  const creatorName = (body?.creatorName ?? "").trim() || null;

  if (!message || !signature) {
    return res.status(400).json({ ok: false, code: "INVALID_PAYLOAD", message: "Missing message or signature" });
  }

  // Nonce bevorzugt aus Header, sonst Cookie
  const providedNonce = readNonceFromReq(req);
  if (!providedNonce) {
    return res.status(400).json({ ok: false, code: "MISSING_SERVER_NONCE" });
  }

  // SIWE verifizieren (inkl. Nonce)
  const siweMsg = new SiweMessage(message);
  const fields = await siweMsg.verify({ signature, nonce: String(providedNonce) });
  const siwe = fields?.data;
  if (!siwe) return res.status(400).json({ ok: false, code: "SIWE_VERIFY_FAILED" });

  // Policies
  if (!ALLOWED_DOMAINS.has(siwe.domain)) return res.status(400).json({ ok: false, code: "DOMAIN_NOT_ALLOWED" });
  try {
    const u = new URL(siwe.uri);
    if (!ALLOWED_URI_PREFIXES.some((p) => u.href.startsWith(p))) {
      return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
    }
  } catch {
    return res.status(400).json({ ok: false, code: "URI_NOT_ALLOWED" });
  }
  if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) return res.status(400).json({ ok: false, code: "CHAIN_NOT_ALLOWED" });
  if (!withinAge(siwe.issuedAt)) return res.status(400).json({ ok: false, code: "MESSAGE_TOO_OLD" });

  // Supabase Admin
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }
  const { createClient } = await import("@supabase/supabase-js");
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

  const addressLower = String(siwe.address || "").toLowerCase();

  // --- 1) Wallet upsert (nur Adresse) ---
  {
    const { error: upErr } = await sb
      .from("wallets")
      .upsert({ address: addressLower }, { onConflict: "address" });
    if (upErr) {
      console.error("[register] upsert wallets failed:", upErr);
      return res.status(500).json({ ok: false, code: "DB_UPSERT_ERROR" });
    }
  }

  // --- 2) Wallet Zustand lesen ---
  let { data: walletRow, error: wErr } = await sb
    .from("wallets")
    .select("address,user_id")
    .eq("address", addressLower)
    .maybeSingle();
  if (wErr) {
    console.error("[register] select wallets failed:", wErr);
    return res.status(500).json({ ok: false, code: "DB_SELECT_ERROR" });
  }

  let profileId = walletRow?.user_id ?? null;

  // --- 3) LINK-Fall: aktiver E-Mail-User möchte Wallet verknüpfen ---
  let linkProfileId = null;
  if (intent === "link" && bearer) {
    try {
      const { data: authData, error: authErr } = await sb.auth.getUser(bearer);
      if (authErr) {
        console.warn("[register] getUser via bearer failed:", authErr);
      } else {
        const authUserId = authData?.user?.id || null;
        if (authUserId) {
          const { data: profExisting } = await sb
            .from("profiles")
            .select("id")
            .eq("user_id", authUserId)
            .maybeSingle();

          if (profExisting?.id) {
            linkProfileId = profExisting.id;
          } else {
            const { data: profNew, error: pInsErr } = await sb
              .from("profiles")
              .insert({ user_id: authUserId, ...(creatorName ? { creator_name: creatorName } : {}) })
              .select("id")
              .single();
            if (pInsErr) {
              console.error("[register] create profiles(user_id=auth) failed:", pInsErr);
              return res.status(500).json({ ok: false, code: "PROFILE_CREATE_ERROR" });
            }
            linkProfileId = profNew.id;
          }

          // Konflikt: Wallet bereits mit anderem Profil verknüpft
          if (walletRow?.user_id && walletRow.user_id !== linkProfileId) {
            return res.status(409).json({
              ok: false,
              code: "WALLET_ALREADY_LINKED",
              message: "This wallet is already linked to another profile.",
            });
          }

          // Verlinken, falls noch nicht verknüpft
          if (!walletRow?.user_id) {
            const { error: linkErr } = await sb
              .from("wallets")
              .update({ user_id: linkProfileId })
              .eq("address", addressLower);
            if (linkErr) {
              console.error("[register] link wallet->profile failed:", linkErr);
              return res.status(500).json({ ok: false, code: "LINK_ERROR" });
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

  // --- 4) Standard-Fall (kein Bearer/kein Link): Profil anlegen & Wallet verknüpfen ---
  if (!profileId && !linkProfileId) {
    const insertPayload = creatorName ? { creator_name: creatorName } : {};
    const { data: prof, error: pErr } = await sb
      .from("profiles")
      .insert(insertPayload)
      .select("id")
      .single();
    if (pErr) {
      console.error("[register] create profile failed:", pErr);
      return res.status(500).json({ ok: false, code: "PROFILE_UPSERT_ERROR" });
    }
    profileId = prof.id;

    const { error: linkErr } = await sb
      .from("wallets")
      .update({ user_id: profileId })
      .eq("address", addressLower);
    if (linkErr) {
      console.error("[register] link wallet->profile failed:", linkErr);
      return res.status(500).json({ ok: false, code: "LINK_ERROR" });
    }
  } else if (creatorName && profileId) {
    // optional Creator-Name aktualisieren
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
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
