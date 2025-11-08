// /api/auth/exists.js — gehärtet
import { createClient } from "@supabase/supabase-js";

const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const CACHE_TTL_SEC = 60 * 5;

function originAllowed(origin) {
  try {
    if (!origin) return false;
    const host = new URL(origin).hostname;
    if (ALLOWED_DOMAINS.has(host)) return true;
    if (host.endsWith(".framer.app") || host.endsWith(".framer.website")) return true;
    if (host === "localhost" || host === "127.0.0.1") return true;
    return false;
  } catch { return false; }
}

function projectRefFromUrl(url) {
  try { return new URL(url).hostname.split(".")[0]; } catch { return "unknown"; }
}

export default async function handler(req, res) {
  const origin = req.headers.origin || req.headers.Origin || "";
  const allowed = originAllowed(origin);

  res.setHeader("Vary", "Origin");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-TC-Intent");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ ok:false, code:"METHOD_NOT_ALLOWED" });
  if (!allowed) return res.status(403).json({ ok:false, code:"ORIGIN_NOT_ALLOWED" });

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok:false, code:"SERVER_CONFIG_MISSING" });
  }
  // kleine Debug-Hilfe: welches SB-Projekt?
  res.setHeader("X-TC-Project", projectRefFromUrl(SUPABASE_URL));

  const raw = String(req.query.address || "").trim().toLowerCase();
  if (!raw) return res.status(400).json({ ok:false, code:"MISSING_ADDRESS" });
  if (!/^0x[0-9a-f]{40}$/.test(raw)) return res.status(400).json({ ok:false, code:"INVALID_ADDRESS" });

  const authHeader = req.headers.authorization || req.headers.Authorization || "";
  const m = String(authHeader).match(/^Bearer\s+(.+)$/i);
  const bearer = m ? m[1] : null;

  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

  try {
    // 1) Wallet-Owner lesen
    const { data: w, error: wErr } = await sb
      .from("wallets")
      .select("user_id")
      .eq("address", raw)
      .maybeSingle();
    if (wErr) return res.status(500).json({ ok:false, code:"DB_ERROR", message:wErr.message });

    const exists = !!w;
    const walletOwner = w?.user_id ?? null;

    // 2) Falls Bearer: mein Profil bestimmen
    let myUserId = null;
    let myProfileId = null;

    if (bearer) {
      try {
        const { data: authData } = await sb.auth.getUser(bearer);
        myUserId = authData?.user?.id || null;
        if (myUserId) {
          const { data: prof } = await sb
            .from("profiles")
            .select("id")
            .eq("user_id", myUserId)
            .maybeSingle();
          myProfileId = prof?.id ?? null;
        }
      } catch {/* ignore */}
    }

    // 3) Beziehung auswerten
    //    - linkedToMe: Wallet hat Owner UND Owner == mein Profil
    //    - linkedToOther: Wallet hat Owner UND (kein Profil gefunden ODER Owner != mein Profil)
    let linkedToMe = false;
    let linkedToOther = false;

    if (bearer) {
      if (exists && walletOwner) {
        if (myProfileId && walletOwner === myProfileId) linkedToMe = true;
        else linkedToOther = true; // wichtig: auch wenn Profil (noch) fehlt → blocken
      }
    }

    const body = bearer
      ? { ok:true, exists, linkedToMe, linkedToOther, userId: myProfileId } // userId nur Debug
      : { ok:true, exists };

    if (bearer) res.setHeader("Cache-Control", "no-store");
    else res.setHeader("Cache-Control", `public, max-age=${CACHE_TTL_SEC}, must-revalidate`);

    return res.status(200).json(body);
  } catch (e) {
    return res.status(500).json({ ok:false, code:"INTERNAL_ERROR", message: e?.message || "Unexpected error" });
  }
}

export const config = { runtime: "nodejs" };
