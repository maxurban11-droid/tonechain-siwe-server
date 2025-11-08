// /api/auth/exists.js — prüft, ob eine Wallet-Adresse bereits registriert ist
import { createClient } from "@supabase/supabase-js";

/* ===== Konfiguration ===== */
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const CACHE_TTL_SEC = 60 * 5; // 5 Minuten

/* ===== Helfer: Origin-Whitelist ===== */
function originAllowed(origin) {
  try {
    if (!origin) return false;
    const u = new URL(origin);
    const host = u.hostname;

    if (ALLOWED_DOMAINS.has(host)) return true;
    if (host.endsWith(".framer.app") || host.endsWith(".framer.website")) return true;
    if (host === "localhost" || host === "127.0.0.1") return true;

    return false;
  } catch {
    return false;
  }
}

/* ===== Handler ===== */
export default async function handler(req, res) {
  const origin = req.headers.origin || req.headers.Origin || "";
  const allowed = originAllowed(origin);

  // --- CORS Grundgerüst ---
  res.setHeader("Vary", "Origin");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-TC-Intent"
  );
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET")
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED", message: "Use GET" });

  // Origin-Gate (nach Preflight)
  if (!allowed)
    return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED", message: "Origin denied" });

  // --- ENV prüfen (Admin-Client) ---
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });

  // --- Adresse prüfen ---
  const raw = String(req.query.address || "").trim();
  if (!raw)
    return res.status(400).json({ ok: false, code: "MISSING_ADDRESS", message: "Missing ?address" });

  const address = raw.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address))
    return res.status(400).json({ ok: false, code: "INVALID_ADDRESS", message: "Invalid wallet" });

  // --- Bearer ist für diese sicherheitskritische Abfrage Pflicht ---
  const auth = req.headers.authorization || req.headers.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  const bearer = m ? m[1] : null;
  if (!bearer) {
    // Wichtig: 401 zurückgeben, damit der Client „no-bearer“ sauber erkennt
    res.setHeader("Cache-Control", "no-store");
    return res.status(401).json({ ok: false, code: "MISSING_BEARER" });
  }

  // --- Supabase Admin-Client ---
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  try {
    // Aktuellen Benutzer verifizieren → Profil-ID holen
    const { data: authData, error: authErr } = await sb.auth.getUser(bearer);
    if (authErr || !authData?.user) {
      res.setHeader("Cache-Control", "no-store");
      return res.status(401).json({ ok: false, code: "INVALID_BEARER" });
    }

    const authUserId = authData.user.id;
    let myProfileId = null;
    const { data: prof } = await sb
      .from("profiles")
      .select("id")
      .eq("user_id", authUserId)
      .maybeSingle();
    myProfileId = prof?.id ?? null;

    // Wallet nachschlagen (immer in lower-case)
    const { data: w, error } = await sb
      .from("wallets")
      .select("user_id")
      .eq("address", address)
      .maybeSingle();

    if (error) {
      console.error("[exists] DB query failed:", error);
      res.setHeader("Cache-Control", "no-store");
      return res.status(500).json({ ok: false, code: "DB_ERROR", message: error.message });
    }

    const exists = !!w;
    const linkedToAny = !!w?.user_id;
    const linkedToMe = !!(linkedToAny && myProfileId && w.user_id === myProfileId);
    const linkedToOther = !!(linkedToAny && myProfileId && w.user_id !== myProfileId);

    // Nutzerbezogene Antwort → nicht cachen
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      ok: true,
      exists,
      linkedToMe,
      linkedToOther,
      // optional informativ:
      linked: linkedToAny,
    });
  } catch (e) {
    console.error("[exists] Unexpected error:", e);
    res.setHeader("Cache-Control", "no-store");
    return res.status(500).json({
      ok: false,
      code: "INTERNAL_ERROR",
      message: e?.message || "Unexpected error",
    });
  }
}

// Sicherstellen, dass Vercel Node (nicht Edge) nutzt
export const config = { runtime: "nodejs" };
