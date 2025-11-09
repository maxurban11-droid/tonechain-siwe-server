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

    if (ALLOWED_DOMAINS.has(host)) return true;               // explizit erlaubte Hosts
    if (host.endsWith(".framer.app") || host.endsWith(".framer.website")) return true; // Framer-Previews
    if (host === "localhost" || host === "127.0.0.1") return true; // lokale Entwicklung
    return false;
  } catch {
    return false;
  }
}

/* ===== Handler ===== */
export default async function handler(req, res) {
  const origin = req.headers.origin || req.headers.Origin || "";
  const allowed = originAllowed(origin);

  // --- CORS Grundgerüst (robust) ---
  res.setHeader("Vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method === "OPTIONS") {
    // Preflight: angefragte Header exakt zurückspiegeln (wichtig für Authorization)
    const reqHeaders = String(req.headers["access-control-request-headers"] || "").toLowerCase();
    res.setHeader("Access-Control-Allow-Headers", reqHeaders || "authorization, content-type, x-tc-intent");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Max-Age", "86400");
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED", message: "Use GET" });
  }

  // Origin-Gate (nach Preflight)
  if (!allowed) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED", message: "Origin denied" });
  }

  // --- ENV prüfen (Admin-Client) ---
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }

  // --- Adresse prüfen ---
  const raw = String(req.query.address || "").trim();
  if (!raw) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(400).json({ ok: false, code: "MISSING_ADDRESS", message: "Missing ?address" });
  }
  const address = raw.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(400).json({ ok: false, code: "INVALID_ADDRESS", message: "Invalid wallet" });
  }

  // --- optionaler Bearer (für linkedToMe/linkedToOther) ---
  const auth = req.headers.authorization || req.headers.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  const bearer = m ? m[1] : null;

  // --- Supabase Admin-Client ---
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

  try {
    // Wenn Bearer vorhanden: aktuelles Profil ermitteln
    let myProfileId = null;
    if (bearer) {
      try {
        const { data: authData } = await sb.auth.getUser(bearer);
        const authUserId = authData?.user?.id || null;
        if (authUserId) {
          const { data: prof } = await sb
            .from("profiles")
            .select("id")
            .eq("user_id", authUserId)
            .maybeSingle();
          myProfileId = prof?.id ?? null;
        }
      } catch {
        // stumm – fällt auf "kein Profil" zurück
      }
    }

    // Wallet nachschlagen (Adresse ist bereits lower-case)
    const { data: w, error } = await sb
      .from("wallets")
      .select("user_id")
      .eq("address", address)
      .maybeSingle();

    if (error) {
      console.error("[exists] DB query failed:", error);
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      return res.status(500).json({ ok: false, code: "DB_ERROR", message: error.message });
    }

    const exists = !!w;
    const assignedTo = w?.user_id ?? null; // null → unassigned
    let linkedToMe = false;
    let linkedToOther = false;

    if (bearer && myProfileId) {
      linkedToMe = !!(exists && assignedTo && assignedTo === myProfileId);
      linkedToOther = !!(exists && assignedTo && assignedTo !== myProfileId);
    }

    // 👇 exakt die Felder, die das Frontend braucht — keine PII
    const body = bearer
      ? { ok: true, exists, linkedToMe, linkedToOther }
      : { ok: true, exists };

    // Caching:
    // - mit Bearer (nutzerbezogen): no-store
    // - ohne Bearer: public Cache
    res.setHeader("Cache-Control", bearer ? "no-store" : `public, max-age=${CACHE_TTL_SEC}, must-revalidate`);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(200).json(body);
  } catch (e) {
    console.error("[exists] Unexpected error:", e);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(500).json({ ok: false, code: "INTERNAL_ERROR", message: e?.message || "Unexpected error" });
  }
}

// Sicherstellen, dass Vercel Node (nicht Edge) nutzt
export const config = { runtime: "nodejs" };
