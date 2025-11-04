// /api/auth/exists.js — prüft, ob eine Wallet-Adresse bereits registriert ist
import { createClient } from "@supabase/supabase-js";

/* ===== Konfiguration ===== */
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const CACHE_TTL_SEC = 60 * 5; // 5 Minuten

/* ===== kleine Helfer ===== */
function originAllowed(origin) {
  try {
    if (!origin) return false;
    const u = new URL(origin);
    const host = u.hostname;

    // explizit erlaubte Hosts
    if (ALLOWED_DOMAINS.has(host)) return true;

    // alle Framer-Previews zulassen
    if (host.endsWith(".framer.app") || host.endsWith(".framer.website"))
      return true;

    // lokale Entwicklung
    if (host === "localhost" || host === "127.0.0.1") return true;

    return false;
  } catch {
    return false;
  }
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
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-TC-Intent"
  );

  if (req.method === "OPTIONS") {
    // Preflight immer kurz beantworten
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    return res
      .status(405)
      .json({ ok: false, code: "METHOD_NOT_ALLOWED", message: "Use GET" });
  }

  // Origin-Gate (nach Preflight)
  if (!allowed) {
    return res.status(403).json({
      ok: false,
      code: "ORIGIN_NOT_ALLOWED",
      message: "Origin denied",
    });
  }

  // ENV prüfen
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res
      .status(500)
      .json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }

  // Adresse prüfen
  const raw = String(req.query.address || "").trim();
  if (!raw) {
    return res.status(400).json({
      ok: false,
      code: "MISSING_ADDRESS",
      message: "Missing ?address",
    });
  }

  const address = raw.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/i.test(address)) {
    return res.status(400).json({
      ok: false,
      code: "INVALID_ADDRESS",
      message: "Invalid wallet",
    });
  }

  // Supabase
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  try {
    const { data, error } = await sb
      .from("wallets")
      .select("address")
      .eq("address", address)
      .maybeSingle();

    if (error) {
      console.error("[exists] DB query failed:", error);
      return res
        .status(500)
        .json({ ok: false, code: "DB_ERROR", message: error.message });
    }

    const exists = !!data;

    // leichtes Edge/Browser-Caching (optional)
    res.setHeader("Cache-Control", `public, max-age=${CACHE_TTL_SEC}`);

    return res.status(200).json({ ok: true, exists });
  } catch (e) {
    console.error("[exists] Unexpected error:", e);
    return res.status(500).json({
      ok: false,
      code: "INTERNAL_ERROR",
      message: e?.message || "Unexpected error",
    });
  }
}

// Sicherstellen, dass Vercel nicht als Edge läuft
export const config = { runtime: "nodejs" };
