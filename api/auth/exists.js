// /api/auth/exists.js — prüft, ob eine Wallet-Adresse bereits registriert ist
import { createClient } from "@supabase/supabase-js"

/* ===== Konfiguration ===== */
const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
])
const COOKIE_MAX_AGE = 60 * 5 // 5 Min Cache (optional)

/* ===== kleine Helfer ===== */
function originAllowed(origin) {
  try {
    if (!origin) return false
    const u = new URL(origin)
    return ALLOWED_DOMAINS.has(u.hostname)
  } catch {
    return false
  }
}

/* ===== Handler ===== */
export default async function handler(req, res) {
  const origin = req.headers.origin || ""
  const allowed = originAllowed(origin)

  // --- CORS ---
  res.setHeader("Vary", "Origin")
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin)
    res.setHeader("Access-Control-Allow-Credentials", "true")
  }
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-TC-Intent"
  )
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS")
  if (req.method === "OPTIONS") return res.status(204).end()

  // --- Method Check ---
  if (req.method !== "GET")
    return res
      .status(405)
      .json({ ok: false, code: "METHOD_NOT_ALLOWED", message: "Use GET" })

  // --- Origin Gate ---
  if (!allowed)
    return res
      .status(403)
      .json({ ok: false, code: "ORIGIN_NOT_ALLOWED", message: "Origin denied" })

  // --- ENV Check ---
  const SUPABASE_URL = process.env.SUPABASE_URL
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)
    return res
      .status(500)
      .json({ ok: false, code: "SERVER_CONFIG_MISSING" })

  // --- Address Validation ---
  const raw = String(req.query.address || "").trim()
  if (!raw)
    return res
      .status(400)
      .json({ ok: false, code: "MISSING_ADDRESS", message: "Missing ?address" })

  const address = raw.toLowerCase()
  if (!/^0x[0-9a-f]{40}$/.test(address))
    return res
      .status(400)
      .json({ ok: false, code: "INVALID_ADDRESS", message: "Invalid wallet" })

  // --- Supabase Query ---
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  try {
    const { data, error } = await sb
      .from("wallets")
      .select("address")
      .eq("address", address)
      .maybeSingle()

    if (error) {
      console.error("[exists] DB query failed:", error)
      return res
        .status(500)
        .json({ ok: false, code: "DB_ERROR", message: error.message })
    }

    const exists = !!data
    res.setHeader("Cache-Control", `public, max-age=${COOKIE_MAX_AGE}`)
    return res.status(200).json({ ok: true, exists })
  } catch (e) {
    console.error("[exists] Unexpected error:", e)
    return res
      .status(500)
      .json({ ok: false, code: "INTERNAL_ERROR", message: e.message })
  }
}

// Sicherstellen, dass Vercel nicht Edge verwendet
export const config = { runtime: "nodejs" }
