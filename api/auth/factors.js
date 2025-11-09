// /api/auth/factors.js
// Liefert aktuellen Faktorzustand (wallet/email/level) + hasWallet für das aktive Profil.

import crypto from "node:crypto";
import { withCors } from "../../helpers/cors.js";

// === Session/Cookie Konstante(n) ===
const COOKIE_SESSION = "tc_session";
const SESSION_SECRET = process.env.SESSION_SECRET || null;

// === Supabase Admin-Konfiguration ===
const SUPABASE_URL = process.env.SUPABASE_URL || null;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || null;

// ---------- kleine Helfer ----------
function sign(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  if (!hit) return null;
  const val = hit.split("=").slice(1).join("=");
  try {
    return decodeURIComponent(val);
  } catch {
    return val;
  }
}

function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

/** HttpOnly-Session-Cookie robust dekodieren & validieren. */
function parseSessionCookie(req) {
  const b64 = getCookie(req, COOKIE_SESSION);
  if (!b64) return null;
  try {
    const outer = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
    const raw = outer?.raw;
    const sig = outer?.sig || null;
    if (!raw || typeof raw !== "string") return null;

    if (sig && SESSION_SECRET) {
      const expect = sign(raw);
      if (!expect || expect !== sig) return null; // Signatur passt nicht
    }

    const payload = JSON.parse(raw);
    // { v, addr, userId, ts, exp, factors?, level? }
    if (!payload || typeof payload !== "object") return null;

    // Ablauf prüfen (nicht hart failen – nur ignorieren, wenn abgelaufen)
    if (typeof payload.exp === "number" && payload.exp < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}

/** Bestimme (falls möglich) Profil-ID via Supabase-Bearer. */
async function getProfileIdFromBearer(bearer) {
  if (!bearer || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return { profileId: null, emailActive: false };
  const { createClient } = await import("@supabase/supabase-js");
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

  try {
    const { data: authData, error: authErr } = await sb.auth.getUser(bearer);
    if (authErr) return { profileId: null, emailActive: false };
    const authUserId = authData?.user?.id || null;
    if (!authUserId) return { profileId: null, emailActive: false };

    const { data: prof } = await sb
      .from("profiles")
      .select("id")
      .eq("user_id", authUserId)
      .maybeSingle();

    const profileId = prof?.id ?? null;
    return { profileId, emailActive: !!profileId };
  } catch {
    return { profileId: null, emailActive: false };
  }
}

/** Prüfe, ob für profileId mind. eine Wallet existiert. */
async function hasAtLeastOneWallet(profileId) {
  if (!profileId || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return false;
  const { createClient } = await import("@supabase/supabase-js");
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
  try {
    const { count, error } = await sb
      .from("wallets")
      .select("id", { count: "exact", head: true })
      .eq("user_id", profileId);

    if (error) return false;
    return (count || 0) > 0;
  } catch {
    return false;
  }
}

// ---------- Handler ----------
async function handler(req, res) {
  // Nur GET
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET")
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED", message: "Use GET" });

  // Keine Caches für Faktor-Status
  res.setHeader("Cache-Control", "no-store");

  // 1) Session-Cookie lesen (SIWE)
  const sess = parseSessionCookie(req);
  const cookieWallet = !!(sess?.factors?.wallet || sess?.addr);
  const cookieEmail = !!(sess?.factors?.email);
  const cookieProfileId = sess?.userId || null; // das ist eure profiles.id

  // 2) Optional: Supabase-Bearer auslesen und daraus E-Mail-Faktor & Profil-ID ableiten
  const bearer = readBearer(req);
  const { profileId: bearerProfileId, emailActive } = await getProfileIdFromBearer(bearer);

  // 3) Finaler Faktor-Status:
  //    - wallet: nur valide, wenn ein aktives tc_session (SIWE) vorliegt
  //    - email: nur valide, wenn ein gültiger Supabase-Bearer aktiv ist
  const sessionWallet = cookieWallet;
  const sessionEmail = emailActive; // bewusst NICHT cookieEmail, um Staleness zu vermeiden

  const level = sessionWallet && sessionEmail ? "high" : "basic";

  // 4) hasWallet für das "beste" bekannte Profil (Prio: Cookie → Bearer)
  const profileForHasWallet = cookieProfileId || bearerProfileId || null;
  const hasWallet = await hasAtLeastOneWallet(profileForHasWallet);

  // 5) Antwort
  return res.status(200).json({
    ok: true,
    hasWallet,
    session: { wallet: sessionWallet, email: sessionEmail, level },
    policy: { mfaRequired: false },
  });
}

// CORS + Node runtime
export default withCors(handler);
export const config = { runtime: "nodejs" };
