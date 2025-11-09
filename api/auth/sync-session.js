// api/auth/sync-session.js
// Upgradet tc_session, wenn zusätzlich eine gültige E-Mail-Session (Supabase Bearer) aktiv ist.

import crypto from "node:crypto";
import { withCors, handleOptions } from "../../helpers/cors.js";

const COOKIE_SESSION = "tc_session";
const SESSION_TTL_SEC = 60 * 60 * 24;
const SESSION_SECRET = process.env.SESSION_SECRET || null;

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
function decodeSessionCookie(val) {
  if (!val) return null;
  try {
    const buf = Buffer.from(val, "base64").toString("utf8");
    const obj = JSON.parse(buf);
    // Format A: { raw, sig }
    if (obj && typeof obj === "object" && (obj.raw || obj.sig)) {
      if (obj.sig && SESSION_SECRET) {
        const expSig = sign(String(obj.raw));
        if (expSig !== obj.sig) return null; // Signatur ungültig
      }
      return JSON.parse(String(obj.raw));
    }
    // Format B: { raw } (unsigniert)
    if (obj && obj.raw) return JSON.parse(String(obj.raw));
    // Format C: payload direkt
    return obj;
  } catch {
    return null;
  }
}

async function handler(req, res) {
  // CORS/Preflight
  if (req.method === "OPTIONS") return handleOptions(req, res);
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });

  res.setHeader("Cache-Control", "no-store");

  // 1) Vorhandene tc_session lesen (wir upgraden eine existierende Session)
  const cookieVal = getCookie(req, COOKIE_SESSION);
  const sess = decodeSessionCookie(cookieVal);
  if (!sess) {
    return res.status(400).json({
      ok: false,
      code: "NO_SESSION",
      message: "No existing wallet session to upgrade.",
    });
  }

  // 2) Supabase-Bearer auslesen (muss vorhanden & valide sein)
  const bearer = readBearer(req);
  if (!bearer) {
    return res.status(401).json({
      ok: false,
      code: "MISSING_BEARER",
      message: "Email session (Bearer) required.",
    });
  }

  // 3) Supabase Admin-Client initialisieren
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, code: "SERVER_CONFIG_MISSING" });
  }
  const { createClient } = await import("@supabase/supabase-js");
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  // 4) Aktiven E-Mail-User ermitteln -> Profil-ID (profiles.id)
  const { data: authData, error: authErr } = await sb.auth.getUser(bearer);
  if (authErr || !authData?.user?.id) {
    return res.status(401).json({
      ok: false,
      code: "INVALID_BEARER",
      message: "Supabase bearer invalid.",
    });
  }
  const authUserId = authData.user.id;
  const { data: prof, error: pErr } = await sb
    .from("profiles")
    .select("id")
    .eq("user_id", authUserId)
    .maybeSingle();

  if (pErr || !prof?.id) {
    return res.status(404).json({
      ok: false,
      code: "PROFILE_NOT_FOUND",
      message: "Profile not found for email session.",
    });
  }
  const emailProfileId = prof.id;

  // 5) Prüfen, ob die Wallet-Session zum selben Profil gehört
  //    - Fall A: sess.userId vorhanden -> 1:1 vergleichen
  //    - Fall B: sess.userId fehlt, aber sess.addr da -> via wallets nachschlagen
  let sessionUserId = sess.userId ?? null;
  if (!sessionUserId && sess.addr) {
    const addrLower = String(sess.addr).toLowerCase();
    const { data: w } = await sb
      .from("wallets")
      .select("user_id")
      .eq("address", addrLower)
      .maybeSingle();
    sessionUserId = w?.user_id ?? null;
  }

  if (sessionUserId && sessionUserId !== emailProfileId) {
    // Wallet gehört einem anderen Profil → kein Upgrade
    return res.status(409).json({
      ok: false,
      code: "ACCOUNT_MISMATCH",
      message:
        "Active wallet session belongs to another account. Cannot upgrade.",
    });
  }

  // 6) Cookie-Payload upgraden: factors.email = true, level neu berechnen
  const next = {
    v: 1,
    addr: sess.addr ?? null,
    userId: sessionUserId || emailProfileId || null,
    ts: Date.now(),
    exp: Date.now() + SESSION_TTL_SEC * 1000,
    factors: {
      wallet: !!(sess.factors?.wallet || sess.addr),
      email: true, // <- Upgrade!
    },
  };
  next.level = next.factors.wallet && next.factors.email ? "high" : "basic";

  const raw = JSON.stringify(next);
  const sig = sign(raw);
  const value = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");
  setCookie(res, COOKIE_SESSION, value, { maxAgeSec: SESSION_TTL_SEC });

  return res.status(200).json({
    ok: true,
    upgraded: true,
    session: { wallet: next.factors.wallet, email: next.factors.email, level: next.level },
  });
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
