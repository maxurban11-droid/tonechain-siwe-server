// api/helpers/guards.js
// Step-Up Guards für kritische Endpunkte: requireLevel('high'), requireFactor('wallet'|'email')

import crypto from "node:crypto";

const COOKIE_SESSION = "tc_session";
const SESSION_SECRET = process.env.SESSION_SECRET || null;
const SESSION_TTL_SEC = 60 * 60 * 24;

function hmac(val) {
  if (!SESSION_SECRET) return null;
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const hit = raw.split(/;\s*/).find((s) => s.startsWith(name + "="));
  if (!hit) return null;
  const val = hit.split("=").slice(1).join("=");
  try { return decodeURIComponent(val); } catch { return val; }
}

function decodeSessionCookie(val) {
  if (!val) return null;
  try {
    const buf = Buffer.from(val, "base64").toString("utf8");
    const obj = JSON.parse(buf);
    // { raw, sig } signiert
    if (obj && obj.raw) {
      if (obj.sig && SESSION_SECRET) {
        const expected = hmac(String(obj.raw));
        if (expected !== obj.sig) return null;
      }
      return JSON.parse(String(obj.raw));
    }
    // Fallback: payload direkt
    return obj;
  } catch {
    return null;
  }
}

function readBearer(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

/**
 * Baut einen Context aus tc_session (Wallet) + Supabase-Bearer (E-Mail).
 * Ermittelt auch, ob die Wallet des Cookies zu einem Profil gehört.
 */
export async function buildAuthContext(req) {
  // 1) Cookie
  const sessRaw = decodeSessionCookie(getCookie(req, COOKIE_SESSION));
  const sessionCookie = sessRaw && typeof sessRaw === "object" ? sessRaw : null;

  // 2) Bearer → E-Mail-Profil
  const bearer = readBearer(req);
  let emailProfileId = null;

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const hasSb = !!(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);

  let sb = null;
  if (bearer && hasSb) {
    const { createClient } = await import("@supabase/supabase-js");
    sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
    const { data: auth } = await sb.auth.getUser(bearer);
    const uid = auth?.user?.id || null;
    if (uid) {
      const { data: prof } = await sb.from("profiles").select("id").eq("user_id", uid).maybeSingle();
      emailProfileId = prof?.id ?? null;
    }
  }

  // 3) Wallet-Zugehörigkeit prüfen (falls userId im Cookie fehlt)
  let walletUserId = sessionCookie?.userId ?? null;
  if (!walletUserId && sessionCookie?.addr && sb) {
    const addrLower = String(sessionCookie.addr).toLowerCase();
    const { data: w } = await sb.from("wallets").select("user_id").eq("address", addrLower).maybeSingle();
    walletUserId = w?.user_id ?? null;
  }

  // 4) Faktoren ableiten
  const walletFactor = !!(sessionCookie?.factors?.wallet || sessionCookie?.addr);
  const emailFactor = !!emailProfileId;
  const level = walletFactor && emailFactor ? "high" : (walletFactor || emailFactor ? "basic" : "none");

  return {
    bearer,
    sessionCookie,
    emailProfileId,
    walletUserId,
    factors: { wallet: walletFactor, email: emailFactor, level },
    // Hilfsprüfungen
    missingForLevel(target = "high") {
      const miss = [];
      if (target === "high") {
        if (!walletFactor) miss.push("wallet");
        if (!emailFactor) miss.push("email");
      }
      return miss;
    },
  };
}

/**
 * Guard: verlangt Level "high".
 * Antwortet selbst mit 401 { code:"STEP_UP_REQUIRED", missing:[...], want:"high" }
 * oder 409 { code:"ACCOUNT_MISMATCH" } bei Cross-Account-Situation.
 * Rückgabe: { ok:false } wenn bereits geantwortet, sonst { ok:true, ctx }.
 */
export async function requireLevel(req, res, target = "high") {
  const ctx = await buildAuthContext(req);
  res.setHeader("Cache-Control", "no-store");

  if (target === "high") {
    // Falls beide Faktoren vorhanden, aber unterschiedlichen Profilen zugeordnet → 409
    if (ctx.factors.wallet && ctx.factors.email && ctx.walletUserId && ctx.emailProfileId && ctx.walletUserId !== ctx.emailProfileId) {
      res.status(409).json({ ok: false, code: "ACCOUNT_MISMATCH", message: "Wallet factor belongs to another account." });
      return { ok: false };
    }
    const missing = ctx.missingForLevel("high");
    if (missing.length) {
      res.status(401).json({ ok: false, code: "STEP_UP_REQUIRED", want: "high", missing, session: ctx.factors });
      return { ok: false };
    }
  }
  return { ok: true, ctx };
}

/**
 * Guard: verlangt einen einzelnen Faktor ("wallet" | "email").
 * Antwortet 401 mit { code:"STEP_UP_REQUIRED", missing:["wallet"|"email"] }.
 */
export async function requireFactor(req, res, factor /* 'wallet'|'email' */) {
  const ctx = await buildAuthContext(req);
  res.setHeader("Cache-Control", "no-store");

  const present = !!ctx.factors[factor];
  if (!present) {
    res.status(401).json({ ok: false, code: "STEP_UP_REQUIRED", want: factor, missing: [factor], session: ctx.factors });
    return { ok: false };
  }
  return { ok: true, ctx };
}

/**
 * Optionaler Helper: signiert ein aktualisiertes Cookie (falls ein Endpoint hochstufen möchte).
 */
export function writeSessionCookie(res, payload) {
  const raw = JSON.stringify({
    v: 1,
    addr: payload.addr ?? null,
    userId: payload.userId ?? null,
    ts: Date.now(),
    exp: Date.now() + SESSION_TTL_SEC * 1000,
    factors: payload.factors ?? { wallet: !!payload.addr, email: !!payload.email },
    level: payload.level ?? ((payload.factors?.wallet && payload.factors?.email) ? "high" : "basic"),
  });
  const sig = hmac(raw);
  const val = Buffer.from(JSON.stringify(sig ? { raw, sig } : { raw })).toString("base64");
  const parts = [`${COOKIE_SESSION}=${val}`, "Path=/", "HttpOnly", "SameSite=None", "Secure", "Partitioned", `Max-Age=${SESSION_TTL_SEC}`];
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]);
}
