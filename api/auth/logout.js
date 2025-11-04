// /api/auth/logout.js — robuste Logout-Route (Node runtime, CHIPS-kompatibel)

const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);

const COOKIE_SESSION = "tc_session";
const COOKIE_NONCE   = "tc_nonce";

/* ============ Helpers ============ */
function originAllowed(origin) {
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch {
    return false;
  }
}

function pushCookie(res, cookie) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [cookie]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [String(prev), cookie]);
}

function clearCookieAllVariants(res, name) {
  // Basis (host-only, Path=/, sofort ablaufen, cross-site fähig)
  const base =
    `${name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure`;
  // 1) normale Variante
  pushCookie(res, base);
  // 2) CHIPS/Partitioned-Variante
  pushCookie(res, `${base}; Partitioned`);
}

/* ============ Handler ============ */
export default async function handler(req, res) {
  const origin  = req.headers.origin || "";
  const allowed = originAllowed(origin);

  // CORS
  res.setHeader("Vary", "Origin");
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    // keine Freigabe für fremde Origins
    res.setHeader("Access-Control-Allow-Origin", "null");
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  if (!allowed) {
    return res.status(403).json({ ok: false, code: "ORIGIN_NOT_ALLOWED" });
  }
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  try {
    // beide Cookies in allen Varianten löschen
    clearCookieAllVariants(res, COOKIE_SESSION);
    clearCookieAllVariants(res, COOKIE_NONCE);

    // kein Caching
    res.setHeader("Cache-Control", "no-store");

    return res.status(200).json({ ok: true, loggedOut: true });
  } catch (e) {
    console.error("[logout] error:", e);
    return res
      .status(500)
      .json({ ok: false, code: "LOGOUT_FAILED", message: e?.message });
  }
}

export const config = { runtime: "nodejs" };
