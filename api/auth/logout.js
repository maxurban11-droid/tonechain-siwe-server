// /api/auth/logout.js — stabile Logout-Route (Node runtime, keine externen Abhängigkeiten)

const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);

const COOKIE_SESSION = "tc_session";
const COOKIE_NONCE = "tc_nonce";

/* ============ Helper ============ */
function originAllowed(req) {
  const origin = req.headers.origin || "";
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

function clearCookie(res, name) {
  // Cross-site kompatibel löschen
  pushCookie(
    res,
    `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`
  );
}

/* ============ Handler ============ */
export default async function handler(req, res) {
  // --- CORS ---
  const origin = req.headers.origin || "";
  if (origin && originAllowed(req)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", "null");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res
      .status(405)
      .json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  try {
    clearCookie(res, COOKIE_SESSION);
    clearCookie(res, COOKIE_NONCE);
    res.setHeader("Cache-Control", "no-store");

    return res.status(200).json({
      ok: true,
      loggedOut: true,
    });
  } catch (e) {
    console.error("[logout] error:", e);
    return res
      .status(500)
      .json({ ok: false, code: "LOGOUT_FAILED", message: e?.message });
  }
}
