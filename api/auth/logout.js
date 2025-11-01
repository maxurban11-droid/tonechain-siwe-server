// api/auth/logout.js — Minimal, keine externen Imports
function pushCookie(res, cookie) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [cookie]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [String(prev), cookie]);
}

function clearCookie(res, name) {
  // Cross-site delete
  pushCookie(res, `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`);
}

export default async function handler(req, res) {
  const origin = req.headers.origin || "*";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  clearCookie(res, "tc_session");
  clearCookie(res, "tc_nonce");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, loggedOut: true });
}
