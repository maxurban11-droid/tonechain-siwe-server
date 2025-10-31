// api/auth/logout.js — standalone: CORS + Cookies invalidieren
module.exports = (req, res) => {
  const origin = req.headers.origin || "";
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  // Session & ggf. Nonce löschen (gleiche Flags wie beim Setzen)
  res.setHeader("Set-Cookie", [
    "tc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure",
    "tc_nonce=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure"
  ]);

  return res.status(200).json({ ok: true, loggedOut: true });
};
