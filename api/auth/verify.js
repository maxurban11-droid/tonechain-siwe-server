// api/auth/verify.js — Ultra-Minimal: nur CORS + 200
module.exports = (req, res) => {
  const origin = req.headers.origin || "";
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") return res.status(204).end();

  // ✨ KEIN Zugriff auf req.body, KEINE Cookies, KEIN ethers
  return res.status(200).json({
    ok: true,
    meta: {
      method: req.method,
      ct: req.headers["content-type"] || null,
      has_body: typeof req.body !== "undefined"
    }
  });
};
