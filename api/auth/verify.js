// api/auth/verify.js — TEMP: Body-Echo + CORS (keine ethers, keine Cookies)
function setCors(req, res) {
  const origin = req.headers.origin || "";
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
}

module.exports = async (req, res) => {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  try {
    let body = req.body;
    const snapshot = {
      typeof_body: typeof body,
      is_buffer: Buffer.isBuffer(body),
      has_message: !!(body && body.message),
      has_signature: !!(body && body.signature),
      headers_ct: req.headers["content-type"] || null,
    };

    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
        snapshot.parsed_from_string = true;
      } catch (e) {
        snapshot.parse_error = String(e && e.message);
      }
    }

    return res.status(200).json({ ok: true, snapshot, body });
  } catch (err) {
    return res
      .status(500)
      .json({ ok: false, error: String(err && err.message) });
  }
};
