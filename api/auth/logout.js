// api/auth/logout.js
const { withCors, handleOptions } = require("../../helpers/cors.js");

module.exports = (req, res) => {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  withCors(req, res);

  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  res.setHeader("Set-Cookie", [
    "tc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure",
    "tc_nonce=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure",
  ]);

  return res.status(200).json({ ok: true, loggedOut: true });
};
