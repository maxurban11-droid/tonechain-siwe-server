// api/auth/verify.js
const { withCors, handleOptions } = require("../../helpers/cors.js");
const { verifyMessage } = require("@ethersproject/wallet"); // ethers v5
const { splitSignature } = require("@ethersproject/bytes");

module.exports = async (req, res) => {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  await withCors(req, res);

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // Body
  let body = {};
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
  } catch {
    return res.status(400).json({ ok: false, error: "Invalid JSON" });
  }
  const { message, signature } = body || {};
  if (!message || !signature) {
    return res.status(400).json({ ok: false, error: "Missing message/signature" });
  }

  // Nonce aus httpOnly Cookie
  const cookie = String(req.headers.cookie || "");
  const nonce = (cookie.match(/(?:^|;\s*)tc_nonce=([^;]+)/) || [])[1];
  if (!nonce) return res.status(400).json({ ok: false, error: "Nonce cookie missing or expired" });

  // Nonce im SIWE-Text prüfen (einfacher Check)
  if (!message.includes(`Nonce: ${nonce}`)) {
    return res.status(400).json({ ok: false, error: "Nonce mismatch" });
  }

  // Signaturformat prüfen (wirft bei ungültigen Werten)
  try { splitSignature(signature); } catch {
    return res.status(400).json({ ok: false, error: "Invalid signature format" });
  }

  // Signatur verifizieren
  let recovered;
  try {
    recovered = verifyMessage(message, signature);
  } catch (e) {
    return res.status(400).json({ ok: false, error: `Verify failed` });
  }

  // Session-Cookie setzen & Nonce löschen
  const session = Buffer.from(
    JSON.stringify({ a: recovered, t: Date.now() })
  ).toString("base64url");

  res.setHeader("Set-Cookie", [
    "tc_nonce=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure",
    `tc_session=${session}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; SameSite=None; Secure`
  ]);

  return res.status(200).json({ ok: true, address: recovered });
};
