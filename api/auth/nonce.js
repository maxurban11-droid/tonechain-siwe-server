// api/auth/nonce.js
const { withCors, handleOptions } = require("../../helpers/cors.js");
const crypto = require("crypto");

export default async function handler(req, res) {
  if (req.method === "OPTIONS") return handleOptions(req, res); // Preflight

  await withCors(req, res); // <- MUSS vor der Antwort passieren

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

module.exports = async (req, res) => {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  await withCors(req, res);

  if (req.method !== "POST" && req.method !== "GET") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // Nonce generieren
  const nonce = crypto.randomBytes(16).toString("hex");

  // httpOnly Cookie setzen – 10 Minuten
  res.setHeader(
    "Set-Cookie",
    `tc_nonce=${nonce}; Path=/; Max-Age=${60 * 10}; HttpOnly; SameSite=None; Secure`
  );

  return res.status(200).json({ ok: true, nonce });
};
