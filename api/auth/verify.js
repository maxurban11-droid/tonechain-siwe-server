// api/auth/verify.js — prüft SIWE-Signatur + setzt Session-Cookie
const crypto = require("crypto");
const { ethers } = require("ethers");

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

function clearCookie(res, name) {
  res.setHeader(
    "Set-Cookie",
    `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`
  );
}

function setCookie(res, name, value, maxAgeSec) {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    `Max-Age=${maxAgeSec}`,
    "HttpOnly",
    "SameSite=None",
    "Secure"
  ];
  res.setHeader("Set-Cookie", parts.join("; "));
}

module.exports = async (req, res) => {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  try {
    const { message, signature } = req.body || {};
    if (!message || !signature)
      return res.status(400).json({ ok: false, error: "Missing params" });

    const addr = ethers.utils.verifyMessage(message, signature);
    if (!addr)
      return res.status(400).json({ ok: false, error: "Invalid signature" });

    // Session-Token (8 Std gültig)
    const token = crypto.randomBytes(20).toString("hex");
    setCookie(res, "tc_session", token, 60 * 60 * 8);

    clearCookie(res, "tc_nonce");
    return res.status(200).json({ ok: true, address: addr });
  } catch (err) {
    console.error("Verify failed:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
};
