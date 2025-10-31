// api/auth/verify.js — robuste Eingangsvalidierung + 400 bei ungültiger Signatur
const crypto = require("crypto");

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
    "Secure",
  ];
  res.setHeader("Set-Cookie", parts.join("; "));
}

module.exports = async (req, res) => {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  try {
    // Body sicher lesen (Vercel liefert meist schon JSON-Objekt)
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        return res
          .status(400)
          .json({ ok: false, error: "Invalid JSON body" });
      }
    }

    const message = body?.message;
    const signature = body?.signature;

    if (typeof message !== "string" || typeof signature !== "string") {
      return res
        .status(400)
        .json({ ok: false, error: "Missing params (message, signature)" });
    }

    // einfache Signatur-Validierung (65-Byte, 0x-prefixed)
    const hexRe = /^0x[0-9a-fA-F]+$/;
    if (!hexRe.test(signature) || signature.length < 132) {
      return res
        .status(400)
        .json({ ok: false, error: "Invalid signature format" });
    }

    // lazy require, damit OPTIONS nie bricht
    let ethers;
    try {
      ethers = require("ethers");
    } catch {
      return res.status(500).json({
        ok: false,
        error: "Server missing dependency 'ethers'.",
      });
    }

    let addr;
    try {
      addr = ethers.utils.verifyMessage(message, signature);
    } catch (e) {
      // z. B. "bad signature" etc. → 400, nicht 500
      return res
        .status(400)
        .json({ ok: false, error: "Invalid signature" });
    }

    if (!addr) {
      return res
        .status(400)
        .json({ ok: false, error: "Invalid signature" });
    }

    // Session 8h
    const token = crypto.randomBytes(20).toString("hex");
    setCookie(res, "tc_session", token, 60 * 60 * 8);
    clearCookie(res, "tc_nonce");

    return res.status(200).json({ ok: true, address: addr });
  } catch (err) {
    console.error("Verify failed:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
};
