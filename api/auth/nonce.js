// api/auth/nonce.js
// Gibt eine frische Nonce aus und setzt sie als HttpOnly-Cookie (tc_nonce).
// Akzeptiert GET/POST, CORS identisch zu register/verify.

import { withCors } from "../../helpers/cors.js";
import crypto from "node:crypto";

const COOKIE_NONCE = "tc_nonce";
const NONCE_TTL_SEC = 10 * 60; // 10 Minuten

function randomNonce() {
  // URL-sicher, kurz & ausreichend entropisch
  return crypto.randomBytes(16).toString("base64url");
}

function setCookie(res, name, value, opts = {}) {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=None",
    "Secure",
    "Partitioned", // wichtig bei Third-Party-Cookies (Framer → Vercel)
  ];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);

  const prev = res.getHeader("Set-Cookie");
  res.setHeader(
    "Set-Cookie",
    [...(Array.isArray(prev) ? prev : prev ? [String(prev)] : []), parts.join("; ")]
  );
}

async function handler(req, res) {
  // withCors beantwortet OPTIONS bereits korrekt
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });
  }

  const nonce = randomNonce();
  setCookie(res, COOKIE_NONCE, nonce, { maxAgeSec: NONCE_TTL_SEC });
  res.setHeader("Cache-Control", "no-store");

  // Body enthält Nonce für die SIWE-Message
  return res.status(200).json({ ok: true, nonce, ttlSec: NONCE_TTL_SEC });
}

export default withCors(handler);
export const config = { runtime: "nodejs" };
