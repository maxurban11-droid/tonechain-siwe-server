// /api/auth/nonce.js — stabile Nonce-Route für SIWE (Node runtime)
import crypto from "node:crypto";

const ALLOWED_DOMAINS = new Set([
  "tonechain.app",
  "concave-device-193297.framer.app",
]);
const COOKIE_NONCE = "tc_nonce";
const MAX_AGE_SEC = 600; // 10 Minuten

function originAllowed(req) {
  const origin = req.headers.origin || "";
  try {
    if (!origin) return false;
    const u = new URL(origin);
    return ALLOWED_DOMAINS.has(u.hostname);
  } catch { return false; }
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`, "Path=/"];
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  parts.push("HttpOnly", "SameSite=None", "Secure");
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(prev ? [].concat(prev) : []), parts.join("; ")]);
}

export default async function handler(req, res) {
  const origin = req.headers.origin || "";
  // Debug-Header: im Network-Tab leicht sichtbar
  res.setHeader("X-TC-Origin", origin || "EMPTY");

  // CORS – nur Whitelist spiegeln (nie "*", da credentials:true)
  if (origin && originAllowed(req)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, code: "METHOD_NOT_ALLOWED" });

  // Nonce generieren
  let nonce;
  try {
    nonce =
      (globalThis.crypto?.randomUUID?.() ?? null) ||
      crypto.randomBytes(16).toString("hex");
  } catch {
    nonce = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  }

  // Cookie setzen
  setCookie(res, COOKIE_NONCE, nonce, { maxAgeSec: MAX_AGE_SEC });
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, nonce });
}

// **WICHTIG**: Node-Runtime erzwingen
export const config = { runtime: "nodejs" };
