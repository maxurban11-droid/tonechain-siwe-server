// api/auth/nonce.js — Minimalvariante ohne externe Imports
export default async function handler(req, res) {
  // CORS direkt setzen, damit der Browser nicht blockt
  const origin = req.headers.origin || "*";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // robuste Nonce-Generierung
  const nonce =
    (globalThis.crypto && globalThis.crypto.randomUUID && globalThis.crypto.randomUUID()) ||
    Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);

  // Cross-site Cookies IMMER mit SameSite=None; Secure; HttpOnly
  res.setHeader("Set-Cookie", [
    `tc_nonce=${nonce}; Path=/; Max-Age=600; HttpOnly; SameSite=None; Secure`
  ]);

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, nonce });
}
