// api/auth/nonce.js
import { randomUUID } from "crypto";
import { withCors } from "../../helpers/cors.js";

function setCookie(name, value, maxAgeSec) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ];
  if (maxAgeSec) parts.push(`Max-Age=${maxAgeSec}`);
  return parts.join("; ");
}

async function core(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }
  const nonce = crypto.randomUUID();
  res.setHeader("Set-Cookie", setCookie("tc_nonce", nonce, 600)); // 10 min
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, nonce });
}

export default withCors(core);

function allowCors(req, res) {
  const origin = req.headers.origin || "";
  // Whitelist: dein Live-/Preview-Origin (z.B. Framer)
  const allow = /^https:\/\/([a-z0-9-]+\.)?framer\.app$/.test(origin)
    || origin.includes("framer.com") // falls nötig
    || origin.includes("localhost"); // für lokale Tests

  if (allow) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
}

export default async function handler(req, res) {
  allowCors(req, res);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // 1) Nonce erzeugen
  const nonce = randomUUID();

  // 2) Cookie setzen – Cross-Site zwingend: SameSite=None; Secure
  //    httpOnly + Path + Max-Age nicht vergessen
  const cookie = [
    `tc_nonce=${encodeURIComponent(nonce)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Max-Age=600", // 10 min
  ].join("; ");

  res.setHeader("Set-Cookie", cookie);

  // 3) Response
  return res.status(200).json({ ok: true, nonce });
}
