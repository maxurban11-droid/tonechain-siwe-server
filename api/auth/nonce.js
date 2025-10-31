// api/auth/nonce.js
import { randomUUID } from "crypto";

// Falls du already einen withCors-Wrapper nutzt, lass ihn drum.
// Wichtig: Er muss Access-Control-Allow-Origin = <req.headers.origin> (nicht "*")
//          und Access-Control-Allow-Credentials = "true" setzen,
//          plus OPTIONS 204 handeln.

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
