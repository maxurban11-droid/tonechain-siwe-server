// api/auth/logout.js
import { withCors } from "../../helpers/cors.js";

function killCookie(name) {
  return (
    `${name}=; Path=/; HttpOnly; Secure; SameSite=None;` +
    ` Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0`
  );
}

async function core(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }
  const cookiesToClear = ["tc_session", "tc_nonce", "tonechain_session", "tonechain_nonce"];
  res.setHeader("Set-Cookie", cookiesToClear.map(killCookie));
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, loggedOut: true });
}

export default withCors(core);
export default async function handler(req, res) {
  // --- CORS (hart, bis der Helper wieder dran ist)
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // --- Cookies löschen (eventuelle alte Namen mit abräumen)
  const cookiesToClear = [
    "tc_session",
    "tc_nonce",
    // evtl. Legacy-Namen hier ergänzen:
    "tonechain_session",
    "tonechain_nonce",
  ];
  res.setHeader("Set-Cookie", cookiesToClear.map(killCookie));

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, loggedOut: true });
}
