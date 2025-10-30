// api/auth/verify.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { withCors, handleOptions } from "../../helpers/cors";
import { setCookie, clearCookie } from "../../helpers/cookies";
import { verifyPersonalSign } from "../../utils/siwe";

const COOKIE_NONCE = "tc_nonce";
const COOKIE_SESSION = "tc_session";
const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  if (req.method !== "POST") {
    withCors(req, res);
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const nonce = req.cookies?.[COOKIE_NONCE];
  if (!nonce) {
    withCors(req, res);
    return res.status(400).json({ ok: false, error: "Nonce cookie missing or expired" });
  }

  // Parse body (Vercel can give already-parsed object or string)
  let payload: any = null;
  try {
    payload = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    payload = null;
  }
  const message: string = payload?.message ?? "";
  const signature: string = payload?.signature ?? "";
  if (!message || !signature) {
    withCors(req, res);
    return res.status(400).json({ ok: false, error: "Invalid payload" });
  }

  // Nonce must be inside message
  if (!message.includes(`Nonce: ${nonce}`)) {
    withCors(req, res);
    return res.status(400).json({ ok: false, error: "Nonce mismatch" });
  }

  const result = await verifyPersonalSign(message, signature);
  if (!result.ok) {
    withCors(req, res);
    return res.status(400).json({ ok: false, error: result.error });
  }

  // Success: set session and clear nonce
  setCookie(res, COOKIE_SESSION, "1", {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    path: "/",
    maxAge: SESSION_TTL
  });
  clearCookie(res, COOKIE_NONCE, { httpOnly: true, sameSite: "none", secure: true, path: "/" });

  withCors(req, res);
  res.status(200).json({ ok: true, address: result.address });
}
