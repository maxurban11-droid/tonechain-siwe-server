// api/auth/nonce.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { withCors, handleOptions } from "../../helpers/cors";
import { setCookie } from "../../helpers/cookies";

const COOKIE_NONCE = "tc_nonce";
const NONCE_TTL = 60 * 10; // 10 minutes

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  if (req.method !== "GET") {
    withCors(req, res);
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }
  const nonce = (crypto.randomUUID?.() ?? `${Date.now()}-${Math.random()}`).replace(/-/g, "");
  setCookie(res, COOKIE_NONCE, nonce, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    path: "/",
    maxAge: NONCE_TTL
  });
  withCors(req, res);
  res.status(200).json({ ok: true, nonce });
}
