// api/auth/logout.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { withCors, handleOptions } from "../../helpers/cors";
import { clearCookie } from "../../helpers/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  if (req.method !== "POST") {
    withCors(req, res);
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }
  clearCookie(res, "tc_session", { httpOnly: true, sameSite: "none", secure: true, path: "/" });
  clearCookie(res, "tc_nonce",   { httpOnly: true, sameSite: "none", secure: true, path: "/" });
  withCors(req, res);
  res.status(200).json({ ok: true });
}
