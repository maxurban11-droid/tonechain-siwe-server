// api/health.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { withCors, handleOptions } from "../helpers/cors.js";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  withCors(req, res);
  res.status(200).json({ ok: true });
}
