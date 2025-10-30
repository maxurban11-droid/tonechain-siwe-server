// helpers/cors.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { ORIGIN_WHITELIST } from "./env";

function allowOrigin(origin: string | undefined): string | null {
  if (!origin) return null;
  const o = origin.replace(/\/+$/, "").toLowerCase();
  if (ORIGIN_WHITELIST.length === 0) return o;
  for (const raw of ORIGIN_WHITELIST) {
    const entry = String(raw).replace(/\/+$/, "").toLowerCase();
    if (!entry.includes("*")) {
      if (o === entry) return o;
      continue;
    }
    const esc = entry
      .replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&")
      .replace(/\\\*\\\./g, "(?:[a-z0-9-]+\\.)+");
    if (new RegExp(`^${esc}$`, "i").test(o)) return o;
  }
  return null;
}

export function withCors(req: VercelRequest, res: VercelResponse) {
  const origin = req.headers.origin as string | undefined;
  const allowed = allowOrigin(origin);
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", allowed);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,Accept,X-Requested-With");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Max-Age", "86400");
}

export function handleOptions(req: VercelRequest, res: VercelResponse) {
  withCors(req, res);
  res.status(204).end();
}
