import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { ORIGIN_WHITELIST } from "./env";

function allowOrigin(origin: string | null): string | null {
  if (!origin) return null;
  if (ORIGIN_WHITELIST.length === 0) return origin;
  return ORIGIN_WHITELIST.includes(origin) ? origin : null;
}

export function withCors(req: NextRequest, res: NextResponse) {
  const origin = req.headers.get("origin");
  const allowed = allowOrigin(origin);
  if (allowed) {
    res.headers.set("Access-Control-Allow-Origin", allowed);
    res.headers.set("Vary", "Origin");
  }
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.headers.set("Access-Control-Allow-Credentials", "true");
  return res;
}

export function handleOptions(req: NextRequest) {
  const res = new NextResponse(null, { status: 204 });
  return withCors(req, res);
}
