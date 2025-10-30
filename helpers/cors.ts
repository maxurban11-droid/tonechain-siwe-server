import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { ORIGIN_WHITELIST } from "./env";

function allowOrigin(origin: string | null): string | null {
  if (!origin) return null;
  const o = origin.replace(/\/+$/, "").toLowerCase();
  if (ORIGIN_WHITELIST.length === 0) return o;
  for (const entryRaw of ORIGIN_WHITELIST) {
    const entry = String(entryRaw).replace(/\/+$/, "").toLowerCase();
    if (!entry.includes("*")) {
      if (o === entry) return o;
      continue;
    }
    // Wildcard → baue Regex, aber nur für Subdomain-Teil
    const esc = entry
      .replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&")
      .replace(/\\\*\\\./g, "(?:[a-z0-9-]+\\.)+"); // *.domain.tld
    const re = new RegExp(`^${esc}$`, "i");
    if (re.test(o)) return o;
  }
  return null;
}

export function withCors(req: NextRequest, res: NextResponse) {
  const origin = req.headers.get("origin");
  const allowed = allowOrigin(origin);
  if (allowed) {
    res.headers.set("Access-Control-Allow-Origin", allowed);
    res.headers.set("Vary", "Origin");
  }
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,Accept,X-Requested-With"
  );
  res.headers.set("Access-Control-Allow-Credentials", "true");
  res.headers.set("Access-Control-Max-Age", "86400");
  return res;
}

export function handleOptions(req: NextRequest) {
  const res = new NextResponse(null, { status: 204 });
  return withCors(req, res);
}
