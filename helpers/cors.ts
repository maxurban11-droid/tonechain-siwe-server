// helpers/cors.ts
import type { NextResponse } from "next/server"
import { NextResponse as NR } from "next/server"

const ORIGIN = process.env.CORS_ORIGIN || "*"
// In Prod you can set CORS_ORIGIN="https://your-framer-site.framer.website" (or your custom domain)

function apply(res: NextResponse, origin: string) {
  res.headers.set("Access-Control-Allow-Origin", origin)
  res.headers.set("Vary", "Origin")
  res.headers.set("Access-Control-Allow-Credentials", "true")
  res.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With"
  )
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
  return res
}

/** Attach CORS headers to any response */
export function cors(_req: Request, res: NextResponse, origin = ORIGIN) {
  return apply(res, origin)
}

/** Return a 204 preflight with CORS headers */
export async function preflight(_req: Request, origin = ORIGIN) {
  return apply(new NR(null, { status: 204 }), origin)
}
