// helpers/cors.ts
import { NextResponse } from "next/server"

const ALLOWED_ORIGINS = [
  "https://framer.com",
  "https://framerusercontent.com",
  "https://*.framer.website",
  "https://*.framer.app",
  "https://tonechain.framer.website", // dein Projekt
]

export function withCORS(req: Request, res: NextResponse) {
  const origin = req.headers.get("origin") || ""
  const allowed = ALLOWED_ORIGINS.some((o) =>
    o.startsWith("https://*.") ? origin.endsWith(o.slice(8)) : origin === o
  )
  if (allowed) {
    res.headers.set("Access-Control-Allow-Origin", origin)
    res.headers.set("Access-Control-Allow-Credentials", "true")
  }
  res.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With"
  )
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
  res.headers.set("Vary", "Origin")
  return res
}
