// app/api/auth/logout/route.ts
import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

const SECURE = process.env.NODE_ENV === "production"

/** OPTIONS – Preflight (204 + CORS-Header) */
export async function OPTIONS(req: Request) {
  return preflight(req)
}

/** POST – Session-Cookie invalidieren */
export async function POST(req: Request) {
  const res = NextResponse.json({ ok: true })

  // tc_session löschen
  res.cookies.set("tc_session", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE,
    path: "/",
    maxAge: 0,
  })

  // optional: übrig gebliebene Nonce ebenfalls invalidieren
  res.cookies.set("tc_nonce", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE,
    path: "/",
    maxAge: 0,
  })

  return cors(req, res)
}
