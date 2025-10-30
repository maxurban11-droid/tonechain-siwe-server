// app/api/auth/logout/route.ts
import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

const SECURE = process.env.NODE_ENV === "production"

/** OPTIONS – preflight */
export async function OPTIONS(req: Request) {
  return preflight(req)
}

/** POST – clear session cookie */
export async function POST(req: Request) {
  const res = NextResponse.json({ ok: true })

  res.cookies.set("tc_session", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE,
    path: "/",
    maxAge: 0,
  })
  // also clear leftover nonce
  res.cookies.set("tc_nonce", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE,
    path: "/",
    maxAge: 0,
  })

  return cors(req, res)
}
