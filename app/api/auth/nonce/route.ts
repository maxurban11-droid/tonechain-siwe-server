// app/api/auth/nonce/route.ts
import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

const SECURE = process.env.NODE_ENV === "production"

function genNonce() {
  // Web Crypto: supported by Next on Node 18+ / Edge too
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

/** OPTIONS – preflight */
export async function OPTIONS(req: Request) {
  return preflight(req)
}

/** GET – issues nonce + sets httpOnly cookie */
export async function GET(req: Request) {
  const nonce = genNonce()
  const res = NextResponse.json({ nonce })
  res.cookies.set("tc_nonce", nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE,
    path: "/",
    maxAge: 60 * 10, // 10 minutes
  })
  return cors(req, res)
}
