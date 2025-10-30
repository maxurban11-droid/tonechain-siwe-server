// app/api/auth/nonce/route.ts
import { NextResponse } from "next/server"
import { withCORS } from "@/helpers/cors" // Pfad anpassen, falls kein baseUrl in tsconfig

function genNonce() {
  // kurze, kryptografisch starke Nonce
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

// Für Preflight
export function OPTIONS(req: Request) {
  return withCORS(req, new NextResponse(null, { status: 204 }))
}

// Nonce holen (GET)
export async function GET(req: Request) {
  const nonce = genNonce()

  const res = NextResponse.json({ nonce })
  // httpOnly Nonce-Cookie setzen (10 Min)
  res.cookies.set("tc_nonce", nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,            // Vercel = HTTPS
    path: "/",
    maxAge: 60 * 10,
  })
  return withCORS(req, res)
}
