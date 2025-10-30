// app/api/auth/nonce/route.ts
import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors" // einheitlicher CORS-Helper

// Secure Flag dynamisch: in Produktion true, lokal false
const SECURE = process.env.NODE_ENV === "production"

/** 
 * OPTIONS – Preflight 
 * Liefert 204 mit gültigen CORS-Headern
 */
export async function OPTIONS(req: Request) {
  return preflight(req)
}

/** 
 * Hilfsfunktion: kurze, kryptografisch starke Nonce erzeugen 
 */
function genNonce() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

/** 
 * GET – neue Nonce generieren, httpOnly Cookie setzen
 * Response: { nonce: "…" }
 */
export async function GET(req: Request) {
  const nonce = genNonce()

  // Antwortkörper (JSON) + Cookie (httpOnly, 10 min)
  const res = NextResponse.json({ nonce })
  res.cookies.set("tc_nonce", nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: SECURE,
    path: "/",
    maxAge: 60 * 10, // 10 Minuten
  })

  return cors(req, res)
}
