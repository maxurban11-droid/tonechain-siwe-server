import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

function genNonce() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

export function OPTIONS(req: Request) {
  return preflight(req)
}

export async function GET(req: Request) {
  const nonce = genNonce()
  const res = NextResponse.json({ nonce })

  res.cookies.set("tc_nonce", nonce, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
    maxAge: 60 * 10,
  })

  return cors(req, res)
}
