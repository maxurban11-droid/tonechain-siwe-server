import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

export const dynamic = "force-dynamic"

export function OPTIONS(req: Request) {
  return preflight(req)
}

export async function POST(req: Request) {
  const res = NextResponse.json({ ok: true })
  res.cookies.set("tc_session", "", {
    httpOnly: true,
    sameSite: "none",  // cross-site korrekt löschen
    secure: true,
    path: "/",
    maxAge: 0,
  })
  res.cookies.set("tc_nonce", "", {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    path: "/",
    maxAge: 0,
  })
  return cors(req, res)
}
