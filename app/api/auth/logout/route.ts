// app/api/auth/logout/route.ts
import { NextResponse } from "next/server"
import { withCORS } from "@/helpers/cors"
import { cors } from "@/helpers/cors"     // dein shared CORS-Helper

export async function OPTIONS(req: Request) {
  // 204 + korrekte CORS-Header zurück
  return cors(req, new Response(null, { status: 204 }))
}

export function OPTIONS(req: Request) {
  return withCORS(req, new NextResponse(null, { status: 204 }))
}

export async function POST(req: Request) {
  const res = NextResponse.json({ ok: true })
  res.cookies.set("tc_session", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
    maxAge: 0,
  })
  return withCORS(req, res)
}
