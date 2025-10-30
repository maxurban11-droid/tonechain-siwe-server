// app/api/auth/logout/route.ts
import { NextResponse } from "next/server"
import { withCORS } from "@/helpers/cors"

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
