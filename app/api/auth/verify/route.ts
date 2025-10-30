// app/api/auth/verify/route.ts
import { NextResponse } from "next/server"
import { cookies, headers } from "next/headers"
import { withCORS } from "@/helpers/cors"
import { SiweMessage } from "siwe"
import { cors } from "@/helpers/cors"     // dein shared CORS-Helper

export async function OPTIONS(req: Request) {
  // 204 + korrekte CORS-Header zurück
  return cors(req, new Response(null, { status: 204 }))
}

export function OPTIONS(req: Request) {
  return withCORS(req, new NextResponse(null, { status: 204 }))
}

type Body = { message: string; signature: string }

export async function POST(req: Request) {
  try {
    const { message, signature } = (await req.json()) as Body
    if (!message || !signature) {
      return withCORS(req, NextResponse.json({ ok: false, error: "Bad payload" }, { status: 400 }))
    }

    // Nonce aus httpOnly-Cookie lesen
    const nonceCookie = cookies().get("tc_nonce")?.value
    if (!nonceCookie) {
      return withCORS(req, NextResponse.json({ ok: false, error: "Missing nonce" }, { status: 400 }))
    }

    // Domain/Origin optional streng prüfen
    const hdrs = headers()
    const host = hdrs.get("host") || ""
    const origin = hdrs.get("origin") || ""
    const domain = host.split(":")[0]

    // SIWE prüfen
    const siwe = new SiweMessage(message)
    const result = await siwe.verify({
      signature,
      nonce: nonceCookie,
      domain,                    // stellt sicher, dass die Message für diese Domain ist
      time: new Date().toISOString(),
    })

    if (!result.success) {
      return withCORS(req, NextResponse.json({ ok: false, error: "Invalid signature" }, { status: 401 }))
    }

    // Session bauen (hier minimalistisch)
    const session = JSON.stringify({
      address: siwe.address,
      iat: Date.now(),
    })

    const res = NextResponse.json({ ok: true, address: siwe.address })

    // Session setzen (7 Tage), Nonce invalidieren
    res.cookies.set("tc_session", session, {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    })
    res.cookies.set("tc_nonce", "", {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      path: "/",
      maxAge: 0,
    })

    return withCORS(req, res)
  } catch (e: any) {
    return withCORS(
      req,
      NextResponse.json({ ok: false, error: e?.message || "Verify failed" }, { status: 500 })
    )
  }
}
