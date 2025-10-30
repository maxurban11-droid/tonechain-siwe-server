// app/api/auth/verify/route.ts
import { NextResponse, NextRequest } from "next/server"
import { cookies, headers } from "next/headers"
import { cors, preflight } from "@/helpers/cors"   // einheitlicher CORS-Helper
import { SiweMessage } from "siwe"

type Body = { message: string; signature: string }

const SECURE = process.env.NODE_ENV === "production"

export async function OPTIONS(req: Request) {
  // Preflight: 204 + korrekte CORS-Header
  return preflight(req)
}

export async function POST(req: NextRequest) {
  try {
    // --- Payload prüfen ---
    const { message, signature } = (await req.json()) as Body
    if (!message || !signature) {
      return cors(req, NextResponse.json({ ok: false, error: "Bad payload" }, { status: 400 }))
    }

    // --- Nonce aus httpOnly-Cookie ---
    const nonceCookie = cookies().get("tc_nonce")?.value
    if (!nonceCookie) {
      return cors(req, NextResponse.json({ ok: false, error: "Missing nonce" }, { status: 400 }))
    }

    // --- Domain/Origin aus Request-Headern (optional streng) ---
    const hdrs = headers()
    const host = hdrs.get("host") || ""
    const domain = host.split(":")[0] // "example.com" ohne Port

    // --- SIWE Verify ---
    const siwe = new SiweMessage(message)
    const result = await siwe.verify({
      signature,
      nonce: nonceCookie,
      domain,
      time: new Date().toISOString(),
    })

    if (!result.success) {
      return cors(req, NextResponse.json({ ok: false, error: "Invalid signature" }, { status: 401 }))
    }

    // --- Session bauen (minimal) ---
    const sessionPayload = {
      address: siwe.address,
      iat: Date.now(),
    }
    const res = NextResponse.json({ ok: true, address: siwe.address })

    // --- Cookies setzen/löschen (Flags konsistent) ---
    res.cookies.set("tc_session", JSON.stringify(sessionPayload), {
      httpOnly: true,
      sameSite: "lax",
      secure: SECURE,
      path: "/",
      maxAge: 60 * 60 * 24 * 7, // 7 Tage
    })
    // Nonce invalidieren (single-use)
    res.cookies.set("tc_nonce", "", {
      httpOnly: true,
      sameSite: "lax",
      secure: SECURE,
      path: "/",
      maxAge: 0,
    })

    return cors(req, res)
  } catch (e: any) {
    return cors(
      req,
      NextResponse.json({ ok: false, error: e?.message || "Verify failed" }, { status: 500 })
    )
  }
}
