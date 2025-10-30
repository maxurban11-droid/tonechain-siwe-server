import { NextResponse } from "next/server"
import { cookies, headers } from "next/headers"
import { cors, preflight } from "@/helpers/cors"
import { SiweMessage } from "siwe"

export const dynamic = "force-dynamic"

type Body = { message: string; signature: string }

export function OPTIONS(req: Request) {
  return preflight(req)
}

export async function POST(req: Request) {
  try {
    const { message, signature } = (await req.json()) as Body
    if (!message || !signature) {
      return cors(req, NextResponse.json({ ok: false, error: "Bad payload" }, { status: 400 }))
    }

    const nonceCookie = cookies().get("tc_nonce")?.value
    if (!nonceCookie) {
      return cors(req, NextResponse.json({ ok: false, error: "Missing nonce" }, { status: 400 }))
    }

    const host = headers().get("host") || ""
    const domain = host.split(":")[0]

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

    const session = JSON.stringify({ address: siwe.address, iat: Date.now() })

    const res = NextResponse.json({ ok: true, address: siwe.address })

    // *** Cross-site kompatibel ***
    res.cookies.set("tc_session", session, {
      httpOnly: true,
      sameSite: "none",  // <— WICHTIG für Framer (cross-site)
      secure: true,
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    })
    res.cookies.set("tc_nonce", "", {
      httpOnly: true,
      sameSite: "none",
      secure: true,
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
