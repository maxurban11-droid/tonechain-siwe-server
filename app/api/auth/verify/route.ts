// app/api/auth/verify/route.ts
import { NextResponse } from "next/server"
import { cookies, headers } from "next/headers"
import { cors, preflight } from "@/helpers/cors"
import { SiweMessage } from "siwe"

const SECURE = process.env.NODE_ENV === "production"

type Body = { message: string; signature: string }

/** OPTIONS – preflight */
export async function OPTIONS(req: Request) {
  return preflight(req)
}

/** POST – verify SIWE and set session */
export async function POST(req: Request) {
  try {
    const { message, signature } = (await req.json()) as Body
    if (!message || !signature) {
      return cors(req, NextResponse.json({ ok: false, error: "Bad payload" }, { status: 400 }))
    }

    const nonce = cookies().get("tc_nonce")?.value
    if (!nonce) {
      return cors(req, NextResponse.json({ ok: false, error: "Missing nonce" }, { status: 400 }))
    }

    // Validate domain strictly (optional but recommended)
    const host = headers().get("host") || ""
    const domain = host.split(":")[0] // strip :port if present

    const siwe = new SiweMessage(message)
    const result = await siwe.verify({
      signature,
      nonce,
      domain,
      time: new Date().toISOString(),
    })

    if (!result.success) {
      return cors(req, NextResponse.json({ ok: false, error: "Invalid signature" }, { status: 401 }))
    }

    const res = NextResponse.json({ ok: true, address: siwe.address })

    // Set httpOnly session (7 days)
    res.cookies.set("tc_session", JSON.stringify({ address: siwe.address, iat: Date.now() }), {
      httpOnly: true,
      sameSite: "lax",
      secure: SECURE,
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    })

    // Invalidate nonce
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
