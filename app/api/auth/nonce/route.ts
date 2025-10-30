import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

export const dynamic = "force-dynamic" // keine Edge/Cache-Irritation

function genNonce(): string {
  try {
    const getRand =
      (globalThis as any).crypto?.getRandomValues ??
      (globalThis as any).crypto?.webcrypto?.getRandomValues
    if (getRand) {
      const a = new Uint8Array(16); getRand(a)
      return Array.from(a).map(b => b.toString(16).padStart(2, "0")).join("")
    }
  } catch {}
  // Fallback (nicht kryptografisch, aber praktisch nie nötig)
  return (Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)).slice(0, 32)
}

export function OPTIONS(req: Request) {
  return preflight(req)
}

export async function GET(req: Request) {
  const nonce = genNonce()
  const res = NextResponse.json({ nonce })

  // *** Cross-site kompatibel ***
  res.cookies.set("tc_nonce", nonce, {
    httpOnly: true,
    sameSite: "none",   // <— WICHTIG für Framer (cross-site)
    secure: true,
    path: "/",
    maxAge: 60 * 10,
  })

  return cors(req, res)
}
