// src/app/api/auth/check-email/route.ts
import { NextResponse } from "next/server"

// ⬅️ Pfad ggf. anpassen – hier relativ vom /api/auth/check-email Ordner:
import { corsHeadersForOrigin } from "@/helpers/cors.js"

export const runtime = "nodejs" // Admin-Requests brauchen Node, kein Edge

type CheckResult = { exists: boolean; confirmed: boolean }

// Hilfsfunktion: Supabase Admin REST (v1) nach E-Mail abfragen
async function fetchUserByEmail(email: string): Promise<CheckResult> {
  const urlBase = process.env.NEXT_PUBLIC_SUPABASE_URL
  const srk = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!urlBase || !srk) {
    // Fallback: nichts blocken, aber sauber antworten
    return { exists: false, confirmed: false }
  }

  // Admin-Endpoint: /auth/v1/admin/users?email=...
  const url = `${urlBase.replace(/\/+$/, "")}/auth/v1/admin/users?email=${encodeURIComponent(
    email
  )}`

  const r = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${srk}`,
      apikey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || srk,
    },
    // Wichtig: hier KEINE Credentials, das ist Server-to-Server
    cache: "no-store",
  })

  // Supabase antwortet mit 200 + [] wenn kein Treffer
  if (!r.ok) return { exists: false, confirmed: false }

  const arr = (await r.json().catch(() => [])) as any[]
  const user = Array.isArray(arr) ? arr[0] : null
  const exists = !!user
  const confirmed = exists && !!user.email_confirmed_at
  return { exists, confirmed }
}

/** OPTIONS – Preflight */
export async function OPTIONS(req: Request) {
  const origin = req.headers.get("origin") || ""
  const cors = corsHeadersForOrigin(origin) ?? {}
  return new NextResponse(null, { status: 204, headers: cors })
}

/** POST – eigentlicher Check */
export async function POST(req: Request) {
  const origin = req.headers.get("origin") || ""
  const cors = corsHeadersForOrigin(origin)

  // Wenn Origin nicht erlaubt → neutral/403 antworten (ohne Leak)
  if (!cors) {
    return new NextResponse(JSON.stringify({ ok: false, error: "Origin not allowed" }), {
      status: 403,
      headers: { Vary: "Origin" },
    })
  }

  let email: unknown
  try {
    const body = await req.json()
    email = body?.email
  } catch {
    /* ignore */
  }

  if (typeof email !== "string" || !email.trim()) {
    return new NextResponse(JSON.stringify({ ok: false, error: "bad_input" }), {
      status: 400,
      headers: cors,
    })
  }

  try {
    const { exists, confirmed } = await fetchUserByEmail(email.trim().toLowerCase())

    // Vereinbarte Payload mit dem Client:
    // - exists && confirmed   → EMAIL_EXISTS (sign in)
    // - exists && !confirmed  → EMAIL_PENDING (Verify-Step, Re-Send)
    // - !exists               → ok für neuen Sign-up
    return new NextResponse(JSON.stringify({ exists, confirmed }), {
      status: 200,
      headers: cors,
    })
  } catch {
    return new NextResponse(JSON.stringify({ ok: false }), {
      status: 500,
      headers: cors,
    })
  }
}
