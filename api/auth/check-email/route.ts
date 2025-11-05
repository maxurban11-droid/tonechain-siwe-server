// src/app/api/auth/check-email/route.ts
import { NextRequest, NextResponse } from "next/server"
import { createClient } from "@supabase/supabase-js"

export const runtime = "nodejs"

function corsHeaders(req: NextRequest) {
  const origin = req.headers.get("origin") ?? "*"
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type, authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  }
}

export async function OPTIONS(req: NextRequest) {
  return new NextResponse(null, { headers: corsHeaders(req) })
}

export async function POST(req: NextRequest) {
  const headers = corsHeaders(req)
  try {
    const { email } = await req.json().catch(() => ({}))
    if (!email || !/.+@.+\..+/.test(email)) {
      return NextResponse.json({ ok: false, error: "bad_email" }, { status: 400, headers })
    }

    const url = process.env.NEXT_PUBLIC_SUPABASE_URL!
    const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!
    if (!url || !serviceKey) {
      return NextResponse.json({ ok: false, error: "server_misconfig" }, { status: 500, headers })
    }

    const admin = createClient(url, serviceKey, { auth: { persistSession: false } })
    const { data, error } = await admin.auth.admin.getUserByEmail(email)

    if (error && !String(error.message || "").toLowerCase().includes("user not found")) {
      return NextResponse.json({ ok: false, error: "upstream", detail: error.message }, { status: 502, headers })
    }

    const user = data?.user ?? null
    const confirmed = !!user?.email_confirmed_at
    return NextResponse.json(
      { ok: true, exists: !!user, confirmed, userId: user?.id ?? null },
      { headers }
    )
  } catch (e: any) {
    return NextResponse.json({ ok: false, error: "exception", message: e?.message || "unknown" }, { status: 500, headers })
  }
}
