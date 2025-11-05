// app/api/auth/check-email/route.js
export const runtime = "nodejs";         // wichtig: Node Runtime (admin API)
export const dynamic = "force-dynamic";  // keine statische Zwischenspeicherung

import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { corsHeadersForOrigin } from "../../../../helpers/cors.js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const service = process.env.SUPABASE_SERVICE_ROLE;

const supabaseAdmin = createClient(url, service, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function withCorsHeaders(origin, body, status = 200) {
  const h = corsHeadersForOrigin(origin);
  if (!h) return new NextResponse(JSON.stringify({ ok: false, error: "origin_not_allowed" }), { status: 403 });
  return new NextResponse(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...h } });
}

export async function OPTIONS(request) {
  const origin = request.headers.get("origin") || "";
  const h = corsHeadersForOrigin(origin);
  return new NextResponse(null, { status: 204, headers: h ?? {} });
}

export async function POST(request) {
  const origin = request.headers.get("origin") || "";
  try {
    const { email } = await request.json();
    const mail = normalizeEmail(email);
    if (!mail) return withCorsHeaders(origin, { ok: false, error: "bad_input" }, 400);

    // 1) Auth-User prüfen
    let user = null;
    try {
      const { data, error } = await supabaseAdmin.auth.admin.getUserByEmail(mail);
      user = error ? null : (data?.user ?? null);
    } catch { user = null; }

    // 2) Profile prüfen
    let profile = null;
    try {
      const { data: prof } = await supabaseAdmin
        .from("profiles")
        .select("id,user_id,email")
        .or(`email.eq.${mail},user_id.eq.${user?.id ?? "00000000-0000-0000-0000-000000000000"}`)
        .maybeSingle();
      profile = prof ?? null;
    } catch { profile = null; }

    const exists = !!(user || profile);
    const confirmed = !!(user && (user.email_confirmed_at || user.confirmed_at));

    return withCorsHeaders(origin, { exists, confirmed }, 200);
  } catch (e) {
    console.error("[check-email] error:", e);
    return withCorsHeaders(origin, { exists: false, confirmed: false }, 200);
  }
}
