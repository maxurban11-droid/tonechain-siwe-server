// app/api/auth/check-email/route.js
export const runtime = "nodejs"; // wichtig: Service-Role sicher nutzen

import { createClient } from "@supabase/supabase-js";
// Achtung: relative Endung .js ist bei ESM wichtig
import { corsHeadersForOrigin } from "../../../helpers/cors.js";

function getCors(origin) {
  return corsHeadersForOrigin(origin) || {}; // ggf. leeres Objekt
}

function getAdminClient() {
  const url =
    process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || "";
  const serviceRole = process.env.SUPABASE_SERVICE_ROLE || "";
  if (!url || !serviceRole) {
    throw new Error("Missing SUPABASE env (URL or SERVICE_ROLE).");
  }
  return createClient(url, serviceRole, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export async function OPTIONS(req) {
  const origin = req.headers.get("origin") || "";
  // Preflight IMMER beantworten (mit oder ohne Match – Browser blockt sonst)
  return new Response(null, { status: 204, headers: getCors(origin) });
}

export async function POST(req) {
  const origin = req.headers.get("origin") || "";
  const cors = getCors(origin);

  try {
    const { email } = await req.json().catch(() => ({}));
    if (!email || typeof email !== "string") {
      return new Response(
        JSON.stringify({ ok: false, code: "bad_input" }),
        { status: 400, headers: { "content-type": "application/json", ...cors } }
      );
    }

    const admin = getAdminClient();

    // Zuverlässige Abfrage: Auth Admin REST (E-Mail-Filter)
    const url =
      (process.env.NEXT_PUBLIC_SUPABASE_URL || "").replace(/\/+$/, "") +
      `/auth/v1/admin/users?email=${encodeURIComponent(email)}`;

    const serviceRole = process.env.SUPABASE_SERVICE_ROLE;
    const r = await fetch(url, {
      headers: {
        apikey: serviceRole,
        Authorization: `Bearer ${serviceRole}`,
        "content-type": "application/json",
      },
    });

    if (!r.ok) {
      const txt = await r.text().catch(() => "");
      throw new Error(`admin users lookup failed (${r.status}): ${txt}`);
    }

    const j = await r.json().catch(() => ({}));
    // Antwortform: { users: [...] } oder Array – je nach Version → beides abfangen
    const users = Array.isArray(j) ? j : j.users || [];
    const user = users.find(
      (u) => String(u.email || "").toLowerCase() === email.toLowerCase()
    );

    const exists = !!user;
    const confirmed = !!user?.email_confirmed_at;

    return new Response(JSON.stringify({ exists, confirmed }), {
      status: 200,
      headers: { "content-type": "application/json", ...cors },
    });
  } catch (e) {
    return new Response(
      JSON.stringify({
        ok: false,
        code: "server_error",
        message: e?.message || "Server error",
      }),
      { status: 500, headers: { "content-type": "application/json", ...cors } }
    );
  }
}
