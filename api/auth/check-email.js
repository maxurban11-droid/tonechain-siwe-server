// api/auth/check-email.js
import { withCors } from "../../helpers/cors.js";
import { createClient } from "@supabase/supabase-js";

function getSupabaseUrl() {
  const raw = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "";
  if (!raw) throw new Error("Missing SUPABASE_URL");
  return String(raw).replace(/\/+$/, "");
}
function getServiceRole() {
  return (
    process.env.SUPABASE_SERVICE_ROLE ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    ""
  );
}

async function findByAdminRest(base, serviceRole, email) {
  const url = new URL(`${base}/auth/v1/admin/users`);
  url.searchParams.set("email", email.toLowerCase());
  url.searchParams.set("per_page", "200");
  const r = await fetch(url.toString(), {
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
  const users = Array.isArray(j) ? j : (j.users || []);
  return users.find(u => String(u.email || "").toLowerCase() === email.toLowerCase()) || null;
}

async function findByAdminList(admin, email) {
  // Fallback: bis zu 5 Seiten à 200 User (max. ~1000)
  const perPage = 200;
  for (let page = 1; page <= 5; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const users = data?.users || [];
    const hit = users.find(u => String(u.email || "").toLowerCase() === email.toLowerCase());
    if (hit) return hit;
    if (users.length < perPage) break;
  }
  return null;
}

export default withCors(async function handler(req, res) {
  if (req.method === "OPTIONS" || req.method === "HEAD") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, code:"method_not_allowed" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const email = String(body.email || "").trim();
    if (!email) return res.status(400).json({ ok:false, code:"bad_input" });

    const base = getSupabaseUrl();
    const role = getServiceRole();
    if (!role) throw new Error("Missing SUPABASE_SERVICE_ROLE(_KEY)");

    if (process.env.DEBUG_CHECK_EMAIL === "1") {
      console.log("[check-email] project:", new URL(base).host);
      console.log("[check-email] query:", email);
    }

    // 1) Primär: Admin REST mit Email-Filter
    let user = null;
    try {
      user = await findByAdminRest(base, role, email);
    } catch (e) {
      console.warn("[check-email] admin REST failed → fallback listUsers:", e?.message);
    }

    // 2) Fallback: paginierte listUsers()
    if (!user) {
      const admin = createClient(base, role, { auth: { persistSession: false, autoRefreshToken: false } });
      user = await findByAdminList(admin, email);
    }

    const exists = !!user;
    const confirmed = !!user?.email_confirmed_at;

    if (process.env.DEBUG_CHECK_EMAIL === "1") {
      console.log("[check-email] result:", { exists, confirmed });
    }

    return res.status(200).json({ exists, confirmed });
  } catch (e) {
    console.error("[check-email] error:", e);
    return res.status(500).json({ ok:false, code:"server_error", message: e?.message || "Server error" });
  }
});
