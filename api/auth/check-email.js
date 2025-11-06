// api/auth/check-email.js
import { withCors } from "../../helpers/cors.js";

function getSupabaseUrl() {
  const raw =
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    "";
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

export default withCors(async function handler(req, res) {
  if (req.method === "OPTIONS" || req.method === "HEAD") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok:false, code:"method_not_allowed" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const email = String(body.email || "").trim();
    if (!email) return res.status(400).json({ ok:false, code:"bad_input" });

    const base = getSupabaseUrl();
    const serviceRole = getServiceRole();
    if (!serviceRole) throw new Error("Missing SUPABASE_SERVICE_ROLE(_KEY)");

    if (process.env.DEBUG_CHECK_EMAIL === "1") {
      console.log("[check-email] project:", new URL(base).host); // e.g. sxqwohevhodeaiqcpygj.supabase.co
    }

    const r = await fetch(`${base}/auth/v1/admin/users?email=${encodeURIComponent(email)}`, {
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
    const user = users.find(u => String(u.email || "").toLowerCase() === email.toLowerCase());

    return res.status(200).json({ exists: !!user, confirmed: !!user?.email_confirmed_at });
  } catch (e) {
    console.error("[check-email] error:", e);
    return res.status(500).json({ ok:false, code:"server_error", message: e?.message || "Server error" });
  }
});
