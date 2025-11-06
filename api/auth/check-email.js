// /api/auth/check-email.js  (Pages Router)
import { withCors } from "../helpers/cors.js"; // <- Pfad von /api/auth → /helpers
// Wenn dein helpers-Ordner direkt unter Root liegt, ist der Pfad "../helpers/cors.js" korrekt.
// Liegt er unter /api/helpers, nimm "./../helpers/cors.js".

const SUPABASE_URL =
  process.env.NEXT_PUBLIC_SUPABASE_URL ||
  process.env.SUPABASE_URL ||
  "";

const SERVICE_ROLE =
  process.env.SUPABASE_SERVICE_ROLE ||
  process.env.SUPABASE_SERVICE_ROLE_KEY || // <- wichtig: _KEY fallback
  "";

async function handler(req, res) {
  // Preflight & HEAD werden von withCors schon korrekt beantwortet.
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, code: "method_not_allowed" });
  }

  if (!SUPABASE_URL || !SERVICE_ROLE) {
    return res.status(500).json({
      ok: false,
      code: "server_error",
      message: "Missing SUPABASE env (URL or SERVICE_ROLE_KEY).",
    });
  }

  const email = (req.body && (req.body.email ?? req.body?.data?.email)) || "";
  if (!email || typeof email !== "string") {
    return res.status(400).json({ ok: false, code: "bad_input" });
  }

  const adminEndpoint =
    SUPABASE_URL.replace(/\/+$/, "") +
    "/auth/v1/admin/users?email=" +
    encodeURIComponent(email);

  const r = await fetch(adminEndpoint, {
    headers: {
      apikey: SERVICE_ROLE,
      Authorization: `Bearer ${SERVICE_ROLE}`,
      "content-type": "application/json",
    },
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    return res.status(500).json({
      ok: false,
      code: "supabase_admin_failed",
      message: `admin users lookup failed (${r.status}): ${txt}`,
    });
  }

  const j = await r.json().catch(() => ({}));
  const users = Array.isArray(j) ? j : j.users || [];
  const user = users.find(
    (u) => String(u.email || "").toLowerCase() === email.toLowerCase()
  );

  const exists = !!user;
  const confirmed = !!user?.email_confirmed_at;

  return res.status(200).json({ exists, confirmed });
}

export default withCors(handler);
