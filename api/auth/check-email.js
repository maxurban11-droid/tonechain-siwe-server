// pages/api/auth/check-email.js
import { withCors } from "../../../helpers/cors.js";
import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const service = process.env.SUPABASE_SERVICE_ROLE;

// Admin-Client: nur im Servercode (Service-Role)!
const supabaseAdmin = createClient(url, service, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  try {
    const { email } = (req.body || {});
    const mail = normalizeEmail(email);
    if (!mail) return res.status(400).json({ ok: false, error: "bad_input" });

    // 1) Auth-User prüfen
    let user = null;
    try {
      const { data, error } = await supabaseAdmin.auth.admin.getUserByEmail(mail);
      if (error) {
        // z.B. wenn Mail nicht existiert
        user = null;
      } else {
        user = data?.user ?? null;
      }
    } catch (e) {
      // Fallback: treat as not found (keine harten Fehler nach außen)
      user = null;
    }

    // 2) Profile prüfen (existiert evtl. schon ohne bestätigte Mail)
    let profile = null;
    try {
      const { data: prof } = await supabaseAdmin
        .from("profiles")
        .select("id,user_id,email")
        .or(`email.eq.${mail},user_id.eq.${user?.id ?? "00000000-0000-0000-0000-000000000000"}`)
        .maybeSingle();
      profile = prof ?? null;
    } catch {
      profile = null;
    }

    const exists = !!(user || profile);
    const confirmed =
      !!(user && (user.email_confirmed_at || user.confirmed_at)); // supabase user model

    return res.status(200).json({ exists, confirmed });
  } catch (e) {
    console.error("[check-email] error:", e);
    // Kein Leak, aber stabile Antwort
    return res.status(200).json({ exists: false, confirmed: false });
  }
}

export default withCors(handler);
