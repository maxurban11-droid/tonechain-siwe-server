// pages/api/auth/check-email.js
import { withCors } from "../../helpers/cors.js"; // ggf. Pfad anpassen

async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  const email = (req.body?.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: "bad_input" });

  const urlBase = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const srk = process.env.SUPABASE_SERVICE_ROLE_KEY; // Server-only!
  const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || srk;

  // Fehlt Admin-Zugriff? → neutral antworten (Signup nicht blocken)
  if (!urlBase || !srk) {
    return res.status(200).json({ exists: false, confirmed: false });
  }

  const url = `${urlBase.replace(/\/+$/, "")}/auth/v1/admin/users?email=${encodeURIComponent(email)}`;

  try {
    const r = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${srk}`, apikey: anon },
      cache: "no-store",
    });

    if (!r.ok) return res.status(200).json({ exists: false, confirmed: false });

    const list = await r.json().catch(() => []);
    const user = Array.isArray(list) ? list[0] : null;
    const exists = !!user;
    const confirmed = exists && !!user.email_confirmed_at;

    return res.status(200).json({ exists, confirmed });
  } catch {
    return res.status(200).json({ exists: false, confirmed: false });
  }
}

export default withCors(handler);
