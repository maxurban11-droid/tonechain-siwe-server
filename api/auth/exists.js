// /api/auth/exists.js — prüft, ob eine Wallet-Adresse registriert ist
import { createClient } from "@supabase/supabase-js";

export default async function handler(req, res) {
  // CORS (immer zuerst)
  const origin = req.headers.origin || "*";
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ ok: false, error: "METHOD_NOT_ALLOWED" });

  // ENV prüfen
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return res.status(500).json({ ok: false, error: "SERVER_CONFIG_MISSING" });

  const addressRaw = String(req.query.address || "").trim();
  const address = addressRaw.toLowerCase();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return res.status(400).json({ ok: false, error: "INVALID_ADDRESS" });
  }

  const sb = createClient(url, key, { auth: { persistSession: false } });
  try {
    const { data, error } = await sb
      .from("wallets")
      .select("id")
      .eq("address", address)
      .limit(1);
    if (error) throw error;
    const exists = (data?.length ?? 0) > 0;
    return res.status(200).json({ ok: true, exists });
  } catch (e) {
    console.error("/api/auth/exists error:", e);
    return res.status(500).json({ ok: false, error: "DB_ERROR" });
  }
}
