// /api/pay/notify.js
import { VercelRequest, VercelResponse } from "@vercel/node";

export default async function handler(req, res) {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method not allowed" });

  try {
    res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
    const { txHash, amount, chainId } = req.body || {};
    if (!txHash || typeof txHash !== "string") return res.status(400).json({ ok: false, error: "Missing txHash" });

    // Optional: Session aus Cookie lesen (später)
    // const addr = readSession(req)?.address ?? null;

    // Minimal: audit-log (Vercel log)
    console.log("[PAY/NOTIFY]", { txHash, amount, chainId, at: new Date().toISOString() });

    // Idempotenter Erfolg – du kannst hier schon z. B. Webhook an dein CRM feuern
    return res.status(200).json({ ok: true, accepted: true });
  } catch (e) {
    console.error("[PAY/NOTIFY] error", e?.message || e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
}
