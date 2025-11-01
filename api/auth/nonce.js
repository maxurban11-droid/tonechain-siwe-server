// api/auth/nonce.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { withCors } from "../../helpers/cors"; // <— WICHTIG: richtiger Pfad!

function setCookie(res: VercelResponse, name: string, value: string, maxAgeSec: number) {
  // Cross-site: SameSite=None; Secure + HttpOnly
  const cookie = `${name}=${value}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; SameSite=None; Secure`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", [cookie]);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [String(prev), cookie]);
}

export default withCors(async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method Not Allowed" });

    const nonce =
      (globalThis as any).crypto?.randomUUID?.() ||
      Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);

    setCookie(res, "tc_nonce", nonce, 60 * 10); // 10 Min
    res.setHeader("Cache-Control", "no-store");

    return res.status(200).json({ ok: true, nonce });
  } catch (e: any) {
    // Hilfreich für Vercel Runtime Logs
    console.error("[nonce] error:", e?.stack || e);
    return res.status(500).json({ ok: false, error: "internal", detail: String(e?.message || e) });
  }
});
