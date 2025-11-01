// api/auth/logout.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { withCors } from "../../helpers/cors";

function pushCookie(res: VercelResponse, cookie: string) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) {
    res.setHeader("Set-Cookie", [cookie]);
  } else if (Array.isArray(prev)) {
    res.setHeader("Set-Cookie", [...prev, cookie]);
  } else {
    res.setHeader("Set-Cookie", [String(prev), cookie]);
  }
}

function clearCookie(res: VercelResponse, name: string) {
  // Cross-site: SameSite=None; Secure; HttpOnly
  pushCookie(
    res,
    `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`
  );
}

export default withCors(async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  // Beide Cookies wirklich löschen (nicht überschreiben)
  clearCookie(res, "tc_session");
  clearCookie(res, "tc_nonce");

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, loggedOut: true });
});
