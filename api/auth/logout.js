// api/auth/logout.js  (TEMP-TEST)
import { withCors } from "../../helpers/cors.js";

export default withCors(async (req, res) => {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // NUR Test: noch KEIN Cookie-Löschen, wir prüfen erst CORS + 500
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, test: "logout-minimal" });
});
