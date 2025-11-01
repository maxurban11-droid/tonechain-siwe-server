// api/auth/logout.js  — super-minimal, keine Imports
export default async function handler(req, res) {
  // CORS Preflight & CORS Antwort (hart, nur für den Test)
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // Noch KEIN Cookie-Löschen – wir prüfen nur, ob die Route stabil 200 liefert
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, test: "logout-min-noimport" });
}
