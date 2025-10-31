// api/auth/nonce.js
export default async function handler(req, res) {
  // --- CORS / Preflight ---
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }

  // --- CORS für eigentliche Antwort ---
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // --- Nonce erzeugen ---
  let nonce;
  try {
    nonce =
      globalThis.crypto?.randomUUID?.() ||
      require("crypto").randomBytes(16).toString("hex");
  } catch {
    // Fallback falls require nicht geht (ESM)
    const arr = new Uint8Array(16);
    (globalThis.crypto || window.crypto).getRandomValues(arr);
    nonce = Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // --- httpOnly Cookie setzen (10 Minuten) ---
  const maxAge = 60 * 10;
  const isProd =
    process.env.VERCEL_ENV === "production" ||
    process.env.NODE_ENV === "production";

  const cookieParts = [
    `tc_nonce=${nonce}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
    isProd ? "Secure" : null,
  ].filter(Boolean);

  res.setHeader("Set-Cookie", cookieParts.join("; "));

  return res.status(200).json({ ok: true, nonce });
}
