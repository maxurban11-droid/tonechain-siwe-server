// api/auth/register.js
import { withCors } from "../../helpers/cors.js";

/**
 * Very first minimal register handler.
 * Goal: make CORS & client flow pass (intent: "signup").
 *
 * Body: { message: string, signature: string, creatorName?: string }
 * Returns: { ok: true }
 */
async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // Body lesen
  let body = null;
  try {
    body = req.body ?? JSON.parse(req.body || "{}");
  } catch {
    // noop
  }

  const message = body?.message;
  const signature = body?.signature;
  const creatorName = body?.creatorName ?? null;

  if (!message || !signature) {
    return res
      .status(400)
      .json({ ok: false, error: "Missing message or signature" });
  }

  // 🔒 Hier könntest du OPTIONAL schon die Signatur prüfen
  // (z. B. mit siwe / personal_sign Verify), falls deine utils das hergeben.
  // Für den schnellen CORS-/Flow-Test lassen wir es bewusst weg.

  // 📝 Später: Wallet in DB/Storage anlegen (profiles/wallets table, etc.)
  // Aktuell: Nur Erfolg melden, damit der Client danach erneut /verify ruft.
  return res.status(200).json({ ok: true, registered: true, creatorName });
}

export default withCors(handler);
