// api/auth/logout.js
import { withCors, handleOptions } from "../../helpers/cors.js";
import { clearCookie } from "../../helpers/cookies.js";

export default withCors(async function handler(req, res) {
  // Preflight sauber beantworten
  if (req.method === "OPTIONS") return handleOptions(req, res);

  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "Method not allowed" });
    return;
  }

  // Session-Cookies löschen
  clearCookie(res, "tc_session");
  clearCookie(res, "tc_nonce"); // optional, schadet nicht

  // CORS-Helper setzt:
  // - Access-Control-Allow-Origin: <erlaubter Origin>
  // - Access-Control-Allow-Credentials: true
  res.status(200).json({ ok: true, loggedOut: true });
});
