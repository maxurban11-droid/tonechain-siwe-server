// api/auth/peek.js
import { withCors } from "../../helpers/cors.js";

function readCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(/;\s*/)) {
    const [k, v] = part.split("=");
    if (k === name) return decodeURIComponent(v || "");
  }
  return null;
}

async function core(req, res) {
  const nonce = readCookie(req, "tc_nonce");
  const session = readCookie(req, "tc_session");
  return res
    .status(200)
    .json({ ok: true, nonceOnServer: nonce, hasSession: !!session });
}

export default withCors(core);
