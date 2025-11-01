import { withCors } from "../../helpers/cors.js"
import { clearCookie } from "../../helpers/cookies.js"

export default withCors(async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" })
  }

  try {
    clearCookie(res, "tc_session")
    clearCookie(res, "tc_nonce")
    return res.status(200).json({ ok: true, loggedOut: true })
  } catch (err) {
    console.error("Logout error:", err)
    return res.status(500).json({ ok: false, error: "Server error" })
  }
})
