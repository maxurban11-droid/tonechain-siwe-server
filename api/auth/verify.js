// api/auth/verify.js  (CommonJS, CORS-sicher)
const { withCors } = require('../../helpers/cors.js');
// Falls du später Cookies setzen/löschen willst:
// const { setCookie, clearCookie } = require('../../helpers/cookies.js');
// Echte SIWE-Prüfung später (vorhanden lassen, aber aktuell ungenutzt):
// const { verifyMessage } = require('ethers');

module.exports = withCors(async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      return res
        .status(400)
        .json({ ok: false, error: 'Missing message or signature' });
    }

    // 🔒 Hier später die echte SIWE-Validierung einfügen.
    // Aktuell bewusst nur Stub, damit Preflight + POST stabil laufen:
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res
      .status(400)
      .json({ ok: false, error: e?.message || 'Verify failed' });
  }
});
