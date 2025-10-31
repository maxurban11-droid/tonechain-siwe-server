// api/auth/nonce.js — erzeugt Nonce + setzt httpOnly Cookie `tc_nonce` (10 min)
const crypto = require('crypto');

function setCors(req, res) {
  const origin = req.headers.origin || '';
  // Für Cross-Site-Cookies braucht es eine spezifische Origin + Credentials
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function setCookie(res, name, value, maxAgeSec) {
  const parts = [
    `${name}=${value}`,
    'Path=/',
    `Max-Age=${maxAgeSec}`,
    'HttpOnly',
    'SameSite=None',
    'Secure'
  ];
  res.setHeader('Set-Cookie', parts.join('; '));
}

module.exports = (req, res) => {
  setCors(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  const nonce = crypto.randomBytes(16).toString('hex'); // 32 Zeichen
  setCookie(res, 'tc_nonce', nonce, 600); // 10 Minuten

  return res.status(200).json({ ok: true, nonce });
};
