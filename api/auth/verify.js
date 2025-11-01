// api/auth/verify.js (CommonJS, echte SIWE-Validierung)
const { withCors } = require('../../helpers/cors.js');
const { setCookie, clearCookie, getCookie } = require('../../helpers/cookies.js');
const { verifyMessage } = require('ethers');

// ---- Projekt-Konstanten (klein & leicht änderbar) ----
const COOKIE_NONCE   = 'tc_nonce';
const COOKIE_SESSION = 'tc_session';

// Wo darf die Sign-In Nachricht her kommen
const ALLOWED_DOMAINS = new Set([
  'tonechain.app',
  'concave-device-193297.framer.app',
]);

// Welche URI-Präfixe akzeptieren wir in der SIWE-Message
const ALLOWED_URI_PREFIXES = [
  'https://tonechain.app',
  'https://concave-device-193297.framer.app',
];

// Erlaubte Chain IDs (mainnet & sepolia)
const ALLOWED_CHAINS = new Set([1, 11155111]);

// EIP-4361: `Issued At` darf nicht älter als 10min sein (+/- 5min Clock Skew)
const MAX_AGE_MIN = 10;
const MAX_SKEW_MS = 5 * 60 * 1000;

// ---- kleine Utils ----
const now = () => new Date(Date.now());

function parseSiweMessage(raw) {
  // Wir lesen nur, was wir brauchen – robustes Parsing für deine Message-Struktur
  // (die du im AuthWidget erzeugst).
  const lines = String(raw).split('\n');

  // Zeile 0: "<domain> wants you to sign in with your Ethereum account:"
  const first = lines[0] || '';
  const domain = first.replace(/ wants you to sign in with your Ethereum account:?$/i, '').trim();

  // Zeile 1: Adresse
  const address = (lines[1] || '').trim();

  // Restliche Felder als "Key: Value" paars
  const map = new Map();
  for (let i = 2; i < lines.length; i++) {
    const m = lines[i].match(/^([A-Za-z ]+):\s*(.*)$/);
    if (m) map.set(m[1].toLowerCase(), m[2]);
  }

  const uri       = map.get('uri') || '';
  const version   = map.get('version') || '1';
  const chainId   = Number(map.get('chain id') || '0');
  const nonce     = map.get('nonce') || '';
  const issuedAt  = map.get('issued at') || '';

  return { domain, address, uri, version, chainId, nonce, issuedAt };
}

function withinAllowedUri(uri) {
  return ALLOWED_URI_PREFIXES.some(p => uri.startsWith(p));
}

function checkIssuedAt(issuedAt) {
  // erlaubt: [now - MAX_AGE_MIN … now + MAX_SKEW_MS]
  const t = Date.parse(issuedAt);
  if (Number.isNaN(t)) return false;
  const ts  = new Date(t).getTime();
  const lo  = now().getTime() - MAX_AGE_MIN * 60 * 1000 - MAX_SKEW_MS;
  const hi  = now().getTime() + MAX_SKEW_MS;
  return ts >= lo && ts <= hi;
}

module.exports = withCors(async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    const { message, signature } = req.body || {};
    if (!message || !signature) {
      return res.status(400).json({ ok: false, error: 'Missing message or signature' });
    }

    // 1) SIWE-Message parsen
    const siwe = parseSiweMessage(message);

    // 2) Basisvalidierungen
    if (!siwe.address || !/^0x[a-fA-F0-9]{40}$/.test(siwe.address)) {
      return res.status(400).json({ ok: false, error: 'Invalid address' });
    }
    if (!ALLOWED_DOMAINS.has(siwe.domain)) {
      return res.status(400).json({ ok: false, error: 'Invalid domain' });
    }
    if (!withinAllowedUri(siwe.uri)) {
      return res.status(400).json({ ok: false, error: 'Invalid URI' });
    }
    if (siwe.version !== '1') {
      return res.status(400).json({ ok: false, error: 'Invalid SIWE version' });
    }
    if (!ALLOWED_CHAINS.has(Number(siwe.chainId))) {
      return res.status(400).json({ ok: false, error: 'Unsupported chain' });
    }
    if (!checkIssuedAt(siwe.issuedAt)) {
      return res.status(400).json({ ok: false, error: 'IssuedAt out of range' });
    }

    // 3) Nonce vom Cookie muss mit der Message übereinstimmen
    const nonceCookie = getCookie(req, COOKIE_NONCE);
    if (!nonceCookie || nonceCookie !== siwe.nonce) {
      return res.status(401).json({ ok: false, error: 'Nonce mismatch' });
    }

    // 4) Signatur prüfen → Adresse muss mit recoveredAddr übereinstimmen
    let recovered;
    try {
      recovered = verifyMessage(message, signature);
    } catch (e) {
      return res.status(400).json({ ok: false, error: 'Invalid signature', detail: String(e?.message || e) });
    }
    if (!recovered || recovered.toLowerCase() !== siwe.address.toLowerCase()) {
      return res.status(401).json({ ok: false, error: 'Signature does not match address' });
    }

    // 5) Replay-Schutz: Nonce nur einmal gültig
    // (einfach: wir löschen den Nonce-Cookie; komplexer: Nonce-DB blacklist)
    clearCookie(res, COOKIE_NONCE);

    // 6) Session setzen
    // Achtung: SameSite=None; Secure ist Pflicht für Cross-Site-Cookies
    setCookie(res, COOKIE_SESSION, siwe.address, {
      httpOnly: true,
      sameSite: 'None',
      secure: true,
      path: '/',
      // z.B. 1 Tag:
      maxAge: 60 * 60 * 24,
    });

    return res.status(200).json({ ok: true, address: siwe.address });
  } catch (e) {
    return res.status(400).json({ ok: false, error: e?.message || 'Verify failed' });
  }
});
