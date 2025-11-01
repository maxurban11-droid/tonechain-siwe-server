// api/auth/logout.ts  (Node/Edge neutral, Vercel Functions)
// Falls du TS nicht nutzt: gleiche Logik in .js ohne Typen.
import type { VercelRequest, VercelResponse } from '@vercel/node';

const ALLOW_ORIGINS = [
  'https://concave-device-193297.framer.app',
  'https://*.framer.app',                 // Wildcard wird unten manuell gematcht
  'https://tonechain.app',
];

function matchOrigin(origin: string | undefined) {
  if (!origin) return null;
  for (const pat of ALLOW_ORIGINS) {
    if (pat.includes('*')) {
      // sehr einfache Wildcard (nur *.domain.tld)
      const re = new RegExp('^https://[^/]*\\.' + pat.replace('https://*.','').replace('.','\\.') + '$');
      if (re.test(origin)) return origin;
    } else if (origin === pat) {
      return origin;
    }
  }
  return null;
}

function setCors(res: VercelResponse, origin?: string | null) {
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin'); // wichtig für Caches
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

function clearCookie(res: VercelResponse, name: string) {
  // Cookie für Cross-Site-Use immer mit SameSite=None; Secure
  res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const origin = matchOrigin(req.headers.origin as string | undefined);
  setCors(res, origin);

  // Preflight sauber beantworten
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  // Session-Cookies löschen (Namen ggf. anpassen)
  clearCookie(res, 'tc_session');
  clearCookie(res, 'tc_nonce');

  return res.status(200).json({ ok: true, loggedOut: true });
}
