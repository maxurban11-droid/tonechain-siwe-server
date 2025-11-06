// helpers/nonce.js
export function readNonceFromReq(req) {
  const h = req.headers['x-tc-nonce'] || req.headers['X-TC-Nonce'];
  const cookie = req.headers.cookie || "";
  const m = /(?:^|;\s*)tc_nonce=([^;]+)/i.exec(cookie);
  const c = m ? decodeURIComponent(m[1]) : null;
  return (h && String(h)) || c || null;
}
