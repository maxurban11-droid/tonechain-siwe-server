// Liest Nonce bevorzugt aus Header, sonst aus Cookie.
export function readNonceFromReq(req) {
  // Pages-Router: Header-Objekt ist klein geschrieben ODER gemischt – beides abfangen
  const h = (req.headers["x-tc-nonce"] || req.headers["X-TC-Nonce"]);
  if (h) return String(h);

  const cookie = req.headers.cookie || "";
  const m = /(?:^|;\s*)tc_nonce=([^;]+)/i.exec(cookie);
  return m ? decodeURIComponent(m[1]) : null;
}
