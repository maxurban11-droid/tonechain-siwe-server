# ToneChain SIWE Server (Vercel Functions)

**P0-ready, triple-checked**: CORS-hardened, SameSite=None cookies, single-use nonce, unified `/api/auth/*`.

## Endpoints
- `GET /api/auth/nonce` → sets httpOnly `tc_nonce` (SameSite=None; Secure; Path=/; Max-Age 10min)
- `POST /api/auth/verify` → verifies `personal_sign`, sets httpOnly `tc_session`, clears nonce
- `POST /api/auth/logout` → clears `tc_session` and `tc_nonce`
- `GET /api/health` → health with CORS

## CORS
Provide env var `ORIGIN_WHITELIST` (CSV):
```
https://*.framer.app,https://*.framer.website,https://framer.com,https://tonechain.app,https://beta.tonechain.io,http://localhost:3000
```

## Deploy
1) Push to GitHub.
2) Import in Vercel → set `ORIGIN_WHITELIST`.
3) That's it. No extra setup.
