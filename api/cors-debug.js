const { withCors, handleOptions } = require("../helpers/cors.js");

module.exports = withCors(async (req, res) => {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  res.status(200).json({
    ok: true,
    requestOrigin: req.headers.origin || null,
    envCORS: process.env.CORS_ORIGIN || null,
  });
});
