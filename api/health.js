// api/health.js
const { withCors, handleOptions } = require("../helpers/cors.js");

module.exports = withCors(async function handler(req, res) {
  if (req.method === "OPTIONS") return handleOptions(req, res);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.status(200).json({ ok: true, health: "up" });
});
