'use strict';
const PIXEL_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
function respondForged(req, res, info) {
  res.status(info.blocked ? 403 : info.ok ? 200 : 400);
  if (req.method === 'GET') {
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(PIXEL_GIF);
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(`<!DOCTYPE html><html><body style="font:14px system-ui;padding:2rem;background:#0b1220;color:#e2e8f0">
    <h3>CSRF payload delivered${info.blocked ? ' — BLOCKED by defense' : ''}</h3>
    <p>${info.ok ? 'The forged request reached the VaultLink agent.' : (info.reason || '')}</p>
    <p>Return to the <b>CSRF Attack Console</b> tab — the request and the agent's reply now appear in the chat.</p>
  </body></html>`);
}

module.exports = { respondForged };
