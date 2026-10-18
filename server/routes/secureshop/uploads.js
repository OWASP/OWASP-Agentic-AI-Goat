/**
 * SecureShop v2 — uploads REST router.
 *
 * Mounted alongside the customer/merchant/admin routers. Provides the HTTP
 * surface for the uploads task-agent tools plus a static-serve endpoint
 * intentionally weak in the "inline disposition + trusted MIME + no sniff
 * protection" style.
 *
 * @intentional-vulnerability file-upload-svg-xss
 * @teaches OWASP-Web:A03
 * @location server/routes/secureshop/uploads.js
 * intentional — /uploads/secureshop/... serves files with Content-Disposition:
 * inline and X-Content-Type-Options is NOT set. SVGs with <script> execute.
 */

const express = require('express');
const multer = require('multer');
const path = require('node:path');
const fs = require('node:fs');

const { getSecureShopUploadRoot } = require('../../services/secureshop/assetPaths.js');

const { createUploadTools } = require('../../../agent-host/agents/uploads/tools/index.js');

// Multer: in-memory storage — we route through the tool layer, which does the
// actual filesystem write. That way the RAG-poisoning + traversal paths
// converge for both MCP-tool AND HTTP callers.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
});

module.exports = function buildUploadsRouter({ uploadRoot = getSecureShopUploadRoot() } = {}) {
  const uploads = createUploadTools({ uploadRoot });
  uploadRoot = uploads.UPLOAD_ROOT;
  const router = express.Router();

  // ---- Upload endpoint -----------------------------------------------------

  router.post('/uploads', upload.single('file'), async (req, res) => {
    try {
      const kind = req.body?.kind || 'avatar';
      const scopeId = Number(req.body?.scope_id || req.body?.user_id || req.body?.product_id || req.body?.order_id || 0);
      const filename = (req.file && req.file.originalname) || req.body?.filename || 'file';
      const mime = (req.file && req.file.mimetype) || req.body?.mime || 'application/octet-stream';
      let file_bytes_base64;
      if (req.file && req.file.buffer) {
        file_bytes_base64 = req.file.buffer.toString('base64');
      } else if (req.body?.file_bytes_base64) {
        file_bytes_base64 = req.body.file_bytes_base64;
      } else {
        return res.status(400).json({ ok: false, error: 'no file' });
      }

      let result;
      switch (kind) {
        case 'avatar':
          result = await uploads.upload_avatar({ user_id: scopeId, file_bytes_base64, filename, mime });
          break;
        case 'product_image':
          result = await uploads.upload_product_image({ product_id: scopeId, file_bytes_base64, filename, mime });
          break;
        case 'return_evidence':
          result = await uploads.upload_return_evidence({ order_id: scopeId, file_bytes_base64, filename, mime });
          break;
        case 'product_manual':
          result = await uploads.upload_product_manual({ product_id: scopeId, file_bytes_base64, filename, mime });
          break;
        default:
          return res.status(400).json({ ok: false, error: `unknown kind ${kind}` });
      }
      res.json(result);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.get('/uploads/download', async (req, res) => {
    const id = req.query.id;
    const kind = req.query.kind || null;
    if (!id) return res.status(400).json({ ok: false, error: 'id required' });
    try {
    const r = await uploads.download({ id, kind });
    if (!r.ok) return res.status(404).json(r);
    res.set('Content-Type', r.mime);
    // intentional — inline disposition + no nosniff = svg/html rendered
    res.set('Content-Disposition', `inline; filename="${path.basename(r.abs)}"`);
    res.send(Buffer.from(r.body_base64, 'base64'));
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ---- Static serve --------------------------------------------------------
  // Serve files under /uploads/secureshop/**. This mirrors the download tool
  // and is what real browser rendering will hit.
  router.get(/^\/uploads\/static\/(.*)$/, (req, res) => {
    // Preserve the wildcard string capture in req.params[0] with Express 5.
    const rel = String(req.params[0] || '');
    // intentional — same single-pass strip as the tool. `....//` bypass valid here too.
    const cleaned = rel.replace(/\.\.\//g, '');
    const abs = path.resolve(uploadRoot, cleaned);
    try {
      const st = fs.statSync(abs);
      if (st.isDirectory()) return res.status(404).json({ ok: false, error: 'is directory' });
      const ext = path.extname(abs).toLowerCase();
      const mime = ({
        '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
        '.svg': 'image/svg+xml', '.pdf': 'application/pdf', '.txt': 'text/plain',
        '.md': 'text/markdown', '.html': 'text/html', '.js': 'application/javascript',
        '.php': 'application/x-httpd-php', '.json': 'application/json',
      })[ext] || 'application/octet-stream';
      res.set('Content-Type', mime);
      // intentional — inline + no nosniff
      res.set('Content-Disposition', `inline; filename="${path.basename(abs)}"`);
      // (NOT setting X-Content-Type-Options: nosniff — that is the point.)
      fs.createReadStream(abs).pipe(res);
    } catch (e) {
      res.status(404).json({ ok: false, error: e.message });
    }
  });

  return router;
};
