const express = require('express');
const router = express.Router();
const store = require('../database/legacyChallengeStore');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const { checkVulnerabilityAccess } = require('../middleware/workshopMode');
const { authenticateToken } = require('../middleware/adminAuth');
const logger = require('../utils/logger');
const { getClassicXxeLab, ClassicXxeError } = require('../services/classicXxeLab');
const { getSessionDisclosureLab } = require('../services/sessionDisclosureLab');

// Configure multer for file uploads - Intentionally insecure
const postgresUploads = typeof process !== 'undefined' && process.env?.PLATFORM_DATABASE_ENGINE === 'postgres';
const { isPlatformDataLifecycleRequested } = require('../services/platformDataLifecycleActivation');
const platformLifecycle = isPlatformDataLifecycleRequested(typeof process === 'undefined' ? {} : process.env);
const {legacyPlatformMutationMiddleware}=require('../services/legacyPlatformMutationLifecycle');
const uploadRoot = path.join(__dirname, '../uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const destination = platformLifecycle ? req.legacyUploadLease?.directory : uploadRoot;
    if (!destination) return cb(new Error('Durable upload admission required'));
    // The PostgreSQL lifecycle creates this unique directory before durable
    // admission. Recreating it here could resurrect bytes after a concurrent
    // retirement when the admission connection is lost.
    if (platformLifecycle && !fs.existsSync(destination)) return cb(new Error('Durable upload authority expired'));
    if (!platformLifecycle && !fs.existsSync(destination)) fs.mkdirSync(destination, { recursive: true });
    cb(null, destination);
  },
  filename: (req, file, cb) => {
    // Vulnerable: preserving original filename and unrestricted file type.
    const finish = value => cb(null, value || file.originalname);
    if (!platformLifecycle) return finish();
    if (!req.legacyUploadLease) return cb(new Error('Durable upload admission required'));
    req.legacyUploadLease.bindFilename(file.originalname).then(finish, cb);
  }
});

const upload = multer({ 
  storage: storage,
  // No file type restrictions - vulnerable
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// SQL Injection vulnerability - Intentionally vulnerable
router.get('/sqli/search', checkVulnerabilityAccess('sql_injection'), (req, res) => {
  const { query, category } = req.query;
  
  // Vulnerable SQL query
  let sql = `SELECT * FROM products WHERE 1=1`;
  
  if (query) {
    sql += ` AND name LIKE '%${query}%'`;
  }
  
  if (category) {
    sql += ` AND category = '${category}'`;
  }
  
  store.searchProducts(sql, (err, products) => {
    if (err) {
      logger.error('route_error', { route: 'GET /api/vulnerabilities/products', message: err.message });
      return res.status(500).json({
        error: 'Database error',
        query: sql, // Vulnerable: exposing query
        details: err.message
      });
    }
    
    res.json({
      products,
      query: sql, // Educational: show the vulnerable query
      vulnerability: 'SQL Injection'
    });
  });
});

// Blind SQL Injection
router.get('/sqli/blind', checkVulnerabilityAccess('sql_injection'), (req, res) => {
  const { userId } = req.query;
  
  const sql = `SELECT username FROM users WHERE id = ${userId}`;
  
  store.readDemoUser(sql, (err, user) => {
    if (err) {
      logger.error('route_error', { route: 'GET /api/vulnerabilities/sqli/blind', message: err.message });
      return res.status(500).json({ error: 'Error occurred' });
    }
    
    // Only return success/failure - blind injection
    res.json({ 
      exists: !!user,
      message: user ? 'User exists' : 'User not found'
    });
  });
});

// XSS - Reflected
router.get('/xss/reflected', checkVulnerabilityAccess('xss'), (req, res) => {
  const { search } = req.query;
  
  // Vulnerable: directly embedding user input
  const html = `
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results for: ${search}</h1>
        <p>No results found for "${search}"</p>
        <a href="/vulnerabilities/xss">Open the graded XSS workshop</a>
      </body>
    </html>
  `;
  
  res.send(html);
});

// XSS - Stored (via comments)
router.post('/xss/comment', legacyPlatformMutationMiddleware, checkVulnerabilityAccess('xss'), (req, res) => {
  const { content } = req.body;
  const userId = req.session.userId || 1;
  
  // Vulnerable: storing unsanitized content
  const sql = `INSERT INTO comments (user_id, content) VALUES (?, ?)`;
  
  store.addComment(req.legacyPlatformMutation?[userId,content,req.legacyPlatformMutation.ownerId]:[userId,content], function(err) {
    if (err) {
      logger.error('route_error', { route: 'POST /api/vulnerabilities/xss/comment', message: err.message });
      return res.status(500).json({ error: 'Failed to save comment' });
    }
    
    res.json({ 
      success: true, 
      commentId: this.lastID,
      vulnerability: 'Unsanitized stored-comment sink (browser execution not demonstrated)'
    });
  });
});

// Get comments for XSS demo
router.get('/xss/comments', checkVulnerabilityAccess('xss'), (req, res) => {
  const sql = `
    SELECT c.id, c.content, c.created_at, u.username 
    FROM comments c 
    JOIN users u ON c.user_id = u.id 
    ORDER BY c.created_at DESC
  `;
  
  store.listComments((err, comments) => {
    if (err) {
      logger.error('route_error', { route: 'GET /api/vulnerabilities/xss/comments', message: err.message });
      return res.status(500).json({ error: 'Failed to fetch comments' });
    }
    
    res.json({ comments });
  });
});

// CSRF - Money transfer without CSRF token
router.post('/csrf/transfer', checkVulnerabilityAccess('csrf'), (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  res.status(410).json({
    success: false,
    message: 'This response-only duplicate has been retired. Use the graded POST CSRF exercise for an observed victim-state effect.',
    effect: 'none',
    from: req.session.username,
    vulnerability: 'Retired duplicate — no transfer or objective credit',
    replacement: {
      page: '/vulnerabilities/csrf-via-ai?scenario=post&objective=csrf_p1',
      objectiveId: 'csrf_p1'
    }
  });
});

// File Upload - No restrictions
const requireUploadIdentity = platformLifecycle ? authenticateToken : (_req, _res, next) => next();
const receiveUpload = (req, res) => new Promise((resolve, reject) => upload.single('file')(req, res, error => error ? reject(error) : resolve()));
router.post('/upload', checkVulnerabilityAccess('file_upload'), requireUploadIdentity, async (req, res) => {
  const write = async lease => {
    if (lease) req.legacyUploadLease = lease;
    if (lease) {
      const aborted = new Promise((_, reject) => lease.signal.addEventListener('abort', () => {
        const reason = lease.signal.reason || new Error('Upload authority connection was lost');
        req.destroy?.(reason); reject(reason);
      }, { once: true }));
      await Promise.race([receiveUpload(req, res), aborted]);
      lease.signal.throwIfAborted();
    } else await receiveUpload(req, res);
    if (!req.file) throw Object.assign(new Error('No file uploaded'), { statusCode: 400 });
    const owner = platformLifecycle ? req.user.id : (req.session.userId || 1);
    const inserted = platformLifecycle
      ? await store.addManagedFile([req.file.filename,req.file.originalname,req.file.path,
        req.file.size,req.file.mimetype,owner,owner,lease.intentId])
      : await store.addFile([req.file.filename, req.file.originalname, req.file.path,
        req.file.size, req.file.mimetype, owner]);
    const publicPath = path.relative(uploadRoot, req.file.path).split(path.sep).join('/');
    return { fileId: inserted.lastID, file: { filename: req.file.filename,
      originalName: req.file.originalname, size: req.file.size, mimetype: req.file.mimetype,
      path: `/uploads/${publicPath}` } };
  };
  try {
    const result = platformLifecycle
      ? await require('../services/legacyUploadLifecycle').getLegacyUploadLifecycle().runUpload({
        ownerId: req.user.id, sessionId: req.identitySession?.id,
      }, write) : await write();
    res.json({ success: true, ...result, vulnerability: 'Unrestricted File Upload' });
  } catch (error) {
    logger.error('route_error', { route: 'POST /api/vulnerabilities/upload', message: error.message });
    res.status(error.statusCode || 500).json({ error: error.statusCode === 400 ? error.message : 'Failed to save file info' });
  } finally { delete req.legacyUploadLease; }
});

// Directory Traversal
router.get('/files/:filename', (req, res) => {
  const { filename } = req.params;
  
  // Vulnerable: no path sanitization
  const filePath = path.join(__dirname, '../uploads/', filename);
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).json({ 
        error: 'File not found',
        path: filePath // Vulnerable: exposing file path
      });
    }
    
    res.send(data);
  });
});

// Command Injection
router.post('/command', checkVulnerabilityAccess('command_injection'), (req, res) => {
  const { command } = req.body;
  const { exec } = require('child_process');
  
  // Extremely vulnerable: direct command execution
  exec(`echo "Executing: ${command}"`, (error, stdout, stderr) => {
    if (error) {
      logger.error('route_error', { route: 'POST /api/vulnerabilities/command', message: error.message });
      return res.status(500).json({
        error: error.message,
        vulnerability: 'Command Injection'
      });
    }
    
    res.json({
      output: stdout,
      error: stderr,
      vulnerability: 'Command Injection - Never do this!'
    });
  });
});

// XXE - intentionally resolves one virtual training URI to an isolated file.
router.post('/xxe', async (req, res) => {
  try {
    const result = await getClassicXxeLab()(req.body?.xmlData);
    res.json({
      parsed: result.parsed,
      vulnerability: result.observation
        ? 'XXE - isolated synthetic file disclosure through a custom SAX entity resolver'
        : 'XML parsing demonstration (no external entity was resolved)',
      ...(result.observation ? { observation: result.observation } : {})
    });
  } catch (error) {
    logger.error('route_error', { route: 'POST /api/vulnerabilities/xxe', message: error.message });
    const unavailable = error instanceof ClassicXxeError && error.unavailable;
    res.status(unavailable ? 503 : 400).json({
      error: unavailable ? 'XXE training lab unavailable' : 'XML parsing error',
      details: error.message
    });
  }
});

// IDOR - Insecure Direct Object Reference
router.get('/idor/user/:id', checkVulnerabilityAccess('idor'), (req, res) => {
  const { id } = req.params;
  
  // No authorization check
  const sql = `SELECT id, username, email, role FROM users WHERE id = ${id}`;
  
  store.readDemoUser(sql, (err, user) => {
    if (err) {
      logger.error('route_error', { route: 'GET /api/vulnerabilities/idor/user/:id', message: err.message });
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      res.json({
        user,
        vulnerability: 'IDOR - Insecure Direct Object Reference'
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});

// Server-Side Request Forgery (SSRF)
router.post('/ssrf', (req, res) => {
  const { url } = req.body;
  const axios = require('axios');
  
  // Vulnerable: no URL validation
  axios.get(url)
    .then(response => {
      res.json({
        data: response.data,
        status: response.status,
        headers: response.headers,
        vulnerability: 'SSRF - Server-Side Request Forgery'
      });
    })
    .catch(error => {
      logger.error('route_error', { route: 'POST /api/vulnerabilities/ssrf', message: error.message });
      res.status(500).json({
        error: error.message,
        vulnerability: 'SSRF - Server-Side Request Forgery'
      });
    });
});

const LAB_SESSION_COOKIE = 'dvaia_lab_session';
const LAB_COOKIE_OPTIONS = Object.freeze({
  httpOnly: false, // Deliberately readable challenge-only credential.
  sameSite: 'lax',
  secure: false,
  path: '/api/vulnerabilities/session'
});
function sessionLabUnavailable(res) {
  return res.status(503).json({
    error: 'Isolated session disclosure lab unavailable',
    vulnerability: 'Session Information Disclosure'
  });
}
function exposedLabState(record) {
  return {
    session: {
      sessionId: record.sessionId,
      labUserId: record.labUserId,
      role: record.role,
      csrfToken: record.csrfToken,
      generation: record.generation,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    },
    cookies: { [LAB_SESSION_COOKIE]: record.cookie },
    vulnerability: 'Session Information Disclosure (isolated lab credential)',
    scope: 'isolated synthetic lab session'
  };
}

// Weak Session Management: discloses only a persistent credential from a dedicated lab store.
router.get('/session/info', authenticateToken, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const lab = getSessionDisclosureLab();
    const presented = req.cookies?.[LAB_SESSION_COOKIE];
    const record = presented
      ? await lab.resolve(req.user.id, presented)
      : await lab.getOrCreate(req.user.id);
    if (!record) {
      res.clearCookie(LAB_SESSION_COOKIE, LAB_COOKIE_OPTIONS);
      return res.status(401).json({
        error: 'Lab session credential is invalid or expired',
        vulnerability: 'Session Information Disclosure'
      });
    }
    res.cookie(LAB_SESSION_COOKIE, record.cookie, LAB_COOKIE_OPTIONS);
    return res.json(exposedLabState(record));
  } catch (error) {
    logger.error('route_error', { route: 'GET /api/vulnerabilities/session/info',
      message: error?.code || 'SESSION_DISCLOSURE_UNAVAILABLE' });
    return sessionLabUnavailable(res);
  }
});

router.post('/session/reset', authenticateToken, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const record = await getSessionDisclosureLab().reset(req.user.id);
    res.clearCookie(LAB_SESSION_COOKIE, LAB_COOKIE_OPTIONS);
    return res.json({ success: true, generation: record.generation,
      message: 'Isolated lab session rotated' });
  } catch (error) {
    logger.error('route_error', { route: 'POST /api/vulnerabilities/session/reset',
      message: error?.code || 'SESSION_DISCLOSURE_UNAVAILABLE' });
    return sessionLabUnavailable(res);
  }
});

// Authentication Bypass
router.get('/admin/bypass', (req, res) => {
  const { admin } = req.query;
  
  // Vulnerable: simple parameter-based bypass
  if (admin === 'true') {
    res.json({
      message: 'Demo accepted admin=true; no privileged operation was granted',
      privilegedEffect: false,
      adminAccess: true,
      vulnerability: 'Parameter-trust demonstration (simulated admin flag)'
    });
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
});

module.exports = router;
