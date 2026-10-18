const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const performanceMonitor = require('../middleware/performanceMonitor');
const ollamaService = require('../services/ollamaService');
const { hasAdminLevel } = require('../middleware/postgresAdminAuth');

const JWT_SECRET = process.env.JWT_SECRET || 'dvaia-secret-key-2024';


// Fast liveness ping — used by ALB health checks (no external deps)
router.get('/ping', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// Performance monitoring dashboard endpoint
router.get('/performance', (req, res) => {
  const monitoringData = performanceMonitor.getMonitoringData();
  res.json(monitoringData);
});

// Build health payload without sending a response
async function buildHealthPayload() {
  try {
    const ollamaHealth = await ollamaService.healthCheck();
    const systemStats = performanceMonitor.getSystemStats();

    const isHealthy = ollamaHealth.status === 'healthy' &&
                     systemStats.memoryUsage.percentage < 90 &&
                     systemStats.activeConnections < 200;

    const status = isHealthy ? 'healthy' : 'degraded';
    return {
      statusCode: 200,
      body: {
        status,
        ollama: ollamaHealth,
        system: systemStats,
        timestamp: new Date().toISOString()
      },
      recommendations: generateRecommendations(ollamaHealth, systemStats)
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      },
      recommendations: []
    };
  }
}

const renderHealthPage = require('../views/monitoringHealthPage');

function renderAuthGate() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DVAIA — System Health</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2.5rem;max-width:420px;text-align:center}
h1{font-size:1.5rem;margin-bottom:.75rem;color:#f87171}
p{color:#94a3b8;margin-bottom:1.5rem;line-height:1.5}
a.btn{display:inline-block;background:#6366f1;color:#fff;text-decoration:none;padding:.65rem 1.5rem;border-radius:8px;font-weight:600;transition:background .2s}
a.btn:hover{background:#4f46e5}
.lock{font-size:2.5rem;margin-bottom:1rem}
#loading{text-align:center;padding:3rem;color:#94a3b8}
</style>
</head>
<body>
<div id="loading">Verifying access...</div>
<div id="denied" style="display:none">
<div class="card">
  <div class="lock">&#128274;</div>
  <h1>Admin Access Required</h1>
  <p>The System Health Dashboard is restricted to administrators. Please log in with an admin account to view this page.</p>
  <a class="btn" href="/workshop-login">Log In</a>
</div>
</div>
<script>
(function(){
  var token = localStorage.getItem('token');
  if (!token) { showDenied(); return; }
  fetch('/api/monitoring/health?format=html', {
    headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'text/html' }
  }).then(function(r) {
    if (r.status === 401) { showDenied(); return; }
    return r.text().then(function(html) { document.open(); document.write(html); document.close(); });
  }).catch(function() { showDenied(); });
  function showDenied() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('denied').style.display = 'flex';
  }
})();
</script>
</body>
</html>`;
}

// Verify admin token from Authorization header or cookie
async function verifyAdmin(req) {
  try {
    const authHeader = req.headers['authorization'];
    const token = (authHeader && authHeader.split(' ')[1]) || req.cookies?.token;
    if (!token) return null;
    const decoded = jwt.verify(token, JWT_SECRET);
    const { repository } = require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const record = await repository.findActiveSession(token, decoded.userId);
    const user = record?.user;
    return hasAdminLevel(user) ? user : null;
  } catch { return null; }
}

// Operational mutations and logs belong to the platform, outside teaching sinks.
async function requireMonitoringAdmin(req, res, next) {
  if (!/^Bearer\s+\S+$/i.test(req.headers.authorization || '') || !await verifyAdmin(req)) {
    return res.status(403).json({ error: 'Active administrator session required' });
  }
  next();
}

// System health check
router.get('/health', async (req, res) => {
  const payload = await buildHealthPayload();
  const wantsHtml = req.query.format === 'html' ||
    (req.query.format !== 'json' && req.accepts(['json', 'html']) === 'html');

  if (wantsHtml) {
    const admin = await verifyAdmin(req);
    if (!admin) {
      return res.status(401).type('html').send(renderAuthGate());
    }
    return res.status(payload.statusCode).type('html').send(renderHealthPage(payload));
  }
  return res.status(payload.statusCode).json(payload.body);
});

// Ollama specific monitoring
router.get('/ollama/status', async (req, res) => {
  try {
    const health = await ollamaService.healthCheck();
    const stats = ollamaService.getStats();
    
    res.json({
      health,
      stats,
      recommendations: generateRecommendations(health, stats)
    });
  } catch (error) {
    res.status(500).json({
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Configuration endpoint for adjusting performance
router.post('/ollama/config', requireMonitoringAdmin, (req, res) => {
  const { maxConcurrent } = req.body || {};
  
  if (Number.isInteger(maxConcurrent) && maxConcurrent >= 1 && maxConcurrent <= 8) {
    ollamaService.updateConcurrencyLimits(maxConcurrent);
    res.json({
      success: true,
      message: `Updated max concurrent requests to ${maxConcurrent}`,
      newStats: ollamaService.getStats()
    });
  } else {
    res.status(400).json({
      error: 'maxConcurrent must be an integer from 1 to 8.'
    });
  }
});

// Load testing endpoint (for testing with 100 users)
router.post('/stress-test', requireMonitoringAdmin, async (req, res) => {
  const { concurrent = 4, requests = 50 } = req.body || {};
  
  if (!Number.isInteger(concurrent) || concurrent < 1 || concurrent > 8 ||
      !Number.isInteger(requests) || requests < 1 || requests > 200) {
    return res.status(400).json({ error: 'concurrent must be 1–8 and requests must be 1–200, both integers.' });
  }
  console.log(`Starting stress test: ${concurrent} concurrent requests, ${requests} total requests`);
  
  const startTime = Date.now();
  const promises = [];
  const results = {
    successful: 0,
    failed: 0,
    totalTime: 0,
    errors: []
  };
  
  // Create batches of concurrent requests
  for (let i = 0; i < requests; i += concurrent) {
    const batch = [];
    
    for (let j = 0; j < concurrent && i + j < requests; j++) {
      const testPrompt = `Test request ${i + j}: Hello, this is a stress test message for Ollama performance testing.`;
      
      batch.push(
        ollamaService.generateResponse(testPrompt, { num_predict: 50 })
          .then(result => {
            results.successful++;
            return result;
          })
          .catch(error => {
            results.failed++;
            results.errors.push(error.message);
            return { error: error.message };
          })
      );
    }
    
    // Wait for batch to complete before starting next batch
    await Promise.all(batch);
    
    // Small delay between batches to prevent overwhelming
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  
  const totalTime = Date.now() - startTime;
  
  res.json({
    testCompleted: true,
    totalRequests: requests,
    concurrent: concurrent,
    results: {
      successful: results.successful,
      failed: results.failed,
      successRate: ((results.successful / requests) * 100).toFixed(2) + '%',
      totalTime: totalTime + 'ms',
      avgTimePerRequest: (totalTime / requests).toFixed(2) + 'ms',
      requestsPerSecond: ((requests / (totalTime / 1000)).toFixed(2))
    },
    errors: results.errors.slice(0, 10), // Show first 10 errors
    timestamp: new Date().toISOString()
  });
});

// Real-time performance metrics (for monitoring dashboard)
router.get('/metrics/realtime', (req, res) => {
  const monitoringData = performanceMonitor.getMonitoringData();
  
  // Add additional real-time metrics
  const realTimeMetrics = {
    ...monitoringData,
    recommendations: generateRecommendations(
      monitoringData.ollama, 
      monitoringData.system
    ),
    alerts: generateAlerts(monitoringData)
  };
  
  res.json(realTimeMetrics);
});

function generateRecommendations(ollamaHealth, systemStats) {
  const recommendations = [];
  
  if (systemStats && systemStats.memoryUsage.percentage > 80) {
    recommendations.push({
      type: 'warning',
      message: 'High memory usage detected. Consider reducing concurrent requests.',
      action: 'Reduce maxConcurrentRequests in Ollama service'
    });
  }
  
  if (ollamaHealth && ollamaHealth.queue_length > 50) {
    recommendations.push({
      type: 'warning',
      message: 'High request queue. Users may experience delays.',
      action: 'Consider increasing concurrent request limits or optimizing prompts'
    });
  }
  
  if (ollamaHealth && ollamaHealth.status === 'unhealthy') {
    recommendations.push({
      type: 'error',
      message: 'Ollama service is not responding. Check if Ollama is running.',
      action: 'Start Ollama service: ollama serve'
    });
  }
  
  if (!ollamaHealth || !ollamaHealth.has_llama3) {
    recommendations.push({
      type: 'warning',
      message: 'Llama3 model not found. Some features may not work correctly.',
      action: 'Pull Llama3 model: ollama pull llama3'
    });
  }
  
  return recommendations;
}

function generateAlerts(monitoringData) {
  const alerts = [];
  
  if (monitoringData.system.memoryUsage.percentage > 90) {
    alerts.push({
      severity: 'critical',
      message: 'Memory usage critical (>90%)',
      timestamp: new Date().toISOString()
    });
  }
  
  if (monitoringData.system.activeConnections > 150) {
    alerts.push({
      severity: 'warning',
      message: `High number of active connections: ${monitoringData.system.activeConnections}`,
      timestamp: new Date().toISOString()
    });
  }
  
  if (monitoringData.ollama.queue_length > 100) {
    alerts.push({
      severity: 'warning',
      message: `High Ollama queue length: ${monitoringData.ollama.queue_length}`,
      timestamp: new Date().toISOString()
    });
  }
  
  return alerts;
}

// GET /api/monitoring/logs/recent?lines=100
// Returns the last N lines from server/logs/app.log as parsed JSON objects.
router.get('/logs/recent', requireMonitoringAdmin, (req, res) => {
  try {
    const logFile = path.join(__dirname, '../logs/app.log');
    const n = Math.min(parseInt(req.query.lines || '100', 10), 500);
    if (!fs.existsSync(logFile)) return res.json({ lines: [], count: 0 });
    const lines = fs.readFileSync(logFile, 'utf8')
      .trim().split('\n').filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch (_) { return { raw: l }; } })
      .slice(-n);
    res.json({ lines, count: lines.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/monitoring/llm/recent?lines=50
// Returns the last N raw lines from server/logs/llm_requests.log.
router.get('/llm/recent', requireMonitoringAdmin, (req, res) => {
  try {
    const logFile = path.join(__dirname, '../logs/llm_requests.log');
    const n = Math.min(parseInt(req.query.lines || '50', 10), 200);
    if (!fs.existsSync(logFile)) return res.json({ lines: [], count: 0 });
    const lines = fs.readFileSync(logFile, 'utf8')
      .trim().split('\n').filter(Boolean)
      .slice(-n);
    res.json({ lines, count: lines.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
