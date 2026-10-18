'use strict';

const fs = require('fs');
const path = require('path');

const HTTP_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/i;

function replaceEnvLine(content, key, value) {
  const pattern = new RegExp(`^#?\\s*${key}=.*`, 'm');
  return pattern.test(content) ? content.replace(pattern, `${key}=${value}`)
    : `${content}${content.endsWith('\n') ? '' : '\n'}${key}=${value}\n`;
}

function readJsonLogTail(fileSystem, filePath, maxLines) {
  const directory = path.dirname(filePath), base = path.basename(filePath, path.extname(filePath)), extension = path.extname(filePath);
  const files = [filePath, ...[1, 2, 3].map(index => path.join(directory, `${base}${index}${extension}`))]
    .filter(file => fileSystem.existsSync(file));
  return files.flatMap(file => fileSystem.readFileSync(file, 'utf8').split('\n').filter(Boolean))
    .map(line => { try { return JSON.parse(line); } catch { return { raw: line }; } }).slice(-maxLines);
}

function inferProvider(model) {
  const value = String(model || '').toLowerCase();
  if (value.includes('claude') || value.includes('anthropic')) return 'claude';
  if (value.includes('gpt') || value.includes('openai')) return 'openai';
  if (value.includes('bedrock') || value.includes('amazon')) return 'bedrock';
  return 'ollama';
}

function parseLlmRequest(line) {
  const match = line.match(/^\[([^\]]+)\]\s+user=(\S+)(?:\s+username=(\S+)\s+ip=(\S+))?\s+model=(\S+)\s+mode=(\S+)\s+message="([\s\S]*?)"\s+tools_called=(\S+)\s+response="([\s\S]*?)"\s*$/);
  if (!match) return null;
  const [, timestamp, userId, username, ip, model, mode, prompt, tools, response] = match;
  return { timestamp, provider: inferProvider(model), model, latencyMs: null, success: true,
    promptLength: prompt.length, responseLength: response.length, messageSummary: prompt, responseSnippet: response,
    error: null, userId: userId === 'system' ? null : userId, username: !username || username === 'system' ? null : username,
    ip: !ip || ip === '-' ? null : ip, mode: mode === 'n/a' ? null : mode, toolsCalled: tools === 'none' ? null : tools };
}

function createAdminOperationalHandlers(options = {}) {
  const fileSystem = options.fs || fs;
  const environment = options.environment || process.env;
  const runtime = options.runtime || process;
  const envPath = options.envPath || path.join(__dirname, '../../.env');
  const logsDir = options.logsDir || environment.LOGS_DIR || path.join(__dirname, '../logs');
  const ai = () => options.aiService || require('../services/multiProviderAIService');
  const fetchImpl = options.fetch || global.fetch;
  const delay = options.delay || (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)));
  const logLLMCall = options.logLLMCall || ((entry) => require('../middleware/llmLogger').logLLMCall(entry));

  function readMergedLlmLogs(maxLines) {
    const structured = ['app.log', 'app1.log', 'app2.log', 'app3.log'].flatMap(name => {
      const file = path.join(logsDir, name);
      if (!fileSystem.existsSync(file)) return [];
      return fileSystem.readFileSync(file, 'utf8').split('\n').flatMap(line => {
        try {
          const item = JSON.parse(line);
          if (!['llm_call', 'llm_call_error'].includes(item.message)) return [];
          return [{ ...item, timestamp: item.timestamp || item.ts || null, provider: item.provider || inferProvider(item.model),
            success: item.message === 'llm_call_error' ? false : item.success !== false }];
        } catch { return []; }
      });
    });
    const timestamps = new Set(structured.map(item => item.timestamp));
    const flatFile = path.join(logsDir, 'llm_requests.log');
    const flat = fileSystem.existsSync(flatFile) ? fileSystem.readFileSync(flatFile, 'utf8').split('\n').map(parseLlmRequest)
      .filter(item => item && !timestamps.has(item.timestamp)) : [];
    return [...structured, ...flat].sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp))).slice(-maxLines);
  }

  function providers() {
    return {
      ollama: { name: 'Ollama (Local LLM)', configured: true, baseUrl: environment.OLLAMA_BASE_URL || 'http://localhost:11434', model: environment.OLLAMA_MODEL || 'llama3.1:8b', cost: 'FREE' },
      lmstudio: { name: 'LM Studio (Local LLM)', configured: true, baseUrl: environment.LMSTUDIO_BASE_URL || 'http://localhost:1234/v1', model: environment.LMSTUDIO_MODEL || 'local-model', cost: 'FREE' },
      chatgpt: { name: 'ChatGPT/OpenAI', configured: Boolean(environment.OPENAI_API_KEY), model: environment.OPENAI_MODEL || 'gpt-4', cost: 'Paid' },
      claude: { name: 'Claude API (Anthropic)', configured: Boolean(environment.CLAUDE_API_KEY), model: environment.CLAUDE_MODEL || 'claude-3-5-sonnet-20241022', cost: 'Paid' },
      bedrock: { name: 'Amazon Bedrock', configured: Boolean(environment.BEDROCK_MODEL_ID || environment.AWS_REGION || environment.BEDROCK_REGION), model: environment.BEDROCK_MODEL_ID || 'us.meta.llama3-1-8b-instruct-v1:0', region: environment.AWS_REGION || environment.BEDROCK_REGION || 'us-east-1', cost: 'Paid' },
    };
  }

  return {
    async providerStatus(_req, res) {
      try {
        const descriptors = providers(), keys = Object.keys(descriptors);
        const checks = await Promise.allSettled(keys.map(key => ai().verifyProviderConnection(key)));
        const result = Object.fromEntries(keys.map((key, index) => {
          const verification = checks[index].status === 'fulfilled' ? checks[index].value : {};
          const configured = verification.configured === undefined ? descriptors[key].configured : Boolean(verification.configured);
          const healthy = Boolean(verification.healthy);
          return [key, { ...descriptors[key], ...verification, configured, available: Boolean(verification.available), healthy,
            status: healthy ? 'healthy' : configured ? 'unhealthy' : 'not_configured' }];
        }));
        const available = Object.values(result).some(item => item.available);
        res.json({ success: true, config: { currentProvider: environment.AI_PROVIDER || 'ollama', providers: result,
          fallbackEnabled: true, fallbackActive: !available }, message: available ? 'AI services operational' : 'Running in fallback mode - all AI endpoints use intelligent responses' });
      } catch (error) { res.status(500).json({ success: false, error: 'Failed to fetch AI provider configuration', details: error.message }); }
    },

    async switchProvider(req, res) {
      const provider = req.body.provider;
      if (!['ollama', 'lmstudio', 'claude', 'chatgpt', 'openai', 'bedrock'].includes(provider)) return res.status(400).json({ success: false, error: 'Invalid provider. Must be: ollama, lmstudio, claude, chatgpt, openai, or bedrock' });
      try {
        const verification = await ai().verifyProviderConnection(provider);
        if (!verification.configured || !verification.healthy) return res.status(400).json({ success: false,
          error: `Cannot switch to ${provider}: Provider is ${verification.configured ? 'not healthy' : 'not configured'}`, verification,
          message: verification.message });
        const inFlight = ai().inFlightRequests?.size || 0;
        if (inFlight > 0) await delay(Math.min(inFlight * 100, 3000));
        let content = fileSystem.readFileSync(envPath, 'utf8');
        content = replaceEnvLine(content, 'AI_PROVIDER', provider);
        fileSystem.writeFileSync(envPath, content);
        const oldProvider = environment.AI_PROVIDER;
        environment.AI_PROVIDER = provider;
        ai().reloadConfig();
        res.json({ success: true, message: `AI provider switched to ${provider}. All users will use this provider immediately.`,
          newProvider: provider, oldProvider, verification, inFlightRequestsHandled: inFlight, hotReloaded: true, restartRequired: false });
      } catch (error) { res.status(500).json({ success: false, error: 'Failed to switch AI provider', details: error.message }); }
    },

    async configureProvider(req, res) {
      const { provider, apiKey, model, baseUrl, region, accessKeyId, secretAccessKey, sessionToken } = req.body;
      const keyed = ['claude', 'openai', 'chatgpt'];
      if (![...keyed, 'lmstudio', 'bedrock'].includes(provider)) return res.status(400).json({ success: false, error: 'Invalid provider. Must be: claude, openai, chatgpt, lmstudio, or bedrock' });
      if (keyed.includes(provider) && !apiKey) return res.status(400).json({ success: false, error: 'API key is required' });
      try {
        let content = fileSystem.readFileSync(envPath, 'utf8');
        const update = (key, value) => { if (value !== undefined && value !== '') { content = replaceEnvLine(content, key, value); environment[key] = value; } };
        if (provider === 'claude') { update('CLAUDE_API_KEY', apiKey); update('CLAUDE_MODEL', model); }
        if (provider === 'openai' || provider === 'chatgpt') { update('OPENAI_API_KEY', apiKey); update('OPENAI_MODEL', model); }
        if (provider === 'lmstudio') { update('LMSTUDIO_BASE_URL', baseUrl); update('LMSTUDIO_MODEL', model); }
        if (provider === 'bedrock') { update('BEDROCK_MODEL_ID', model); update('AWS_REGION', region); update('BEDROCK_REGION', region);
          update('AWS_ACCESS_KEY_ID', accessKeyId); update('AWS_SECRET_ACCESS_KEY', secretAccessKey); update('AWS_SESSION_TOKEN', sessionToken); }
        fileSystem.writeFileSync(envPath, content);
        ai().reloadConfig();
        const verification = await ai().verifyProviderConnection(provider);
        res.json({ success: true, message: `${provider} configured successfully. ${verification.healthy ? 'Connection verified and active!' : 'Configuration saved but connection test failed.'}`,
          provider, modelConfigured: Boolean(model), verification, hotReloaded: true, restartRequired: false });
      } catch (error) { res.status(500).json({ success: false, error: 'Failed to configure AI provider', details: error.message }); }
    },

    async testProvider(req, res) {
      if (!req.body.provider) return res.status(400).json({ success: false, error: 'Provider is required' });
      const started = Date.now();
      try {
        const result = await ai().verifyProviderConnection(req.body.provider);
        res.json({ success: true, test: { provider: req.body.provider, success: Boolean(result.healthy), message: result.message,
          error: result.error || null, responseTime: result.responseTime || Date.now() - started } });
      } catch (error) { res.json({ success: true, test: { provider: req.body.provider, success: false, message: `Connection failed: ${error.message}`, error: error.message, responseTime: Date.now() - started } }); }
    },

    async testLlm(_req, res) {
      const model = environment.OLLAMA_MODEL || 'llama3.1:8b', prompt = 'Hello, please respond with "LLM connection test successful"', started = Date.now();
      try {
        const response = await fetchImpl(`${environment.OLLAMA_BASE_URL || 'http://localhost:11434'}/api/generate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model, prompt, stream: false }) });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        logLLMCall({ provider: environment.AI_PROVIDER || 'ollama', model, promptLength: prompt.length, responseLength: (data.response || '').length,
          latencyMs: Date.now() - started, success: true, messageSummary: prompt, responseSnippet: (data.response || '').slice(0, 150) });
        res.json({ success: true, message: 'LLM connection test successful', response: data.response, model });
      } catch (error) {
        logLLMCall({ provider: environment.AI_PROVIDER || 'ollama', model, promptLength: prompt.length, latencyMs: Date.now() - started, success: false, error: error.message });
        res.status(500).json({ success: false, error: 'LLM connection test failed', details: error.message });
      }
    },

    appLogs(req, res) {
      try {
        const max = Math.min(Number.parseInt(req.query.lines || '100', 10), 500), hideHttp = req.query.hideHttp !== 'false';
        let logs = readJsonLogTail(fileSystem, path.join(logsDir, 'app.log'), 1000);
        if (hideHttp) logs = logs.filter(item => item.component !== 'http' && !HTTP_PATTERN.test(item.message || ''));
        if (req.query.level && req.query.level !== 'all') logs = logs.filter(item => item.level?.toLowerCase() === req.query.level.toLowerCase());
        if (req.query.search) logs = logs.filter(item => JSON.stringify(item).toLowerCase().includes(req.query.search.toLowerCase()));
        if (req.query.username) logs = logs.filter(item => String(item.username || item.userId || item.message || '').toLowerCase().includes(req.query.username.toLowerCase()));
        if (req.query.ip) logs = logs.filter(item => String(item.ip || item.message || '').toLowerCase().includes(req.query.ip.toLowerCase()));
        logs = logs.slice(-max).map(item => { const { timestamp, level, message, userId, username, ip, ...meta } = item;
          return { timestamp: timestamp || null, level: level || 'info', message: message || item.raw || '', userId: userId || null, username: username || null, ip: ip || null, meta }; });
        res.json({ logs, total: logs.length, httpHidden: hideHttp });
      } catch (error) { res.status(500).json({ error: error.message }); }
    },

    llmLogs(req, res) {
      try {
        const max = Math.min(Number.parseInt(req.query.lines || '100', 10), 500);
        let logs = readMergedLlmLogs(max * 3);
        if (req.query.provider) logs = logs.filter(item => item.provider?.toLowerCase() === req.query.provider.toLowerCase());
        if (req.query.success !== undefined && req.query.success !== '') logs = logs.filter(item => item.success === (req.query.success === 'true'));
        if (req.query.username) logs = logs.filter(item => String(item.username || item.userId || '').toLowerCase().includes(req.query.username.toLowerCase()));
        if (req.query.ip) logs = logs.filter(item => item.ip?.toLowerCase().includes(req.query.ip.toLowerCase()));
        logs = logs.slice(-max); res.json({ logs, total: logs.length });
      } catch (error) { res.status(500).json({ error: error.message }); }
    },

    logStats(_req, res) {
      try {
        const cutoff = new Date(Date.now() - 86400000).toISOString();
        const appLogs = readJsonLogTail(fileSystem, path.join(logsDir, 'app.log'), 2000).filter(item => item.component !== 'http' && !HTTP_PATTERN.test(item.message || ''));
        const recent = appLogs.filter(item => String(item.timestamp || '') >= cutoff), llm = readMergedLlmLogs(5000).filter(item => String(item.timestamp || '') >= cutoff);
        const errors = Object.entries(appLogs.filter(item => item.level === 'error' && item.message).reduce((map, item) => ((map[item.message] = (map[item.message] || 0) + 1), map), {}))
          .sort((a, b) => b[1] - a[1]).slice(0, 10).map(([message, count]) => ({ message, count }));
        const latencies = llm.filter(item => typeof item.latencyMs === 'number');
        res.json({ errorCount: recent.filter(item => item.level === 'error').length, warnCount: recent.filter(item => item.level === 'warn').length,
          llmCallCount: llm.length, llmSuccessRate: llm.length ? Math.round(llm.filter(item => item.success).length / llm.length * 100) : null,
          avgLatencyMs: latencies.length ? Math.round(latencies.reduce((sum, item) => sum + item.latencyMs, 0) / latencies.length) : null, topErrors: errors });
      } catch (error) { res.status(500).json({ error: error.message }); }
    },

    systemMonitoring: async (_req, res, repository) => {
      try {
        const [identity, exercises] = await Promise.all([repository.dashboardStats(), repository.listExercisesWithStats()]);
        res.json({ success: true, metrics: { database: { status: 'healthy', connections: repository.poolSize?.() || null, lastQuery: new Date().toISOString() },
          server: { uptime: runtime.uptime(), memory: runtime.memoryUsage(), cpu: runtime.cpuUsage(), pid: runtime.pid },
          users: { active: identity.active_students_24h, total: identity.total_users,
            activePopulation: 'students', activityWindowHours: identity.activity_window_hours }, challenges: { total: exercises.length, enabled: exercises.filter(item => item.is_visible).length } } });
      } catch (error) { res.status(500).json({ success: false, error: 'Failed to fetch system monitoring data', details: error.message }); }
    },
  };
}

module.exports = { createAdminOperationalHandlers, replaceEnvLine, parseLlmRequest, readJsonLogTail };
