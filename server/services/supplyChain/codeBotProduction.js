'use strict';

const FLAG = 'CODEBOT_OWNED_EXECUTION_ENABLED';
const REQUIRED_ISOLATION = 'bwrap-codebot-v1';
const SAFE_REQUEST_KEY = /^[A-Za-z0-9._:-]{16,128}$/;

function enabled(env = process.env) {
  const value = env[FLAG];
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error(`${FLAG} must be true or false`);
}

function runnerOrigin(env = process.env) {
  let value;
  try { value = new URL(env.CODEBOT_SANDBOX_RUNNER_URL); }
  catch { throw new Error('CODEBOT_SANDBOX_RUNNER_URL must be an absolute HTTP URL'); }
  if (!['http:', 'https:'].includes(value.protocol) || value.username || value.password
      || value.search || value.hash || value.pathname !== '/') {
    throw new Error('CODEBOT_SANDBOX_RUNNER_URL must be an origin without credentials');
  }
  return value;
}

function requestKey(supplied, platformSessionId, { postgres = true } = {}) {
  if (supplied == null || supplied === '') {
    if (!postgres) return undefined;
    const error = new Error('Idempotency-Key is required for CodeBot requests'); error.status = 400; throw error;
  }
  if (typeof supplied !== 'string' || !SAFE_REQUEST_KEY.test(supplied)) {
    const error = new Error('Idempotency-Key must contain 16-128 safe characters'); error.status = 400; throw error;
  }
  return require('node:crypto').createHash('sha256').update(`${platformSessionId}:${supplied}`).digest('hex');
}

async function readRunnerReadiness({ env = process.env, fetchImpl = fetch, timeoutMs = 4000 } = {}) {
  const origin = runnerOrigin(env);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(new URL('/health', origin), {
      method: 'GET', redirect: 'error', signal: controller.signal,
    });
    const text = await response.text();
    if (!response.ok || Buffer.byteLength(text) > 16384) throw new Error('CodeBot runner health is unavailable');
    const value = JSON.parse(text);
    const ready = value?.status === 'ok' && value.bwrap === true
      && value.codebotAvailable === true && value.codebotIsolation === REQUIRED_ISOLATION;
    return Object.freeze({ ready, runnerReady: ready, isolation: value?.codebotIsolation || null });
  } catch {
    return Object.freeze({ ready: false, runnerReady: false, isolation: null });
  } finally { clearTimeout(timer); }
}

async function admitCodeBotRequest({ journal, value, execution, activation }) {
  if (!journal) throw Object.assign(new Error('CodeBot request replay storage is unavailable'), { code: 'CODEBOT_REQUEST_JOURNAL_UNAVAILABLE' });
  await journal.assertReady();
  const replay = await journal.replay(value);
  await execution.check();
  if (replay?.replayed) return replay;
  await activation.assertEffectReady();
  const claim = await journal.claim(value);
  await execution.check();
  return claim;
}

function createCodeBotProductionActivation({ env = process.env, journal, runnerReadiness = readRunnerReadiness } = {}) {
  let startup = Object.freeze({ enabled: false, ready: false, journalReady: false, runnerReady: false });
  const configurationReadiness = async () => {
    if (env.PLATFORM_DATABASE_ENGINE !== 'postgres') {
      return Object.freeze({ enabled: false, ready: true, legacy: true, journalReady: false, runnerReady: false });
    }
    if (!enabled(env)) return Object.freeze({ enabled: false, ready: false, journalReady: false, runnerReady: false });
    runnerOrigin(env);
    let journalReady = false;
    try { await journal.assertReady(); journalReady = true; } catch {}
    return Object.freeze({ enabled: true, ready: journalReady, journalReady, runnerReady: false });
  };
  const readiness = async () => {
    const configured = await configurationReadiness();
    if (configured.legacy || !configured.ready) return configured;
    const runner = await runnerReadiness({ env });
    return Object.freeze({ enabled: true, ready: runner.ready === true,
      journalReady: true, runnerReady: runner.runnerReady === true, isolation: runner.isolation || null });
  };
  const unavailable = res => res.status(503).json({ error: 'The isolated CodeBot workshop is unavailable. No model or tool was run.' });
  const assertEffectReady = async () => {
    if (env.PLATFORM_DATABASE_ENGINE !== 'postgres') return true;
    let current;
    try { current = await readiness(); } catch { current = { ready: false }; }
    if (current.ready === true) return true;
    throw Object.assign(new Error('The isolated CodeBot runner is unavailable'), { code: 'CODEBOT_RUNNER_UNAVAILABLE' });
  };
  return Object.freeze({
    async initialize() {
      try { startup = await readiness(); }
      catch { startup = Object.freeze({ enabled: env[FLAG] === 'true', ready: false,
        journalReady: false, runnerReady: false }); }
      return startup;
    },
    snapshot() { return startup; },
    configurationReadiness,
    readiness,
    assertEffectReady,
    async requireConfigured(req, res, next) {
      if (env.PLATFORM_DATABASE_ENGINE !== 'postgres') return next();
      let current;
      try { current = await configurationReadiness(); } catch { current = { ready: false }; }
      if (current.ready === true) return next();
      return unavailable(res);
    },
    async requireReady(req, res, next) {
      if (env.PLATFORM_DATABASE_ENGINE !== 'postgres') return next();
      try { await assertEffectReady(); return next(); } catch { return unavailable(res); }
    },
  });
}

let configured;
function getCodeBotProductionActivation() {
  if (!configured) configured = createCodeBotProductionActivation({
    env: process.env,
    journal: require('../../agent-runtime/codeBotRequestJournal').getConfiguredCodeBotRequestJournal(),
  });
  return configured;
}

module.exports = { FLAG, REQUIRED_ISOLATION, enabled, runnerOrigin, requestKey, readRunnerReadiness, admitCodeBotRequest,
  createCodeBotProductionActivation, getCodeBotProductionActivation };
