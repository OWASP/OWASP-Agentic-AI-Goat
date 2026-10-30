const csrfRuntimeBudget = require('../services/csrfRuntimeBudget');
const {ownerWorkflowRoute: coordinatedOwnerRoute,checkOwnerRun,getOwnerExecution,withOwnerExecution} = require('../agent-runtime/ownerWorkflowRoutes');
const ownerRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({family:'CSRF',defaultTimeoutMs:csrfRuntimeBudget.ownerMs,ledger:require('../agent-runtime/postgresRunLedger').configuredRunLedger()});
/**
 * CSRF Attack Console — 4-tab workshop routes (GET / POST / XSS / Indirect)
 * =========================================================================
 * Each tab has its own logged-in victim, its own defense toggle, its own
 * agent-chat gate, its own attack log and its own 3 objectives (12 total).
 * GET/POST objective execution uses a managed Chrome context with independent
 * same-site origins and a synthetic victim cookie. The shared action handler
 * changes the learner's isolated victim state; grading waits for the observed
 * browser response. Manual /agent-action requests retain the teaching sink but
 * cannot supply the private browser receipt required for objective completion.
 */

const express = require('express');
const { randomBytes, randomUUID } = require('node:crypto');
const path = require('path');
const fs = require('fs');
const router = express.Router();
let teachingAuthority = null;
const {
  syncObjectiveComplete,
  checkAndMarkWorkshopComplete,
  resetWorkshopProgress,
  syncWorkshopStarted,
  getUserWorkshopProgress,
} = require('../utils/progressSync');
const csrfWorkshopDb = require('../database/csrfWorkshopDb');
const aiService = require('../services/multiProviderAIService');
const csrfAgent = require('../services/csrfWorkshopAgent');
const victimSandbox = require('../services/csrfVictimSandbox');
const csrfLogger = require('../utils/contextLogger');
// Reused delivery services (mirror the XSS-workshop email + RAG labs).
const { getXssMailProvider, resolveXssMailContext } = require('../services/xssMailProvider');
const { getCsrfEmailDispatch } = require('../services/csrfEmailDispatch');
const canonicalInboxForOwner = require('../services/csrfInboxScope').createCsrfInboxScope({
  getProvider: getXssMailProvider, resolveContext: resolveXssMailContext,
});
const ragVectorStore = require('../services/ragVectorStore').forFamily('CSRF');
let durableRagComposition=null;
async function durableResources(req,t){return require('../services/csrfDurableRagResources').createCsrfDurableRagResources({composition:durableRagComposition,request:req,execution:getOwnerExecution(),tab:t,cleanText:CLEAN_KB_TEXT,noteReceipt:noteGradeReceipt,mutateTab:work=>mutateTeachingSandbox(victimSandbox.getOrCreateSandbox(sessionIdFor(req)),work)});}


async function durableReset(req, res, slots, afterErase) {
  const { OwnerWorkflowHttpError } = require('../agent-runtime/ownerWorkflowHttpError');
  const operationId = req.get('x-reset-operation-id') || randomUUID();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(operationId)) throw new OwnerWorkflowHttpError(400, 'Invalid reset operation identifier');
  res.setHeader('x-reset-operation-id', operationId);
  try {
    const request = await durableRagComposition.resolveRequest(req);
    await request.reset(getOwnerExecution(), { family: 'CSRF', slots, operationId, afterErase: async () => {
      await afterErase();
    } });
  } catch (error) {
    throw new OwnerWorkflowHttpError(error.statusCode === 401 ? 401 : 503, 'Document reset is incomplete; retry with the same reset operation identifier');
  }
  return operationId;
}

const { createWorkshopConfigService } = require('../services/workshopConfigService');

const WORKSHOP_KEY = 'csrf_workshop';
const { TABS, TAB_IDS, ALL_OBJECTIVES } = victimSandbox;
const workshopConfig = createWorkshopConfigService();
const TOTAL_OBJECTIVES = ALL_OBJECTIVES.length;

const OBJECTIVE_TAB = {};
TAB_IDS.forEach((t) => TABS[t].objectives.forEach((o) => { OBJECTIVE_TAB[o] = t; }));

// Objectives that still use the HTML Payload Builder: GET + POST tabs only.
// XSS tab now uses the email-delivery flow; Indirect tab uses RAG poisoning.
const PAYLOAD_OBJECTIVES = ['csrf_g2', 'csrf_g3', 'csrf_p1', 'csrf_p2', 'csrf_p3'];
const { ATTACKER_ORIGIN, VICTIM_ORIGIN } = require('../services/csrfBrowserReceipt');
function createSharedBrowserExecutionBudget(maxConcurrent = 4) {
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16) {
    throw new TypeError('Invalid shared CSRF browser concurrency limit');
  }
  let active = 0;
  let closed = false;
  const wrap = executor => {
    if (!executor || typeof executor.execute !== 'function') throw new TypeError('CSRF browser executor required');
    return Object.freeze({
      async execute(input) {
        if (closed) throw Object.assign(new Error('CSRF browser execution budget is closed'), { code: 'CSRF_BROWSER_CLOSED' });
        if (active >= maxConcurrent) throw Object.assign(new Error('CSRF browser execution budget is busy'), { code: 'CSRF_BROWSER_BUSY' });
        active += 1;
        try { return await executor.execute(input); }
        finally { active -= 1; }
      },
    });
  };
  return Object.freeze({ wrap, close: () => { closed = true; }, active: () => active });
}
const browserExecutionBudget = createSharedBrowserExecutionBudget(4);
const createBrowserExecutor = require('../services/csrfBrowserExecutor').createCsrfBrowserExecutor;
const attackerBrowserExecutor = createBrowserExecutor({
  attackerOrigin: ATTACKER_ORIGIN, victimOrigin: VICTIM_ORIGIN, timeoutMs: csrfRuntimeBudget.browserMs,
});
const victimDocumentBrowserExecutor = createBrowserExecutor({
  attackerOrigin: ATTACKER_ORIGIN, victimOrigin: VICTIM_ORIGIN,
  documentOrigin: 'victim', documentInteraction: 'reader-hover', timeoutMs: 30000,
});
const browserExecutor = browserExecutionBudget.wrap(attackerBrowserExecutor);
const classifiedEmailBrowserExecutor = browserExecutionBudget.wrap(victimDocumentBrowserExecutor);
const browserWorkflow = require('../services/csrfBrowserWorkflow').createCsrfBrowserWorkflow({ executor: browserExecutor, timeoutMs: csrfRuntimeBudget.workflowMs });
const browserGradingContexts = new WeakMap();
function currentGradingContext() {
  const execution = getOwnerExecution();
  return execution?.csrfGrading || (execution && browserGradingContexts.get(execution));
}
async function assertCurrentCsrfAttempt(context){
  await context.execution.check();
  await context.checkSession?.();
  if(context.attempt){
    const scope=await require('../services/postgresPlatformStores').getPostgresPlatformStores().progress.getEvaluationScope(context.userId,WORKSHOP_KEY);
    if(scope.generation!==context.attempt.generation||scope.mode!==context.attempt.mode||scope.modeStamp!==context.attempt.modeStamp)throw Object.assign(Error('Canonical CSRF scope changed'),{code:'MODE_MISMATCH',statusCode:409});
  }
  await context.execution.check();
  await context.checkSession?.();
}

function createClassifiedEmailRouteAdapter({ workflow, contextFor = currentGradingContext,
  makeCookie = () => randomBytes(24).toString('base64url'), record = recordActivity,
  victimOrigin = VICTIM_ORIGIN } = {}) {
  if (!workflow || typeof workflow.run !== 'function' || typeof workflow.inspect !== 'function'
    || typeof contextFor !== 'function' || typeof makeCookie !== 'function'
    || typeof record !== 'function') {
    throw new TypeError('Classified email route dependencies required');
  }
  const context = () => {
    const value = contextFor();
    if (!value?.execution || !Number.isSafeInteger(value.userId) || value.userId < 1) {
      throw new Error('Protected CSRF grading context required');
    }
    return value;
  };
  return Object.freeze({
    async execute({ retrievedMail, summary, selectedRead, gadgetHtml } = {}) {
      const grading = context();
      return workflow.run({ execution: grading.execution, userId: grading.userId,
        sessionId: `csrf_${grading.userId}`, retrievedMail, summary, selectedRead, gadgetHtml,
        victimCookie: { name: 'owasp_ai_goat_csrf_email', value: makeCookie() },
        victimOrigin, recordActivity: record });
    },
    async note({ proof, retrievedMail, summary, selectedRead, browserReceipt, activity } = {}) {
      const grading = context();
      if (!proof || !retrievedMail || (!summary&&!selectedRead) || !browserReceipt || !activity) {
        throw new TypeError('Classified email proof packet required');
      }
      grading.activity = activity;
      grading.classifiedEmail = Object.freeze({ proof, retrievedMail, summary, selectedRead, browserReceipt, activity });
    },
    async inspect({ proof, userId, execution, attempt, activity, receipt } = {}) {
      const grading = context();
      const bound = grading.classifiedEmail;
      if (!bound || grading.execution !== execution || grading.userId !== userId
        || bound.proof !== proof || bound.activity !== activity || bound.browserReceipt !== receipt) return null;
      return workflow.inspect(proof, { execution, userId,
        generation: attempt?.generation ?? execution?.generation,
        retrievedMail: bound.retrievedMail, summary: bound.summary, selectedRead:bound.selectedRead,
        browserReceipt: receipt, activity });
    },
  });
}

async function readCanonicalCsrfGeneration({ userId, execution }) {
  await execution.check();
  const generation = await require('../services/postgresPlatformStores')
    .getPostgresPlatformStores().progress.getGeneration(userId, WORKSHOP_KEY);
  await execution.check();
  return generation;
}

const classifiedEmailWorkflow = require('../services/csrfClassifiedEmailBrowserWorkflow')
  .createCsrfClassifiedEmailBrowserWorkflow({
    executor: classifiedEmailBrowserExecutor,
    managedAction: { classify: csrfAgent.classifyManagedGadgetAction,
      apply: csrfAgent.applyManagedGadgetAction },
    requestProposalModel: aiService,
    readCanonicalGeneration: readCanonicalCsrfGeneration,
  });
const classifiedEmailRoute = createClassifiedEmailRouteAdapter({ workflow: classifiedEmailWorkflow });

// A single CSRF action-directive detector shared by the email + RAG flows.
// Reuses the agent's natural-language action detector.
function directiveToAction(text) {
  return csrfAgent.detectAction(String(text || '').toLowerCase());
}
function directiveParams(text, action) {
  return csrfAgent.extractParams(String(text || ''), action);
}
// Pull the natural-language `message:'…'` the XSS payload posts to the agent —
// this is the text the AI model actually acts on (e.g. "add a payee named Attacker").
function extractGadgetMessage(text) {
  const m = String(text || '').match(/message\s*[:=]\s*['"]([^'"]+)['"]/i);
  return m ? m[1] : null;
}

const LLM_STARTING = '⏳ The assistant is starting up (the model is still loading). Please ask again in a few seconds.';

// Identify the HTML fragments whose exact presence the summary authority records.
function extractHtmlFragments(text) {
  return String(text || '').match(/<[^<>]+>[\s\S]*?<\/[^<>]+>|<[^<>]+\/?>/g) || [];
}
// A model reply is a "refusal / sanitised" answer when it declines OR when the
// context carried HTML the reply dropped — either way the XSS gadget is lost.
function isRefusalOrStripped(reply, context) {
  const r = String(reply || '').toLowerCase();
  const refusalRe = /(i can(?:'|no)?t (?:help|assist|fulfil|comply|do that)|i['’]m (?:sorry|unable)|cannot (?:help|assist|comply|fulfil)|as an ai|phishing|malicious|cross[- ]site scripting|\bxss\b|security (?:risk|concern)|i (?:won'?t|will not))/i;
  if (refusalRe.test(r)) return true;
  // Context had an on…= handler gadget but the reply didn't reproduce it.
  const ctxGadget = (String(context).match(/<[^>]*\son\w+\s*=[^>]*>/i) || [])[0];
  if (ctxGadget && !String(reply).includes(ctxGadget)) return true;
  return false;
}
// The intentionally vulnerable prompt asks the model to preserve context HTML.
// The summary graph returns the actual answer and separate model/HTML provenance;
// refusals and stripped gadgets are never replaced with fabricated model output.
async function summarizeWithHtml(context, question, kind, execution = getOwnerExecution()) {
  return require('../agent-runtime/htmlSummaryGraph').runHtmlSummaryGraph(context, question, kind,
    { aiService, extractHtmlFragments, LLM_STARTING, execution });
}

const SAMPLES_DIR = path.join(__dirname, '..', 'assets', 'csrf_samples');

// ── helpers ───────────────────────────────────────────────────────────
function getUserId(req) { return teachingAuthority ? teachingAuthority.get(req).ownerId : req.user?.id || req.session?.userId || null; }
function getUserKey(req) {
  const userId = getUserId(req);
  if (userId) return String(userId);
  return req.session?.userId ? String(req.session.userId) : `anon_${req.sessionID}`;
}
function sessionIdFor(req) { return `csrf_${getUserKey(req)}`; }
async function requireWorkshopUser(req, res, next) {
  if (getUserId(req)) {
    try { await victimSandbox.getOrCreateSandbox(sessionIdFor(req)).ready(); }
    catch { return res.status(503).json({error:'Victim state unavailable'}); }
    return next();
  }
  return res.status(401).json({ error: 'login_required' });
}

// Self-heal the cookie session: axios calls carry a Bearer JWT (→ req.user),
// but forged <img>/<form> requests carry ONLY the connect.sid cookie. After a
// nodemon restart the in-memory session store is empty, so the cookie maps to
// nothing and every forged request 401s even though the page looks logged in.
// Any Bearer-authenticated hit re-binds req.session.userId so the very next
// cookie-only request finds a valid session.
router.use((req, res, next) => {
  if (teachingAuthority) return teachingAuthority.middleware()(req, res, next);
  if (req.user?.id && req.session && req.session.userId !== req.user.id) {
    req.session.userId = req.user.id;
  }
  next();
});
function tabOf(req) {
  const raw = String(req.query.tab || req.body?.tab || 'get').toLowerCase();
  return TAB_IDS.includes(raw) ? raw : 'get';
}
function requireValidResetTab(req, res, next) {
  const queryHasTab = Object.prototype.hasOwnProperty.call(req.query || {}, 'tab');
  const bodyHasTab = Object.prototype.hasOwnProperty.call(req.body || {}, 'tab');
  if (!queryHasTab && !bodyHasTab) return next();
  const selected = req.query?.tab || req.body?.tab;
  const normalized = typeof selected === 'string' ? selected.toLowerCase() : '';
  if (!TAB_IDS.includes(normalized)) {
    return res.status(400).json({ error: 'A valid workshop tab is required' });
  }
  return next();
}
function safeJsonParse(s) { try { return JSON.parse(s); } catch (_) { return {}; } }

// ── activity log ──────────────────────────────────────────────────────
function classifyFlag(result) {
  if (!result) return 'safe';
  if (result.blocked) return 'warning';
  if (result.kind === 'attack' && !result.blocked) return 'critical';
  return 'safe';
}
function summarise(result) {
  if (!result) return '';
  if (result.kind === 'recon') return 'viewed attack surface';
  if (result.kind === 'defense') return `defenses ${result.on ? 'ENABLED' : 'disabled'}`;
  if (result.kind === 'query') return 'inspected victim state';
  if (result.kind === 'attack') return result.outcome || result.error || '';
  return '';
}
async function recordActivity(userKey, tabId, name, args, result) {
  await checkOwnerRun();
  const gradingContext = currentGradingContext();
  if (gradingContext) gradingContext.activity = { name, tabId, args: args || {}, result: result || {} };
  return csrfWorkshopDb.logToolCall({ userKey, tabId, toolName:name, args:args?JSON.stringify(args):null, resultSummary:summarise(result), flag:classifyFlag(result), success:!result?.blocked });
}

const progressProjection = require('../services/csrfProgressProjection').createCsrfProgressProjection({
  readCanonical: userId => getUserWorkshopProgress(userId),
  markLocal: (owner, objectiveId) => csrfWorkshopDb.markProgress(owner, objectiveId),
  syncLegacy: (userId, objectiveId) => syncObjectiveComplete(userId, WORKSHOP_KEY, objectiveId, objectiveId, OBJECTIVE_TAB[objectiveId] || ''),
  finishWorkshop: userId => checkAndMarkWorkshopComplete(userId, WORKSHOP_KEY, TOTAL_OBJECTIVES),
  check: checkOwnerRun,
  pending: objectiveId => { const context = currentGradingContext(); if (context && !context.projectionPending.includes(objectiveId)) context.projectionPending.push(objectiveId); },
  report: (objectiveId, userId) => csrfLogger.error('progress_projection_pending', {workshop: WORKSHOP_KEY, objectiveId, userId}),
});

async function markProgressDb(userKey, objectiveId, userId, durable = false) {
  return progressProjection.record({ userKey, objectiveId, userId, durable });
}
async function getCompleted(userKey) {
  return new Set((await progressProjection.rows(userKey)).map(row => row.objective_id));
}

// Capture the grading context before any evidence-producing handler work.
const csrfGrader = require('../services/csrfObjectiveGrader').createCsrfObjectiveGrader({
  inspectClassifiedEmailProof: packet => classifiedEmailRoute.inspect(packet),
  inspectBrowserReceipt: require('../services/csrfGadgetBrowserReceipt').hasCsrfGadgetBrowserReceipt,
});
function gradingSnapshot(tab) {
  return {
    defenses: { ...tab.defenses }, reconCount: tab.reconCount || 0,
    xssInboxConfigured: !!tab.xssInbox, xssEmailSent: !!tab.xssEmailSent,
    xssEmailRead: !!tab.xssEmailRead, ragPoisoned: !!tab.ragPoisoned,
    ragFiredCount: (tab.ragFiredQuestions || []).length,
  };
}
function teachingCoordinatedRoute(coordinator, ownerFor, handler, options = {}) {
  return (req, res, next) => {
    if (!teachingAuthority) return coordinatedOwnerRoute(coordinator, ownerFor, handler, options)(req, res, next);
    const authority = teachingAuthority.get(req);
    const normalizeAuthorityError = error => {
      if (['TEACHING_SESSION_AUTHORITY_UNAVAILABLE', 'TEACHING_SESSION_BINDING_UNAVAILABLE', 'CSRF_TEACHING_AUTHORITY_UNAVAILABLE'].includes(error?.code)
          && [401, 423, 503].includes(error.statusCode)) {
        const { OwnerWorkflowHttpError } = require('../agent-runtime/ownerWorkflowHttpError');
        return new OwnerWorkflowHttpError(error.statusCode, 'Teaching session authority unavailable');
      }
      return error;
    };
    const checkAuthority = async () => {
      try { await authority.check(); } catch (error) { throw normalizeAuthorityError(error); }
    };
    const withTeachingEffect = async work => {
      try { return await authority.withTeachingEffect(work); } catch (error) { throw normalizeAuthorityError(error); }
    };
    const guardedHandler = (request, response, continuation) => {
      const execution = getOwnerExecution();
      return withOwnerExecution({ ...execution, withTeachingEffect },
        () => handler(request, response, continuation));
    };
    const withAdmission = async (owner, work) => {
      if (String(owner) !== String(authority.ownerId)) throw new Error('Teaching owner mismatch');
      await checkAuthority();
      if (options.withAdmission) return options.withAdmission(owner, prior => work({
        check: async () => { await checkAuthority(); await prior.check(); },
      }));
      return work({ check: checkAuthority });
    };
    const beforePublish = options.beforePublish
      ? request => withTeachingEffect(() => options.beforePublish(request))
      : undefined;
    return coordinatedOwnerRoute(coordinator, ownerFor, guardedHandler, { ...options, withAdmission, beforePublish })(req, res, next);
  };
}
function ownerWorkflowRoute(coordinator, ownerFor, handler, options = {}) {
  if (options.reset) return teachingCoordinatedRoute(coordinator, ownerFor, handler, options);
  return teachingCoordinatedRoute(coordinator, ownerFor, async (req, res, next) => {
    const execution = getOwnerExecution();
    const gradingExecution = { ...execution, ownerId: getUserId(req), emit: execution.trace };
    const context = { execution: gradingExecution, userId: getUserId(req), judgments: [], projectionPending: [],
      sandbox: victimSandbox.getOrCreateSandbox(sessionIdFor(req)), activity: null, receipt: null,
      classifiedEmail: null };
    execution.csrfGrading = context;
    context.attempt = await csrfGrader.begin(context.userId, gradingExecution);
    if(teachingAuthority){const authority=teachingAuthority.get(req);context.platformSessionId=String(authority.sessionId);context.checkSession=authority.check;}
    context.assertAttempt=()=>assertCurrentCsrfAttempt(context);
    await context.assertAttempt();
    const decorated = new Proxy(res, { get(target, name) {
      if (name === 'json') return value => target.json(value && typeof value === 'object' && !Array.isArray(value)
        ? { ...value, judgments: context.judgments, projectionPending: context.projectionPending } : value);
      if (name === 'status') return code => { target.status(code); return decorated; };
      const value = target[name]; return typeof value === 'function' ? value.bind(target) : value;
    } });
    return handler(req, decorated, next);
  }, options);
}
function noteGradeReceipt(receipt) {
  const context = currentGradingContext();
  if (context) context.receipt = receipt;
}
function gradingGeneration(context) {
  const generation = context?.attempt?.generation ?? context?.execution?.generation;
  if (!Number.isInteger(generation) || generation < 0) throw new Error('Protected CSRF grading attempt required');
  return generation;
}

// ── Objective ordering gate ───────────────────────────────────────────
// Within each tab the objectives array is already in strict learn-order,
// so objective N's prerequisite is objective N-1 in the same tab. Students
// must finish an objective before the next one can be credited — no jumping
// ahead (e.g. forging the GET pixel `csrf_g2` before reconning `csrf_g1`).
const OBJECTIVE_PREREQ = {};
TAB_IDS.forEach((t) => {
  TABS[t].objectives.forEach((oid, i) => {
    OBJECTIVE_PREREQ[oid] = i > 0 ? TABS[t].objectives[i - 1] : null;
  });
});

// Credit an objective ONLY if it isn't already done AND its prerequisite is
// complete. `already` is the caller's completed-set snapshot. Returns true
// when it was newly credited (so callers can push it into newlyCompleted).
async function getVisibleObjectivePrerequisite(objectiveId) {
  const exercise = (await workshopConfig.getSnapshot()).exercises[WORKSHOP_KEY];
  if (exercise?.isVisible !== true || exercise.objectives?.[objectiveId]?.isVisible !== true) {
    return { visible: false, prerequisite: null };
  }
  const tabId = OBJECTIVE_TAB[objectiveId];
  const orderedVisible = (TABS[tabId]?.objectives || []).filter(
    id => exercise.objectives?.[id]?.isVisible === true
  );
  const index = orderedVisible.indexOf(objectiveId);
  return { visible: index >= 0, prerequisite: index > 0 ? orderedVisible[index - 1] : null };
}

async function isObjectiveVisible(objectiveId) {
  return (await getVisibleObjectivePrerequisite(objectiveId)).visible;
}

async function creditObjective(userKey, oid, userId, already, gate = null) {
  await checkOwnerRun();
  if (already.has(oid)) return false;              // already done → no-op
  const visibility = gate || await getVisibleObjectivePrerequisite(oid);
  if (!visibility.visible) return false;
  const prereq = visibility.prerequisite;
  if (prereq && !already.has(prereq)) return false; // prior objective not done → gate
  const context = currentGradingContext();
  if (!context) throw new Error('Protected CSRF grading context required');
  const outcome = await csrfGrader.evaluate({ userId, objectiveId: oid, execution: context.execution,
    attempt: context.attempt, snapshot: gradingSnapshot(context.sandbox.tab(OBJECTIVE_TAB[oid])),
    activity: context.activity, receipt: context.receipt,
    classifiedEmailProof: context.classifiedEmail?.proof,
    browserReceipt: context.classifiedEmail?.browserReceipt,
    mailReceipt: context.receipt });
  context.judgments.push(outcome.judgment);
  if (!outcome.completed) return false;
  await checkOwnerRun();
  await markProgressDb(userKey, oid, userId, outcome.durable);
  already.add(oid);                                 // keep snapshot consistent within one request
  return true;
}

// ── SSE push ──────────────────────────────────────────────────────────
const sseClients = new Map(); // userKey → Set<res>
function pushCsrfEvent(userKey, payload) {
  const set = sseClients.get(userKey);
  if (!set || set.size === 0) return;
  payload = { ...payload, judgments: currentGradingContext()?.judgments || [], projectionPending: currentGradingContext()?.projectionPending || [] };
  const line = `event: csrf_forged\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) { try { res.write(line); } catch (_) {} }
}

// Shared: perform a forged CSRF action on a tab's victim (from email XSS or a
// poisoned RAG chunk), record it, and push the two-phase SSE (request → reply).
// `via` labels how the forged request was delivered (email/rag) for the chat.
async function forgeAndReport(userKey, userId, tabId, sandbox, action, params, via, forgedText) {
  const label = via === 'email' ? 'XSS-in-email → forged CSRF' : 'Poisoned RAG chunk → forged CSRF';
  // Phase 1 — show the forged request instantly.
  pushCsrfEvent(userKey, { phase: 'request', tab: tabId, vector: via, vectorLabel: label, forgedMessage: forgedText });

  const result = sandbox.forge(tabId, tabId === 'xss' ? 'xss' : 'indirect', action, params);
  result.vectorLabel = label;
  await recordActivity(userKey, tabId, `${via} → ${action}`, { action, ...params }, { kind: 'attack', ...result });

  const reply = csrfAgent.deterministicAttackBody(result);
  return { result, reply };
}

// ── payload templates ─────────────────────────────────────────────────
function loadPayloadTemplate(objectiveId, kind, baseUrl) {
  const file = path.join(SAMPLES_DIR, `${objectiveId}_${kind}.html`);
  if (!fs.existsSync(file)) return null;
  return fs.readFileSync(file, 'utf8').replace(/\{\{BASE_URL\}\}/g, baseUrl);
}
// Vector inferred from the real HTTP shape of the forged request.
function detectForgedVector(req, body, tabId) {
  if (body.document) return 'indirect';
  if ((req.get('x-csrf-via') || '').toLowerCase() === 'xss' || body.via === 'xss' || tabId === 'xss') return 'xss';
  if (req.method === 'GET') return 'direct_get';
  const ct = (req.get('content-type') || '').toLowerCase();
  if (ct.includes('application/json')) return 'fetch';
  return 'direct_post';
}

// ═════════════════════════════ ROUTES ═════════════════════════════════

router.get('/llm-status', async (req, res) => {
  try {
    const info = aiService.getActiveProviderInfo();
    const provider = (info.provider || 'ollama').toLowerCase();
    if (provider === 'bedrock') {
      const v = await aiService.verifyProviderConnection('bedrock');
      return res.json({ available: v.available, provider: info.provider, providerName: info.providerName, model: info.model, message: v.message });
    }
    if (provider !== 'ollama') {
      return res.json({ available: true, provider: info.provider, providerName: info.providerName, model: info.model,
        message: `${info.providerName || provider} ready (model: ${info.model}).` });
    }
    const available = await aiService.checkOllamaAvailable();
    const url = aiService.getOllamaBaseURL ? aiService.getOllamaBaseURL() : (process.env.OLLAMA_BASE_URL || 'http://localhost:11434');
    return res.json({ available, model: info.model, ollamaBaseURL: url,
      message: available ? `Ollama ready · model: ${info.model}` : `Ollama not reachable at ${url}.` });
  } catch (err) {
    res.json({ available: false, provider: 'unknown', model: null, message: err.message || 'AI unavailable' });
  }
});

// ── Tab metadata for the frontend ─────────────────────────────────────
router.get('/tabs', (req, res) => {
  res.json({
    success: true,
    tabs: TAB_IDS.map((id) => ({
      id, label: TABS[id].label, victimName: TABS[id].victim.name,
      vectors: TABS[id].vectors, objectives: TABS[id].objectives,
    })),
  });
});

// ── Victim state (per-tab or all) ─────────────────────────────────────
router.get('/victim-state', requireWorkshopUser, (req, res) => {
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const tab = req.query.tab;
  if (tab && TAB_IDS.includes(tab)) {
    return res.json({ success: true, state: sandbox.getTabState(tab), surface: sandbox.describeSurface(tab) });
  }
  res.json({ success: true, state: sandbox.getState() });
});

// ── SSE event stream (all tabs; event carries `.tab`) ─────────────────
router.get('/events', requireWorkshopUser, (req, res) => {
  if (req.aborted || res.destroyed || res.writableEnded) return;
  const userKey = getUserKey(req);
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.write(`: connected ${new Date().toISOString()}\n\n`);
  if (!sseClients.has(userKey)) sseClients.set(userKey, new Set());
  sseClients.get(userKey).add(res);
  const hb = setInterval(() => { try { res.write(': hb\n\n'); } catch (_) {} }, 25000);
  const closeStream = () => {
    clearInterval(hb);
    const set = sseClients.get(userKey);
    if (set) { set.delete(res); if (set.size === 0) sseClients.delete(userKey); }
  };
  req.once('close', closeStream);
  res.once('close', closeStream);
  req.once('aborted', closeStream);
  if (req.aborted || res.destroyed || res.writableEnded) closeStream();
});

// ── /agent-action — THE INTENTIONALLY VULNERABLE CSRF SINK ────────────
// @intentional-vulnerability csrf-agent-sink
const actionHandlerDeps = {
  getUserKey, getUserId, sessionIdFor, victimSandbox, tabOf, detectForgedVector, csrfAgent, recordActivity, getCompleted, creditObjective, pushCsrfEvent, syncWorkshopStarted, workshopKey: WORKSHOP_KEY,
  canonicalMode:()=>currentGradingContext()?.attempt?.mode??'vuln',
  assertCanonicalMode:()=>currentGradingContext()?.assertAttempt?.(),
};
const handleAgentAction = require('../services/csrfActionHandler').createCsrfActionHandler(actionHandlerDeps);

const browserAttemptHandler = require('../services/csrfBrowserController').createCsrfBrowserController({
  workflow: browserWorkflow, getExecution: getOwnerExecution,
  getGate: getVisibleObjectivePrerequisite, getCompleted,
  sandboxFor: req => victimSandbox.getOrCreateSandbox(sessionIdFor(req)), actionHandlerDeps,
  beginGrading: async (userId, execution, sandbox) => {
    const context = { execution, userId, sandbox, judgments: [], projectionPending: [], activity: null, receipt: null };
    // The child is immutable. ALS establishes the exact child identity used by
    // beginAttempt and the post-response completion transaction.
    const attempt = await csrfGrader.begin(userId, execution);
    const gradingContext={...context,attempt};
    gradingContext.assertAttempt=()=>assertCurrentCsrfAttempt(gradingContext);
    await gradingContext.assertAttempt();
    browserGradingContexts.set(execution,gradingContext);
    return attempt;
  },
  finalGrade: (packet, sandbox) => withOwnerExecution(packet.execution, async () => {
    const context = browserGradingContexts.get(packet.execution);
    if (!context || context.attempt !== packet.gradingAttempt) throw new Error('Browser grading admission missing');
    context.activity = packet.activity; context.receipt = packet.receipt;
    const already = await getCompleted(String(packet.userId));
    const gate = await getVisibleObjectivePrerequisite(packet.objectiveId);
    let completed = false;
    if (gate.visible && (!gate.prerequisite || already.has(gate.prerequisite)) && !already.has(packet.objectiveId)) {
      const outcome = await csrfGrader.evaluate({ userId: packet.userId, objectiveId: packet.objectiveId,
        execution: packet.execution, attempt: packet.gradingAttempt,
        snapshot: gradingSnapshot(sandbox.tab(packet.tab)), activity: packet.activity, receipt: packet.receipt });
      context.judgments.push(outcome.judgment);
      if (outcome.completed) {
        await packet.check();
        await markProgressDb(String(packet.userId), packet.objectiveId, packet.userId, outcome.durable);
        completed = true;
      }
    }
    return { completed, judgments: context.judgments, projectionPending: context.projectionPending };
  }),
});
router.post('/browser-attempt', require('../middleware/adminAuth').authenticateToken,
  require('express-rate-limit').rateLimit({ windowMs: 60000, limit: 12,
    keyGenerator: req => String(req.user.id), standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Too many browser attempts. Wait a minute before retrying.' } }),
  requireWorkshopUser, teachingCoordinatedRoute(ownerRuns, req => getUserKey(req), browserAttemptHandler));


router.get('/agent-action', requireWorkshopUser, ownerWorkflowRoute(ownerRuns,req=>getUserKey(req),handleAgentAction,{beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));
router.post('/agent-action', requireWorkshopUser, express.urlencoded({ extended: true }), ownerWorkflowRoute(ownerRuns,req=>getUserKey(req),handleAgentAction,{beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

async function mutateTeachingSandbox(sandbox, work) {
  await currentGradingContext()?.assertAttempt?.();
  return require('../agent-runtime/csrfSelectedEffect').withCsrfTeachingEffect(getOwnerExecution(), sandbox, async () => {
    const result = await work();
    await sandbox.flush?.();
    return result;
  });
}

// Canonical rendering mode is separate from the tab's teaching CSRF defenses.
const emailModeService=require('../services/workshopModeService');
function requireCanonicalModeUser(req,res,next){
  if(!teachingAuthority||!req.user?.id||!req.identitySession?.id||!require('../middleware/bearerToken').readBearerAuthorization(req).token)return res.status(401).json({error:'Canonical authentication required'});
  next();
}
router.get('/mode',require('../middleware/adminAuth').authenticateToken,requireCanonicalModeUser,teachingCoordinatedRoute(ownerRuns,req=>getUserKey(req),async(req,res)=>{
  if(Object.keys(req.query).length)return res.status(400).json({error:'Mode accepts no owner filters'});
  res.set('Cache-Control','no-store');return res.json(require('../services/csrfEmailMode').projection(await emailModeService.getMode({userId:getUserId(req),workshopKey:WORKSHOP_KEY})));
}));
router.post('/mode',require('../middleware/adminAuth').authenticateToken,requireCanonicalModeUser,teachingCoordinatedRoute(ownerRuns,req=>getUserKey(req),async(req,res)=>{
  if(Object.keys(req.query).length||!req.body||Array.isArray(req.body)||Object.keys(req.body).join(',')!=='mode'||!['vuln','fixed'].includes(req.body.mode))return res.status(400).json({error:'A supported rendering mode is required'});
  await checkOwnerRun();const mode=await emailModeService.setMode({userId:getUserId(req),workshopKey:WORKSHOP_KEY,mode:req.body.mode});await checkOwnerRun();return res.json(require('../services/csrfEmailMode').projection(mode));
}));

// ── CSRF-defense toggle (per-tab) — direct button, no chat needed ─────
router.post('/defense-toggle', requireWorkshopUser, ownerWorkflowRoute(ownerRuns,req=>getUserKey(req),async(req,res)=>{
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const tabId = tabOf(req);
  const result = await mutateTeachingSandbox(sandbox, () => {
    const r = sandbox.setDefenses(tabId, !!req.body.enabled);
    return { success: true, tab: tabId, ...r, victimState: sandbox.getTabState(tabId) };
  });
  res.json(result);
},{beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// ── Agent-chat toggle (per-tab) ───────────────────────────────────────
router.post('/agent-chat-toggle', requireWorkshopUser, ownerWorkflowRoute(ownerRuns,req=>getUserKey(req),async(req,res)=>{
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const tabId = tabOf(req);
  const on = await mutateTeachingSandbox(sandbox, () => sandbox.setAgentChat(tabId, !!req.body.enabled));
  res.json({ success: true, tab: tabId, agentChatEnabled: on });
},{beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// ── Per-tab CSRF token (same-origin JS — i.e. the XSS vector — can read this) ──
router.get('/csrf-token', requireWorkshopUser, (req, res) => {
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const tabId = tabOf(req);
  res.json({ tab: tabId, token: sandbox.tab(tabId).csrfToken });
});

// ═══════════════ XSS TAB — email-delivered XSS → CSRF (REAL inbox) ═════
// Mirrors the XSS-workshop email flow with a REAL SharkLaser/GuerrillaMail inbox:
// the attacker emails an XSS payload (real Gmail SMTP), and when the victim's AI
// mail-reader fetches + renders it, the embedded handler fires a CSRF request.
// The read-path parses the CSRF directive out of the fetched body and forges the
// action against the victim sandbox, so completion is reliable.

const { CSRF_EMAIL_PAYLOADS } = require('../data/csrfEmailPayloads');
const ATTACK_SENDER = 'indirectpromptinjection';

// GET /email/payloads — the selectable XSS→CSRF payload catalog.
router.get('/email/payloads', requireWorkshopUser, (req, res) => {
  res.json({ success: true, payloads: CSRF_EMAIL_PAYLOADS });
});

// GET /email/inbox-address — prefill the student's SharkLaser address from the
// DPI/email-agent lab if they configured one there (shared localStorage too).
router.get('/email/inbox-address', requireWorkshopUser, async (req, res) => {
  const userKey = getUserKey(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const t = sandbox.tab('xss');
  if (t.xssInbox) {
    try { return res.json({ success: true, address: await canonicalInboxForOwner(getUserId(req), t.xssInbox), targetVictim: TABS.xss.victim.name }); }
    catch (error) { return res.status(error.statusCode || 503).json({ error: error.statusCode === 403 ? error.message : 'Email configuration unavailable' }); }
  }
  try { return res.json({success:true,address:(await resolveXssMailContext(Number(userKey),userKey)).email,targetVictim:TABS.xss.victim.name}); }
  catch { return res.status(503).json({error:'Email configuration unavailable'}); }
});

// POST /email/verify { address } — validate + init the SharkLaser session (x1).
router.post('/email/verify', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const userKey = getUserKey(req);
  const userId = getUserId(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const t = sandbox.tab('xss');
  const address = String(req.body.address || '').trim().toLowerCase();
  if (!address) return res.status(400).json({ error: 'address required' });
  try {
    const mailbox = getXssMailProvider().mailbox;
    const canonicalAddress = await canonicalInboxForOwner(userId, address);
    const list = await mailbox.fetchEmails(canonicalAddress, false); // initializes the selected mailbox session
    await mutateTeachingSandbox(sandbox, () => { t.xssInbox = canonicalAddress; });
    noteGradeReceipt({ type: 'inbox_verified', success: true, messageCount: (list.emails || []).length });
    await syncWorkshopStarted(userId, WORKSHOP_KEY);
    const already = await getCompleted(userKey);
    const newlyCompleted = [];
    if (await creditObjective(userKey, 'csrf_x1', userId, already)) newlyCompleted.push('csrf_x1');
    await recordActivity(userKey, 'xss', 'email/verify', { address: canonicalAddress }, { kind: 'safe' });
    res.json({ success: true, address: canonicalAddress, reachable: true, count: (list.emails || []).length, newlyCompleted, victimState: sandbox.getTabState('xss') });
  } catch (e) {
    res.status(e.statusCode || 502).json({ error: `Could not reach the inbox: ${e.message}` });
  }
}, {reset:false,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// POST /email/send { address, payload } — REAL Gmail SMTP send to the SharkLaser
// inbox (x2). The payload is embedded in a marketing-style body.
router.post('/email/send', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const userKey = getUserKey(req);
  const userId = getUserId(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const t = sandbox.tab('xss');
  const address = String(req.body.address || t.xssInbox || '').trim().toLowerCase();
  const payload = String(req.body.payload || '').trim();
  if (!payload) return res.status(400).json({ error: 'payload required' });
  try {
    const context = currentGradingContext();
    const generation = gradingGeneration(context);
    const canonicalAddress = await canonicalInboxForOwner(userId, address);
    const delivery = await getCsrfEmailDispatch().send({ userId, generation,
      execution: context.execution }, { recipient: canonicalAddress, payload });
    noteGradeReceipt(delivery);
    await mutateTeachingSandbox(sandbox, () => {
      t.xssInbox = canonicalAddress;
      t.xssEmailSent = true;
      t.xssLastPayload = payload;
    });
    await syncWorkshopStarted(userId, WORKSHOP_KEY);
    const already = await getCompleted(userKey);
    const newlyCompleted = [];
    if (await creditObjective(userKey, 'csrf_x2', userId, already)) newlyCompleted.push('csrf_x2');
    await recordActivity(userKey, 'xss', 'email/send', { to: canonicalAddress }, { kind: 'safe' });
    res.json({ success: true, sentTo: canonicalAddress, newlyCompleted, victimState: sandbox.getTabState('xss') });
  } catch (err) {
    res.status(err.statusCode || 502).json({ error: err.message || 'Send failed.' });
  }
}, {reset:false,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// ═══════════════ INDIRECT TAB — RAG poisoning → CSRF ══════════════════
// A clean VaultLink knowledge base answers bank questions naturally. The
// student poisons it with a policy-looking doc that embeds an XSS→CSRF gadget.
// When a matching (topic-triggered) question retrieves the poison, the RAG
// answer carries the XSS; rendering it fires the forged CSRF (resolved
// server-side for reliability). Repeatable across distinct questions.

const { CLEAN_KB, CLEAN_KB_TEXT, CSRF_RAG_PAYLOADS, XSS_GADGET_RE, extractGadget } = require('../data/csrfRagPayloads');

// Seed the clean KB into a per-user "clean" vector session once.
const ragResources = require('../services/csrfRagResources').createCsrfRagResources({ store: ragVectorStore, cleanText: CLEAN_KB_TEXT });
async function ensureCleanKb(userKey, t) { return ragResources.ensureClean(userKey, t); }

// GET /rag/payloads — the poison document catalog.
router.get('/rag/payloads', requireWorkshopUser, (req, res) => {
  res.json({ success: true, payloads: CSRF_RAG_PAYLOADS });
});

// GET /rag/state — seed the clean KB + report poison status.
router.get('/rag/state', requireWorkshopUser, teachingCoordinatedRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const userKey = getUserKey(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const t = sandbox.tab('indirect');
  try {
    const resources=durableRagComposition?await durableResources(req,t):null;
    if(resources)await resources.ensureClean();else await ensureCleanKb(userKey,t);
    const state=resources?await resources.state():ragResources.state(userKey,t);
    res.status(state.available ? 200 : 503).json({ success: state.available, poisoned: state.poisonReady,
      poisonRecorded: state.poisonRecorded, retrievalReady: state.available,
      ...(!state.available ? { code: 'CSRF_RAG_RESOURCE_UNAVAILABLE', error: 'Stored poison is unavailable; explicitly re-upload the retained document' } : {}),
      cleanTopics: CLEAN_KB.map((d) => d.title) });
  } catch (error) { res.status(503).json({ success: false, retrievalReady: false, code: error.code, error: error.message }); }
}, {beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// POST /rag/poison { doc } — ingest the poisoned KB document (csrf_i1).
router.post('/rag/poison', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const userKey = getUserKey(req);
  const userId = getUserId(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const t = sandbox.tab('indirect');
  const suppliedText=String(req.body.doc||req.body.text||'');
  const text=durableRagComposition?suppliedText:suppliedText.trim();
  if (!text.trim()) return res.status(400).json({ error: 'document text required' });

  try {
    const resources=durableRagComposition?await durableResources(req,t):null;
    if(resources)await resources.ensureClean();else await ensureCleanKb(userKey,t);
    const ragSessionId = t.ragSessionId || `csrf_rag_poison_${Math.random().toString(36).slice(2, 8)}`;
    const stored=resources?await resources.uploadPoison(text):await ragVectorStore.storeDocument(userKey,ragSessionId,Buffer.from(text,'utf8'),'poisoned-kb.txt');
    await mutateTeachingSandbox(sandbox, () => {
      t.ragSessionId=resources?stored.documentId:ragSessionId;
      t.ragPoisoned = true;
      t.ragDocText = text;
    });
    noteGradeReceipt({type:'document_stored',chunks:stored?.chunksStored||0,...(stored.receipt?{documentReceipt:stored.receipt}:{})});
    await syncWorkshopStarted(userId, WORKSHOP_KEY);
    const already = await getCompleted(userKey);
    const newlyCompleted = [];
    if (await creditObjective(userKey, 'csrf_i1', userId, already)) newlyCompleted.push('csrf_i1');
    await recordActivity(userKey, 'indirect', 'rag/poison', { chunks: stored?.chunksStored }, { kind: 'safe' });
    res.json({ success: true, chunksStored: stored?.chunksStored ?? 1, newlyCompleted, victimState: sandbox.getTabState('indirect') });
  } catch (e) {
    const denial=require('../services/csrfEmailMode').publicScopeDenial(e);if(denial)return res.status(denial.status).json(denial.body);
    console.error('[CSRFWorkshop] rag poison:', e.message);
    res.status(500).json({ error: 'Failed to ingest document (embedding model may still be loading).' });
  }
}, {reset:false,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// POST /rag/reset — clear the poison, keep the clean KB (a clean RAG to work with).
router.post('/rag/reset', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const sandbox = victimSandbox.getOrCreateSandbox(sessionIdFor(req));
  const t = sandbox.tab('indirect');
  if (durableRagComposition) {
    const operationId = await durableReset(req, res, ['poison'], async () => {
      await mutateTeachingSandbox(sandbox, () => {
        t.ragSessionId = null; t.ragPoisoned = false; t.ragDocText = null; t.ragFiredQuestions = [];
      });
    });
    return res.json({ success: true, poisoned: false, operationId });
  }
  await ragResources.resetPoison(getUserKey(req), t);
  await ensureCleanKb(getUserKey(req), t);
  res.json({ success: true, poisoned: false });
}, {reset:true,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// ── Payload templates ─────────────────────────────────────────────────
router.get('/payload/:objectiveId/:kind', requireWorkshopUser, async (req, res) => {
  const { objectiveId, kind } = req.params;
  if (!PAYLOAD_OBJECTIVES.includes(objectiveId)) return res.status(404).json({ error: 'unknown objective' });
  if (!(await isObjectiveVisible(objectiveId))) return res.status(404).json({ error: 'objective disabled by instructor' });
  if (!['skeleton', 'solution'].includes(kind)) return res.status(400).json({ error: 'kind must be skeleton|solution' });
  if (kind === 'solution' && !(await workshopConfig.isSolutionVisible(WORKSHOP_KEY, objectiveId))) {
    return res.status(403).json({ error: 'solution disabled by instructor' });
  }
  // The managed browser owns these intercepted origins. Neither the Host header
  // nor a learner-supplied base may redirect its synthetic victim authority.
  const html = loadPayloadTemplate(objectiveId, kind, VICTIM_ORIGIN);
  if (!html) return res.status(404).json({ error: 'template not found' });
  const filename = `${objectiveId}_${kind}.html`;
  if (req.query.download === '1') {
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(html);
  }
  res.json({ objectiveId, kind, filename, tab: OBJECTIVE_TAB[objectiveId], html });
});

// ── Progress ──────────────────────────────────────────────────────────
router.get('/progress', requireWorkshopUser, async (req, res) => {
  try {
    const visible = (await workshopConfig.getSnapshot()).exercises[WORKSHOP_KEY]?.objectives || {};
    const rows = await progressProjection.rows(getUserId(req));
    res.json({success: true, objectives: Object.fromEntries(rows
      .filter(row => visible[row.objective_id]?.isVisible)
      .map(row => [row.objective_id, {completed: true, completedAt: row.completed_at}])),
      total: Object.values(visible).filter(objective => objective.isVisible).length});
  } catch { res.status(500).json({error: 'Unable to load CSRF progress'}); }
});

router.post('/progress/complete', requireWorkshopUser, (_req, res) => {
  res.status(409).json({ success: false, code: 'JUDGED_ATTEMPT_REQUIRED',
    error: 'Objectives are graded from server-observed workshop actions.' });
});

router.post('/progress/reset', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req=>getUserKey(req), async(req,res)=>{
 const userKey=getUserKey(req);
 const cleanup = async () => {
 if(!durableRagComposition)await ragResources.clearOwner(userKey);
 await csrfWorkshopDb.resetUser(userKey);
 const sandbox=victimSandbox.getOrCreateSandbox(sessionIdFor(req));await mutateTeachingSandbox(sandbox,()=>sandbox.reset());
 await resetWorkshopProgress(getUserId(req),WORKSHOP_KEY);
 };
 const operationId=durableRagComposition?await durableReset(req,res,['clean','poison'],cleanup):(await cleanup(),undefined);
 res.json({success:true,...(operationId?{operationId}:{})});
},{reset:true,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));
router.post('/progress/reset-tab', requireWorkshopUser, requireValidResetTab, ownerWorkflowRoute(ownerRuns, req=>getUserKey(req), async(req,res)=>{
 const userKey=getUserKey(req),userId=getUserId(req),tabId=tabOf(req),ids=TABS[tabId].objectives;
 const cleanup = async () => {
 if(tabId==='indirect'&&!durableRagComposition)await ragResources.clearOwner(userKey);
 await resetWorkshopProgress(userId,WORKSHOP_KEY,{objectiveIds:ids});
 await csrfWorkshopDb.resetTab(userKey,tabId,ids);
 const sandbox=victimSandbox.getOrCreateSandbox(sessionIdFor(req));
 await mutateTeachingSandbox(sandbox,()=>sandbox.resetTab(tabId));
 };
 const operationId=durableRagComposition&&tabId==='indirect'?await durableReset(req,res,['clean','poison'],cleanup):(await cleanup(),undefined);
 res.json({success:true,tab:tabId,cleared:ids,...(operationId?{operationId}:{})});
},{reset:true,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

// ── Activity log (per-tab) ────────────────────────────────────────────
router.get('/activity', requireWorkshopUser, async (req, res) => {
  const userKey = getUserKey(req);
  const tabId = req.query.tab && TAB_IDS.includes(req.query.tab) ? req.query.tab : null;
  try { const rows=await csrfWorkshopDb.listActivity(userKey,tabId);return res.json({success:true,entries:rows.map(r=>({id:r.id,tab:r.exercise_id,name:r.tool_name,args:r.args?safeJsonParse(r.args):{},result:r.result_summary||'',flag:r.flag||'safe',success:!!r.success,timestamp:r.created_at}))}); }
  catch { return res.status(500).json({error:'Unable to load CSRF activity'}); }
});

router.delete('/activity', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const userKey = getUserKey(req);
  try {
    await require('../agent-runtime/csrfSelectedEffect').withCsrfTeachingEffect(getOwnerExecution(),
      victimSandbox.getOrCreateSandbox(sessionIdFor(req)), () => csrfWorkshopDb.clearActivity(userKey));
    return res.json({success:true});
  }
  catch { return res.status(500).json({error:'Unable to clear CSRF activity'}); }
}));

// ── Chat — direct conversation with the tab's agent (gated per-tab) ───
router.post('/chat', requireWorkshopUser, ownerWorkflowRoute(ownerRuns, req => getUserKey(req), async (req, res) => {
  const { message } = req.body;
  if (message == null || message === '') return res.status(400).json({ error: 'message is required' });
  const userKey = getUserKey(req);
  const userId = getUserId(req);
  const sessionId = sessionIdFor(req);
  const tabId = tabOf(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionId);
  const t = sandbox.tab(tabId);

  if (!t.agentChatEnabled) {
    return res.json({
      success: true, blocked: true, tab: tabId,
      response: '**Direct agent chat is disabled on this tab.**\n\nForge a CSRF request via the *Payload Builder* (or a downloaded HTML file) to reach the agent.\n\nFlip the **Agent Chat** toggle to enable direct conversation for recon / defense.',
      newlyCompleted: [], victimState: sandbox.getTabState(tabId),
    });
  }

  try {
  const lower = String(message).toLowerCase();

  // ── XSS tab: "list inbox" (recon) or "read/summarize the email" (x3). ──
  if (tabId === 'xss' && teachingAuthority) {
    const context=currentGradingContext();
    if(!t.xssInbox)return res.json({success:true,tab:'xss',response:'Configure and verify your owned inbox first.',newlyCompleted:[],victimState:sandbox.getTabState('xss')});
    await canonicalInboxForOwner(userId,t.xssInbox);
    const assertAttempt=require('../services/csrfEmailMode').createAttemptFence({attempt:context.attempt,execution:context.execution,
      progress:require('../services/postgresPlatformStores').getPostgresPlatformStores().progress,
      platformSessionId:context.platformSessionId,checkSession:context.checkSession});
    const result=await require('../agent-runtime/csrfSelectedInboxGraph').runSelectedInboxGraph({message,recipient:t.xssInbox,attempt:context.attempt,
      scope:{userId,generation:context.attempt.generation,execution:context.execution,platformSessionId:context.platformSessionId}},
      {dispatch:getCsrfEmailDispatch(),model:aiService,assertAttempt,
       executeBrowser:input=>classifiedEmailRoute.execute(input),
       noteBrowser:async input=>{noteGradeReceipt(input.retrievedMail);await classifiedEmailRoute.note(input);
         await mutateTeachingSandbox(sandbox,async()=>{t.xssEmailRead=true;await sandbox.flush?.();});},
       grade:async()=>{await assertAttempt();const already=await getCompleted(userKey);return await creditObjective(userKey,'csrf_x3',userId,already)?['csrf_x3']:[];},
       snapshot:()=>sandbox.getTabState('xss')});
    await assertAttempt();return res.json(result);
  }
  if (tabId === 'xss') {
    const wantsList = /\b(list|show|check|what.?s in|inbox|any (?:new )?mail|emails?)\b/.test(lower) && !/summari|read|open/.test(lower);
    const wantsRead = /\b(read|summari[sz]e|open|render|display)\b/.test(lower);
    if (wantsList || wantsRead) {
      if (t.xssInbox) {
        try { await canonicalInboxForOwner(userId, t.xssInbox); }
        catch (error) { return res.status(error.statusCode || 503).json({ error: error.statusCode === 403 ? error.message : 'Email configuration unavailable' }); }
      }
      const context = currentGradingContext();
      const generation = gradingGeneration(context);
      return res.json(await require('../agent-runtime/csrfInboxGraph').runCsrfInboxGraph({userKey,userId,t,sandbox,wantsList,
        mailScope:{userId,generation,execution:context.execution}},
      {mailDispatch:getCsrfEmailDispatch(),mailbox:getXssMailProvider().mailbox,aiService,TABS,LLM_STARTING,
        executeClassifiedEmail: input => classifiedEmailRoute.execute(input),
        noteClassifiedEmailProof: input => classifiedEmailRoute.note(input),
        recordActivity,getCompleted,creditObjective,summarizeWithHtml,extractGadgetMessage,noteGradeReceipt,
        execution:context.execution}));
    }
  }

  // ── Indirect tab: natural RAG answer; a poisoned chunk embeds an XSS→CSRF. ──
  if (tabId === 'indirect') {
    try {
      const resources=durableRagComposition?await durableResources(req,t):null;
      return res.json(await require('../agent-runtime/csrfRagGraph').runCsrfRagGraph({userKey,userId,t,message,lower,sandbox},{ensureCleanKb:resources?()=>resources.ensureClean():ensureCleanKb,assertRagAvailable:resources?()=>resources.assertPoisonAvailable():(owner,tab)=>ragResources.assertPoisonAvailable(owner,tab),ragVectorStore:resources?resources.store:ragVectorStore,summarizeWithHtml,XSS_GADGET_RE,extractGadget,directiveToAction,directiveParams,recordActivity,getCompleted,creditObjective,extractGadgetMessage,mode:currentGradingContext()?.attempt?.mode??'vuln',assertMode:currentGradingContext()?.assertAttempt}));
    } catch (e) { const denial=require('../services/csrfEmailMode').publicScopeDenial(e);if(denial)return res.status(denial.status).json(denial.body);return res.status(e.statusCode===401?401:503).json({success:false,retrievalReady:false,code:e.code||'CSRF_RAG_RESOURCE_UNAVAILABLE',error:'RAG retrieval unavailable; retry or explicitly re-upload the retained document'}); }
  }

    await syncWorkshopStarted(userId, WORKSHOP_KEY);
    const result = await csrfAgent.chat(sessionId, tabId, String(message),{mode:currentGradingContext()?.attempt?.mode??'vuln',assertMode:currentGradingContext()?.assertAttempt});

    await recordActivity(userKey, tabId,
      result.intent === 'attack' ? `forge:${result.vector} → ${result.action}` : result.intent,
      result.toolResult?.kind === 'attack' ? { vector: result.vector, action: result.action } : {},
      result.toolResult);

    const already = await getCompleted(userKey);
    const newlyCompleted = [];
    for (const oid of result.objectivesHit || []) {
      if (await creditObjective(userKey, oid, userId, already)) newlyCompleted.push(oid);
    }

    res.json({
      success: true, tab: tabId, response: result.response, intent: result.intent,
      toolExecution: result.toolResult?.kind === 'attack'
        ? { vector: result.vector, action: result.action, blocked: !!result.toolResult.blocked,
            outcome: result.toolResult.outcome || result.toolResult.error || '',
            changed: result.toolResult.changed || null, note: result.toolResult.note || null,
            timestamp: new Date().toISOString() }
        : (result.toolResult && result.toolResult.kind !== 'query'
            ? { kind: result.toolResult.kind, timestamp: new Date().toISOString() } : null),
      completedObjectiveId: newlyCompleted[0] || null,
      newlyCompleted,
      reconCount: result.reconCount ?? t.reconCount,
      agentChatEnabled: t.agentChatEnabled,
      victimState: result.victimState,
      llmOk: true,
    });
  } catch (err) {
    if (err instanceof require('../agent-runtime/ownerWorkflowHttpError').OwnerWorkflowHttpError) throw err;
    const denial=require('../services/csrfEmailMode').publicScopeDenial(err);if(denial)return res.status(denial.status).json(denial.body);
    csrfLogger.error('csrf_workshop_chat_error', { error: err.message });
    console.error('[CSRFWorkshop]', err);

    res.status(err.code==='CSRF_RAG_RESOURCE_UNAVAILABLE'?503:500).json({ error: err.code==='CSRF_RAG_RESOURCE_UNAVAILABLE'?err.message:'Internal server error', ...(err.code==='CSRF_RAG_RESOURCE_UNAVAILABLE'?{code:err.code,retrievalReady:false}: {}) });
  }
}, {reset:false,timeoutFor:req=>teachingAuthority&&tabOf(req)==='xss'?300000:undefined,beforePublish:req=>victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush()}));

router.clearRagOwnerState = owner => {if(durableRagComposition)throw Object.assign(new Error('Durable lifecycle authority required'),{code:'RAG_RESET_REQUIRED'});return ragResources.clearOwner(owner);};
router.resetOwner = (owner, work) => ownerRuns.reset(owner, work);
router.closeBrowser = async () => {
  const failures = [];
  try { browserExecutionBudget.close(); } catch (error) { failures.push(error); }
  const closed = await Promise.allSettled([
    Promise.resolve().then(() => attackerBrowserExecutor.close()),
    Promise.resolve().then(() => victimDocumentBrowserExecutor.close()),
  ]);
  for (const result of closed) if (result.status === 'rejected') failures.push(result.reason);
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, 'CSRF browser shutdown failed');
};
module.exports = router;

if (process.env.EXPORT_INTERNALS === '1') {
  module.exports._internals = {
    detectForgedVector, PAYLOAD_OBJECTIVES, OBJECTIVE_TAB, loadPayloadTemplate, pushCsrfEvent, sseClients,
    ALL_OBJECTIVES, TAB_IDS, forgeAndReport, directiveToAction,
    OBJECTIVE_PREREQ, isRefusalOrStripped, extractHtmlFragments, summarizeWithHtml,
    createSharedBrowserExecutionBudget, createClassifiedEmailRouteAdapter,
  };
}

router.configureDurableRag=composition=>{if(typeof composition?.isReady!=='function'||!composition.isReady())throw new TypeError('Ready PostgreSQL RAG composition required');if(durableRagComposition&&durableRagComposition!==composition)throw new Error('Durable RAG composition already configured');durableRagComposition=composition;};
router.durableRagComposition=()=>durableRagComposition;

// Configured only after durable teaching-session readiness. The separate router
// exposes precisely the intentional cookie sink before the umbrella bearer gate.
router.configureTeachingSessions = runtime => {
  if (teachingAuthority) throw new Error('Teaching session authority already configured');
  teachingAuthority = require('../services/csrfTeachingAuthority').createCsrfTeachingAuthority({ runtime });
  const admission = teachingAuthority.middleware({ allowCookie: true });
  const action = () => ownerWorkflowRoute(ownerRuns, req => getUserKey(req), handleAgentAction,
    { beforePublish: req => victimSandbox.getOrCreateSandbox(sessionIdFor(req)).flush() });
  return require('../services/csrfTeachingSinkMount').createCsrfTeachingSinkMount({
    get: [admission, requireWorkshopUser, action()],
    post: [express.urlencoded({ extended: true }), admission, requireWorkshopUser, action()],
  });
};
