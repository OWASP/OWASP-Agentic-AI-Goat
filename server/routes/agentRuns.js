'use strict';

const express = require('express');
const {
  OBSERVABLE_RUN_FAMILIES, UUID, decodeCursor, createPostgresAgentRunReadRepository, createMemoryAgentRunReadRepository,
  createLazyFamilyReceiptAdapters,
} = require('../database/postgres/agentRunReadRepository');

function integer(value, name, fallback, maximum, minimum = 1) {
  if (value === undefined || value === '') return fallback;
  if (!/^\d+$/.test(String(value))) throw new TypeError(`${name} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${name} is out of range`);
  return parsed;
}
function family(value) {
  if (value === undefined || value === '') return undefined;
  if (!OBSERVABLE_RUN_FAMILIES.includes(value)) throw new TypeError('Unknown agent family');
  return value;
}
function defaultRepository() {
  if (process.env.PLATFORM_DATABASE_ENGINE === 'postgres') {
    const adapter = require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const ownership = require('../services/secureshopConversationOwnershipResolver')
      .createSecureShopConversationOwnershipResolver({
        agentsPool: require('../database/postgres/secureshopPools').getAgentsPool(),
        identityPool: adapter.pool,
      });
    return createPostgresAgentRunReadRepository(adapter.pool, { secureShopOwnership: ownership });
  }
  return createMemoryAgentRunReadRepository(require('../agent-runtime/runTraceStore'));
}
function defaultGraph(familyName, { events = [], judgments = [] } = {}) {
  // Browser qualification shares conversation ownership/leases with the shop
  // supervisor, but does not execute that supervisor's decision graph.
  if (familyName === 'SecureShopBoundConversation'
      && (events.some(event => ['stored_browser_assessment', 'mail_browser_assessment'].includes(event.node))
        || judgments.some(judgment => ['ss_stored_browser_execution', 'ss_mail_stored_browser_execution'].includes(judgment.objectiveId)))) return null;
  if (familyName === 'SecureShopBoundConversation') return {
    nodes: ['initialize', 'budget', 'model', 'dispatch_tools', 'finalize', 'emit'].map(id => ({ id })),
    edges: [
      ['initialize', 'budget'], ['budget', 'model', true], ['budget', 'emit', true],
      ['model', 'dispatch_tools', true], ['model', 'finalize', true], ['model', 'emit', true],
      ['dispatch_tools', 'budget', true], ['dispatch_tools', 'emit', true], ['finalize', 'emit'],
    ].map(([source, target, conditional = false]) => ({ source, target, conditional })),
  };
  if (familyName === 'DPI') return {
    ...require('../agent-runtime/dpiGraph').getDpiGraphDefinition(), scope: 'registered-current',
    subgraphs: [{id:'decoder',parentNode:'model',activation:'Obfuscation objective only (conditional)',
      ...require('../agent-runtime/dpiObfuscationGraph').getDpiObfuscationGraphDefinition()}],
  };
  if (familyName === 'FinFlow') return require('../services/sensitiveInfoWorkshopAgent').getFinflowGraphDefinition();
  if (familyName === 'XSS_EMAIL') return require('../agent-runtime/emailTemplateGraph').getEmailTemplateGraphDefinition();
  if (familyName === 'XSS') return require('../agent-runtime/xssWorkshopGraph').getXssWorkshopGraphDefinition();
  if (familyName === 'ExcessiveAgency') return require('../agent-runtime/excessiveAgencyGraph').getExcessiveAgencyGraphDefinition();
  return require('../agent-runtime/workshopGraph').getWorkshopGraphDefinition(familyName);
}
let defaultReceiptAdapters;
function defaultFamilyReceiptAdapters() {
  defaultReceiptAdapters ||= createLazyFamilyReceiptAdapters();
  return defaultReceiptAdapters;
}

function createAgentRunsRouter({ repository, authenticateToken, requirePermission, admin = false, getGraphDefinition = defaultGraph, regrade, listJudgments, receiptAdapters, protectedRecoveryAvailable = () => process.env.MCP_PROTECTED_RECOVERY_ENABLED === 'true' } = {}) {
  repository ||= defaultRepository();
  receiptAdapters ||= defaultFamilyReceiptAdapters();
  authenticateToken ||= require('../middleware/adminAuth').authenticateToken;
  if (admin) requirePermission ||= require('../middleware/adminAuth').requirePermission;
  const router = express.Router();
  router.use(authenticateToken);
  if (admin) router.use(requirePermission('view_analytics'));

  function scope(req) {
    if (!admin && req.query.ownerId !== undefined) throw new TypeError('Owner filters are administrator-only');
    return { admin, userId: String(req.user.id), ownerId: admin && req.query.ownerId !== undefined
      ? String(integer(req.query.ownerId, 'ownerId', undefined, Number.MAX_SAFE_INTEGER)) : undefined,
    family: family(req.query.family) };
  }
  function unavailable(res) { return res.status(503).json({ error: 'Agent run store unavailable', code: 'AGENT_RUN_STORE_UNAVAILABLE' }); }
  function invalid(res, error) { return res.status(400).json({ error: error.message, code: 'INVALID_AGENT_RUN_QUERY' }); }

  if (!admin) router.get('/judgments',async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({code:'BAD_REQUEST',error:'Judgments accept no owner filters'});
    try {
      const list=listJudgments || (async userId=>{
        if(process.env.PLATFORM_DATABASE_ENGINE!=='postgres')throw new Error('PostgreSQL required');
        const {pool}=require('../services/postgresPlatformStores').getPostgresPlatformStores();
        return require('../database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool).listRecoverable({userId,judgeVersion:require('../agent-runtime/objectiveJudge').JUDGE_VERSION});
      });
      return res.json({judgments:await list(req.user.id)});
    }catch{return res.status(503).json({code:'GRADE_STORE_NOT_READY',error:'Grade recovery store unavailable'});}
  });

  if (!admin) router.post('/judgments/:evaluationId/retry', async (req,res)=>{
    if(!UUID.test(req.params.evaluationId))return res.status(400).json({code:'BAD_REQUEST',error:'Invalid evaluation ID'});
    if(Object.keys(req.body||{}).length)return res.status(400).json({code:'BAD_REQUEST',error:'Retry accepts no evidence or verdict'});
    try {return res.json(await (regrade || require('../services/objectiveRegradeService').getObjectiveRegradeService())({userId:req.user.id,evaluationId:req.params.evaluationId}));}
    catch(error){return res.status(error.code==='NOT_FOUND'?404:['GRADE_STORE_NOT_READY','GRAPH_RUN_CAPACITY_EXCEEDED'].includes(error.code)?503:409).json({code:error.code||'RETRY_UNAVAILABLE',error:'Grading retry unavailable',canRetry:false});}
  });

  router.get('/', async (req, res) => {
    let input;
    try {
      input = { ...scope(req), limit: integer(req.query.limit, 'limit', 25, 100),
        before: req.query.before ? decodeCursor(req.query.before) : undefined };
    } catch (error) { return invalid(res, error); }
    try { return res.json({ ...(await repository.list(input)), families: OBSERVABLE_RUN_FAMILIES }); }
    catch { return unavailable(res); }
  });

  router.get('/:runId', async (req, res) => {
    if (!UUID.test(req.params.runId)) return res.status(400).json({ error: 'Invalid run ID', code: 'INVALID_AGENT_RUN_QUERY' });
    let access;
    try { access = scope(req); } catch (error) { return invalid(res, error); }
    try {
      const page = await repository.events(req.params.runId, access, 0, 100);
      if (!page) return res.status(404).json({ error: 'Agent run not found' });
      let judgments = [];
      if (typeof repository.judgments === 'function') judgments = (await repository.judgments(req.params.runId, access)) || [];
      const receiptSources = [{ source: 'canonical', status: 'available', count: judgments.length }];
      const adapter = receiptAdapters?.[page.run.family];
      if (adapter) {
        try {
          const ownerId = admin ? page.run.ownerId : access.userId;
          const separate = await adapter({ runId: page.run.runId, ownerId, run: page.run });
          const familyReceipts = Array.isArray(separate) ? separate : [];
          judgments = [...judgments, ...familyReceipts];
          receiptSources.push({ source: familyReceipts[0]?.source || page.run.family, status: 'available', count: familyReceipts.length });
        } catch {
          receiptSources.push({ source: page.run.family, status: 'unavailable', code: 'FAMILY_RECEIPT_UNAVAILABLE' });
        }
      }
      let protectedOperations=[],protectedOperationsStatus='not_applicable';
      if(page.run.family==='MCP'&&typeof repository.protectedOperations==='function'){
        try{protectedOperations=await repository.protectedOperations(req.params.runId,access,Number(req.identitySession?.id));
          const enabled=!admin&&await protectedRecoveryAvailable();protectedOperations=protectedOperations.map(item=>({...item,canReconcile:enabled&&item.canReconcile===true}));protectedOperationsStatus='available';
        }catch{protectedOperationsStatus='unavailable';}
      }
      let graph = null;
      try { graph = getGraphDefinition(page.run.family, { events: page.events, judgments }) || null; } catch {}
      return res.json({ run: page.run, events: page.events, nextCursor: page.nextCursor, graph, judgments, receiptSources, protectedOperations, protectedOperationsStatus });
    } catch { return unavailable(res); }
  });

  router.get('/:runId/events', async (req, res) => {
    if (!UUID.test(req.params.runId)) return res.status(400).json({ error: 'Invalid run ID', code: 'INVALID_AGENT_RUN_QUERY' });
    let access, after, limit;
    try {
      access = scope(req); after = integer(req.query.after, 'after', 0, 200, 0);
      limit = integer(req.query.limit, 'limit', 100, 100);
    } catch (error) { return invalid(res, error); }
    try {
      const page = await repository.events(req.params.runId, access, after, limit);
      if (!page) return res.status(404).json({ error: 'Agent run not found' });
      return res.json({ run: page.run, events: page.events, nextCursor: page.nextCursor });
    } catch { return unavailable(res); }
  });
  return router;
}

module.exports = { createAgentRunsRouter, defaultGraph, integer, family };
