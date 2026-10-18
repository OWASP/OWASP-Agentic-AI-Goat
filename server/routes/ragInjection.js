/**
 * RAG-based Indirect Prompt Injection — upload .txt, chunk+embed, query with Llama.
 * Raw context injection (no sanitization) for educational vulnerability demo.
 * Sessions are scoped per user/student so each has isolated RAG data.
 */

const express = require('express');
const router = express.Router();
const ragRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({ family: 'RAG' });
const multer = require('multer');
const crypto = require('crypto');
const ragVectorStore = require('../services/ragVectorStore');
const aiService = require('../services/multiProviderAIService');
const { authenticateToken } = require('../middleware/adminAuth');
const modeService = require('../services/workshopModeService');
const IPI_WORKSHOP_KEY = 'indirect_prompt_injection';
const modeConfig = modeService.WORKSHOP_MODE_CATALOG[IPI_WORKSHOP_KEY];
const modeReply = mode => ({ success:true, mode, defaultMode:modeConfig.defaultMode,
  allowedModes:modeConfig.allowedModes, fixedObjectiveIds:modeConfig.fixedObjectiveIds || ['rag_injected_doc','email_understand_defense'] });
const readMode = userId => process.env.PLATFORM_DATABASE_ENGINE === 'postgres'
  ? modeService.getMode({ userId, workshopKey:IPI_WORKSHOP_KEY }) : Promise.resolve(null);
// Staged explicit composition injection; enabled durable requests never use RAM.
let durableRagComposition = null;
function durableFailure(res, error) {
  const status = error.name === 'AbortError' ? 409 : error.statusCode === 400 ? 400 : error.statusCode === 401 ? 401 : error.code === 'RAG_DOCUMENT_NOT_FOUND' ? 404 : 503;
  return res.status(status).json({ error: status === 400 ? 'Invalid document operation request' : status === 401 ? 'The platform session is no longer current' : status === 404 ? 'Session not found. Please upload a document first.' : status === 409 ? 'Request invalidated by reset' : 'Durable document operation unavailable; retry', code: error.code || (status === 400 ? 'RAG_REQUEST_INVALID' : 'RAG_STORAGE_UNAVAILABLE') });
}


const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB
function resetOperation(req,res){const supplied=req.get?.('x-reset-operation-id');if(supplied&&!UUID_REGEX.test(supplied))throw Object.assign(new Error('Invalid reset operation ID'),{statusCode:400});const id=supplied||crypto.randomUUID();res.setHeader('x-reset-operation-id',id);return id;}


const RAG_OBJECTIVE_IDS = [
  'rag_upload', 'rag_query',
  'rag_clean_doc', 'rag_injected_doc', 'rag_query_injection'
];
const ragProgress = require('../services/ragProgressStore').createDefaultRagProgressStore(RAG_OBJECTIVE_IDS);

function getRagUserKey(req) {
  return String(req.user.id);
}

/** Only the owning user or an admin may reset progress. */
function canResetRagProgress(req, targetUserKey) {
  const currentKey = getRagUserKey(req);
  if (targetUserKey === currentKey) return true;
  const adminLevel = req.user && (req.user.admin_level ?? req.user.adminLevel);
  if (adminLevel != null && Number(adminLevel) > 0) return true;
  return false;
}

async function markRagObjectiveComplete(userKey, objectiveId, platformUserId, {durable=false}={}) {
  await ragProgress.complete({ userKey, objectiveId, platformUserId, durable });
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE }
});

const { getRagSystemPrompt } = require('../agent-runtime/ragPolicies');

// Router is mounted at /api/workshop/rag-injection
router.get('/mode', authenticateToken, async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({error:'Mode accepts no owner filters'});
  try { res.set('Cache-Control','no-store'); res.json(modeReply(await readMode(Number(req.user.id)))); }
  catch { res.status(503).json({error:'Mode unavailable'}); }
});
router.post('/mode', authenticateToken, express.json(), async (req, res) => {
  if (Object.keys(req.query).length || !req.body || Array.isArray(req.body)
      || Object.keys(req.body).join(',') !== 'mode' || !modeConfig.allowedModes.includes(req.body.mode)) {
    return res.status(400).json({error:'A supported mode is required'});
  }
  try { res.set('Cache-Control','no-store'); res.json(modeReply(await modeService.setMode({userId:Number(req.user.id),workshopKey:IPI_WORKSHOP_KEY,mode:req.body.mode}))); }
  catch { res.status(503).json({error:'Mode unavailable'}); }
});
router.post('/upload', authenticateToken, upload.single('document'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  const name = (req.file.originalname || '').toLowerCase();
  if (!name.endsWith('.txt')) {
    return res.status(400).json({ error: 'Only .txt files are accepted' });
  }
  if (req.file.size > MAX_FILE_SIZE) {
    return res.status(400).json({ error: 'File too large. Maximum size is 1MB' });
  }
  let content;
  try {
    content = new TextDecoder('utf-8', { fatal: true }).decode(req.file.buffer).trim();
  } catch {
    return res.status(400).json({ error: 'Document must contain valid UTF-8 text' });
  }
  if (content.includes('\0')) {
    return res.status(400).json({ error: 'Document must contain text without null bytes' });
  }
  if (!content) {
    return res.status(400).json({ error: 'Document is empty' });
  }

  const userKey = getRagUserKey(req);
  const sessionId = crypto.randomUUID();
  const filename = (req.file.originalname || 'document.txt').toLowerCase();
  const displayFilename = req.file.originalname || 'document.txt';
  let requestScope;
  try { if(durableRagComposition)requestScope=await durableRagComposition.resolveRequest(req); }
  catch(error){return durableFailure(res,error);}
  ragRuns.run(userKey, {}, async execution => {
    const durableRagStore=requestScope?await requestScope.bind(execution):undefined;
    return require('../agent-runtime/ragIngestGraph').runRagIngestGraph({userKey,sessionId,buffer:req.file.buffer,filename,displayFilename,platformUserId:req.user.id}, {ragVectorStore,durableRagStore,markRagObjectiveComplete,execution});
  }).then(payload => res.status(200).json(payload))
    .catch((err) => {
      if(durableRagComposition)return durableFailure(res,err);
      if (err.name === 'AbortError' && err.cleanupUncertain !== true) {
        return res.status(409).json({ error: 'Request invalidated by reset', code: 'RUN_INVALIDATED' });
      }
      console.error('[RAG] Upload/store error:', err);
      res.status(err.cleanupUncertain === true || err.code === 'RAG_EMBEDDING_NOT_READY' ? 503 : 500).json({ error: err.message || 'Failed to process document', ...(err.code === 'RAG_EMBEDDING_NOT_READY' ? { code: err.code } : {}), ...(err.cleanupUncertain === true ? { cleanup_uncertain: true } : {}) });
    });
});

router.post('/query', authenticateToken, express.json(), async (req, res) => {
  const { question, session_id, active_objective } = req.body || {};
  if (session_id == null || session_id === '') {
    return res.status(400).json({ error: 'session_id and question are required' });
  }
  if (typeof question !== 'string' || !question.trim()) {
    return res.status(400).json({ error: 'session_id and question are required' });
  }
  if (!UUID_REGEX.test(String(session_id).trim())) {
    return res.status(400).json({ error: 'Invalid session_id' });
  }
  if (question.length > 500) {
    return res.status(400).json({ error: 'Question too long (max 500 characters)' });
  }

  const userKey = getRagUserKey(req);
  const sessionId = String(session_id).trim();
  if(!durableRagComposition && !ragVectorStore.getSessionInfo(userKey,sessionId).exists)return res.status(404).json({error:'Session not found. Please upload a document first.'});
  try {
    const requestScope=durableRagComposition?await durableRagComposition.resolveRequest(req):null;
    const payload = await ragRuns.run(userKey, {}, async execution => {
      const durableRagStore=requestScope?await requestScope.bind(execution):undefined;
      const info=durableRagStore?await durableRagStore.document(sessionId):ragVectorStore.getSessionInfo(userKey,sessionId);
      const mode=await readMode(Number(req.user.id));
      if ((mode === 'fixed' && active_objective === 'rag_query_injection')
          || (mode === 'vuln' && active_objective === 'rag_injected_doc')) {
        const error = new Error('The selected objective belongs to the other mode');
        error.code = 'IPI_OBJECTIVE_MODE_MISMATCH'; error.statusCode = 409; throw error;
      }
      return require('../agent-runtime/ragQueryGraph').runRagQueryGraph(
        { userKey, sessionId, question, active_objective, sessionFilename:(info.filename||'').toLowerCase(), platformUserId:req.user.id, mode },
        { ragVectorStore,durableRagStore,aiService,getRagSystemPrompt,markRagObjectiveComplete,execution });
    });
    if (payload.mode && await readMode(Number(req.user.id)) !== payload.mode) {
      return res.status(409).json({error:'Mode changed during the document response',code:'IPI_MODE_CHANGED'});
    }
    res.status(200).json(payload);
  } catch (err) {
    if (err.code === 'IPI_OBJECTIVE_MODE_MISMATCH') return res.status(409).json({error:err.message,code:err.code});
    if(durableRagComposition)return durableFailure(res,err);
    if (err.name === 'AbortError') {
      return res.status(409).json({ error: 'Request invalidated by reset', code: 'RUN_INVALIDATED' });
    }
    if (err.message === 'Session not found') {
      return res.status(404).json({ error: 'Session not found. Please upload a document first.' });
    }
    console.error('[RAG] Query error:', err);
    res.status(err.code === 'RAG_EMBEDDING_NOT_READY' ? 503 : 500).json({ error: err.message || 'Query failed', ...(err.code === 'RAG_EMBEDDING_NOT_READY' ? { code: err.code } : {}) });
  }
});

router.delete('/session/:sessionId', authenticateToken, async (req, res) => {
  const sessionId = (req.params.sessionId || '').trim();
  if (!UUID_REGEX.test(sessionId)) {
    return res.status(400).json({ error: 'Invalid session_id' });
  }
  const userKey = getRagUserKey(req);
  if(durableRagComposition){
    try{const requestScope=await durableRagComposition.resolveRequest(req),operationId=resetOperation(req,res);let result;
      await ragRuns.reset(userKey,async execution=>{result=await requestScope.retireDocument(execution,{documentId:sessionId,operationId});});
      return res.status(result.deleted?200:404).json(result);
    }catch(error){return durableFailure(res,error);}
  }
  if (!ragVectorStore.getSessionInfo(userKey, sessionId).exists) {
    return res.status(404).json({ deleted: false, message: 'Session not found' });
  }
  try {
    let deleted = false;
    await ragRuns.reset(userKey, async () => {
      deleted = ragVectorStore.deleteSession(userKey, sessionId);
    });
    if (deleted) return res.status(200).json({ deleted: true });
    return res.status(404).json({ deleted: false, message: 'Session not found' });
  } catch (error) {
    return res.status(503).json({ deleted: false, error: 'Session deletion incomplete; retry to reconcile state' });
  }
});

/** GET /current-session — return the last-used RAG session for this user so the UI can show "document loaded" after refresh. */
router.get('/current-session', authenticateToken, async (req, res) => {
  const userKey = getRagUserKey(req);
  if(durableRagComposition){
    try{const scope=await durableRagComposition.resolveRequest(req),current=await scope.read();
      return res.json(current.document?{session_id:current.documentId,filename:current.document.filename,chunks_stored:current.document.chunks.length}:{session_id:null,filename:null,chunks_stored:0});
    }catch(error){return durableFailure(res,error);}
  }
  const current = ragVectorStore.getCurrentSession(userKey);
  if (!current) {
    return res.status(200).json({ session_id: null, filename: null, chunks_stored: 0 });
  }
  res.status(200).json(current);
});

router.get('/health', async (req, res) => {
  try {
    // Health is intentionally public; its session count is only diagnostic.
    const userKey = 'public';
    const ollamaBaseURL = aiService.getOllamaBaseURL ? aiService.getOllamaBaseURL() : (process.env.OLLAMA_BASE_URL || 'http://localhost:11434');

    const embeddingReady = durableRagComposition ? durableRagComposition.isEmbeddingReady() : ragVectorStore.modelReady === true;

    let llmReady = false;
    let ollamaError = null;
    let ollamaVersion = null;
    let availableModels = [];
    let activeModel = null;
    let activeProvider = null;
    let activeProviderName = null;

    // Provider-aware LLM readiness (mirrors csrfWorkshop.js /llm-status). On AWS
    // the app runs AI_PROVIDER=bedrock with DISABLE_OLLAMA=true, so an Ollama-only
    // probe would always report the LLM as down even when Bedrock works fine.
    try {
      const info = aiService.getActiveProviderInfo();
      activeProvider = (info.provider || 'ollama').toLowerCase();
      activeProviderName = info.providerName || info.provider;
      activeModel = info.model;

      if (activeProvider !== 'ollama') {
        const v = await aiService.verifyProviderConnection(activeProvider);
        llmReady = v.available === true && activeProvider !== 'mock' && !v.mocked;
        if (!llmReady) ollamaError = v.message || 'Configured provider connection failed';

      } else {
        llmReady = await aiService.checkOllamaAvailable();
        if (llmReady) {
          if (aiService.getOllamaVersion) {
            ollamaVersion = await aiService.getOllamaVersion();
          }
          if (aiService.getOllamaAvailableModels) {
            availableModels = await aiService.getOllamaAvailableModels();
          }
        }
      }
    } catch (llmErr) {
      ollamaError = llmErr.message;
      console.error('[RAG Health] LLM check failed:', llmErr.message);
    }

    const allReady = embeddingReady && llmReady;
    const status = allReady ? 'ok' : 'degraded';

    const isOllama = activeProvider === 'ollama' || activeProvider == null;
    const messageParts = [];
    if (!embeddingReady) messageParts.push('Embedding model (Xenova/all-MiniLM-L6-v2) not loaded — check server startup logs for ONNX/libc errors.');
    if (!llmReady) messageParts.push(isOllama ? `LLM not reachable at ${ollamaBaseURL}.` : `${activeProviderName || activeProvider} LLM not reachable.`);
    if (allReady) messageParts.push(`All systems ready (LLM: ${activeProviderName || activeProvider} / ${activeModel}${ollamaVersion ? `, v${ollamaVersion}` : ''}).`);

    res.status(200).json({
      status,
      embeddingModel: 'Xenova/all-MiniLM-L6-v2',
      embeddingReady,
      llmReady: !!llmReady,
      provider: activeProvider || undefined,
      providerName: activeProviderName || undefined,
      // Backward-compat aliases
      modelReady: embeddingReady,
      ollamaAvailable: !!llmReady,
      ollamaBaseURL,
      ollamaVersion: ollamaVersion || undefined,
      activeModel: activeModel || undefined,
      availableModels: availableModels.length ? availableModels : undefined,
      activeSessions: ragVectorStore.getActiveSessionsCount(userKey),
      message: messageParts.join(' '),
      ollamaError: ollamaError || undefined
    });
  } catch (err) {
    const ollamaBaseURL = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
    console.error('[RAG Health] Health check error:', err.message);
    res.status(200).json({
      status: 'degraded',
      embeddingModel: 'Xenova/all-MiniLM-L6-v2',
      embeddingReady: ragVectorStore.modelReady === true,
      llmReady: false,
      modelReady: ragVectorStore.modelReady === true,
      ollamaAvailable: false,
      ollamaBaseURL,
      activeSessions: 0,
      error: err.message,
      message: `Health check failed: ${err.message}`
    });
  }
});

router.get('/progress', authenticateToken, async (req, res) => {
  const userKey = getRagUserKey(req);
  try {
    const objectives = await ragProgress.get({ userKey, platformUserId: req.user.id });
    res.json({ success: true, objectives });
  } catch (error) {
    console.error('[RAG] Error loading progress:', error);
    res.status(500).json({ error: 'Failed to load progress' });
  }
});

router.post('/progress/complete', authenticateToken, (req,res)=>res.status(409).json({error:'Objective completion requires observed workflow evidence and an accepted judge verdict'}));

router.post('/progress/reset', authenticateToken, async (req, res) => {
  const userKey = getRagUserKey(req);
  if (!canResetRagProgress(req, userKey)) return res.status(403).json({ error: 'Only the account owner or an admin can reset progress.' });
  try {
    const requestScope=durableRagComposition?await durableRagComposition.resolveRequest(req):null;
    const operationId=requestScope?resetOperation(req,res):null;
    await ragRuns.reset(userKey, async execution => {
      if(requestScope)await requestScope.reset(execution,{operationId,afterErase:()=>ragProgress.reset({userKey,platformUserId:req.user.id})});
      else{await ragVectorStore.clearUserSessions(userKey);await ragProgress.reset({userKey,platformUserId:req.user.id});}
    });
    res.json({ success: true });
  } catch (error) {
    if (durableRagComposition) return durableFailure(res, error);
    res.status(503).json({ error: 'Reset incomplete; retry to reconcile progress' });
  }
});

module.exports = router;
module.exports.resetOwner = (owner, work) => ragRuns.reset(owner, work);
module.exports.clearOwnerState = (owner) => {if(durableRagComposition)throw Object.assign(new Error('Durable lifecycle authority required'),{code:'RAG_RESET_REQUIRED'});return ragVectorStore.clearUserSessions(String(owner));};

module.exports.configureDurableRag = composition => { if(process.env.PLATFORM_DATABASE_ENGINE!=='postgres'||typeof composition?.resolveRequest!=='function'||typeof composition?.isReady!=='function'||!composition.isReady())throw new TypeError('Ready PostgreSQL RAG composition required');if(durableRagComposition&&durableRagComposition!==composition)throw new Error('Durable RAG composition already configured');durableRagComposition=composition; };
module.exports.durableRagComposition = () => durableRagComposition;
