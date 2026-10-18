'use strict';

const express = require('express');
const { ownerWorkflowRoute } = require('../agent-runtime/ownerWorkflowRoutes');
const { legacySensitiveRuns } = require('../services/legacySensitiveRunCoordinator');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const WORKSHOP_KEY = 'legacy_sensitive_file_ssi';

function createLegacySensitiveCandidateRouter({ resolveApplication,
  modeService = require('../services/workshopModeService'), modeCoordinator = legacySensitiveRuns } = {}) {
  if (typeof resolveApplication !== 'function') throw new TypeError('Legacy Sensitive application resolver is required');
  const router = express.Router();
  const modeHandlers = createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY, modeService });
  function endpoint(work){return async(req,res)=>{
    res.set('Cache-Control','no-store');
    try{const application=await resolveApplication();if(!application)throw Object.assign(new Error('unavailable'),{code:'GRADE_STORE_NOT_READY'});await work(application,req,res);}
    catch(error){const status=error.code==='OBJECTIVE_DISABLED'?403:error instanceof TypeError?400:error.code?.includes('BUSY')||error.code?.includes('SCOPE_MISMATCH')?409:503;
      return res.status(status).json({success:false,error:status===403?'Exercise is not enabled':'File and SSI workshop is unavailable',code:error.code||'GRADE_STORE_NOT_READY'});}
  };}
  router.get('/state',endpoint(async(application,req,res)=>res.json({success:true,...await application.snapshot(req.user.id)})));
  router.get('/mode', modeHandlers.get);
  router.post('/mode', ownerWorkflowRoute(modeCoordinator, req => String(req.user.id),
    modeHandlers.set, { reset: true }));
  router.post('/reset',endpoint(async(application,req,res)=>res.json({success:true,reset:await application.reset(req.user.id,{operationId:req.get('x-reset-operation-id')||undefined})})));
  router.post('/chat', async (req, res) => {
    let application;
    try {
      application = await resolveApplication();
    } catch {
      return res.status(503).json({ success: false, unavailable: true,
        error: 'Canonical Legacy Sensitive agent is not ready' });
    }
    const controller = new AbortController();
    const disconnect = () => {
      if (!res.writableEnded) controller.abort(new DOMException('Client disconnected', 'AbortError'));
    };
    req.once('aborted', disconnect);
    res.once('close', disconnect);
    if (req.aborted || res.destroyed) disconnect();
    try {
      controller.signal.throwIfAborted();
      if (!application || typeof application.run !== 'function') return res.status(503).json({
        success: false, unavailable: true, error: 'Canonical Legacy Sensitive agent is not ready',
      });
      if (typeof req.body?.message !== 'string' || !req.body.message.trim()) {
        return res.status(400).json({ success: false, error: 'Message is required' });
      }
      const result = await application.run({ userId: req.user.id, message: req.body.message,
        request: { ip: req.ip, userAgent: req.get('user-agent') }, signal: controller.signal });
      controller.signal.throwIfAborted();
      return res.json({ success: true, response: result.modelResponse?.response || '',
        objectiveId: result.objectiveId, completed: result.completed, judgment: result.judgment, judgments: result.judgments || [], completedObjectives: result.completedObjectives || [] });
    } catch (error) {
      if (res.destroyed || res.headersSent) return;
      if (error?.name === 'AbortError') {
        return res.status(409).json({ success: false, code: 'RUN_INVALIDATED',
          error: 'Request invalidated by reset' });
      }
      if (error?.code === 'OBJECTIVE_DISABLED') {
        return res.status(403).json({ success: false, code: 'OBJECTIVE_DISABLED',
          error: 'This objective is not enabled for the workshop.' });
      }
      if (error?.code === 'AGENT_STEP_LIMIT') {
        return res.status(422).json({ success: false, code: 'AGENT_STEP_LIMIT',
          error: 'The agent reached its tool step limit. No objective completion was awarded.' });
      }
      const status = error?.code === 'GRADE_STORE_NOT_READY' || error?.code === 'MODEL_PROVIDER_UNAVAILABLE' ? 503 : 422;
      return res.status(status).json({ success: false, error: status === 503
        ? 'Canonical Legacy Sensitive agent is not ready' : 'Agent attempt did not qualify',
        ...(status === 503 ? { unavailable: true } : {}) });
    } finally {
      req.removeListener('aborted', disconnect);
      res.removeListener('close', disconnect);
    }
  });
  return router;
}

module.exports = { createLegacySensitiveCandidateRouter };
