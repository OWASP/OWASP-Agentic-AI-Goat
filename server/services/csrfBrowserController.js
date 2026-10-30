'use strict';
const { randomBytes } = require('node:crypto');
const { BROWSER_OBJECTIVES, ATTACKER_ORIGIN, VICTIM_ORIGIN } = require('./csrfBrowserReceipt');
const { OwnerWorkflowHttpError } = require('../agent-runtime/ownerWorkflowHttpError');

// Mounted behind bearer/session validation and the existing owner coordinator.
// The caller supplies HTML only, never a cookie, owner, observation or receipt.
function createCsrfBrowserController({ workflow, getExecution, getGate, getCompleted,
  sandboxFor, actionHandlerDeps, beginGrading, finalGrade }) {
  return async function browserAttempt(req, res) {
    let execution;
    try {
    execution = getExecution();
    const body = req.body;
    if (!body || Array.isArray(body) || typeof body !== 'object'
      || Object.keys(body).some(key => !['tab', 'objectiveId', 'html'].includes(key))
      || !BROWSER_OBJECTIVES.includes(body.objectiveId)
      || body.tab !== (body.objectiveId.startsWith('csrf_g') ? 'get' : 'post')
      || typeof body.html !== 'string' || !body.html.trim() || Buffer.byteLength(body.html) > 65536) {
      throw new OwnerWorkflowHttpError(400, 'Supply a GET/POST browser objective, matching tab, and HTML up to 64 KiB.');
    }
    const userId = req.user?.id;
    if (!Number.isSafeInteger(userId) || userId < 1) throw new OwnerWorkflowHttpError(401, 'login_required');
    const gate = await getGate(body.objectiveId);
    if (!gate.visible) throw new OwnerWorkflowHttpError(404, 'Objective disabled by instructor');
    const already = await getCompleted(String(userId));
    if (gate.prerequisite && !already.has(gate.prerequisite)) {
      throw new OwnerWorkflowHttpError(409, 'Complete the preceding visible objective before running this objective.');
    }
    const sandbox = sandboxFor(req);
      const result = await workflow.run({ execution, userId, objectiveId: body.objectiveId,
        tab: body.tab, html: body.html,
        attackerOrigin: ATTACKER_ORIGIN, victimOrigin: VICTIM_ORIGIN,
        victimCookie: { name: 'owasp_ai_goat_csrf_victim', value: randomBytes(24).toString('base64url') },
        actionHandlerDeps,
        beginGrading: child => beginGrading(userId, child, sandbox),
        finalGrade: async packet => {
          await packet.check();
          await sandbox.flush();
          await packet.check();
          return finalGrade(packet, sandbox);
        },
      });
      await execution.check();
      await sandbox.flush();
      await execution.check();
      return res.json({ tab: body.tab, objectiveId: body.objectiveId, graded: result.graded,
        newlyCompleted: result.grade?.completed ? [body.objectiveId] : [],
        judgments: result.grade?.judgments || [], projectionPending: result.grade?.projectionPending || [],
        victimState: sandbox.getTabState(body.tab), payloadDigest: result.payloadDigest,
        browser: { method: result.browser.observation?.method,
          resourceType: result.browser.observation?.resourceType,
          responseStatus: result.browser.responseStatus, responseObserved: result.browser.responseObserved,
          boundary: result.browser.boundary } });
    } catch (error) {
      // The coordinator owns cancellation/reset publication. No failed browser
      // result is translated into a successful objective or a mock response.
      if (error instanceof OwnerWorkflowHttpError || execution?.signal.aborted) throw error;
      if (['CSRF_BROWSER_TIMEOUT', 'CSRF_BROWSER_WORKFLOW_TIMEOUT'].includes(error.code)) {
        throw new OwnerWorkflowHttpError(504, 'The lab browser timed out. Check the payload target and refresh progress before retrying.');
      }
      if (error.name === 'AbortError') throw error;
      if (error.code === 'CSRF_BROWSER_BUSY') {
        throw new OwnerWorkflowHttpError(429, 'All lab browsers are busy. Retry shortly.', 5);
      }
      if (['CSRF_BROWSER_REQUEST_TOO_LARGE', 'CSRF_BROWSER_WRONG_FRAME'].includes(error.code)) {
        throw new OwnerWorkflowHttpError(400, 'The observed request is too large or did not originate from the managed attacker page.');
      }
      throw new OwnerWorkflowHttpError(503, 'Browser execution could not be confirmed. Check the payload target and server browser installation, then refresh progress before retrying.');
    }
  };
}
module.exports = { createCsrfBrowserController };
