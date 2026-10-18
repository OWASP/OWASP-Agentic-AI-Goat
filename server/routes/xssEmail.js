const express = require('express');
const router = express.Router();
const store = require('../database/postgres/xssWorkshopDb').emailBuilder;
const aiService = require('../services/multiProviderAIService');
const { authenticateToken } = require('../middleware/adminAuth');
const { createXssEmailObjectiveGrader } = require('../services/xssEmailObjectiveGrader');
const { getOwnerExecution } = require('../agent-runtime/ownerWorkflowRoutes');
const xssModeService = require('../services/workshopModeService');
const { projectWorkshopModeCapability } = require('../services/workshopModeCapability');
const { effectiveXssMode, renderChatHtml, renderEmailDocument,
  assertXssAttemptModeCurrent } = require('../services/xssModePolicy');
const ownerRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({ family: 'XSS_EMAIL',
  ledger: require('../agent-runtime/postgresRunLedger').configuredRunLedger() });
const ownerRouteBase = require('../agent-runtime/xssOwnerWorkflowRoute').createXssOwnerWorkflowRoute({
  coordinator: ownerRuns, ownerFor: req => req.user.id, allowAnonymous: false,
});

const canonical = require('../services/xssEmailBuilderCanonical').getXssEmailBuilderCanonical();
const ownerRoute = (handler, options) => ownerRouteBase(async (req,res,next) => {
  await canonical.admit(req.user.id,getOwnerExecution());
  return handler(req,res,next);
},options);
const objectiveGrader = createXssEmailObjectiveGrader({
  canonical,
  persistCompletion: row => store.persistCompletion(row), persistJudgment: row => store.persistJudgment(row),
});

/**
 * XSS EMAIL TEMPLATE BUILDER API
 * ================================
 * ⚠️  INTENTIONALLY VULNERABLE for educational purposes
 *
 * This API demonstrates how AI-powered email builders can be
 * vulnerable to Stored XSS through user profile data.
 */

const MAX_INPUT_BYTES = 65536;
const isBody = value => value && typeof value === 'object' && !Array.isArray(value);
const isText = value => typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= MAX_INPUT_BYTES;
const WORKSHOP_KEY = 'xss_email_builder';

async function currentMode(ownerId, execution) {
  await execution?.check?.();
  const mode = effectiveXssMode(await xssModeService.getMode({ userId: ownerId, workshopKey: WORKSHOP_KEY }));
  await execution?.check?.();
  return mode;
}

async function assertAttemptModeCurrent(ownerId, attempt, execution) {
  return assertXssAttemptModeCurrent({ ownerId, workshopKey: WORKSHOP_KEY, attempt, execution,
    readScope: (owner, key) => require('../services/postgresPlatformStores')
      .getPostgresPlatformStores().progress.getEvaluationScope(owner, key) });
}

const presentTemplate = (template, mode) => !template || mode !== 'fixed' ? template : {
  ...template,
  ...(typeof template.html === 'string' ? { html: renderChatHtml(template.html, mode) } : {}),
  ...(typeof template.html_content === 'string' ? { html_content: renderChatHtml(template.html_content, mode) } : {}),
};

router.get('/mode', authenticateToken, ownerRoute(async (req, res) => {
  if (Object.keys(req.query).length) return res.status(400).json({ error: 'Mode accepts no owner filters' });
  const mode = await xssModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
  await getOwnerExecution().check();
  res.set('Cache-Control', 'no-store');
  res.json(projectWorkshopModeCapability(WORKSHOP_KEY, mode));
}));
router.post('/mode', authenticateToken, ownerRoute(async (req, res) => {
  if (Object.keys(req.query).length || !isBody(req.body) || Object.keys(req.body).join(',') !== 'mode'
      || !['vuln', 'fixed'].includes(req.body.mode)) {
    return res.status(400).json({ error: 'A supported mode is required' });
  }
  const mode = await xssModeService.setMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY,
    mode: req.body.mode });
  await getOwnerExecution().check();
  res.set('Cache-Control', 'no-store');
  res.json(projectWorkshopModeCapability(WORKSHOP_KEY, mode));
}));

// ============================================================================
// PROFILE MANAGEMENT
// ============================================================================

// Get user's email profile
router.get('/profile/:userId', authenticateToken, ownerRoute(async (req, res) => {
  const execution = getOwnerExecution();
  await execution?.check?.();
  try { res.json({ profile: await store.ensureProfile(req.user.id) }); }
  catch (error) { res.status(500).json({ error: 'Database error' }); }
}));

// Intentionally stores unsanitized teaching HTML.
router.put('/profile/:userId', authenticateToken, ownerRoute(async (req, res) => {
  if (!isBody(req.body) || ['full_name', 'email_address', 'company_name', 'job_title', 'phone_number', 'signature_html', 'signature_plain']
    .some(key => req.body[key] != null && !isText(req.body[key]))) {
    return res.status(400).json({ error: 'Profile fields must be text up to 64 KiB or null' });
  }
  const fields = ['full_name','email_address','company_name','job_title','phone_number','signature_html','signature_plain'].map(key => req.body[key] ?? null);
  try {
    await getOwnerExecution()?.check?.();
    const profile = await store.updateProfile(req.user.id, fields);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json({ success: true, profile, message: 'Profile updated successfully' });
  } catch (error) { res.status(500).json({ error: 'Failed to update profile' }); }
}));

// ============================================================================
// AI EMAIL GENERATION
// ============================================================================

// Generate email template using AI (VULNERABLE!)
router.post('/generate', authenticateToken, ownerRoute(async (req, res) => {
  if (!isBody(req.body) || !isText(req.body.prompt) || !req.body.prompt.trim()
    || (req.body.templateType !== undefined && (typeof req.body.templateType !== 'string' || Buffer.byteLength(req.body.templateType, 'utf8') > 128))
    || (req.body.includeSignature !== undefined && typeof req.body.includeSignature !== 'boolean')
    || (req.body.challengeLevel !== undefined && ![1, 2, 3, 4].includes(req.body.challengeLevel))) {
    return res.status(400).json({ error: 'Provide a text prompt up to 64 KiB, an optional text template type and a boolean includeSignature' });
  }
  if(![1,2,3,4].includes(req.body.challengeLevel))return res.status(400).json({error:'Select a builder challengeLevel from 1 through 4'});
  const { prompt, templateType, includeSignature } = req.body;
  const userId = req.user.id;
  const execution = getOwnerExecution();
  if (!prompt) return res.status(400).json({ error: 'Missing required field: prompt' });
  try {
    const attempt = await canonical.begin(userId,req.body.challengeLevel,execution);
    const mode = effectiveXssMode(attempt.mode);
    let loadedProfile = null;
    let rawModelResponse = null;
    let generationProvenance = null;
    let templateEffect = null;
    const result = await require('../agent-runtime/emailTemplateGraph').runEmailTemplateGraph(
      { userId, prompt, templateType, includeSignature, mode, challengeLevel: req.body.challengeLevel }, {
        decisionMode: 'model',
        aiService: { generateResponse: async (...args) => {
          await execution.check();
          rawModelResponse = await aiService.generateResponse(...args);
          await execution.check();
          return rawModelResponse;
        } },
        loadProfile: async id => { loadedProfile = await store.getProfile(id); return loadedProfile; },
        saveTemplate: async params => {
          await assertAttemptModeCurrent(userId, attempt, execution);
          const result=await execution.effectWithReceipt('persist_template',async()=>{
            await assertAttemptModeCurrent(userId, attempt, execution);
            return store.saveTemplate(params);
          });
          templateEffect=result.receipt;return result.value;
        },
        onProvenance: proof => { generationProvenance = proof; }, execution,
      });
    await assertAttemptModeCurrent(userId, attempt, execution);
    if(!result.template)return res.json({...result,mode,completedLevels:[],judgments:[]});
    const grading = await objectiveGrader.evaluate({
      attempt, templateEffect,
      userId, templateId: result.template.id, profile: loadedProfile, prompt, includeSignature,
      rawModelResponse, persistedHtml: result.template.html, generationProvenance, execution, requestedLevel: req.body.challengeLevel,
    });
    await assertAttemptModeCurrent(userId, attempt, execution);
    res.json({ ...result, mode, template: presentTemplate(result.template, mode),
      ...(mode === 'fixed' ? { vulnerability_note: 'Fixed preview renders stored HTML as inert text.' } : {}),
      completedLevels: grading.completedLevels, judgments: grading.judgments,
      render: { method: 'POST', path: '/api/xss-email/preview/render', templateId: result.template.id } });
  } catch (error) {
    if (error.code === 'XSS_MODE_STALE') return res.status(409).json({ error: 'XSS builder mode changed during this attempt; retry in the current mode.', code: error.code });
    if (error.status === 404) return res.status(404).json({ error: 'Profile not found' });
    if (error.publicMessage) return res.status(500).json({ error: error.publicMessage });
    res.status(500).json({ error: 'AI generation failed', details: error.message });
  }
}));

// ============================================================================
// TEMPLATE MANAGEMENT
// ============================================================================

// Get all templates for user
router.get('/templates/:userId', authenticateToken, ownerRoute(async (req, res) => {
  try { const mode = await currentMode(req.user.id, getOwnerExecution()); res.json({ mode,
    templates: (await store.listTemplates(req.user.id)).map(template => presentTemplate(template, mode)) }); }
  catch (error) { res.status(500).json({ error: 'Database error' }); }
}));

router.get('/template/:id', authenticateToken, ownerRoute(async (req, res) => {
  try {
    const template = await store.getTemplate(req.user.id, req.params.id);
    if (!template) return res.status(404).json({ error: 'Template not found' });
    const mode = await currentMode(req.user.id, getOwnerExecution());
    await getOwnerExecution()?.check?.();
    await store.recordView(req.user.id, req.params.id);
    // Intentional teaching sink: return unsanitized HTML.
    res.json({ mode, template: presentTemplate(template, mode) });
  } catch (error) { res.status(500).json({ error: 'Database error' }); }
}));

router.post('/preview', authenticateToken, ownerRoute(async (req, res) => {
  try {
    const template = await store.getTemplate(req.user.id, req.body.templateId);
    if (!template) return res.status(404).json({ error: 'Template not found' });
    const mode = await currentMode(req.user.id, getOwnerExecution());
    const hasXSS = /<script|javascript:|on\w+\s*=/i.test(template.html_content);
    await getOwnerExecution()?.check?.();
    await store.recordPreview(req.user.id, req.body.templateId, hasXSS);
    // Intentional teaching HTML is not sanitized; syntax alone awards no credit.
    res.json({ success: true, mode, html: renderChatHtml(template.html_content, mode),
      xss_warning: hasXSS ? (mode === 'fixed'
        ? 'XSS payload is inert in the fixed preview.' : '⚠️  XSS payload detected in template!') : null });
  } catch (error) { res.status(500).json({ error: 'Database error' }); }
}));

// Intentional teaching sink: render the authenticated owner's persisted email
// as an HTML document. Document parsing is required for the published level-one
// <script> behavior; the JSON preview above remains available for API clients.
router.post('/preview/render', authenticateToken, ownerRoute(async (req, res) => {
  try {
    const template = await store.getTemplate(req.user.id, req.body.templateId);
    if (!template) return res.status(404).json({ error: 'Template not found' });
    const mode = await currentMode(req.user.id, getOwnerExecution());
    const hasXSS = /<script|javascript:|on\w+\s*=/i.test(template.html_content);
    await getOwnerExecution()?.check?.();
    await store.recordPreview(req.user.id, req.body.templateId, hasXSS);
    res.set('Cache-Control', 'no-store');
    // Preserve the teaching script/event-handler sink while placing the
    // learner document in an opaque origin without platform storage/network.
    res.set('Content-Security-Policy', mode === 'fixed'
      ? "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'"
      : "sandbox allow-scripts allow-modals; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'");
    res.set('X-XSS-Workshop-Mode', mode);
    res.status(200).type('html').send(renderEmailDocument(template.html_content, mode));
  } catch (error) { res.status(500).json({ error: 'Database error' }); }
}));

router.get('/challenge/progress/:userId', authenticateToken, async (req, res) => {
  try {
    const snapshot=await canonical.snapshot(req.user.id);
    res.json({canonical:snapshot,progress:(snapshot?.objectives||[]).map(o=>({challenge_level:Number(o.id.slice(-1)),challenge_name:o.label,completed:o.completed?1:0,completed_at:o.completedAt}))});
  }
  catch (error) { res.status(500).json({ error: 'Database error' }); }
});

// Update challenge progress
router.post('/challenge/complete', authenticateToken, (_req, res) => {
  res.status(409).json({ success: false, code: 'JUDGED_ATTEMPT_REQUIRED',
    message: 'Challenge credit is evaluated from persisted email generation and isolated browser evidence.' });
});

// Reset invalidates an in-flight generation before clearing its local
// templates, preview receipts, and judged progress. Stored profile payloads are
// retained so a learner can retry the same teaching input after resetting.
router.post('/challenge/reset', authenticateToken, async(req,res,next)=>{
  try {
    if(!isBody(req.body)||Object.keys(req.body).some(key=>key!=='operationId'))return res.status(400).json({error:'Only an optional operationId is accepted'});
    const fence=require('../agent-runtime/admittedPlatformSession').createAdmittedPlatformSessionFence(req,{
      validateSession:token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token)});
    await fence.check();
    await canonical.cancelBeforeReset({owner:req.user.id,operationId:req.body.operationId,runs:ownerRuns,check:fence.check});
    const operation=await require('../services/xssMutationAdmission').configuredXssMutationAdmission(req.user.id, async lifecycle=>{
      await require('../services/xssMutationAdmission').configuredXssProfileResetPendingCheck(req.user.id,lifecycle);
      return canonical.reset({owner:req.user.id,operationId:req.body.operationId,lifecycle,runs:ownerRuns,sessionCheck:fence.check});
    });
    await fence.check();
    res.json({success:true,message:'Generated templates, previews, and judged progress reset.',operation});
  } catch(error) {res.status(error.statusCode||503).json({error:error.message,code:error.code||'BUILDER_RESET_UNAVAILABLE'});}
});

// Verify XSS payload for challenge
router.post('/challenge/verify', authenticateToken, (req, res) => {
  if (!isBody(req.body) || !['1', '2', '3', '4'].includes(String(req.body.challengeLevel))
    || !['number', 'string'].includes(typeof req.body.challengeLevel)
    || !isText(req.body.testPayload) || typeof req.body.profileField !== 'string') {
    return res.status(400).json({ error: 'Provide a valid level, text payload and profile field' });
  }
  const { challengeLevel, testPayload, profileField } = req.body;

  // Define expected XSS patterns for each level
  const levelRequirements = {
    1: {
      pattern: /<script/i,
      field: 'full_name',
      description: 'Script tag injection in name field'
    },
    2: {
      pattern: /on\w+\s*=/i,
      field: 'signature_html',
      description: 'Event handler XSS in signature (script tags are filtered)'
    },
    3: {
      pattern: /on\w+\s*=|<.*?on\w+/i,
      field: 'company_name',
      description: 'Event handler injection in company'
    },
    4: {
      pattern: /<script|<img.*onerror|<svg.*onload|on\w+\s*=/i,
      field: 'any',
      description: 'XSS via AI prompt manipulation'
    }
  };

  const requirement = levelRequirements[challengeLevel];
  if (!requirement) {
    return res.status(400).json({ error: 'Invalid challenge level' });
  }

  const isValid = requirement.pattern.test(testPayload) &&
                  (requirement.field === 'any' || profileField === requirement.field);

  res.json({
    valid: isValid,
    creditAwarded: false,
    level: challengeLevel,
    requirement: requirement.description,
    hint: isValid ? 'Candidate syntax recognized. Generate an email to create browser-qualified evidence.' : `Try a ${requirement.description} payload in the ${requirement.field} field`
  });
});

router.builderRuns=ownerRuns;
module.exports = router;
