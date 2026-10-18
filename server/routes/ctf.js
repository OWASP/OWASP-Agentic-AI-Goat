const {randomUUID}=require('node:crypto');
const {stageDigest,judgeCtfStage}=require('../agent-runtime/ctfStageJudge');
const {ownerWorkflowRoute,getOwnerExecution}=require('../agent-runtime/ownerWorkflowRoutes');
const ctfRuns=require('../agent-runtime/runCoordinator').createRunCoordinator({family:'CTF'});
const express = require('express');
const router = express.Router();
const { CTFHelpers } = require('../database/ctfDb');
const crypto = require('crypto');
const { classifyTechnique, hashPayload, isNearDuplicate, TECHNIQUE_TAGS } = require('../services/promptInjectionCTF');
const { runDefenseLayers, runOutputDefenses, normalizedContains,
  reviewerProfileEvidence } = require('../services/ctfDefenseLayers');
const { requireCtfGuardianResult } = require('../agent-runtime/ctfGuardianResult');
const { createCtfLessonReceipt } = require('../agent-runtime/ctfLessonState');
const { ctfAttemptInput, ctfStageIdInput,
  ctfStageSecretInput: ctfStageConfigurationInput } = require('../middleware/ctfAttemptInput');
const aiService = require('../services/multiProviderAIService');
const ctfLogger = require('../utils/contextLogger');
const ctfSolutions = require('../data/ctfSolutions');
const { stages: canonicalCtfStages } = require('../data/ctfDefaults');
const {
  COMPARISON_POLICY: CTF_SOLUTION_COMPARISON_POLICY,
  annotateCtfSolutionLevels,
} = require('../services/ctfSolutionApplicability');
const { ctfHintConfigInput } = require('../middleware/ctfHintConfigInput');
const { createLeaderboardRefreshCoordinator } = require('../services/ctfLeaderboardRefreshCoordinator');
const { MAX_CTF_HINTS, parseCtfHints, purchasedCtfHints } = require('../services/ctfHintState');

const leaderboardRefresh = createLeaderboardRefreshCoordinator({
  updateLeaderboard: () => CTFHelpers.updateLeaderboard(),
});

// PostgreSQL serializes the progress update and checks its admitted identity.
function atomicIncrementAttempts(participantId, stageId, alsoIncrementFailed = false, progressId = null) {
  return CTFHelpers.incrementAttempts(participantId,stageId,alsoIncrementFailed,progressId).then(count=>{leaderboardRefresh.requestRefresh();return count;});
}

// Rate limiting: per user per stage
const attemptRateLimits = new Map();
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX = 10;

function checkRateLimit(userId, stageId) {
  const key = `${userId}:${stageId}`;
  const now = Date.now();
  const entries = attemptRateLimits.get(key) || [];
  const recent = entries.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
  if (recent.length >= RATE_LIMIT_MAX) {
    return { limited: true, retryAfter: Math.ceil((recent[0] + RATE_LIMIT_WINDOW_MS - now) / 1000) };
  }
  recent.push(now);
  attemptRateLimits.set(key, recent);
  return { limited: false };
}

// Middleware
const checkCTFEnabled = async (req, res, next) => {
  try {
    const ctfEnabled = await CTFHelpers.getConfig('ctf_enabled');
    if (ctfEnabled !== 'true') {
      return res.status(403).json({ error: 'CTF is currently disabled' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Failed to check CTF availability' });
  }
};

const checkCTFVisibility = async (req, res, next) => {
  try {
    if (req.user && (req.user.role === 'admin' || req.user.adminLevel > 0)) return next();
    const ctfVisible = await CTFHelpers.getConfig('ctf_visible_to_students');
    if (ctfVisible !== 'true') {
      return res.status(403).json({ error: 'CTF is not accessible to students' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Failed to check CTF visibility' });
  }
};

const requireAdmin = (req, res, next) => {
  // Distinguish unauthenticated (401) from authenticated-but-not-admin (403) so
  // the client can tell "log in" apart from "you're not allowed". A student token
  // populates req.user but has role !== 'admin' and adminLevel 0 → 403.
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin' && (req.user.adminLevel || 0) <= 0) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Get CTF configuration (admins can read even when disabled)
router.get('/config', async (req, res) => {
  const ctfEnabled = await CTFHelpers.getConfig('ctf_enabled');
  if (ctfEnabled !== 'true' && !(req.user && (req.user.role === 'admin' || req.user.adminLevel > 0))) {
    return res.status(403).json({ error: 'CTF is currently disabled' });
  }
  try {
    const config = {};
    const configKeys = [
      'ctf_enabled', 'ctf_visible_to_students', 'student_leaderboard_visible',
      'public_leaderboard_visible', 'ctf_registration_open', 'ctf_max_participants',
      'ctf_time_limit', 'leaderboard_update_interval', 'ctf_nav_visible',
      'ctf_show_technique_feedback', 'ctf_show_attempt_counter', 'ctf_hint_gating_attempts',
      'ctf_hint_cost_1', 'ctf_hint_cost_2', 'ctf_hint_cost_3'
    ];
    for (const key of configKeys) {
      config[key] = await CTFHelpers.getConfig(key);
    }
    const participantCount = await CTFHelpers.countParticipants();
    config.current_participants = participantCount;
    config.registration_available = config.ctf_registration_open === 'true' &&
      (config.ctf_max_participants === '-1' || participantCount < parseInt(config.ctf_max_participants));
    res.json({ config });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch CTF configuration' });
  }
});

// Get CTF stages (student-safe, no system_prompt/success_criteria)
router.get('/stages', checkCTFEnabled, checkCTFVisibility, async (req, res) => {
  try {
    const stages = await CTFHelpers.listStudentStages();
    res.json({ stages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch CTF stages' });
  }
});

// Register for CTF
router.post('/register', checkCTFEnabled, checkCTFVisibility, async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { displayName } = req.body;
    const chosenName = (displayName && displayName.trim()) || req.user.username;
    const admission = await CTFHelpers.admitParticipant(req.user.id, chosenName, req.user.email, null);
    if (!admission.admitted) {
      return res.status(403).json({ error: admission.reason === 'registration_closed'
        ? 'CTF registration is currently closed' : 'CTF participant limit reached' });
    }
    const participantId = admission.participantId;
    leaderboardRefresh.requestRefresh();
    const sessionToken = crypto.randomUUID();
    await CTFHelpers.createSession(participantId, sessionToken, req.ip, req.get('User-Agent'));

    await CTFHelpers.recordRegistration(participantId, JSON.stringify({ username: chosenName }));

    res.json({ message: 'Successfully registered for CTF', participantId, sessionToken });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register for CTF' });
  }
});

// Get participant status and progress
router.get('/status', checkCTFEnabled, checkCTFVisibility, async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const participant = await CTFHelpers.findActiveParticipant(req.user.id);
    if (!participant) return res.json({ registered: false });

    const progress = await CTFHelpers.listProgress(participant.id);

    const leaderboardEntry = await CTFHelpers.getLeaderboardEntry(participant.id);

    res.json({ registered: true, participant, progress, leaderboardEntry });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch CTF status' });
  }
});

// Start a CTF stage
router.post('/stage/:stageId/start', checkCTFEnabled, checkCTFVisibility, ctfStageIdInput('stageId'), async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const stageId = Number(req.params.stageId);

    const participant = await CTFHelpers.findActiveParticipant(req.user.id);
    if (!participant) return res.status(400).json({ error: 'Not registered for CTF' });

    // Ban check
    const banned = await CTFHelpers.isBanned(req.user.id);
    if (banned) return res.status(403).json({ error: 'You have been banned from the CTF' });

    const stage = await CTFHelpers.getActiveStage(stageId);
    if (!stage) return res.status(404).json({ error: 'Stage not found' });

    // Match the dashboard's previous visible stage when instructors hide levels
    // or use nonconsecutive ordering. A gap must not bypass an active prerequisite.
    if (stage.stage_order > 1) {
      const prevStage = await CTFHelpers.getPreviousActiveStage(stage.stage_order);
      if (prevStage) {
        const prevProgress = await CTFHelpers.getProgressStatus(participant.id, prevStage.id);
        if (!prevProgress || prevProgress.status !== 'completed') {
          return res.status(403).json({ error: 'Previous stage must be completed first' });
        }
      }
    }

    // Time limit enforcement
    const timeLimit = await CTFHelpers.getConfig('ctf_time_limit');
    if (timeLimit && timeLimit !== '-1') {
      const elapsed = Date.now() - new Date(participant.started_at).getTime();
      if (elapsed > parseInt(timeLimit)) {
        return res.status(403).json({ error: 'CTF time limit exceeded' });
      }
    }

    // Check if already started (idempotent)
    const existingProgress = await CTFHelpers.getProgress(participant.id, stageId);
    if (existingProgress && existingProgress.status === 'in_progress') {
      const hg = parseInt(await CTFHelpers.getConfig('ctf_hint_gating_attempts') || '3');
      const hintsAvailable = (existingProgress.attempts_count || 0) >= hg;
      const purchasedHints = existingProgress.hints_used > 0
        ? purchasedCtfHints((await CTFHelpers.getStageHints(stageId))?.hints, existingProgress.hints_used)
        : [];
      return res.json({
        message: 'Stage already in progress',
        stage: { id: stage.id, stage_number: stage.stage_number, stage_name: stage.stage_name,
          stage_description: stage.stage_description, difficulty_level: stage.difficulty_level,
          difficulty: stage.difficulty, ai_guardian_name: stage.ai_guardian_name,
          ai_guardian_personality: stage.ai_guardian_personality, adaptive_mode: stage.adaptive_mode,
          level_score: stage.level_score },
        alreadyStarted: true, attemptsSoFar: existingProgress.attempts_count,
        hintsAvailable,
        hintsUsed: existingProgress.hints_used || 0,
        hintPenaltyTotal: existingProgress.hint_penalty_total || 0,
        purchasedHints,
      });
    }
    if (existingProgress && existingProgress.status === 'completed') {
      return res.json({ message: 'Stage already completed', alreadyCompleted: true });
    }
    if (existingProgress && existingProgress.status === 'not_started') {
      // Row exists but wasn't properly started — startStage will update it via ON CONFLICT
    }

    await CTFHelpers.startStage(participant.id, stageId);
    await CTFHelpers.updateParticipantActivity(participant.id);

    await CTFHelpers.recordStageStart(participant.id, stageId, JSON.stringify({ stage_name: stage.stage_name }));

    res.json({
      message: 'Stage started successfully',
      stage: {
        id: stage.id,
        stage_number: stage.stage_number,
        stage_name: stage.stage_name,
        stage_description: stage.stage_description,
        difficulty_level: stage.difficulty_level,
        difficulty: stage.difficulty,
        ai_guardian_name: stage.ai_guardian_name,
        ai_guardian_personality: stage.ai_guardian_personality,
        adaptive_mode: stage.adaptive_mode,
        level_score: stage.level_score,
      },
      hintsAvailable: false,
      hintsUsed: 0,
      hintPenaltyTotal: 0,
      purchasedHints: [],
    });
  } catch (error) {
    console.error('Error starting CTF stage:', error);
    res.status(500).json({ error: 'Failed to start CTF stage' });
  }
});

// Bind asynchronous attempt authority to the canonical session admitted at request entry.
async function withCtfAttemptSession(_owner, run, req) {
  const fence = require('../agent-runtime/admittedPlatformSession').createAdmittedPlatformSessionFence(req, {
    validateSession: token => require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token),
  });
  await fence.check();
  return run({ check: fence.check, wrap: fence.wrap, wrapOwnsAdmission: true, checkPublication: fence.check });
}

// Submit attempt for a CTF stage — core flow
router.post('/stage/:stageId/attempt', checkCTFEnabled, checkCTFVisibility, ctfAttemptInput('stageId'), ownerWorkflowRoute(ctfRuns,req=>req.user?.id,async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const stageId = Number(req.params.stageId);
    const { payload, sessionToken } = req.body;

    if (!payload || !payload.trim()) return res.status(400).json({ error: 'Payload is required' });

    // 1. Rate limit
    const rateCheck = checkRateLimit(req.user.id, stageId);
    if (rateCheck.limited) {
      return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: rateCheck.retryAfter });
    }

    // 2. Get participant
    const participant = await CTFHelpers.findActiveParticipant(req.user.id);
    if (!participant) return res.status(400).json({ error: 'Not registered for CTF' });

    // 3. Ban check
    const banned = await CTFHelpers.isBanned(req.user.id);
    if (banned) return res.status(403).json({ error: 'You have been banned from the CTF' });

    // 4. Time limit
    const timeLimit = await CTFHelpers.getConfig('ctf_time_limit');
    if (timeLimit && timeLimit !== '-1') {
      const elapsed = Date.now() - new Date(participant.started_at).getTime();
      if (elapsed > parseInt(timeLimit)) {
        return res.status(403).json({ error: 'CTF time limit exceeded' });
      }
    }

    // 5. Get stage
    const stage = await CTFHelpers.getActiveStage(stageId);
    if (!stage) return res.status(404).json({ error: 'Stage not found' });

    // 6. Get progress
    const progress = await CTFHelpers.getProgress(participant.id, stageId);
    if (!progress || progress.status !== 'in_progress') {
      return res.status(400).json({ error: 'Stage not started or already completed' });
    }

    const capturedStageDigest=stageDigest(stage);
    const reviewerProfile=reviewerProfileEvidence(stage);
    const stage6ReviewerProfile=stage.stage_number===6?reviewerProfile:null;
    const execution=getOwnerExecution();
    const lessonReceipt=createCtfLessonReceipt({ownerId:req.user.id,participantId:participant.id,
      stageId,stageNumber:stage.stage_number,stageDigest:capturedStageDigest,reviewerProfile:stage6ReviewerProfile});
    const {techniqueTag,techniqueConfidence,payloadHash,normalizedSnippet,adaptiveMode,showFeedback,attemptNumber,blockedResponse}=await require('../agent-runtime/ctfAdmissionGraph').runCtfAdmissionGraph({payload,stage,participant,stageId,sessionToken,ownerId:req.user.id,lessonReceipt},{classifyTechnique,hashPayload,isNearDuplicate,TECHNIQUE_TAGS,CTFHelpers,atomicIncrementAttempts:(participantId,stageId,failed)=>atomicIncrementAttempts(participantId,stageId,failed,progress.id),runDefenseLayers,execution,languageModel:aiService});
    if (blockedResponse) return res.json(blockedResponse);

    const startTime = Date.now();
    let aiResponse = '', processedResponse, wasSuccessful, modelResponseTime, realModel=false, guardianUnavailable=false, guardianResult;

    try {
      ({aiResponse,processedResponse,wasSuccessful}=await require('../agent-runtime/ctfGuardianGraph').runCtfGuardianGraph(stage,payload,{runOutputDefenses,normalizedContains,execution,outputModel:aiService,lessonReceipt,generate:async()=>{
      await execution.check();
      const ctfPrompt = `${stage.system_prompt}\n\nUser: ${payload}\nAssistant:`;
      const result = await aiService.generateResponse(ctfPrompt, {
        temperature: 0.7,
        max_tokens: 1000,
        timeout: 120000
      });
      await execution.check();
      const guardian = requireCtfGuardianResult(result);
      guardianResult = result;
      aiResponse = guardian.text;
      realModel = guardian.realModel;

      modelResponseTime = Date.now() - startTime;
      return aiResponse;
      }}));
    } catch (aiError) {
      if(aiError.name==='AbortError'||aiError.code==='SESSION_REVOKED')throw aiError;
      ctfLogger.error('ctf_llm_error', { level: stage.stage_number, error: aiError.message });
      guardianUnavailable=true;realModel=false;wasSuccessful=false;processedResponse='AI system temporarily unavailable. Please try again.';modelResponseTime=Date.now()-startTime;
    }

    const responseTime = modelResponseTime;

    // 12. Output defense layers
    // Output defense and visible-response grading run inside the guardian graph.

    // 13. Check success against the POST-defense response the player actually
    // receives. A level is only solved when the secret truly reaches the player
    // (normalised match also catches spaced/hyphenated/spelled leaks). If the
    // output filters redacted it, or the meta-judge replaced the reply, the
    // attempt does NOT count — this is what makes the escalating output
    // defenses real gates instead of cosmetic display filters.
    const studentResponse = processedResponse;
    // wasSuccessful was computed from this exact post-defense response.

    await execution.check();
    const judgment=guardianUnavailable?{verdict:'unavailable',rubricVersion:'ctf-visible-secret-v2',evidenceSummary:'guardian_unavailable'}:await judgeCtfStage({stage,processedResponse,realModel,observedSecret:wasSuccessful,execution,...(stage6ReviewerProfile?{reviewerProfile:stage6ReviewerProfile}:{})});
    await execution.check();
    const observedSecret=wasSuccessful;
    const guardianBase=require('../agent-runtime/ctfGuardianResult').captureCtfGuardianEvidence(guardianResult,studentResponse);
    const boundProfile=lessonReceipt.profileEvidence();
    const guardianEvidence=guardianBase&&boundProfile
      ? Object.freeze({...guardianBase,...boundProfile})
      : guardianBase&&reviewerProfile?Object.freeze({...guardianBase,reviewerProfile}):guardianBase;
    const commitInput={runId:execution?.runId||randomUUID(),participant,stage,progress,stageDigest:capturedStageDigest,judgment,execution,realModel,guardianEvidence,observedSecret,attemptNumber,payload,studentResponse,responseTime,sessionToken,techniqueTag,techniqueConfidence,payloadHash,normalizedSnippet,adaptiveMode,otherTechnique:TECHNIQUE_TAGS.OTHER};
    const commit=async()=>{await execution.check();return CTFHelpers.commitAttempt(commitInput);};
    if(guardianUnavailable){const result=await commit();const lessonState=!result.stale
      ? lessonReceipt.project({ownerId:req.user.id,participantId:participant.id,stageId,attemptNumber}) : undefined;
      return res.status(result.stale?409:503).json({error:result.stale?'CTF attempt invalidated by reset or stage edit':'AI system temporarily unavailable. Please try again.',retryable:!result.stale,attemptNumber,judgment:{verdict:'unavailable'},...(lessonState?{lessonState}:{})});}
    res.json(await require('../agent-runtime/ctfResultGraph').runCtfResultGraph({wasSuccessful,progress,participant,stageId,payload,techniqueTag,adaptiveMode,payloadHash,normalizedSnippet,stage,attemptNumber,studentResponse,responseTime,sessionToken,techniqueConfidence,showFeedback,ownerId:req.user.id,lessonReceipt},{CTFHelpers,leaderboardRefresh,TECHNIQUE_TAGS,commit,judgment}));

  } catch (error) {
    if(error.code==='SESSION_REVOKED')throw error;
    console.error('Error processing CTF attempt:', error);
    res.status(error.name==='AbortError'?409:500).json({ error:error.name==='AbortError'?'CTF attempt invalidated by reset or stage edit':'Failed to process attempt' });
  }
}, { withAdmission: withCtfAttemptSession }));

// Purchase a hint for a stage (progressive, costs points)
router.post('/stage/:stageId/hint', checkCTFEnabled, checkCTFVisibility, ctfStageIdInput('stageId'), async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const stageId = Number(req.params.stageId);
    const { hintIndex } = req.body;

    if (!Number.isInteger(hintIndex) || hintIndex < 0 || hintIndex >= MAX_CTF_HINTS) {
      return res.status(400).json({ error: 'Invalid hintIndex (must be 0, 1, or 2)' });
    }

    const participant = await CTFHelpers.findActiveParticipant(req.user.id);
    if (!participant) return res.status(403).json({ error: 'Not registered for CTF' });

    const progress = await CTFHelpers.getProgress(participant.id, stageId);
    if (!progress || progress.status !== 'in_progress') {
      return res.status(400).json({ error: 'Stage must be in progress to purchase hints' });
    }

    const hintGating = parseInt(await CTFHelpers.getConfig('ctf_hint_gating_attempts') || '3');
    if (progress.attempts_count < hintGating) {
      return res.status(403).json({ error: `Hints unlock after ${hintGating} attempts. You have ${progress.attempts_count}.` });
    }

    if (hintIndex !== (progress.hints_used || 0)) {
      return res.status(400).json({ error: 'Hints must be purchased sequentially' });
    }

    const stage = await CTFHelpers.getStageHints(stageId);
    if (!stage) return res.status(404).json({ error: 'Stage not found' });

    const allHints = parseCtfHints(stage.hints);
    if (hintIndex >= allHints.length) {
      return res.status(400).json({ error: 'No more hints available for this stage' });
    }

    const costKey = `ctf_hint_cost_${hintIndex + 1}`;
    const cost = parseInt(await CTFHelpers.getConfig(costKey) || '20');

    const newHintsUsed = (progress.hints_used || 0) + 1;
    const newPenalty = (progress.hint_penalty_total || 0) + cost;

    await CTFHelpers.purchaseHint(progress.id,progress.hints_used||0,cost);
    leaderboardRefresh.requestRefresh();

    const effectiveScore = Math.max(0, (stage.level_score ?? 100) - newPenalty);

    res.json({
      hint: allHints[hintIndex],
      hintIndex,
      cost,
      hintsUsed: newHintsUsed,
      totalPenalty: newPenalty,
      remainingHints: allHints.length - newHintsUsed,
      effectiveStageScore: effectiveScore,
    });
  } catch (error) {
    console.error('Error purchasing hint:', error);
    res.status(500).json({ error: 'Failed to purchase hint' });
  }
});

// Get leaderboard
router.get('/leaderboard', checkCTFEnabled, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    if (req.user && req.user.role !== 'admin') {
      const studentVisible = await CTFHelpers.getConfig('student_leaderboard_visible');
      if (studentVisible !== 'true') return res.status(403).json({ error: 'Leaderboard is not visible' });
    }
    const leaderboard = await CTFHelpers.getLeaderboard(parseInt(limit));
    if (!req.user || (req.user.role !== 'admin' && req.user.adminLevel <= 0)) {
      const publicVisible = await CTFHelpers.getConfig('public_leaderboard_visible');
      if (publicVisible !== 'true') {
        leaderboard.forEach(entry => { entry.username = entry.username.substring(0, 3) + '***'; });
      }
    }
    res.json({ leaderboard });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

// Get events feed
router.get('/events', checkCTFEnabled, checkCTFVisibility, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const events = await CTFHelpers.listEvents(parseInt(limit));
    res.json({ events });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch CTF events' });
  }
});

// Heartbeat
router.post('/heartbeat', checkCTFEnabled, async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { sessionToken } = req.body;
    if (sessionToken) {
      await CTFHelpers.heartbeat(sessionToken, req.user.id);
    }
    res.json({ status: 'ok' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update heartbeat' });
  }
});

// ============ ADMIN ENDPOINTS ============

// Admin analytics
router.get('/admin/analytics', requireAdmin, async (req, res) => {
  try {
    const analytics = {};
    analytics.participants = await CTFHelpers.participantAnalytics();
    analytics.stages = await CTFHelpers.stageAnalytics();
    analytics.topTechniques = await CTFHelpers.techniqueAnalytics();
    analytics.blockRates = await CTFHelpers.blockAnalytics();
    analytics.recent_activity = await CTFHelpers.recentActivity();
    res.json({ analytics });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch CTF analytics' });
  }
});

// Admin: verified instructor solutions (spoilers — admin only)
router.get('/admin/solutions', requireAdmin, async (req, res) => {
  try {
    const currentStages = await CTFHelpers.getAllStages();
    res.json({
      howWinningWorks: ctfSolutions.howWinningWorks,
      payloadFamilies: ctfSolutions.payloadFamilies,
      instructorNotes: ctfSolutions.instructorNotes,
      comparisonPolicy: CTF_SOLUTION_COMPARISON_POLICY,
      levels: annotateCtfSolutionLevels(ctfSolutions.levels, currentStages, canonicalCtfStages),
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch CTF solutions' });
  }
});

// Admin config update
router.post('/admin/config', requireAdmin, ctfHintConfigInput, async (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: 'Key and value are required' });
    await CTFHelpers.updateConfig(key, value);
    res.json({ message: 'Configuration updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update configuration' });
  }
});

// Admin: get all stages (including system_prompt, success_criteria)
router.get('/admin/stages', requireAdmin, async (req, res) => {
  try {
    const stages = await CTFHelpers.getAllStages();
    res.json({ stages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stages' });
  }
});

function rejectInactiveTimeBonus(req, res, next) {
  if (Object.prototype.hasOwnProperty.call(req.body || {}, 'time_bonus_seconds')) {
    return res.status(400).json({ error: 'time_bonus_seconds is a legacy inactive setting and cannot be edited' });
  }
  next();
}

// Admin: create stage
router.post('/admin/stages', requireAdmin, rejectInactiveTimeBonus, ctfStageConfigurationInput(), async (req, res) => {
  try {
    const id = await CTFHelpers.createStage(req.body);
    leaderboardRefresh.requestRefresh();
    res.json({ message: 'Stage created', id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create stage', details: error.message });
  }
});

// Admin: update stage
router.put('/admin/stages/:id', requireAdmin, ctfStageIdInput('id'), rejectInactiveTimeBonus, ctfStageConfigurationInput({ partial: true }), async (req, res) => {
  try {
    const success = await CTFHelpers.updateStage(Number(req.params.id), req.body);
    if (!success) return res.status(404).json({ error: 'Stage not found or no changes' });
    leaderboardRefresh.requestRefresh();
    res.json({ message: 'Stage updated' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update stage', details: error.message });
  }
});

// Admin: delete stage
router.delete('/admin/stages/:id', requireAdmin, ctfStageIdInput('id'), async (req, res) => {
  try {
    const success = await CTFHelpers.deleteStage(Number(req.params.id));
    if (!success) return res.status(404).json({ error: 'Stage not found' });
    leaderboardRefresh.requestRefresh();
    res.json({ message: 'Stage deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete stage' });
  }
});

// Admin: preview stage (dry-run a payload)
router.post('/admin/stages/:id/preview', requireAdmin, ctfAttemptInput('id'), async (req, res) => {
  let detachPreviewCancellation = () => {};
  try {
    const stage = await CTFHelpers.getStage(Number(req.params.id));
    if (!stage) return res.status(404).json({ error: 'Stage not found' });
    const { payload } = req.body;
    if (!payload) return res.status(400).json({ error: 'Payload required' });

    const controller = new AbortController();
    const runId = randomUUID();
    const previewTrace = [];
    const disconnected = () => {
      if (res.writableEnded || controller.signal.aborted) return;
      const error = new Error('Client disconnected'); error.name = 'AbortError';
      controller.abort(error);
    };
    req.once?.('aborted', disconnected);
    res.once?.('close', disconnected);
    detachPreviewCancellation = () => {
      req.removeListener?.('aborted', disconnected);
      res.removeListener?.('close', disconnected);
    };
    if (req.aborted || res.destroyed) disconnected();
    const execution = {
      runId,
      ownerId: `ctf-admin-preview:${req.user.id}:${runId}`,
      signal: controller.signal,
      check: async () => controller.signal.throwIfAborted(),
      trace: async event => {
        controller.signal.throwIfAborted();
        previewTrace.push(structuredClone(event));
      },
    };

    const { tag, confidence } = classifyTechnique(payload);
    const { hash } = hashPayload(payload);
    const defenseCheck = await runDefenseLayers(stage, payload, { execution, languageModel: aiService });

    let aiResponse = null;
    let processedResponse = null;
    if (!defenseCheck.blocked) {
      try {
        ({aiResponse,processedResponse}=await require('../agent-runtime/ctfGuardianGraph').runCtfGuardianGraph(stage,payload,{runOutputDefenses,normalizedContains,execution,outputModel:aiService,generate:async()=>{
          await execution.check();
          const ctfPrompt = `${stage.system_prompt}\n\nUser: ${payload}\nAssistant:`;
          const result = await aiService.generateResponse(ctfPrompt, { temperature: 0.7, max_tokens: 1000,
            timeout: 120000, signal: execution.signal, ownerId: execution.ownerId });
          await execution.check();
          const guardian = requireCtfGuardianResult(result);
          await execution.trace({ node: 'ctf_preview_guardian', type: 'decision', data: {
            provider: guardian.provider, model: guardian.model,
            responseSha256: crypto.createHash('sha256').update(guardian.text).digest('hex') } });
          return guardian.text;
        }}));
        await execution.check();
      } catch (err) {
        if (execution.signal.aborted || err?.name === 'AbortError') throw err;
        ctfLogger.error('ctf_llm_error', { level: stage.stage_number, error: err.message });
        return res.status(503).json({ error: 'AI system temporarily unavailable. Please try again.', retryable: true });
      }
    }

    // Score on the post-defense response the player would actually receive,
    // matching the live student pipeline (normalised match).
    const wouldSucceed = (!defenseCheck.blocked && processedResponse)
      ? normalizedContains(processedResponse, stage.success_criteria)
      : false;

    res.json({
      classification: { tag, confidence },
      payloadHash: hash,
      defenseBlocked: defenseCheck.blocked,
      defenseReason: defenseCheck.reason || null,
      defenseLayer: defenseCheck.layer || null,
      languageDecision: defenseCheck.languageDecision || null,
      previewTrace,
      rawResponse: aiResponse,
      processedResponse,
      wouldSucceed,
      secretCriteria: stage.success_criteria
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      if (!res.headersSent && !res.destroyed) res.status(409).json({ error: 'Preview invalidated by disconnect' });
      return;
    }
    res.status(500).json({ error: 'Preview failed', details: error.message });
  } finally {
    detachPreviewCancellation();
  }
});

// Admin: get attempts with filters
router.get('/admin/attempts', requireAdmin, async (req, res) => {
  try {
    const filters = {
      participantId: req.query.participantId ? parseInt(req.query.participantId) : undefined,
      stageId: req.query.stageId ? parseInt(req.query.stageId) : undefined,
      blocked: req.query.blocked !== undefined ? req.query.blocked === 'true' : undefined,
      techniqueTag: req.query.techniqueTag || undefined,
      wasSuccessful: req.query.wasSuccessful !== undefined ? req.query.wasSuccessful === 'true' : undefined,
      limit: parseInt(req.query.limit) || 100,
      offset: parseInt(req.query.offset) || 0
    };
    const attempts = await CTFHelpers.getAttempts(filters);
    res.json({ attempts });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attempts' });
  }
});

// Admin: get participants
router.get('/admin/participants', requireAdmin, async (req, res) => {
  try {
    const participants = await CTFHelpers.getParticipants();
    res.json({ participants });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch participants' });
  }
});

// Admin: reset participant
router.post('/admin/participants/:userId/reset', requireAdmin, ctfStageIdInput('userId', 'participant'), async (req, res) => {
  try {
    const participant = await CTFHelpers.findParticipant(Number(req.params.userId));
    if (!participant) return res.status(404).json({ error: 'Participant not found' });
    await ctfRuns.reset(req.params.userId,()=>CTFHelpers.resetParticipant(participant.id));
    leaderboardRefresh.requestRefresh();
    await leaderboardRefresh.flush({ throwOnError: true });
    res.json({ message: 'Participant reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset participant' });
  }
});

// Admin: ban user
router.post('/admin/participants/:userId/ban', requireAdmin, ctfStageIdInput('userId', 'participant'), async (req, res) => {
  try {
    const { reason } = req.body;
    await CTFHelpers.banUser(Number(req.params.userId), reason || 'Banned by admin', req.user.id);
    res.json({ message: 'User banned from CTF' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

// Admin: unban user
router.post('/admin/participants/:userId/unban', requireAdmin, ctfStageIdInput('userId', 'participant'), async (req, res) => {
  try {
    await CTFHelpers.unbanUser(Number(req.params.userId));
    res.json({ message: 'User unbanned' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unban user' });
  }
});

// Admin: remove participant from CTF entirely (they can re-register)
router.post('/admin/participants/:userId/remove', requireAdmin, ctfStageIdInput('userId', 'participant'), async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    const participant = await CTFHelpers.findParticipant(userId);
    if (!participant) return res.status(404).json({ error: 'Participant not found' });

    await ctfRuns.reset(userId,()=>CTFHelpers.reset({participantId:participant.id,userId,remove:true}));

    leaderboardRefresh.requestRefresh();
    await leaderboardRefresh.flush({ throwOnError: true });
    res.json({ message: `${participant.username} removed from CTF. They can re-register.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove participant' });
  }
});

// Admin: clear technique blocklist
router.post('/admin/blocklists/technique/clear', requireAdmin, async (req, res) => {
  try {
    const { stageId } = req.body;
    const count = await CTFHelpers.clearTechniqueBlocklist(stageId || null);
    res.json({ message: `Technique blocklist cleared (${count} entries removed)` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clear technique blocklist' });
  }
});

// Admin: clear payload blocklist
router.post('/admin/blocklists/payload/clear', requireAdmin, async (req, res) => {
  try {
    const { stageId } = req.body;
    const count = await CTFHelpers.clearPayloadBlocklist(stageId || null);
    res.json({ message: `Payload blocklist cleared (${count} entries removed)` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clear payload blocklist' });
  }
});

// Admin: full CTF reset
router.post('/admin/reset', requireAdmin, async (req, res) => {
  try {
    const { confirm } = req.body;
    if (confirm !== 'RESET_CTF_CONFIRM') return res.status(400).json({ error: 'Confirmation required. Send confirm: "RESET_CTF_CONFIRM"' });

    const owners=await CTFHelpers.listOwners();
    for(const owner of owners)ctfRuns.cancel(owner.user_id);
    await CTFHelpers.reset({all:true});

    leaderboardRefresh.requestRefresh();
    res.json({ message: 'CTF reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset CTF' });
  }
});

module.exports = { router, leaderboardRefresh, resetOwner: (owner, work) => ctfRuns.reset(owner, work) };
