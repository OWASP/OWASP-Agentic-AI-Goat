'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadAndValidate, files } = require('../scripts/lib/ctfSupportedParticipantActionManifest');
const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');
function rejects(file, before, after, reason) {
  const original = source(file);
  assert(original.includes(before), `Fixture source changed: ${file}`);
  assert.throws(() => loadAndValidate({ root, sources: { [file]: original.replace(before, after) } }), reason);
}

test('five participant variants form a bounded source-reviewed partition', () => {
  const review = loadAndValidate({ root });
  assert.equal(review.actions.length, 5);
  assert.deepEqual(review.actions.map(a => a.id), ['register','start','hint','attempt','practice'].map(s => `ctf.participant.${s}`));
  assert.match(review.scope, /partition/);
  assert.match(review.qualification, /unverified/);
  assert.match(review.unresolved, /remain open/);
  assert.match(review.actions[3].recovery, /GET publications/);
  assert.match(review.actions[4].consequence, /no scored transcript/);
});

test('client request, mounted navigation, confirmation and mode joins reject decoys', () => {
  rejects(files.dashboard, "'/api/ctf/register'", "'/api/ctf/registration' /* '/api/ctf/register' */", /Register UI endpoint/);
  rejects(files.dashboard, '<form onSubmit={handleRegister}', '<form onSubmit={otherRegister}', /Registration form submit/);
  rejects(files.dashboard, "navigate('/ctf/challenge'", "navigate('/ctf/other'", /Stage selection/);
  rejects(files.challenge, '`/api/ctf/stage/${initialStage.id}/start`', "`/api/ctf/stage/${initialStage.id}/other`", /Start UI request/);
  rejects(files.challenge, '`/api/ctf/stage/${stage.id}/hint`', '`/api/ctf/stage/${stage.id}/other`', /hint UI request/);
  rejects(files.challenge, '{ hintIndex: confirmHintIndex }', '{ hintIndex: otherIndex }', /Hint UI endpoint/);
  rejects(files.challenge, '`/api/ctf/stage/${stage.id}/attempt`', '`/api/ctf/stage/${stage.id}/other`', /Attempt UI endpoint/);
  rejects(files.challenge, '`/api/ctf/stage/${stage.id}/practice`', '`/api/ctf/stage/${stage.id}/other`', /Practice UI endpoint/);
  rejects(files.challenge, "selectPracticeMode('fixed')", "selectPracticeMode('vulnerable')", /fixed visible mode/);
});

test('supported authority route and effect joins fail on swapped handlers, kinds and adapter', () => {
  rejects(files.assembly, "require('./ctfAuthorityAttemptRoute')", "require('./otherAttemptRoute')", /supported import/);
  rejects(files.assembly, 'createCtfFixedPracticeRoute({runtime,coordinator})', 'createCtfFixedPracticeRoute({runtime:otherRuntime,coordinator})', /Practice handler assembly/);
  rejects(files.assembly, 'createCtfAuthorityRouter({runtime,attemptHandlers,previewHandler,practiceHandler,authenticate:validateSession})', 'createCtfAuthorityRouter({runtime,attemptHandlers,previewHandler,practiceHandler:otherHandler,authenticate:validateSession})', /router injection/);
  rejects(files.router, "mutate('register',req=>req.body??{})", "mutate('start',req=>req.body??{})", /register handler or kind/);
  rejects(files.router, "mutate('hint',req=>({stageId:req.params.stageId", "mutate('start',req=>({stageId:req.params.stageId", /hint handler or kind/);
  rejects(files.router, "wrap(attemptHandlers.attempt)", "wrap(practiceHandler)", /attempt handler or kind/);
  rejects(files.router, "wrap(practiceHandler)", "wrap(otherHandler)", /practice handler or kind/);
  rejects(files.router, "router.post('/register',auth(),body(['displayName','teamName']),mutate('register',req=>req.body??{}));", "router.post('/register',auth(),body(['displayName','teamName']),mutate('register',req=>req.body??{}));router.post('/register',auth(),body(['displayName','teamName']),mutate('register',req=>req.body??{}));", /expected one executable join/);
  rejects(files.projection, 'm.purchaseHint(s.progressId,b.expectedHints,b.cost)', "m.purchaseHint(s.progressId,b.expectedHints,0); const decoy='m.purchaseHint(s.progressId,b.expectedHints,b.cost)'", /hint m.purchaseHint effect mapping/);
  rejects(files.projection, 'm.startStage(p,stage)', 'm.startStage(p,otherStage)', /start m.startStage effect mapping/);
  rejects(files.prepare, "body={expectedHints:s.progress.hints_used,cost:s.config['hint_cost_'+(s.progress.hints_used+1)]}", "body={expectedHints:s.progress.hints_used,cost:0}", /Server-owned hint cost/);
});

test('graded attempt and unscored practice stay distinct, with consequence recovery retained', () => {
  rejects(files.attemptRoute, 'runtime.attempt({req,runId:execution.runId', 'runtime.other({req,runId:execution.runId', /Attempt route owner\/runtime/);
  rejects(files.decision, 'judge({stage,processedResponse:visibleResponse,realModel:true', 'otherJudge({stage,processedResponse:visibleResponse,realModel:true', /Canonical attempt Judge/);
  rejects(files.worker, "event.command?.kind==='decision'?applyCtfDecisionProjection", "event.command?.kind==='decision'?applyCtfProjection", /Authorized decision projection worker/);
  rejects(files.predefense, "applied(consumed.blockedOperationId,'record_blocked_attempt'", "applied(consumed.blockedOperationId,'admit_attempt'", /Attempt admission\/blocked lifecycle/);
  rejects(files.projection, 'm.incrementAttempts(p,stage,b.failed,s.progressId)', 'm.otherAttempts(p,stage,b.failed,s.progressId)', /Attempt admission\/blocked effects/);
  rejects(files.decisionProjection, "d.accepted?f.stageScore:null", 'f.stageScore', /Accepted-only score/);
  rejects(files.practice, 'provider.generateResponse(', 'otherProvider.generateResponse(', /Practice configured model/);
  rejects(files.practice, 'scoringEligible:false', 'scoringEligible:true', /Practice unscored response/);
  rejects(files.recovery, '`/api/ctf/publications/${state.decisionId}`', '`/api/ctf/other/${state.decisionId}`', /Attempt continuation/);
  rejects(files.recovery, '`/api/ctf/decisions/${state.admissionId}/authorize`', '`/api/ctf/other/${state.admissionId}/authorize`', /Attempt continuation/);
  rejects(files.facade, 'worker.pump({maxEvents:1,signal})', 'otherWorker.pump({maxEvents:1,signal})', /Operation recovery worker/);
});
