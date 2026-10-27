'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadAndValidate, files } = require('../scripts/lib/ctfSupportedAdminActionManifest');
const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');
function altered(file, before, after) {
  const original = source(file);
  assert(original.includes(before), `Fixture source changed: ${file}`);
  return { [file]: original.replace(before, after) };
}
function rejects(file, before, after, reason) {
  assert.throws(() => loadAndValidate({ root, sources: altered(file, before, after) }), reason);
}

test('thirteen advertised CTF admin action variants have connected source joins and honest limits', () => {
  const review = loadAndValidate({ root });
  assert.equal(review.actions.length, 13);
  assert.equal(new Set(review.actions.map(a => a.id)).size, 13);
  assert.match(review.scope, /partition/);
  assert.match(review.qualification, /unverified/);
  assert.match(review.unresolved, /outside these thirteen/);
  assert.equal(review.actions.filter(a => a.applicability === 'manual_admin_model_preview_ungraded_no_judge_or_credit_claim').length, 1);
  assert.equal(review.unresolvedActions.length, 5);
  assert(review.unresolvedActions.every(a => a.status === 'source_unreviewed'));
  assert.equal(review.routeOnly.length, 2);
  assert.equal(review.actions.find(a => a.id === 'ctf.admin.config.save').parameterizedKeys.length, 15);
  for (const id of ['ctf.admin.blocklist.technique.clear', 'ctf.admin.blocklist.payload.clear']) {
    const confirmation = review.actions.find(a => a.id === id).confirmation;
    assert.match(confirmation, /rendered ConfirmDialog/);
    assert.doesNotMatch(confirmation, /window\.confirm/);
  }
});

test('comments and strings cannot stand in for executable UI, route, or effect joins', () => {
  const panel = files.panel;
  const original = source(panel);
  const before = "`/api/ctf/admin/participants/${userId}/ban`";
  const changed = original.replace(before, "`/api/ctf/admin/participants/${userId}/noop`") + `\n// ${before}\n`;
  assert.throws(() => loadAndValidate({ root, sources: { [panel]: changed } }), /handleBan endpoint changed/);
  const router = files.router;
  rejects(router, "['ban','ban']", "['ban','noop'] /* ['ban','ban'] */", /Participant route\/kind mapping changed/);
  const projection = files.projection;
  rejects(projection, 'await m.reset({all:true})', "await m.reset({all:false}); const decoy='await m.reset({all:true})'", /Global reset effect changed/);
});

test('wrong endpoint, method, kind, handler, and ambiguous joins fail closed', () => {
  rejects(files.panel, "recovery.request('post',`/api/ctf/admin/participants/${userId}/reset`", "recovery.request('put',`/api/ctf/admin/participants/${userId}/reset`", /confirmReset method changed/);
  rejects(files.router, "'/admin/participants/:userId/'+route", "'/admin/people/:userId/'+route", /Participant route path changed/);
  rejects(files.router, "['remove','owner_remove']", "['remove','owner_reset']", /Participant route\/kind mapping changed/);
  rejects(files.panel, "onClick={() => stageBanAction(entry, 'unban')}", "onClick={() => stageBanAction(entry, 'ban')}", /Visible control/);
  rejects(files.router, "for(const memory of ['technique','payload'])", "for(const memory of ['technique','payload'])router.post('/admin/blocklists/'+memory+'/clear',auth(false,true),body(['stageId']),mutate('blocklist_clear',req=>({memory,stageId:null}))); for(const memory of ['technique','payload'])", /expected one executable source join/);
});

test('blocklist rendered confirmation binds stage, cancel, authority, and exclusive destructive controls', () => {
  rejects(files.panel,
    'if (destructiveActionRef.current || stagedBlocklistRef.current || stagedResetRef.current) return;',
    'if (destructiveActionRef.current || stagedBlocklistRef.current || false) return;',
    /guard destructiveActionRef/);
  rejects(files.panel,
    'stagedBlocklistRef.current = null;\n    setBlocklistDialog(null);\n  };',
    'stagedBlocklistRef.current = null;\n    setBlocklistDialog(\'technique\');\n  };',
    /Blocklist cancel must retire stage/);
  rejects(files.panel,
    'if (!authority.isCurrent(staged.authority)) return;\n    const { type } = staged;',
    'if (authority.isCurrent(staged.authority)) return;\n    const { type } = staged;',
    /guard !authority.isCurrent/);
  rejects(files.panel, 'onConfirm={clearBlocklist}', 'onConfirm={fullReset}',
    /staged blocklist confirmation dialog|Confirmation dialog clearBlocklist/);
  rejects(files.panel, 'onClick={() => requestClearBlocklist(\'technique\')}',
    'onClick={() => clearBlocklist(\'technique\')}', /Visible control/);
  rejects(files.panel, 'disabled={destructiveBusy}', 'disabled={false}',
    /mutually exclusive visible controls/);
  rejects(files.panel,
    "if (resetConfirm !== 'RESET_CTF_CONFIRM' || destructiveActionRef.current || stagedBlocklistRef.current) return;",
    "if (resetConfirm !== 'RESET_CTF_CONFIRM' || destructiveActionRef.current) return;",
    /guard resetConfirm/);
  const panel = files.panel;
  const original = source(panel);
  const before = 'if (!authority.isCurrent(staged.authority)) return;\n    const { type } = staged;';
  const changed = original.replace(before, 'if (true) return;\n    const { type } = staged;')
    + '\n// if (!authority.isCurrent(staged.authority)) return;\n';
  assert.throws(() => loadAndValidate({ root, sources: { [panel]: changed } }), /guard !authority.isCurrent/);
});

test('disconnected production, runtime, effect adapter, and recovery paths fail closed', () => {
  rejects(files.production, "require('./ctfAuthorityApplication')", "require('./legacyCtfAuthorityApplication')", /Imported createCtfAuthorityApplication/);
  rejects(files.assembly, "require('./ctfAuthorityRuntime')", "require('./legacyCtfAuthorityRuntime')", /Imported createCtfAuthorityRuntime/);
  rejects(files.assembly, "require('../routes/ctfAuthorityRouter')", "require('../routes/ctf')", /Imported createCtfAuthorityRouter/);
  rejects(files.runtime, "require('./ctfAuthorityFacade')", "require('./legacyCtfAuthorityFacade')", /Imported createCtfAuthorityFacade/);
  rejects(files.projection, "require('./ctfDb')", "require('./legacyCtfDb')", /Imported createCtfMutationAdapter/);
  rejects(files.app, 'ctfAuthorityRouter(req,res,next)', "'ctfAuthorityRouter(req,res,next)'", /Deferred CTF route does not invoke published router/);
  rejects(files.assembly, 'routes(req,res,next)', "'routes(req,res,next)'", /Application router does not invoke constructed routes/);
  rejects(files.app, 'const authority = await checked(', 'const unusedAuthority = await checked(', /binding authority/);
  rejects(files.production, 'candidate=createCtfAuthorityApplication(', 'unusedCandidate=createCtfAuthorityApplication(', /Created application is not production candidate/);
  rejects(files.assembly, 'const runtime=createCtfAuthorityRuntime(', 'const unusedRuntime=createCtfAuthorityRuntime(', /binding runtime/);
  rejects(files.assembly, 'const routes=createCtfAuthorityRouter(', 'const unusedRoutes=createCtfAuthorityRouter(', /binding routes/);
  rejects(files.assembly, 'const routes=createCtfAuthorityRouter({runtime,', 'const routes=createCtfAuthorityRouter({runtime:otherRuntime,', /Router runtime or authentication injection changed/);
  rejects(files.assembly, 'return Object.freeze({router,runtime,', 'return Object.freeze({router:otherRouter,runtime,', /Application does not return connected router and runtime/);
  rejects(files.runtime, 'signal=>facade.execute({...args,signal})', 'signal=>otherFacade.execute({...args,signal})', /Runtime mutate does not execute through facade/);
  rejects(files.projection, 'm.clearTechniqueBlocklist:m.clearPayloadBlocklist', 'm.clearPayloadBlocklist:m.clearTechniqueBlocklist', /Blocklist effect branch changed/);
  rejects(files.projection, 'const m=createCtfMutationAdapter(client,', 'const m=otherMutationAdapter(client,', /Projection effect adapter disconnected/);
  rejects(files.router, "['operations','operationId','recoverOperation']", "['operations','operationId','otherRecovery']", /Operation recovery route changed/);
});

test('stage and configuration variants reject endpoint, handler, and catalog effect drift', () => {
  rejects(files.panel, "recovery.request('put',`/api/ctf/admin/stages/${id}/content`", "recovery.request('put',`/api/ctf/admin/stages/${id}/other`", /handleSaveTeaching request mapping changed/);
  rejects(files.panel, "recovery.request('delete',`/api/ctf/admin/stages/${staged.id}`", "recovery.request('post',`/api/ctf/admin/stages/${staged.id}`", /confirmDelete request mapping changed/);
  rejects(files.router, "mutate('catalog_mutation',req=>({action:'delete',stageId:req.params.id,fields:{}}))", "mutate('catalog_mutation',req=>({action:'update',stageId:req.params.id,fields:{}}))", /Stage delete catalog dispatch changed/);
  rejects(files.router, "mutate('config_mutation',req=>({key:req.body.key,value:req.body.value}))", "mutate('config_mutation',req=>({key:req.body.value,value:req.body.key}))", /Config mutation dispatch changed/);
  rejects(files.projection, 'm.updateStage(stage,b.fields)', 'm.updateStage(stage,b.key)', /Catalog update\/delete effect mapping changed/);
  rejects(files.projection, 'm.updateConfig(b.key,b.value)', 'm.updateConfig(b.value,b.key)', /Config effect mapping changed/);
  rejects(files.panel, 'onSave={(id, data) => stageSaveAdvanced(id, data, editor)}', 'onSave={handleDelete}', /StageEditForm onSave binding changed/);
  rejects(files.panel, 'onConfirm={() => confirmSaveAdvanced(advancedReview)}', 'onConfirm={() => confirmSaveAdvanced(null)}', /Advanced Save rendered confirmation/);
  rejects(files.panel, 'advancedReviewRef.current = staged;', 'advancedReviewRef.current = null;', /Advanced Save exact editor\/authority confirmation/);
  rejects(files.panel, 'onSave={onSaveTeaching}', 'onSave={onSave}', /TeachingContentForm save binding changed/);
  rejects(files.panel, 'onConfirm={() => handleSaveTeaching(teachingReview)}', 'onConfirm={() => handleSaveTeaching(null)}', /Teaching Save rendered confirmation/);
  rejects(files.panel, 'Object.keys(CONFIG_LABELS)', 'Object.keys(OTHER_LABELS)', /Config editable key source changed/);
  rejects(files.panel, 'onConfirm={() => confirmConfigSave(configReview)}', 'onConfirm={() => cancelConfigSave(configReview)}', /Config Save rendered confirmation/);
  rejects(files.panel, "recovery.request('post','/api/ctf/admin/config'", "recovery.request('put','/api/ctf/admin/config'", /confirmConfigSave request mapping changed/);
  rejects(files.panel, '{ key: staged.key, value: staged.value }', '{ key: staged.value, value: staged.key }', /confirmConfigSave request mapping changed/);
  rejects(files.panel, "{ headers: { Authorization: `Bearer ${staged.authority.token}` } });\n      mutationCompleted = true;", "{ headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } });\n      mutationCompleted = true;", /Config staged authority or readback/);
  rejects(files.panel, 'onClick={() => stageConfigSave(key, config[key])}', 'onClick={() => confirmConfigSave(key, config[key])}', /Visible control/);
  rejects(files.panel, "onChange={(on) => stageConfigSave(key, on ? 'true' : 'false')}", "onChange={(on) => confirmConfigSave(key, on ? 'true' : 'false')}", /Stage\/config toggle controls changed/);
  rejects(files.panel, 'onConfirm={() => confirmDelete(deleteReview)}', 'onConfirm={() => cancelDelete(deleteReview)}', /Stage delete rendered confirmation/);
});

test('preview remains an ungraded direct handler with captured stage and configured guardian', () => {
  rejects(files.router, 'wrap(previewHandler));', "mutate('catalog_mutation',req=>({action:'preview',stageId:req.params.id,fields:req.body})));", /Preview direct handler dispatch changed/);
  rejects(files.assembly, "require('./ctfAuthorityPreviewRoute')", "require('./legacyPreview')", /Imported createCtfAuthorityPreviewRoute/);
  rejects(files.assembly, 'createCtfAuthorityPreviewRoute({runtime})', 'createCtfAuthorityPreviewRoute({runtime:otherRuntime})', /Preview handler runtime injection changed/);
  rejects(files.preview, 'runCtfGuardianGraph(stage,payload,', 'otherGuardianGraph(stage,payload,', /Preview model\/defense path changed/);
  rejects(files.panel, '`/api/ctf/admin/stages/${preview.stageId}/preview`', '`/api/ctf/admin/stages/${preview.stageId}/other`', /Preview captured request changed/);
  rejects(files.panel, 'onPreview={() => openPreview(stage, editor)}', 'onPreview={setPreviewStage}', /StageEditForm onPreview binding changed/);
  rejects(files.panel, 'pendingRef.current = controller;', 'pendingRef.current = null;', /Preview authority, singleflight, or response fence changed/);
});
