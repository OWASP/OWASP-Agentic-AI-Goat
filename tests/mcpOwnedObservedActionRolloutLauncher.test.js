'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'postgres/run-mcp-owned-observed-action-rollout.py'),'utf8');
test('runner upgrade pins immutable rollback image and never recreates Mailpit',()=>{
 assert.match(source,/old_image=old\['Image'\]/);assert.match(source,/docker\+\['tag',old_image,rollback_tag\]/);
 assert.match(source,/rollback-image-restore/);assert.match(source,/--force-recreate','--no-build','--wait','mcp-owned-sandbox/);
 assert.doesNotMatch(source,/compose'.*up'.*mailpit/);assert.doesNotMatch(source,/rm','--force',MAILPIT/);
 assert.ok(source.indexOf('runner_replaced=True')<source.indexOf("stage='runner-replace'"),'uncertain compose creation must roll back');
});
test('runner upgrade freezes admission then proves durable and lock drain before replacement',()=>{
 const stop=source.indexOf('pause.stop(a.watcher_pid,os.kill)');const backendStop=source.indexOf('pause.stop(active_backend,os.kill)');const drain=source.indexOf('require_drained();');const replace=source.indexOf("stage='runner-replace'");
 assert.ok(stop>0&&backendStop>stop&&drain>backendStop&&replace>drain);assert.match(source,/status='running'/);assert.match(source,/status='started'/);assert.match(source,/target-lock-drain/);
});
test('runner upgrade preserves exact volume, Mailpit and private configuration',()=>{
 assert.match(source,/VOLUME_DEST='\/sandbox\/owned-targets'/);assert.match(source,/targetVolumeSha256/);assert.match(source,/volume_digest\(\)!=volume_before/);
 assert.match(source,/now_mail\['Id'\]!=mail_identity\['id'\]/);assert.match(source,/mail_count\(\)!=mail_identity\['count'\]/);
 assert.match(source,/sha\(ROOT\/'\.env'\)!=private_sha/);assert.match(source,/sha\(MANAGED\)!=managed_sha/);
});
test('runner rollout requires protected v2, observed action, and CodeBot before authenticated six-objective report',()=>{
 assert.match(source,/protectedStateCapability/);assert.match(source,/CAPABILITY='mcp-owned-protected-state-transition\.v2'/);
 assert.match(source,/observedActionCapability/);assert.match(source,/OBSERVED_CAPABILITY='mcp-owned-observed-action\.v1'/);
 assert.match(source,/OBSERVED_QUALIFICATION='mcp-owned-connected\.observed-action-v1'/);
 assert.match(source,/SIX=FIVE\+\('mcp_tool_poisoning',\)/);
 assert.match(source,/codebotIsolation/);assert.match(source,/bwrap-codebot-v1/);assert.match(source,/tuple\(qualified\)!=tuple\(expected_objectives\)/);
 assert.match(source,/owned-targets\/health/);assert.match(source,/def runner_status\(\):/);
 assert.match(source,/api\/workshop\/mcp\/infra/);assert.match(source,/api\/auth\/logout/);
 assert.match(source,/private_cookie_opener/);assert.match(source,/validate_logout_result/);assert.match(source,/validate_revoked_status/);
});
test('runner rollout changes only the managed release gate and rolls it back after any uncertain attempt',()=>{
 assert.match(source,/activateObservedAction:true/);
 assert.ok(source.indexOf('managed_transition_attempted=True')<source.indexOf("stage='managed-observed-action-activation'"));
 assert.match(source,/write_private_atomic\(MANAGED,managed_bytes,clear_owned_pending=True\)/);
 assert.match(source,/if parse_env\(private_file\(MANAGED\)\)!=expected_config/);
 assert.match(source,/sha\(ROOT\/'\.env'\)!=private_sha/);
});
test('runner rollout preserves instructor and learner projection while changing exact five to exact six',()=>{
 assert.match(source,/before_smoke=smoke\(QUALIFICATION,FIVE\)/);
 assert.match(source,/smoke_result=smoke\(OBSERVED_QUALIFICATION,SIX\)/);
 assert.match(source,/progressDigest/);
 assert.match(source,/instructor or learner progress projection changed/);
});
test('runner upgrade consumes an exact source-bound grant after actual handle handshake',()=>{
 const wait=source.indexOf('WAITING_OWNER_HANDLE');const consume=source.indexOf("g.update(status='consumed'");assert.ok(wait>0&&consume>wait);
 assert.match(source,/g\.get\('sourceHashes'\)!=current/);assert.match(source,/g\.get\('allowedLaunches'\)!=1/);
 assert.match(source,/diagnostics\.jsonl/);assert.match(source,/0o600/);
 assert.match(source,/mcp-owned-observed-action-rollout-source-hashes\.json/);
 assert.doesNotMatch(source,/mcp-owned-runner-upgrade-source-hashes\.json/);
 assert.match(source,/validate_owner_handle\(owner_text,consumer_pid=os\.getpid\(\)\)/);
});

test('rollback image is retained whenever restoration or preservation remains incomplete',()=>{
 assert.match(source,/rollbackImageRetention/);assert.match(source,/rollback_retention_decision/);
 assert.ok(source.indexOf('rollback_retention_decision\(cleanup')<source.indexOf("stage='rollback-tag-cleanup'"));
});
