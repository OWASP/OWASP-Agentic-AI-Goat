'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'postgres/run-mcp-owned-runner-upgrade.py'),'utf8');
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
test('runner upgrade requires protected v2 and CodeBot before authenticated five-objective report',()=>{
 assert.match(source,/protectedStateCapability/);assert.match(source,/CAPABILITY='mcp-owned-protected-state-transition\.v2'/);
 assert.match(source,/codebotIsolation/);assert.match(source,/bwrap-codebot-v1/);assert.match(source,/validate_qualified_objectives\(qualified\)/);
 assert.match(source,/owned-targets\/health/);assert.match(source,/def runner_status\(\):/);
 assert.match(source,/api\/workshop\/mcp\/infra/);assert.match(source,/api\/auth\/logout/);
});
test('runner upgrade consumes an exact source-bound grant after actual handle handshake',()=>{
 const wait=source.indexOf('WAITING_OWNER_HANDLE');const consume=source.indexOf("g.update(status='consumed'");assert.ok(wait>0&&consume>wait);
 assert.match(source,/g\.get\('sourceHashes'\)!=current/);assert.match(source,/g\.get\('allowedLaunches'\)!=1/);
 assert.match(source,/diagnostics\.jsonl/);assert.match(source,/0o600/);
});
