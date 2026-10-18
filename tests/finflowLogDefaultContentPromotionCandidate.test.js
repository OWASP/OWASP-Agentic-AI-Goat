'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..');
const read=relative=>fs.readFileSync(path.join(root,relative));
const sha=relative=>crypto.createHash('sha256').update(read(relative)).digest('hex');
const candidate='docs/modernization/drafts/0054_finflow_log_default_content.candidate.sql';
const qualified='docs/modernization/drafts/finflow_llm_request_log_default_content_guarded.sql';
const manifest=JSON.parse(read('docs/modernization/drafts/finflow-log-default-content-promotion-candidate-2026-09-14.json'));
test('historical FinFlow default-content candidate is preserved and superseded by registered policy defaults',()=>{
 assert.match(manifest.status,/candidate|promoted/);
 assert.equal(manifest.proposedReservation.prefix,'0054');
 assert.equal(manifest.candidate.draft,candidate);assert.equal(manifest.candidate.qualifiedSource,qualified);
 assert.equal(sha(candidate),manifest.candidate.sha256);assert.equal(sha(qualified),manifest.candidate.qualifiedSourceSha256);
 assert.deepEqual(read(candidate),read(qualified));
 assert.equal(fs.existsSync(path.join(root,manifest.candidate.promotionDestination)),false,
   'the superseded draft must not become a second migration at the same prefix');
 const ledger=JSON.parse(read('tests/release-inputs/identity-migration-reservations.json'));
 const reservation=ledger.reservations.find(entry=>entry.prefix==='0054');
 assert.ok(reservation);assert.match(reservation.status,/applied/);
 assert.equal(sha('db/postgres/identity-migrations/0054_finflow_log_policy_defaults.sql'),reservation.sha256,
   'installed policy defaults match the applied reservation, not the superseded candidate');
});
test('FinFlow default-content candidate guards defaults and leaves protected state outside scope',()=>{
 const sql=read(candidate).toString('utf8');
 for(const id of ['admin_read_logs','admin_llm_logs','admin_modify_logs'])assert.match(sql,new RegExp(`objective_id='${id}'`));
 assert.match(sql,/ELSE solution_content END/);assert.match(sql,/ELSE hint_content END/);assert.match(sql,/solution_content=\$old_admin_llm_logs_solution\$/);assert.match(sql,/hint_content=\$old_admin_llm_logs_hint\$/);
 assert.match(sql,/UPDATE workshop_platform\.config_revision/);assert.match(sql,/WHERE id=1 AND EXISTS \(SELECT 1 FROM changed\)/);
 assert.doesNotMatch(sql,/UPDATE workshop_platform\.(?:user_state|completions)/);assert.doesNotMatch(sql,/INSERT INTO workshop_platform\.(?:user_state|completions)/);assert.doesNotMatch(sql,/DELETE FROM workshop_platform/);
 for(const field of ['label','category','ordinal','is_enabled','catalog_active','hint_enabled','solution_enabled'])assert.doesNotMatch(sql,new RegExp(`SET[^;]*\\b${field}\\s=`, 's'));
});
