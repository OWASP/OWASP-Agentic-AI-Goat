'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const base=fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0106_ctf_authoritative_decisions.sql'),'utf8');
const next=fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0120_ctf_completed_proposal_authorization.sql'),'utf8');
const lock=` PERFORM 1 FROM graph_runtime.runs rr WHERE rr.run_id=p.run_id AND rr.owner_key='["CTF","'||p_actor||'"]' AND rr.generation=(b->>'ownerGeneration')::bigint FOR UPDATE;\n`;
test('forward replacement differs only by exact run lock and completed eligibility; all grants/fences retained',()=>{
 const original=base.slice(base.indexOf('CREATE FUNCTION identity.authorize_ctf_decision'));
 const restored=next.slice(next.indexOf('CREATE OR REPLACE FUNCTION')).replace('CREATE OR REPLACE FUNCTION','CREATE FUNCTION').replace(lock,'').replace("status IN ('running','completed')","status='running'");
 assert.equal(restored,original);assert.equal(next.split(lock).length,2);
});
test('new authorization locks owner then run after historical replay; terminal rejection stays closed',()=>{
 const owner=next.indexOf('PERFORM 1 FROM graph_runtime.owners'),replay=next.indexOf('RETURN QUERY SELECT prior.decision_id'),run=next.indexOf(lock),eligibility=next.indexOf("status IN ('running','completed')");
 assert(owner<replay&&replay<run&&run<eligibility);
 assert.match(next,/rr\.run_id=p\.run_id.*rr\.owner_key=.*rr\.generation=\(b->>'ownerGeneration'\)::bigint FOR UPDATE/);
 assert(!next.includes("'cancelled'"));assert(!next.includes("'failed'"));assert(!next.includes("'interrupted'"));
 assert.match(base.slice(0,base.indexOf('CREATE FUNCTION identity.authorize_ctf_decision')),/rr\.status='running'/);
});
