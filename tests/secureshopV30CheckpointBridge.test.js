'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'postgres/run-secureshop-agent-host-transport-main.py'),'utf8');
const start=source.indexOf('def v30_original_receipt_v2('),end=source.indexOf('\ndef ',start+1);
const body=source.slice(start,end<0?undefined:end);
const match=body.match(/"(\{mcpRows:\(\)=>rows[^\n]*?\}),\{run:path.dirname/);
assert(match,'actual V30 recorder bridge must exist');
function recorder(reader){return vm.runInNewContext('('+match[1]+')',{rows:[{id:1}],mod:{privateCheckpointRows:reader},path,process:{argv:['node','fixture','/owned/run/result.json']}});}
test('actual V30 bridge forwards exact owned run and unchanged MCP rows',()=>{
 let called;const checkpoints=[{kind:'checkpoint'}];const r=recorder(run=>{called=run;return checkpoints;});
 assert.equal(r.mcpRows()[0].id,1);assert.equal(r.checkpointRows(),checkpoints);assert.equal(called,'/owned/run');
});
test('actual V30 bridge preserves private reader rejection',()=>{
 const error=new Error('owned checkpoint denied');assert.throws(()=>recorder(()=>{throw error;}).checkpointRows(),e=>e===error);
});
test('actual V30 bridge neither invents empty checkpoints nor suppresses missing reader',()=>{
 const empty=[];assert.equal(recorder(()=>empty).checkpointRows(),empty);
 assert.throws(()=>recorder(undefined).checkpointRows(),/privateCheckpointRows/);
});
test('actual V30 verifier retains profile environment and bounded child guard',()=>{
 assert(body.includes('question_env = v30_question_environment(profile,question_candidate)'));
 assert(body.includes("'TMPDIR': str(parent), **question_env"));assert(body.includes('timeout=60'));
 assert(body.includes("checked.returncode != 0 or checked.stdout != 'verified\\n'"));
});
