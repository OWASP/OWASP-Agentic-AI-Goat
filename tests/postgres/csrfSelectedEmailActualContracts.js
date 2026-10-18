'use strict';
const assert=require('node:assert/strict');
function assertTerminalReplay(response,receipt){
 assert.ok(['pass','fail'].includes(receipt.verdict),'Only original terminal judgments use this denial contract');
 assert.equal(response.status,409);
 assert.deepEqual(response.body,{code:'RETRY_NOT_ALLOWED',error:'Grading retry unavailable',canRetry:false});
}
module.exports={assertTerminalReplay};

function readOllamaWireText(raw){
 assert.equal(typeof raw,'string');assert.ok(raw.trim()&&Buffer.byteLength(raw)<=1048576,'Bounded nonempty wire required');
 const lines=raw.trimEnd().split('\n');let rows;
 try{rows=[JSON.parse(raw)];}catch{rows=lines.map(line=>JSON.parse(line));}
 assert.ok(rows.length>0);let output='';
 rows.forEach((row,index)=>{
  assert.ok(row&&typeof row==='object'&&!Array.isArray(row));assert.equal(Object.hasOwn(row,'error'),false,'Provider error is not response evidence');assert.equal(row.model,'llama3.1:8b');
  assert.equal(row.done,index===rows.length-1,'Complete terminal frame required');
  const generate=Object.hasOwn(row,'response'),chat=row.message&&Object.hasOwn(row.message,'content');assert.equal(Boolean(generate&&chat),false,'Ambiguous text fields');
  if(generate){assert.equal(typeof row.response,'string');output+=row.response;}
  else if(chat){assert.equal(typeof row.message.content,'string');output+=row.message.content;}
  else assert.equal(index,rows.length-1,'Only terminal metadata may omit text');
 });
 assert.ok(output.length>0,'Empty output is not selection evidence');return output;
}
module.exports.readOllamaWireText=readOllamaWireText;

function assertResetVictimState(state){
 const {CsrfVictimSandbox,TAB_IDS}=require('../../server/services/csrfVictimSandbox');
 const expected=new CsrfVictimSandbox('fixture-reset-contract').tabs;
 assert.ok(state&&typeof state==='object');assert.deepEqual(Object.keys(state).sort(),[...TAB_IDS].sort());
 for(const tab of TAB_IDS){
  assert.equal(typeof state[tab].csrfToken,'string');assert.match(state[tab].csrfToken,/^tok_[a-z0-9]+$/);
  const {csrfToken:actualToken,...actual}=state[tab],{csrfToken:expectedToken,...baseline}=expected[tab];
  assert.deepEqual(actual,baseline,`Reset restores the complete ${tab} default state`);
 }
}
module.exports.assertResetVictimState=assertResetVictimState;
