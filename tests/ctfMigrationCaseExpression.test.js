'use strict';
// Narrow PL/pgSQL lexical regression, not a PostgreSQL parser/qualification.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
function exposedCaseOperands(source){
 const clean=source.replace(/--[^\n]*|\/\*[\s\S]*?\*\/|'(?:''|[^'])*'|"(?:""|[^"])*"/g,s=>s.replace(/[^\n]/g,' '));
 const tokens=[...clean.matchAll(/[A-Za-z_][A-Za-z_0-9]*|[();]/g)];
 let condition=false,depth=0,previous='',hazards=[];
 for(const token of tokens){
  const value=token[0].toUpperCase();
  if((value==='IF'&&previous!=='END')||value==='ELSIF'){condition=true;depth=0;}
  else if(condition){
   if(value==='(')depth++;
   else if(value===')')depth--;
   else if(value==='CASE'&&depth===0)hazards.push(clean.slice(0,token.index).split('\n').length);
   else if(value==='THEN'&&depth===0)condition=false;
  }
  previous=value;
 }
 return hazards;
}
test('unparenthesized CASE operands expose internal THEN in PL/pgSQL IF',()=>{
 for(const expression of ['value < CASE WHEN enabled THEN 0 ELSE 1 END','value IS DISTINCT FROM CASE n WHEN 0 THEN 1 ELSE 2 END','value <> count + CASE WHEN failed THEN 1 ELSE 0 END'])assert.equal(exposedCaseOperands(`IF ${expression} THEN RETURN; END IF;`).length,1);
 assert.deepEqual(exposedCaseOperands('IF value < (CASE WHEN enabled THEN 0 ELSE 1 END) THEN RETURN; END IF;'),[]);
 assert.deepEqual(exposedCaseOperands('IF EXISTS(SELECT CASE WHEN enabled THEN 1 ELSE 0 END) THEN RETURN; END IF;'),[]);
});
test('0105 and0007 contain no exposed CASE operand in IF conditions',()=>{
 for(const file of ['db/postgres/identity-migrations/0105_ctf_lifecycle_projection.sql','db/postgres/workshop-migrations/ctf/0007_ordered_projection_receipts.sql'])assert.deepEqual(exposedCaseOperands(fs.readFileSync(path.join(__dirname,'..',file),'utf8')),[],file);
});

test('0105 predicate reads qualify RETURNS TABLE names rather than shadowing them',()=>{
 const source=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0105_ctf_lifecycle_projection.sql'),'utf8');
 const functions=source.slice(source.indexOf('CREATE FUNCTION identity.enqueue_ctf_user_command'));
 const bare=/\b(?:WHERE|AND|OR)\s+(?:state|operation_id|sequence|command_hash|applied_sequence)\b/gi;
 assert(bare.test("SELECT count(*) FROM identity.ctf_outbox WHERE state='pending'"));
 assert.deepEqual([...functions.matchAll(new RegExp(bare.source,'gi'))],[]);
});
