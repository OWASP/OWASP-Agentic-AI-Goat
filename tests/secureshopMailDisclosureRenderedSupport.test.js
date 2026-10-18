'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {stageDisclosureCandidate}=require('./fixtures/secureshopMailDisclosureRenderedSupport');
test('private candidate staging preserves qualified source without edits and cannot stage the live repository',()=>{
 const evidence=fs.mkdtempSync(path.join(os.tmpdir(),'disclosure-stage-control-')),root=path.join(evidence,'source'),files=['server/config/secureshopCurriculum.js','server/services/secureshopMailObjectiveReadiness.js'],original=files.map(f=>fs.readFileSync(f,'utf8')),prior={PG_TEST_DISPOSABLE:process.env.PG_TEST_DISPOSABLE,DVAIA_ISOLATED_TEST_WORKSPACE:process.env.DVAIA_ISOLATED_TEST_WORKSPACE};
 const donor={[files[0]]:"{ id: 'ss_mail_cross_persona_read', qualification: 'native-model' }\n",[files[1]]:'ss_mail_cross_persona_read:true\n'};
 try{for(const f of files){fs.mkdirSync(path.dirname(path.join(root,f)),{recursive:true});fs.writeFileSync(path.join(root,f),donor[f],{mode:0o444});}process.env.PG_TEST_DISPOSABLE='yes';process.env.DVAIA_ISOLATED_TEST_WORKSPACE=root;const rows=stageDisclosureCandidate(root,evidence);assert.equal(rows.length,0);
 // Staging admission uses minimal synthetic text; real content is read only in main.
 const live=require('../server/config/secureshopCurriculum');
 const {document}=require('../server/database/postgres/catalogDefaultProvenance');
 // Exercise the same strict source-document boundary used by the canonical seed.
 // JSON.stringify alone would hide undefined array entries by converting them to null.
 for(const objective of live.OBJECTIVES){
  assert.doesNotThrow(()=>document(live.HINTS[objective.id]),`hint ${objective.id}`);
  assert.doesNotThrow(()=>document(live.SOLUTIONS[objective.id]),`solution ${objective.id}`);
 }
 const disclosure=live.SOLUTIONS.ss_mail_cross_persona_read;
 assert.equal(typeof disclosure.examples[0].action,'string');
 assert.match(disclosure.examples[0].action,/Read for assessment, then Check saved disclosure/);
 assert(live.HINTS.ss_mail_cross_persona_read.hints.some(h=>h.includes('Reload is ungraded')));
 assert(!disclosure.tips.some(t=>t.includes('no disclosure assessment button')));
 assert(!disclosure.tips.some(t=>t.includes('Production availability remains pending')));
 assert(live.OBJECTIVES.every(o=>o.defaultEnabled===false));
 assert.equal(typeof disclosure.examples[0].explanation,'string');
 assert.throws(()=>document({...disclosure,examples:[undefined]}),/catalog defaults must be JSON values/);
 assert.equal(live.OBJECTIVES.find(o=>o.id==='ss_mail_cross_persona_read').qualification,'native-model');
 assert.equal(live.isQualifiedObjective('ss_mail_cross_persona_read'),true);
assert(rows.every(r=>r.before!==r.after));for(const f of files){assert.equal(fs.statSync(path.join(root,f)).mode&0o777,0o444);assert.equal(fs.readFileSync(path.join(root,f),'utf8'),donor[f]);}assert.equal(JSON.parse(fs.readFileSync(path.join(evidence,'mail-disclosure-private-staging.json'))).productionPromotion,false);assert.throws(()=>stageDisclosureCandidate(process.cwd(),evidence));assert.deepEqual(stageDisclosureCandidate(root,evidence),[]);for(const [i,f]of files.entries())assert.equal(fs.readFileSync(f,'utf8'),original[i]);}
 finally{for(const[k,v]of Object.entries(prior))if(v===undefined)delete process.env[k];else process.env[k]=v;fs.rmSync(evidence,{recursive:true,force:true});}
});

test('pending synthetic catalog stages exactly three chained edits and preserves unrelated content',()=>{
 const {createHash}=require('node:crypto'),digest=text=>createHash('sha256').update(text).digest('hex');
 const evidence=fs.mkdtempSync(path.join(os.tmpdir(),'disclosure-pending-control-')),root=path.join(evidence,'source');
 const curriculum='server/config/secureshopCurriculum.js',readiness='server/services/secureshopMailObjectiveReadiness.js';
 const note=' Production availability remains pending until the complete native, actual Judge and connected UI qualification is accepted.';
 const source="{ id: 'ss_mail_cross_persona_read', qualification: 'pending' }\n"+
  "const unrelatedHints = {other:['Instructor hint remains']};\nconst unrelatedSolutions = {other:{action:'Instructor solution remains'}};\n"+
  'Disclosure instructions.'+note+'\n';
 const initialReadiness='ss_mail_cross_persona_read:false\nother_objective:false\n';
 const promoted=source.replace("qualification: 'pending'","qualification: 'native-model'"),expected=promoted.replace(note,'');
 const prior={PG_TEST_DISPOSABLE:process.env.PG_TEST_DISPOSABLE,DVAIA_ISOLATED_TEST_WORKSPACE:process.env.DVAIA_ISOLATED_TEST_WORKSPACE};
 try{
  for(const [file,text]of [[curriculum,source],[readiness,initialReadiness]]){fs.mkdirSync(path.dirname(path.join(root,file)),{recursive:true});fs.writeFileSync(path.join(root,file),text,{mode:0o444});}
  process.env.PG_TEST_DISPOSABLE='yes';process.env.DVAIA_ISOLATED_TEST_WORKSPACE=root;
  const rows=stageDisclosureCandidate(root,evidence);
  assert.deepEqual(rows,[
   {file:curriculum,before:digest(source),after:digest(promoted)},
   {file:readiness,before:digest(initialReadiness),after:digest('ss_mail_cross_persona_read:true\nother_objective:false\n')},
   {file:curriculum,before:digest(promoted),after:digest(expected)},
  ]);
  assert.equal(rows[0].after,rows[2].before);assert(rows.every(row=>row.before!==row.after));
  assert.equal(fs.readFileSync(path.join(root,curriculum),'utf8'),expected);
  assert.equal(fs.readFileSync(path.join(root,readiness),'utf8'),'ss_mail_cross_persona_read:true\nother_objective:false\n');
  for(const file of [curriculum,readiness])assert.equal(fs.statSync(path.join(root,file)).mode&0o777,0o444);
  const manifest=JSON.parse(fs.readFileSync(path.join(evidence,'mail-disclosure-private-staging.json')));
  assert.equal(manifest.productionPromotion,false);assert.equal(manifest.candidateOnly,true);assert.deepEqual(manifest.edits,rows);
  assert.throws(()=>stageDisclosureCandidate(process.cwd(),evidence));
  assert.deepEqual(stageDisclosureCandidate(root,evidence),[]);
  assert.equal(fs.readFileSync(path.join(root,curriculum),'utf8'),expected);
 }finally{for(const[key,value]of Object.entries(prior))if(value===undefined)delete process.env[key];else process.env[key]=value;fs.rmSync(evidence,{recursive:true,force:true});}
});
