'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const {WORKSHOP_OBJECTIVES}=require('../server/config/workshopCatalog');
const hints=require('../server/data/workshopHints').sensitive_info_disclosure;
const solutions=require('../server/data/sensitiveInfoSolutions').solutions;
const successor=require('../scripts/generate-finflow-admin-enum-copy-defaults');
const sql=fs.readFileSync(path.join(__dirname,'../docs/modernization/drafts/finflow-recon-scope-managed-defaults.candidate.sql'),'utf8');
test('FinFlow recon copy draft updates only exact managed prior defaults',()=>{
 assert.match(sql,/DRAFT ONLY/);assert.match(sql,/0066 is reserved/);
 assert.equal((sql.match(/\('tool_enum','(?:label|hint_content|solution_content)'/g)||[]).length,3);
 assert.equal((sql.match(/\('admin_enum','(?:label|hint_content|solution_content)'/g)||[]).length,3);
 assert.match(sql,/p\.provenance_state='managed'/);
 assert.match(sql,/p\.applied_default_hash=d\.old_hash/);
 assert.match(sql,/p\.applied_default_document=d\.old_document/);
 assert.match(sql,/END = d\.old_document/);
 assert.doesNotMatch(sql,/provenance_state\s+IN\s*\([^)]*legacy_unknown|provenance_state='legacy_unknown'/);
 assert.doesNotMatch(sql,/INSERT INTO workshop_platform\.catalog_field_defaults/);
 assert.doesNotMatch(sql,/SET\s+(?:objective_id|is_enabled|catalog_active|ordinal|category)\s*=/);
});
test('0067 draft preserves six exact documents and binds its superseded fields through 0068 and 0081',()=>{
 assert.equal(require('node:crypto').createHash('sha256').update(sql).digest('hex'),'5df10119b77c85b52e72dd08477fa636059e7f192660d349b344f8b972492a2f');
 const rows=[...sql.matchAll(/\('([^']+)','([^']+)',\$document\$(.*?)\$document\$::jsonb,'([a-f0-9]{64})',\$document\$(.*?)\$document\$::jsonb,'([a-f0-9]{64})'\)/g)];
 assert.equal(rows.length,6);
 const labels=Object.fromEntries(WORKSHOP_OBJECTIVES.sensitive_info_disclosure.map(row=>[row.id,row.text]));
 const successorByField=new Map(successor.buildRows()
  .filter(row=>row.objectiveId==='admin_enum'&&row.oldLineage==='reserved-identity0067')
  .map(row=>[row.fieldName,row]));
 let directCurrent=0,successorLinks=0;
 for(const [,objectiveId,fieldName,oldJson,oldHash,newJson,newHash] of rows){
  const oldDocument=JSON.parse(oldJson),newDocument=JSON.parse(newJson);
  assert.equal(provenance.hashDocument(oldDocument),oldHash);
  assert.equal(provenance.hashDocument(newDocument),newHash);
  const expected=fieldName==='label'?labels[objectiveId]:fieldName==='hint_content'?hints[objectiveId]:solutions[objectiveId];
  const next=objectiveId==='admin_enum'&&fieldName!=='label'?successorByField.get(fieldName):null;
  if(next){
   assert.equal(next.oldHash,newHash);
   assert.deepEqual(next.oldDocument,newDocument);
   const latest=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0081_finflow_admin_enum_multiturn_defaults.sql'),'utf8');
   const bridge=[...latest.matchAll(/\('admin_enum','([^']+)','canonical-before-0081',\$document\$(.*?)\$document\$::jsonb,'([a-f0-9]{64})',\$document\$(.*?)\$document\$::jsonb,'([a-f0-9]{64})'\)/g)].find(row=>row[1]===fieldName);
   assert.ok(bridge,'forward guidance retains the exact historical target');
   assert.deepEqual(JSON.parse(bridge[2]),next.newDocument);
   assert.equal(bridge[3],next.newHash);
   assert.deepEqual(JSON.parse(bridge[4]),provenance.document(expected));
   assert.equal(bridge[5],provenance.hashDocument(provenance.document(expected)));
   successorLinks+=1;
  }else{
   assert.deepEqual(newDocument,provenance.document(expected));
   directCurrent+=1;
  }
  assert.notDeepEqual(oldDocument,newDocument);
 }
 assert.equal(directCurrent,4);
 assert.equal(successorLinks,2);
});
