'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
// Historical 0096 qualification: canonical bytes, bounded directory views only.
function auditMigrationView(){
 const dir=path.resolve(__dirname,'../../db/postgres/identity-migrations');
 const name='0096_secureshop_audit_instruction_defaults.sql';
 const names=fs.readdirSync(dir).filter(value=>value.endsWith('.sql')).sort();
 assert.ok(names.includes(name),'0096 must remain registered');
 const before=path.join(dir,'.virtual-before-0096'),through=path.join(dir,'.virtual-through-0096');
 const views=new Map([[before,names.filter(value=>value<name)],[through,names.filter(value=>value<=name)]]);
 const filename=require.resolve('../../db/postgres/migrate');
 const nativeRequire=require('node:module').createRequire(filename),nativeFs=require('node:fs/promises');
 const viewFs={...nativeFs,
  readdir:async directory=>views.has(directory)?[...views.get(directory)]:nativeFs.readdir(directory),
  readFile:async(file,...args)=>{
   const directory=path.dirname(file),basename=path.basename(file);
   if(views.has(directory)){assert.ok(views.get(directory).includes(basename),'Unadmitted migration read');return nativeFs.readFile(path.join(dir,basename),...args);}
   return nativeFs.readFile(file,...args);
  }};
 const localRequire=request=>['node:fs/promises','fs/promises'].includes(request)?viewFs:nativeRequire(request);
 const loaded={exports:{}};
 vm.runInThisContext(`(function(require,module,exports,__dirname){${fs.readFileSync(filename,'utf8')}\n})`,{filename})(localRequire,loaded,loaded.exports,path.dirname(filename));
 return {...loaded.exports,before,through,dir,name};
}
async function qualifyAuditInstructionDefaults({migration,customBefore=false}){
 const {migrate,before:prefix,through,dir,name}=auditMigrationView(),{seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
 const id='ss_audit_instruction_followed',key='secureshop_agent_security';
 {
  await migrate(migration,prefix);
  await seedWorkshopPlatform(migration);
  assert.deepEqual((await migration.query('SELECT hint_content FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[key,id])).rows[0].hint_content,require('../../server/config/secureshopCurriculum').HINTS[id]);
  const docs={};for(const match of fs.readFileSync(path.join(dir,name),'utf8').matchAll(/\('(hint_content|solution_content)','((?:[^']|'')*)'::jsonb/g))docs[match[1]]=JSON.parse(match[2].replaceAll("''","'"));assert.equal(Object.keys(docs).length,2);
  await migration.query('UPDATE workshop_platform.objectives SET hint_content=$1,solution_content=$2 WHERE workshop_key=$3 AND objective_id=$4',[docs.hint_content.value,docs.solution_content.value,key,id]);
  for(const field of Object.keys(docs))await migration.query("UPDATE workshop_platform.catalog_field_defaults SET provenance_state='legacy_unknown',observed_document=$1 WHERE workshop_key=$2 AND objective_id=$3 AND field_name=$4",[docs[field],key,id,field]);
  if(customBefore){await migration.query('UPDATE workshop_platform.objectives SET hint_content=$1 WHERE workshop_key=$2 AND objective_id=$3',[{title:'Pre-existing instructor',hints:['Retain this exact customization']},key,id]);await migration.query("UPDATE workshop_platform.catalog_field_defaults SET provenance_state='custom' WHERE workshop_key=$1 AND objective_id=$2 AND field_name='hint_content'",[key,id]);}
  const before=(await migration.query('SELECT is_enabled,hint_enabled,solution_enabled FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[key,id])).rows[0];
  assert.deepEqual(await migrate(migration,through),[name]);await seedWorkshopPlatform(migration);
  const row=async()=>(await migration.query('SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[key,id])).rows[0];
  let value=await row();if(customBefore)assert.equal(value.hint_content.title,'Pre-existing instructor');else assert.deepEqual(value.hint_content,require('../../server/config/secureshopCurriculum').HINTS[id]);assert.deepEqual(value.solution_content,require('../../server/config/secureshopCurriculum').SOLUTIONS[id]);for(const f of Object.keys(before))assert.equal(value[f],before[f]);assert.equal(value.is_enabled,false);
  const snapshot=async()=>JSON.stringify((await migration.query("SELECT jsonb_agg(to_jsonb(t) ORDER BY t.objective_id) AS rows FROM workshop_platform.objectives t")).rows);
  const stable=await snapshot();assert.deepEqual(await migrate(migration,through),[]);await seedWorkshopPlatform(migration);assert.equal(await snapshot(),stable);
  await migration.query("UPDATE workshop_platform.objectives SET hint_content=$1 WHERE workshop_key=$2 AND objective_id=$3",[{title:'Instructor preserved',hints:['Custom owned teaching guidance']},key,id]);await seedWorkshopPlatform(migration);const custom=await row();assert.equal(custom.hint_content.title,'Instructor preserved');await seedWorkshopPlatform(migration);assert.deepEqual(await row(),custom);
  console.log('AUDIT_INSTRUCTION_DEFAULTS_PASSED managed-pending-adoption disabled-preservation custom-preservation second-noop');
 }
}
module.exports={qualifyAuditInstructionDefaults,auditMigrationView};
