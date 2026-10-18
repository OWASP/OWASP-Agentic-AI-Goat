'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {assertLegacyFileSsiDefinitionReadiness}=require('../server/database/postgres/legacyFileSsiReadiness');
const manifest=require('../server/database/postgres/legacyFileSsiReadinessManifest.json');
function fixture(schema){
 const file=schema==='identity'?'0091_legacy_file_ssi_reset':'0013_legacy_file_ssi_cleanup';
 const sql=fs.readFileSync(path.join(__dirname,'../docs/modernization/drafts/legacy-file-ssi',file+'.candidate.sql'),'utf8');
 const bodies=new Map([...sql.matchAll(/CREATE (?:OR REPLACE )?FUNCTION \w+\.(\w+)\([\s\S]*?\)\s*RETURNS[\s\S]*?\$\$([\s\S]*?)\$\$;/g)].map(m=>[m[1],m[2]]));
 const rows=manifest[schema].map(e=>({proname:e.name,prosrc:bodies.get(e.name),prosecdef:e.definer,proconfig:e.config,rolname:`dvaia_${schema}_migration`,argument_types:e.arguments,result_type:e.result,executable:e.execute,public_execute:false}));
 const names=schema==='identity'?['legacy_file_ssi_resets','legacy_file_ssi_reset_steps','legacy_file_ssi_reset_authority']:['legacy_file_ssi_cleanup_operations','legacy_file_ssi_cleanup_receipts'];
 const allowedUpdates={legacy_file_ssi_resets:['status','lease_token','lease_expires_at','failure_code','updated_at','completed_at'],legacy_file_ssi_reset_steps:['status','attempts','failure_code','completed_at']};
 const columns=names.flatMap(relname=>{
  const body=sql.match(new RegExp('CREATE TABLE '+schema+'\\.'+relname+' \\(([\\s\\S]*?)\\n\\);'))[1];
  return body.split('\n').map(line=>line.match(/^ ([a-z_]+) (?:uuid|integer|bigint|text|timestamptz)\b/)).filter(Boolean).map(match=>({relname,attname:match[1],table_write:false,readable:Boolean(allowedUpdates[relname]),writable:allowedUpdates[relname]?.includes(match[1])===true,extra_write:false}));
 });
 const triggers=manifest.triggers[schema].map(e=>({...e,enabled:'O',table_name:e.table,function_name:e.function}));
 return {rows,columns,triggers,pool:{query:async sql=>({rows:sql.includes('FROM pg_proc')?rows:sql.includes('FROM pg_trigger')?triggers:columns})}};
}
for(const schema of ['identity','finflow']){
 test(`${schema} frozen candidate function definitions and least privilege pass`,async()=>{await assertLegacyFileSsiDefinitionReadiness(fixture(schema).pool,schema);});
 for(const [label,mutate] of [
  ['disabled trigger',f=>f.triggers[0].enabled='D'],['wrong trigger table',f=>f.triggers[0].table_name='identity.users'],['body',f=>f.rows[0].prosrc+=' '],['signature',f=>f.rows[0].argument_types='text'],['result',f=>f.rows[0].result_type='text'],['owner',f=>f.rows[0].rolname='dvaia_identity_runtime'],['public execute',f=>f.rows[0].public_execute=true],['overload',f=>f.rows.push({...f.rows[0]})],['column insert',f=>f.columns[0].extra_write=true],['column update',f=>f.columns[0].writable=true],['table delete',f=>f.columns[0].table_write=true],['missing required column',f=>f.columns.splice(f.columns.findIndex(c=>c.attname==='from_generation'),1)],['missing table',f=>{const name=f.columns.at(-1).relname;f.columns.splice(0,f.columns.length,...f.columns.filter(c=>c.relname!==name));}],
 ])test(`${schema} rejects ${label} drift`,async()=>{const f=fixture(schema);mutate(f);await assert.rejects(assertLegacyFileSsiDefinitionReadiness(f.pool,schema),{code:'RESET_STORAGE_NOT_READY'});});
}
