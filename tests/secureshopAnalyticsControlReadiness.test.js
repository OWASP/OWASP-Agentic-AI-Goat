'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{createHash}=require('node:crypto');
const {assertControlReady}=require('../sidecars/analytics-sql-target/bootstrap');
const identity={systemIdentifier:'1234567890123456789',controlDatabase:'dvaia_analytics_control_abcdef123456',clusterName:'dvaia-owned-analytics-abcdef123456'};
const sql=fs.readFileSync(require.resolve('../sidecars/analytics-sql-target/control-migrations/0001_control.sql'),'utf8');
const bodies=[...sql.matchAll(/CREATE FUNCTION (\w+)\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$([\s\S]*?)\$\$;/g)];
function pool(change=()=>{}) {
 const triggers=bodies.map(([_,name,body])=>({tgname:name.endsWith('target')?'owned_analytics_target_immutable':'owned_analytics_query_immutable',tgenabled:'O',tgtype:27,relname:name.endsWith('target')?'owned_analytics_targets':'owned_analytics_queries',proname:name,prosrc:body,prosecdef:false,proconfig:null,pronargs:0,returns:'trigger',nspname:'public',lanname:'plpgsql'}));change(triggers);
 return {query:async text=>{
  if(text.includes('pg_control_system'))return {rows:[{database:identity.controlDatabase,cluster:identity.clusterName,system_identifier:identity.systemIdentifier}]};
  if(text.includes('FROM pg_database'))return {rows:[{datname:identity.controlDatabase,datallowconn:true,public_connect:false}]};
  if(text.includes('owned_analytics_schema_migrations'))return {rows:[{name:'0001_control.sql',sha256:createHash('sha256').update(sql).digest('hex')}]};
  if(text.includes('unnest'))return {rows:['targets','credentials','queries'].map(name=>({name:'owned_analytics_'+name,relation:'owned_analytics_'+name}))};
  if(text.includes('FROM pg_trigger'))return {rows:triggers};
  throw Error('Unexpected SQL');
 }};
}
test('readiness requires enabled exact control trigger definitions on their own tables',async()=>{
 assert.equal((await assertControlReady({pool:pool(),identity})).ready,true);
 for(const mutate of [rows=>{rows[0].tgenabled='D';},rows=>{rows[0].relname='owned_analytics_targets';},rows=>{rows[0].prosrc='BEGIN RETURN NEW; END';},rows=>{rows[0].prosecdef=true;},rows=>{rows[0].tgtype=19;}]){
  await assert.rejects(assertControlReady({pool:pool(mutate),identity}),{code:'ANALYTICS_CONTROL_SCHEMA_UNAVAILABLE'});
 }
});

const {initializeControl}=require('../sidecars/analytics-sql-target/bootstrap');
const fixedSql=fs.readFileSync(require.resolve('../sidecars/analytics-sql-target/control-migrations/0002_fixed_capability.sql'),'utf8');
const hash=value=>createHash('sha256').update(value).digest('hex');
function migrationPool(initial=1){
 let ledger=initial?[{name:'0001_control.sql',sha256:hash(sql)}]:[],exists=!!initial,backup;
 const applied=[];const base=pool();let fixedEnabled=true;
 const db={query:async(text,args)=>{
  if(text==='BEGIN'){backup=structuredClone({ledger,exists});return{rows:[]};}
  if(text==='ROLLBACK'){({ledger,exists}=backup);return{rows:[]};}
  if(text==='COMMIT'||text.startsWith('SET LOCAL')||text.includes('pg_advisory_xact_lock'))return{rows:[]};
  if(text.startsWith("SELECT to_regclass('public.owned_analytics_schema_migrations')"))return{rows:[{ledger:exists?'owned_analytics_schema_migrations':null}]};
  if(text.startsWith('SELECT count(*)::integer AS count FROM pg_class'))return{rows:[{count:0}]};
  if(text.startsWith('CREATE TABLE public.owned_analytics_schema_migrations')){exists=true;return{rows:[]};}
  if(text.startsWith('REVOKE ALL ON public.owned_analytics_schema_migrations'))return{rows:[]};
  if(text.startsWith('INSERT INTO public.owned_analytics_schema_migrations')){ledger.push({name:args[0],sha256:args[1]});return{rows:[]};}
  if(text.startsWith('SELECT name,sha256'))return{rows:structuredClone(ledger)};
  if(text===sql||text===fixedSql){applied.push(text===sql?'v1':'v2');return{rows:[]};}
  if(text.includes("t.tgrelid='public.owned_analytics_fixed_capabilities'"))return{rows:[{tgenabled:fixedEnabled?'O':'D',prosrc:fixedSql.match(/AS \$\$([\s\S]*?)\$\$;/)[1],prosecdef:false,proconfig:null}]};
  return base.query(text,args);
 },connect:async()=>({...db,release(){}})};
 return {db,applied,get ledger(){return ledger;},disableFixed(){fixedEnabled=false;}};
}
test('explicit additive upgrade preserves v1 ledger and repeats without reapplying',async()=>{
 const f=migrationPool(),before=structuredClone(f.ledger);
 await initializeControl({pool:f.db,identity});assert.deepEqual(f.applied,[]);
 const result=await initializeControl({pool:f.db,identity,requiredVersion:2});assert.equal(result.migration,'0002_fixed_capability.sql');assert.deepEqual(f.ledger[0],before[0]);assert.deepEqual(f.applied,['v2']);
 await initializeControl({pool:f.db,identity,requiredVersion:2});await assertControlReady({pool:f.db,identity});assert.deepEqual(f.applied,['v2']);
 f.disableFixed();await assert.rejects(assertControlReady({pool:f.db,identity,requiredVersion:2}),{code:'ANALYTICS_CONTROL_SCHEMA_UNAVAILABLE'});
});
test('explicit v2 fresh initialization applies the ordered chain once',async()=>{
 const f=migrationPool(0);await initializeControl({pool:f.db,identity,requiredVersion:2});assert.deepEqual(f.applied,['v1','v2']);assert.equal(f.ledger.length,2);
});
test('tampered and unknown migration histories reject before any migration',async()=>{
 for(const mutate of [rows=>{rows[0].sha256='0'.repeat(64);},rows=>{rows.push({name:'unrecognized.sql',sha256:'0'.repeat(64)});}]){
  const f=migrationPool();mutate(f.ledger);const before=structuredClone(f.ledger);
  await assert.rejects(initializeControl({pool:f.db,identity,requiredVersion:2}),{code:'ANALYTICS_CONTROL_SCHEMA_UNAVAILABLE'});assert.deepEqual(f.applied,[]);assert.deepEqual(f.ledger,before);
 }
});
