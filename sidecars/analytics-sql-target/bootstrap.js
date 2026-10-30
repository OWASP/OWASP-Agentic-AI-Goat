'use strict';
// Installer-only initialization of the dedicated synthetic cluster. Application
// startup uses assertControlReady and must never initialize an arbitrary URL.
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const {createClusterVerifier}=require('./cluster');
const MIGRATIONS=['0001_control.sql','0002_fixed_capability.sql'];
const source=(name=MIGRATIONS[0])=>fs.readFileSync(path.join(__dirname,'control-migrations',name),'utf8');
function version(value){if(!Number.isInteger(value)||value<1||value>MIGRATIONS.length)throw failure();return value;}
function validateLedger(rows,minimum){if(rows.length<minimum||rows.length>MIGRATIONS.length||rows.some((row,i)=>row.name!==MIGRATIONS[i]||row.sha256!==digest(source(row.name))))throw failure();}
const digest=value=>createHash('sha256').update(value).digest('hex');
const failure=()=>Object.assign(Error('Owned Analytics control schema unavailable'),{code:'ANALYTICS_CONTROL_SCHEMA_UNAVAILABLE'});
async function assertControlReady({pool,identity,requiredVersion=1}) {
 version(requiredVersion);
 await createClusterVerifier(pool,identity).verify();
 const ledger=(await pool.query('SELECT name,sha256 FROM public.owned_analytics_schema_migrations ORDER BY name')).rows;
 validateLedger(ledger,requiredVersion);
 const tables=(await pool.query("SELECT name,to_regclass('public.'||name)::text AS relation FROM unnest($1::text[]) name",[['owned_analytics_targets','owned_analytics_credentials','owned_analytics_queries']])).rows;
 if(tables.length!==3||tables.some(row=>!row.relation))throw failure();
 const triggers=(await pool.query(`SELECT t.tgname,t.tgenabled,t.tgtype,c.relname,p.proname,p.prosrc,p.prosecdef,p.proconfig,p.pronargs,p.prorettype::regtype::text AS returns,n.nspname,l.lanname FROM pg_trigger t
  JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
  WHERE t.tgrelid IN ('public.owned_analytics_targets'::regclass,'public.owned_analytics_queries'::regclass) AND NOT t.tgisinternal`)).rows;
 const expected={owned_analytics_target_immutable:['guard_owned_analytics_target','owned_analytics_targets'],owned_analytics_query_immutable:['guard_owned_analytics_query','owned_analytics_queries']};
 const bodies=Object.fromEntries([...source().matchAll(/CREATE FUNCTION (guard_owned_analytics_\w+)\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$([\s\S]*?)\$\$;/g)].map(match=>[match[1],match[2]]));
 if(Object.entries(expected).some(([name,[fn,table]])=>!triggers.some(row=>row.tgname===name&&['O','A'].includes(row.tgenabled)&&row.proname===fn&&row.nspname==='public'&&row.relname===table&&row.tgtype===27&&row.prosrc===bodies[fn]&&row.prosecdef===false&&row.proconfig===null&&row.pronargs===0&&row.returns==='trigger'&&row.lanname==='plpgsql')))throw failure();
 if(requiredVersion===2){
  const fixed=(await pool.query("SELECT t.tgenabled,p.prosrc,p.prosecdef,p.proconfig FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.pronargs=0 AND p.prorettype='trigger'::regtype AND l.lanname='plpgsql' AND t.tgrelid='public.owned_analytics_fixed_capabilities'::regclass AND t.tgname='owned_analytics_fixed_capability_immutable' AND t.tgtype=27 AND p.proname='guard_owned_analytics_fixed_capability'")).rows;
  const expectedBody=source(MIGRATIONS[1]).match(/AS \$\$([\s\S]*?)\$\$;/)?.[1];
  if(fixed.length!==1||!['O','A'].includes(fixed[0].tgenabled)||fixed[0].prosrc!==expectedBody||fixed[0].prosecdef!==false||fixed[0].proconfig!==null)throw failure();
 }
 return Object.freeze({ready:true,appliedVersion:ledger.length,migration:MIGRATIONS[requiredVersion-1],sha256:ledger[requiredVersion-1].sha256});
}
async function initializeControl({pool,identity,requiredVersion=1}) {
 version(requiredVersion);
 await createClusterVerifier(pool,identity).verify();
 const client=await pool.connect();let applied=0;
 try {
  await client.query('BEGIN');await client.query("SELECT pg_advisory_xact_lock(hashtextextended('owasp-ai-goat-owned-analytics-control-schema-v1',0))");
  await client.query('SET LOCAL search_path=public,pg_catalog');
  const exists=(await client.query("SELECT to_regclass('public.owned_analytics_schema_migrations') AS ledger")).rows[0]?.ledger;
  if(exists){
   const rows=(await client.query('SELECT name,sha256 FROM public.owned_analytics_schema_migrations ORDER BY name')).rows;
   validateLedger(rows,1);applied=rows.length;
  } else {
   const prior=(await client.query("SELECT count(*)::integer AS count FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')")).rows[0];
   if(prior?.count!==0)throw failure();
   await client.query('CREATE TABLE public.owned_analytics_schema_migrations(name text PRIMARY KEY,sha256 text NOT NULL CHECK(sha256 ~ \'^[a-f0-9]{64}$\'),applied_at timestamptz NOT NULL DEFAULT clock_timestamp())');
   await client.query('REVOKE ALL ON public.owned_analytics_schema_migrations FROM PUBLIC');

  }
  for(let i=applied;i<requiredVersion;i++){const name=MIGRATIONS[i],sql=source(name);await client.query(sql);await client.query('INSERT INTO public.owned_analytics_schema_migrations(name,sha256) VALUES($1,$2)',[name,digest(sql)]);}
  await client.query('COMMIT');
 } catch(error) {await client.query('ROLLBACK').catch(()=>{});throw error;} finally {client.release();}
 return assertControlReady({pool,identity,requiredVersion});
}
module.exports={initializeControl,assertControlReady};
