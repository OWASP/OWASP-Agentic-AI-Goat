'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {spawn}=require('node:child_process');
const {createHash}=require('node:crypto');
const {repositories}=require('../../db/postgres/initialize-application');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.PG_SETUP_FRESH_CLUSTER==='yes'&&!!process.env.PG_ADMIN_DATABASE_URL;
const source=path.resolve(__dirname,'../..');
function run(cwd,env){return new Promise((resolve,reject)=>{
 const child=spawn(process.execPath,['scripts/setup-application.js','--no-install'],{cwd,env,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
 const timer=setTimeout(()=>{child.kill('SIGTERM');reject(Error('Setup subprocess timed out'));},300000);
 child.stdout.on('data',chunk=>{stdout+=chunk;});child.stderr.on('data',chunk=>{stderr+=chunk;});
 child.on('error',error=>{clearTimeout(timer);reject(error);});child.on('close',code=>{clearTimeout(timer);resolve({code,stdout,stderr});});
});}
test('fresh setup wrapper provisions all databases, private usable admin and refuses env overwrite',{skip:!enabled,timeout:330000},async()=>{
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-setup-integration-')),root=path.join(temporary,'workspace'),home=path.join(temporary,'home');
 const excluded=new Set(['node_modules','.git','.env','.env.local','.env.production','.env.development','logs','.cache','.next','build','coverage','dist','__pycache__','vector-indexes','workshop_data','sensitive_files','backups','.dvaia']);
 let pool;
 try{
  await fs.mkdir(home,{mode:0o700});
  await fs.cp(source,root,{recursive:true,filter:entry=>{
   const relative=path.relative(source,entry);if(!relative)return true;
   if (/^server[\\/]uploads(?:[\\/]|$)/.test(relative)) return false;
   const segments=relative.split(path.sep);if(segments.some(segment=>excluded.has(segment)))return false;
   return !/\.(db|db-wal|db-shm|sqlite|sqlite3|log|pyc|hnsw)$/.test(entry)&&!segments.some(segment=>segment.startsWith('.env.')&&!segment.endsWith('.example'));
  }});
  await fs.symlink(path.join(source,'node_modules'),path.join(root,'node_modules'),'dir');
  await fs.symlink(path.join(source,'client/node_modules'),path.join(root,'client/node_modules'),'dir');
  const bin=path.join(temporary,'bin');await fs.mkdir(bin);
  await fs.writeFile(path.join(bin,'ollama'),'#!/bin/sh\n[ \"$1\" = show ] && [ \"$2\" = llama3.1:8b ]\n',{mode:0o700});
  const embeddingCache=await fs.realpath(process.env.XENOVA_CACHE);
  assert.equal(process.env.HF_HUB_OFFLINE,'1');assert.equal(process.env.TRANSFORMERS_OFFLINE,'1');
  const env={PATH:bin+path.delimiter+process.env.PATH,...(process.env.PUPPETEER_CACHE_DIR?{PUPPETEER_CACHE_DIR:process.env.PUPPETEER_CACHE_DIR}:{}),...(process.env.PUPPETEER_EXECUTABLE_PATH?{PUPPETEER_EXECUTABLE_PATH:process.env.PUPPETEER_EXECUTABLE_PATH}:{}),HOME:home,USERPROFILE:home,TMPDIR:temporary,NODE_ENV:'test',PG_ADMIN_DATABASE_URL:process.env.PG_ADMIN_DATABASE_URL,...(process.env.PG_TLS?{PG_TLS:process.env.PG_TLS}:{}),XENOVA_CACHE:embeddingCache,HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1'};
  const unavailable={...env,XENOVA_CACHE:path.join(temporary,'missing-model-cache')};
  const unavailableResult=await run(root,unavailable);
  assert.notEqual(unavailableResult.code,0,'Offline setup unexpectedly accepted an empty embedding cache');
  const {Pool}=require('pg');
  pool=new Pool({connectionString:env.PG_ADMIN_DATABASE_URL,max:1,ssl:env.PG_TLS==='require'?{rejectUnauthorized:true}:false});
  const premature=(await pool.query("SELECT datname FROM pg_database WHERE datname LIKE 'dvaia\\_%' ESCAPE '\\' ORDER BY datname")).rows;
  assert.deepEqual(premature,[],'Database provisioning started before embedding verification completed');
  await pool.end();pool=null;
  const first=await run(root,env);assert.equal(first.code,0,`Fresh setup failed: ${first.stderr.trim().slice(0,1000) || 'no public error was emitted'}`);
  const envPath=path.join(root,'.env'),contents=await fs.readFile(envPath,'utf8');
  const config=require('dotenv').parse(contents);assert.equal(config.PLATFORM_DATABASE_ENGINE,'postgres');assert.equal(config.WORKSHOP_DATABASE_ENGINE,'postgres');
  assert.equal(Object.keys(config).filter(key=>key.endsWith('_DATABASE_URL')).length,repositories.length*2);
  assert.equal(config.OLLAMA_MODEL,'llama3.1:8b');assert.equal(config.JUDGE_MODEL,'llama3.1:8b');assert.equal(config.XENOVA_CACHE,embeddingCache);assert.equal((await fs.stat(envPath)).mode&0o777,0o600);
  const id=createHash('sha256').update(await fs.realpath(root)).digest('hex').slice(0,12),privateDir=path.join(home,'.dvaia',id),adminPath=path.join(privateDir,'administrator.json');
  const administrator=JSON.parse(await fs.readFile(adminPath,'utf8'));
  assert.equal((await fs.stat(privateDir)).mode&0o777,0o700);assert.equal((await fs.stat(adminPath)).mode&0o777,0o600);assert.ok(administrator.password.length>=24);
  const output=first.stdout+first.stderr;
  for(const secret of [new URL(env.PG_ADMIN_DATABASE_URL).password,administrator.password,config.JWT_SECRET,config.SESSION_SECRET,...Object.entries(config).filter(([key])=>key.endsWith('_DATABASE_URL')).map(([,url])=>new URL(url).password)])if(secret)assert.equal(output.includes(secret),false,'Setup printed a generated secret');
  for(const [schema,prefix] of repositories){
   pool=new Pool({connectionString:config[`${prefix}_DATABASE_URL`],max:1,ssl:config.PG_TLS==='require'?{rejectUnauthorized:true}:false});
   const row=(await pool.query('SELECT current_database() AS database,current_user AS role,EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1) AS initialized',[schema])).rows[0];
   assert.equal(row.database,`dvaia_${schema}`);assert.equal(row.role,`dvaia_${schema}_runtime`);assert.equal(row.initialized,true);
   if(schema==='identity'){
    const user=(await pool.query('SELECT username,email,password,role,admin_level,is_active FROM identity.users WHERE username=$1',[administrator.username])).rows[0];
    assert.equal(user.role,'super_admin');assert.equal(user.admin_level,2);assert.equal(user.is_active,1);assert.equal(await require('bcryptjs').compare(administrator.password,user.password),true);
   }
   await pool.end();pool=null;
  }
  const manifestBefore=await fs.readFile(path.join(privateDir,'provisioning.json'),'utf8');
  const second=await run(root,env);assert.notEqual(second.code,0);assert.match(second.stderr,/\.env already exists/);
  assert.equal(await fs.readFile(envPath,'utf8'),contents);assert.equal(await fs.readFile(path.join(privateDir,'provisioning.json'),'utf8'),manifestBefore);assert.equal(await fs.readFile(adminPath,'utf8'),JSON.stringify(administrator,null,2)+'\n');
 }finally{if(pool)await pool.end();await fs.rm(temporary,{recursive:true,force:true});}
});
