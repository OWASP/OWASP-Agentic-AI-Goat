'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const REPO = path.resolve(__dirname, '../..');
const DATABASES = Object.freeze({
  IDENTITY: 'IDENTITY',
  SQL_WORKSHOP: 'ARIA',
  NOSQL_WORKSHOP: 'NOVA',
  XSS_WORKSHOP: 'XSS',
  MCP_WORKSHOP: 'MCP',
  CSRF_WORKSHOP: 'CSRF',
  SUPPLY_CHAIN_WORKSHOP: 'SUPPLY_CHAIN',
  FINFLOW_WORKSHOP: 'FINFLOW',
  EXCESSIVE_AGENCY: 'EXCESSIVE_AGENCY',
  CTF: 'CTF',
  LEGACY_CHALLENGE: 'LEGACY_CHALLENGE',
  SENSITIVE_LOOKUP: 'SENSITIVE_LOOKUP',
  SECURESHOP: 'SECURESHOP',
  SECURESHOP_AGENTS: 'SECURESHOP_AGENTS',
  SESSION_DISCLOSURE: 'SESSION_DISCLOSURE',
  SECURESHOP_REVIEW: 'SECURESHOP_REVIEW',
});
const REQUIRED_TEST_URLS = Object.values(DATABASES).flatMap(name => [
  `PG_${name}_TEST_RUNTIME_URL`,
  `PG_${name}_TEST_MIGRATION_URL`,
]);
const enabled=process.env.RUN_LIVE_FULLSTACK==='1'&&process.env.PG_TEST_DISPOSABLE==='yes';

function assertDisposableUrl(value, name) {
  const url = new URL(value);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), `${name} must be loopback-only`);
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/, `${name} must name a disposable test database`);
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

function shouldCopy(source) {
  const relative = path.relative(REPO, source);
  if (!relative) return true;
  const unix = relative.split(path.sep).join('/');
  const parts = unix.split('/');
  if (parts.includes('.git') || parts.includes('node_modules') || parts.includes('coverage')) return false;
  if(parts.includes('sensitive_files')||parts.includes('workshop_data'))return false;
  if (unix === 'client/build' || unix.startsWith('client/build/')) return false;
  if (unix === 'server/logs' || unix.startsWith('server/logs/')) return false;
  if (unix === 'server/uploads' || unix.startsWith('server/uploads/')) return false;
  if (unix === 'server/database/vector-indexes' || unix.startsWith('server/database/vector-indexes/')) return false;
  if (/(^|\/)\.env(?:\.|$)/.test(unix)) return false;
  if (/\.(?:db|db-wal|db-shm|sqlite|sqlite3)(?:$|-)/i.test(path.basename(unix))) return false;
  return true;
}

async function copyApplication() {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-pg-boot-'));
  const workspace = path.join(parent, 'workspace');
  await fs.cp(REPO, workspace, { recursive: true, filter: shouldCopy });
  await fs.symlink(path.join(REPO, 'node_modules'), path.join(workspace, 'node_modules'), 'dir');
  return { parent, workspace };
}

async function waitForJson(url, predicate, child, output, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`application exited before ${url} became ready\n${output()}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1500) });
      const body = await response.json();
      if (response.ok && predicate(body)) return body;
      lastError = new Error(`HTTP ${response.status}: ${JSON.stringify(body)}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error(`timed out waiting for ${url}: ${lastError?.message || 'no response'}\n${output()}`);
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('application did not exit within the shutdown deadline')), timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

function stopProcessTree(child, signal = 'SIGKILL') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32') process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {}
}

test('production bundle login and DPI/IPI browser workflow on owned PostgreSQL',{skip:!enabled,timeout:360000},async t=>{
 const {Pool}=require('pg'),adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['127.0.0.1','localhost'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname,'/postgres');
 const admin=new Pool({connectionString:adminUrl.href}),owned=[],databaseEnv={};let child,browser,identityPool,identityMigrationPool,output='';const {parent,workspace}=await copyApplication();
 try{
  await fs.symlink(path.join(REPO,'client/node_modules'),path.join(workspace,'client/node_modules'),'dir');
  for(const [prefix,family] of Object.entries(DATABASES)){
   const schema=family.toLowerCase(),name=`dvaia_test_browser_${process.pid}_${schema}`;await admin.query(`CREATE DATABASE ${name} OWNER dvaia_${schema}_migration`);owned.push(name);await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_${schema}_runtime`);
   for(const role of ['runtime','migration']){const u=new URL(adminUrl);u.pathname='/'+name;u.username=`dvaia_${schema}_${role}`;u.password='';databaseEnv[`${prefix}_${role==='runtime'?'':'MIGRATION_'}DATABASE_URL`]=u.href;}
  }
  const port=await availablePort(),agentPort=await availablePort();const env={PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:os.tmpdir(),...databaseEnv,PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',PORT:String(port),SS_ALLOWED_ORIGINS:`http://127.0.0.1:${port}`,SS_AGENT_HOST_PORT:String(agentPort),SS_ENABLE:'true',SS_ENABLE_REAL_MCP_SPAWN:'false',MCP_SIDECARS_AUTOSTART:'false',AI_PROVIDER:'ollama',OLLAMA_BASE_URL:'http://127.0.0.1:11434',OLLAMA_MODEL:'llama3.1:8b',JUDGE_PROVIDER:'ollama',JUDGE_MODEL:'llama3.1:8b',JWT_SECRET:'owned-browser-fixture-secret-at-least-32-bytes',EVENT_GATE_ENABLED:'false',NODE_ENV:'test',AWS_EC2_METADATA_DISABLED:'true',XENOVA_CACHE:process.env.XENOVA_CACHE,HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',LANGCHAIN_TRACING_V2:'false',LANGSMITH_TRACING:'false'};
  await new Promise((resolve,reject)=>{const build=spawn(process.execPath,[path.join(workspace,'client/node_modules/vite/bin/vite.js'),'build'],{cwd:path.join(workspace,'client'),env,stdio:'pipe'});let out='';build.stderr.on('data',b=>out+=b);build.on('error',reject);build.on('exit',code=>code===0?resolve():reject(Error('Build failed: '+out)));});
  const guard=path.join(parent,'guard.cjs');await fs.writeFile(guard,"const M=require('node:module'),l=M._load;M._load=function(n,...a){if(['sqlite3','better-sqlite3','mysql2'].includes(n))throw Error('FORBIDDEN_LEGACY_DRIVER '+n);return l.call(this,n,...a)};");env.NODE_OPTIONS='--require='+guard;
  child=spawn(process.execPath,['server/index.js'],{cwd:workspace,env,detached:true,stdio:['ignore','pipe','pipe']});for(const stream of [child.stdout,child.stderr])stream.on('data',b=>output=(output+b).slice(-200000));
  const base=`http://127.0.0.1:${port}`;await waitForJson(base+'/api/monitoring/ping',()=>true,child,()=>output,90000);
  identityPool=new Pool({connectionString:databaseEnv.IDENTITY_DATABASE_URL});identityMigrationPool=new Pool({connectionString:databaseEnv.IDENTITY_MIGRATION_DATABASE_URL});
  await require('../../db/postgres/bootstrap-admin').bootstrapAdmin({pool:identityMigrationPool,username:'browseradmin',email:'browser-admin@example.invalid',password:'BrowserAdminFixture123!'});
  const repository=require('../../server/database/postgres/identityRepository').createIdentityRepository(identityPool);const learner=await repository.createUser({username:'browserlearner',email:'browser@example.invalid',passwordHash:await require('bcryptjs').hash('BrowserFixture123!',4)});
  browser=await require('puppeteer').launch({headless:true,args:['--no-sandbox']});const page=await browser.newPage();page.on('dialog',d=>d.accept());const errors=[],requestedUrls=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',request=>requestedUrls.push(request.url()));
  await page.goto(base+'/workshop-login',{waitUntil:'networkidle0'});await page.type('input[placeholder="Enter your username"]','browserlearner');await page.type('input[placeholder="Enter your password"]','BrowserFixture123!');const learnerLoginPromise=page.waitForResponse(r=>r.url().includes('/api/auth/login')&&r.request().method()==='POST');await page.click('button[type=submit]');const learnerLoginResponse=await learnerLoginPromise;const learnerLoginBody=await learnerLoginResponse.json();t.diagnostic(JSON.stringify({learnerLoginStatus:learnerLoginResponse.status(),learnerLoginBody:{...learnerLoginBody,token:learnerLoginBody.token?'[present]':undefined}}));assert.equal(learnerLoginResponse.status(),200);await page.waitForFunction(()=>!location.pathname.includes('login'),{timeout:15000});
  if(!process.env.FULLSTACK_IPI_ONLY&&!process.env.FULLSTACK_PARITY_ONLY){await page.goto(base+'/vulnerabilities/direct-prompt-injection',{waitUntil:'networkidle0'});await page.waitForSelector('textarea');
  const responsePromise=page.waitForResponse(r=>r.url().includes('/chat')&&r.request().method()==='POST',{timeout:90000});await page.type('textarea','Explain what an Amazon S3 bucket is and give a legitimate storage use case.');await page.click('button[aria-label="Send message"]');const response=await responsePromise;const packet=await response.json();t.diagnostic(JSON.stringify({dpi:packet}));assert.equal(response.status(),200);assert.ok(packet.response);
  assert.equal(packet.judgment.verdict,'pass');assert.equal(packet.progress.objectives.interact.interactionCount,1);
  const secondPromise=page.waitForResponse(r=>r.url().includes('/chat')&&r.request().method()==='POST',{timeout:90000});await page.type('textarea','Explain AWS IAM roles and one legitimate least-privilege use case.');await page.click('button[aria-label="Send message"]');const second=await (await secondPromise).json();t.diagnostic(JSON.stringify({dpiSecond:second}));assert.equal(second.progress.objectives.interact.completed,true);await page.waitForFunction(()=>document.body.innerText.includes('DONE'));
  await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Reset Progress').click());const resetPromise=page.waitForResponse(r=>r.url().includes('reset')&&r.request().method()==='POST');await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent==='Confirm reset'));await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Confirm reset').click());assert.equal((await resetPromise).status(),200);await page.waitForFunction(()=>!document.body.innerText.includes('DONE'));
  await page.goto(base+'/workshop/agent-runs',{waitUntil:'networkidle0'});await page.waitForSelector('[aria-label="Your agent run inspector"]');await page.waitForFunction(()=>document.body.innerText.includes('DPI'));
  const learnerInspectorText=(await page.evaluate(()=>document.body.innerText)).slice(0,5000);t.diagnostic(JSON.stringify({inspectorText:learnerInspectorText}));assert.match(learnerInspectorText,/Decision source\s+model/i);assert.equal(await page.$('[aria-label="Your agent run inspector"] [role="alert"]'),null);
  }if(!process.env.FULLSTACK_PARITY_ONLY&&!process.env.FULLSTACK_SKIP_IPI){await page.goto(base+'/vulnerabilities/indirect-prompt-injection',{waitUntil:'networkidle0'});assert.match(await page.evaluate(()=>document.body.innerText),/Indirect|RAG|Email/);
  await waitForJson(base+'/api/workshop/rag-injection/health',body=>body.embeddingReady===true,child,()=>output,60000);const documentPath=path.join(parent,'synthetic-policy.txt');await fs.writeFile(documentPath,'Remote work policy: Employees may work remotely two days per week with manager approval.');await (await page.$('input[type=file]')).uploadFile(documentPath);
  const uploadPromise=page.waitForResponse(r=>r.url().includes('upload')&&r.request().method()==='POST',{timeout:90000});await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Upload').click());const uploadResponse=await uploadPromise;t.diagnostic(JSON.stringify({uploadStatus:uploadResponse.status(),uploadBody:await uploadResponse.json()}));assert.equal(uploadResponse.status(),200);
  await page.evaluate(()=>[...document.querySelectorAll('.objectives-list > *')].find(e=>e.textContent.includes('3. Ask a question')).click());await page.waitForFunction(()=>!document.querySelector('input[placeholder="What is the remote work policy?"]').disabled);await page.type('input[placeholder="What is the remote work policy?"]','What is the remote work policy?');const queryPromise=page.waitForResponse(r=>r.url().includes('/query')&&r.request().method()==='POST',{timeout:90000});await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Ask').click());const query=await queryPromise;const ipi=await query.json();t.diagnostic(JSON.stringify({ipi}));assert.equal(query.status(),200);await page.waitForFunction(()=>document.body.innerText.includes('Judge:'));
  const eligible=await page.evaluate(()=>[...document.querySelectorAll('button')].some(b=>/re.?grade|retry.*evaluat/i.test(b.textContent)&&!b.disabled));t.diagnostic(JSON.stringify({retainedEvidenceRetryAvailable:eligible}));
  await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Reset Progress').click());await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent==='Confirm reset'));const ipiReset=page.waitForResponse(r=>r.url().includes('reset')&&r.request().method()==='POST');await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Confirm reset').click());assert.equal((await ipiReset).status(),200);

}
  if(process.env.FULLSTACK_PARITY_ONLY){
   const api=async(route,body)=>page.evaluate(async(route,body)=>{const r=await fetch(route,{method:body?'POST':'GET',headers:{'content-type':'application/json',authorization:'Bearer '+localStorage.getItem('token')},...(body?{body:JSON.stringify(body)}:{})});return{status:r.status,data:await r.json()};},route,body);
   const first=await api('/api/workshop/xss/chat',{exerciseId:'reflected',message:'Format hello as HTML.'});assert.equal(first.data.completedObjectiveId,'xss_r1');const result=await api('/api/workshop/xss/chat',{exerciseId:'reflected',message:'<b>hello</b>'});t.diagnostic(JSON.stringify({xssR2:result}));assert.equal(result.status,200);assert.equal(result.data.completedObjectiveId,'xss_r2');
   const a=(await api('/api/workshop/challenges')).data.challenges,b=(await api('/api/workshop/progress')).data.challenges;
   const aggregate=rows=>rows.reduce((o,r)=>({total:o.total+r.objectiveCount,completed:o.completed+r.completedObjectiveCount,time:o.time+r.timeSpentSeconds,exercises:o.exercises+(r.status==='completed'?1:0)}),{total:0,completed:0,time:0,exercises:0});assert.deepEqual(aggregate(a),aggregate(b));const counts=aggregate(a),r2=a.flatMap(r=>r.objectives).find(o=>o.id==='xss_r2');assert.equal(r2.completed,true);const stats=(await api('/api/workshop/student/stats')).data;assert.equal(stats.totalObjectives,counts.total);assert.equal(stats.completedObjectives,counts.completed);assert.equal(stats.totalTime,counts.time);assert.equal(stats.completedChallenges,counts.exercises);assert.equal(counts.time,0,'No synthetic elapsed time is inserted');
   for(const route of ['/workshop-dashboard','/workshop/challenges','/workshop/progress']){await page.goto(base+route,{waitUntil:'networkidle0'});await page.waitForFunction((done,total)=>new RegExp(done+'\\s*/\\s*'+total).test(document.body.innerText),{},counts.completed,counts.total);const text=await page.evaluate(()=>document.body.innerText);t.diagnostic(JSON.stringify({route,actualPath:new URL(page.url()).pathname,counts,text:text.slice(0,2000)}));if(route!=='/workshop/challenges')assert.ok(text.includes('0s'),'Overview renders zero native recorded time');if(route==='/workshop/progress')assert.equal(new URL(page.url()).pathname,'/workshop-dashboard');if(route==='/workshop/challenges'){const color=await page.evaluate(label=>{const e=[...document.querySelectorAll('span')].find(e=>e.textContent===label);return e?getComputedStyle(e).color:null;},r2.text);assert.equal(color,'rgb(45, 106, 79)');}}
  }
  await page.evaluate(()=>{localStorage.removeItem('token');sessionStorage.clear();});await page.goto(base+'/workshop-login',{waitUntil:'networkidle0'});await page.type('input[placeholder="Enter your username"]','browseradmin');await page.type('input[placeholder="Enter your password"]','BrowserAdminFixture123!');const adminLoginPromise=page.waitForResponse(r=>r.url().includes('/api/auth/login')&&r.request().method()==='POST');await page.click('button[type=submit]');const adminLoginResponse=await adminLoginPromise;const adminLoginBody=await adminLoginResponse.json();t.diagnostic(JSON.stringify({adminLoginStatus:adminLoginResponse.status(),adminLoginBody:{...adminLoginBody,token:adminLoginBody.token?'[present]':undefined}}));assert.equal(adminLoginResponse.status(),200);await page.waitForFunction(()=>location.pathname.startsWith('/admin'),{timeout:15000});
  const studentViewResponse=page.waitForResponse(r=>r.url().includes(`/api/admin/student-workshop-view/${learner.id}`)&&r.request().method()==='GET');await page.goto(base+`/admin/student-workshop-view?studentId=${learner.id}`,{waitUntil:'domcontentloaded'});const studentView=await (await studentViewResponse).json();await page.waitForFunction(name=>document.body.innerText.includes(name),{},'browserlearner');
  const studentViewText=await page.evaluate(()=>document.body.innerText);assert.ok(studentView.challenges.length>0);assert.match(studentViewText,new RegExp(`Available Exercises \\(${studentView.challenges.length}\\)`));for(const challenge of studentView.challenges)assert.ok(studentViewText.includes(`${challenge.completedObjectiveCount}/${challenge.objectiveCount} objectives`));
  const finflow=studentView.challenges.find(challenge=>challenge.workshopKey==='sensitive_info_disclosure');assert.ok(finflow?.objectiveCount>0);assert.match(studentViewText,/Sensitive Info Disclosure Workshop — Objective Progress/);assert.ok(studentViewText.includes(`${finflow.completedObjectiveCount} / ${finflow.objectiveCount} objectives completed`));assert.ok(finflow.objectives.every(objective=>studentViewText.includes(objective.label)));assert.equal(requestedUrls.some(url=>url.includes('/api/workshop/sensitive-info/admin-progress/')),false);
  const usersResponse=page.waitForResponse(r=>r.url().includes('/api/admin/users')&&r.request().method()==='GET');await page.goto(base+'/admin/activity',{waitUntil:'domcontentloaded'});const usersPayload=await (await usersResponse).json();await page.waitForFunction(()=>document.body.innerText.includes('Active Users & Their Activity')&&document.body.innerText.includes('browserlearner'));const learnerActivity=usersPayload.users.find(row=>row.id===learner.id);assert.ok(learnerActivity);assert.ok(learnerActivity.recent_activity_count>0);assert.equal(learnerActivity.total_challenges,studentView.challenges.length);assert.equal(learnerActivity.completed_challenges,studentView.challenges.filter(row=>row.status==='completed').length);
  if(!process.env.FULLSTACK_PARITY_ONLY){await page.goto(base+'/admin/agent-runs',{waitUntil:'networkidle0'});await page.waitForSelector('[aria-label="Administrator agent run inspector"]');const ownerInput=await page.$('input[aria-label="Owner ID"]');await ownerInput.click({clickCount:3});await ownerInput.type(String(learner.id));const filteredRuns=page.waitForResponse(r=>r.url().includes('/api/admin/agent-runs')&&r.url().includes(`ownerId=${learner.id}`));await page.evaluate(()=>[...document.querySelectorAll('[aria-label="Administrator agent run inspector"] button')].find(button=>button.textContent.includes('Refresh')).click());const filteredPayload=await (await filteredRuns).json();assert.ok(filteredPayload.runs.some(run=>run.family==='DPI'&&String(run.ownerId)===String(learner.id)));await page.waitForFunction(()=>document.body.innerText.includes('DPI'));assert.equal(await page.$('[aria-label="Administrator agent run inspector"] [role="alert"]'),null);}
  t.diagnostic(JSON.stringify({browserErrors:errors,scope:`production bundle learner/admin login, rendered canonical parity/activity DTO, learner/admin agent-run ownership, DPI actual response/Judge feedback, IPI ${process.env.FULLSTACK_SKIP_IPI?'explicitly skipped: embedding runtime prerequisite unavailable':'navigation and query'}; retry only if eligible receipt appears`}));assert.deepEqual(errors,[]);
 }catch(error){const safeOutput=output.slice(-30000).replace(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[jwt]').replace(/postgres(?:ql)?:\/\/[^\s]+/gi,'[database-url]');t.diagnostic(JSON.stringify({serverOutput:safeOutput}));throw error;}finally{
  await browser?.close();if(child){stopProcessTree(child,'SIGTERM');await waitForExit(child,15000).catch(()=>stopProcessTree(child));}await Promise.all([identityPool?.end(),identityMigrationPool?.end()]);for(const name of owned.reverse())await admin.query(`DROP DATABASE IF EXISTS ${name}`);await admin.end();await fs.rm(parent,{recursive:true,force:true});
 }
});
