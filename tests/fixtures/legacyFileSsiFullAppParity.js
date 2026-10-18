'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{pathToFileURL}=require('node:url'),{randomUUID}=require('node:crypto');
async function mountLegacyParityRoutes({app,adapter,pool,migration,progress,config,identity}){
 const auth=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter),pass=(_q,_s,next)=>next();
 const admin=await identity.createUser({username:randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(randomUUID(),4)});
 await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);
 for(const permission of ['user_management','challenge_management','system_config','manage_progress','system_logs'])await identity.grantPermission({userId:admin.id,permission,grantedBy:admin.id});
 const session=await adapter.createSession(await identity.findCredentialById(admin.id),{});
 const authRouter=require('../../server/routes/postgresAuth').createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});
 app.use('/api/auth',authRouter);
 app.use('/api/workshop/config',require('../../server/routes/workshopConfig').createWorkshopConfigRouter(config));
 app.use('/api/changes',require('../../server/routes/changeRevisions').createChangeRevisionsRouter({store:require('../../server/services/changeRevisionService'),authenticateToken:auth.authenticateToken}));
 app.use('/api/admin/exercises',require('../../server/routes/adminExercises').createAdminExercisesRouter());
 app.use('/api/admin',require('../../server/routes/postgresAdmin').createPostgresAdminRouter({adapter,stores:{pool,progress,config},auth}));
 app.use('/api/workshop',require('../../server/routes/postgresWorkshop').createPostgresWorkshopRouter({stores:{pool,progress,config},authenticateToken:auth.authenticateToken,requirePermission:auth.requirePermission}));
 return {adminToken:session.token,close:()=>authRouter.close()};
}
async function qualifyLegacyFullAppParity({backendPort,token,adminToken,studentId,runtimeRoot}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');const clientRoot=path.resolve('client');process.env.PORT=String(backendPort);
 const {createServer}=await import(pathToFileURL(path.join(clientRoot,'node_modules/vite/dist/node/index.js')));let vite,browser,pid;
 try{
  vite=await createServer({root:clientRoot,configFile:path.join(clientRoot,'vite.config.mjs'),configLoader:'native',cacheDir:path.join(runtimeRoot,'fullapp-vite-cache'),server:{host:'127.0.0.1',port:0,strictPort:false}});await vite.listen();const origin=`http://127.0.0.1:${vite.httpServer.address().port}`;
  browser=await require('puppeteer').launch({headless:true,args:['--disable-background-networking','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',...(process.env.LEGACY_BROWSER_OUTER_SANDBOX==='1'?['--no-sandbox']:[])],userDataDir:path.join(runtimeRoot,'fullapp-browser-profile')});pid=browser.process().pid;fs.writeFileSync(path.join(runtimeRoot,'fullapp-browser-ownership.json'),JSON.stringify({pid}),{mode:0o600});
  const page=await browser.newPage();await page.setViewport({width:1440,height:1000});const errors=[];page.on('pageerror',e=>{errors.push(e.message);console.error('Legacy parity page error:',e.message);});
  await page.setRequestInterception(true);page.on('request',r=>r.url().startsWith(origin+'/')||/^(data|blob|about):/.test(r.url())?r.continue():r.abort());
  await page.evaluateOnNewDocument(t=>{localStorage.setItem('token',t);},token);
  for(const route of ['/workshop-dashboard','/workshop/challenges','/workshop/progress']){
   await page.goto(origin+route);await page.waitForFunction(()=>document.body.innerText.includes('File and SSI Security'),{timeout:45000});
   const text=await page.$eval('body',el=>el.innerText);assert.match(text,/5\s*\/\s*5|5 of 5/);assert.ok(text.includes('1m')); 
   if(route==='/workshop/progress')assert.equal(new URL(page.url()).pathname,'/workshop-dashboard');
  }

  // Change the initial-token hook too so full navigation retains current canonical administrator authority.
  const adminContext=await browser.createBrowserContext();const adminPage=await adminContext.newPage();await adminPage.evaluateOnNewDocument(t=>localStorage.setItem('token',t),adminToken);
  await adminPage.setRequestInterception(true);adminPage.on('request',r=>r.url().startsWith(origin+'/')||/^(data|blob|about):/.test(r.url())?r.continue():r.abort());
  adminPage.on('console',m=>{if(m.type()==='error')console.error('Admin UI error:',m.text().slice(0,240));});adminPage.on('pageerror',e=>{errors.push(e.message);console.error('Legacy parity page error:',e.message);});await adminPage.goto(origin+'/admin/exercises');
  await adminPage.waitForFunction(()=>document.body.innerText.includes('File and SSI Security'),{timeout:45000});
  assert.ok((await adminPage.$eval('body',el=>el.innerText)).includes('Manage Objectives'));
  const card='[data-exercise-key="legacy_sensitive_file_ssi"]';
  const click=async selector=>{await adminPage.bringToFront();await adminPage.waitForSelector(selector);await adminPage.$eval(selector,el=>el.scrollIntoView({block:'center'}));await adminPage.waitForFunction(selector=>{const el=document.querySelector(selector);if(!el)return false;const r=el.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return hit===el||el.contains(hit);},{},selector);await adminPage.click(selector);};
  const waitGate=async(field,value)=>adminPage.waitForFunction(async(field,value)=>{const r=await fetch('/api/workshop/config/snapshot');return (await r.json()).exercises.legacy_sensitive_file_ssi[field]===value;},{},field,value);
  await click(card+' [data-control="solutions"]');await waitGate('showSolutions',false);
  await click(card+' [data-control="hints"]');await waitGate('showHints',true);
  await page.goto(origin+'/workshop/file-ssi');await page.waitForSelector('[data-workshop="legacy_sensitive_file_ssi"]');
  assert.equal(await page.$$eval('summary',els=>els.some(e=>e.textContent==='Hints')),true);assert.equal(await page.$$eval('summary',els=>els.some(e=>e.textContent==='Solution')),false);
  await click(card+' [data-control="solutions"]');await waitGate('showSolutions',true);
  await click(card+' [data-control="hints"]');await waitGate('showHints',false);
  await adminPage.$eval(card,el=>Array.from(el.querySelectorAll('button')).find(b=>b.textContent.includes('Manage Objectives')).click());
  await adminPage.waitForSelector('[data-objective-id="path_traversal"]');assert.equal(await adminPage.$$eval('[data-objective-id]',els=>els.length),5);assert.equal(await adminPage.$$eval('[data-objective-id] [title="Preview Solution"]',els=>els.length),5);
  await click('[data-objective-id="path_traversal"] [data-control="visible"]');
  await page.goto(origin+'/workshop/challenges');await page.waitForFunction(()=>document.body.innerText.includes('4/4'));
  await page.goto(origin+'/workshop-dashboard');await page.waitForFunction(()=>document.body.innerText.includes('4/4'));assert.ok((await page.$eval('body',el=>el.innerText)).includes('1m'));
  await click('[data-objective-id="path_traversal"] [data-control="visible"]');
  await page.goto(origin+'/workshop/challenges');await page.waitForFunction(()=>document.body.innerText.includes('5/5'));
  await adminPage.$$eval('button',els=>els.find(b=>b.textContent==='Done').click());await adminPage.waitForSelector('[data-objective-id="path_traversal"]',{hidden:true});
  await Promise.all([adminPage.waitForResponse(r=>r.url().endsWith('/api/admin/challenges/toggle')&&r.request().method()==='POST').then(async r=>{assert.equal(r.status(),200);}),click(card+' [data-control="active"]')]);await waitGate('isVisible',false);
  await page.goto(origin+'/workshop-dashboard');await page.waitForFunction(()=>document.body.innerText.includes('Objectives')&&!document.body.innerText.includes('File and SSI Security'));
  await Promise.all([adminPage.waitForResponse(r=>r.url().endsWith('/api/admin/challenges/toggle')&&r.request().method()==='POST').then(async r=>{assert.equal(r.status(),200);}),click(card+' [data-control="active"]')]);await waitGate('isVisible',true);
  await page.goto(origin+'/workshop-dashboard');await page.waitForFunction(()=>document.body.innerText.includes('File and SSI Security')&&document.body.innerText.includes('5/5'));
  await adminPage.goto(origin+'/admin/student-workshop-view?studentId='+studentId);await adminPage.waitForFunction(()=>document.body.innerText.includes('File and SSI Security'));const adminText=await adminPage.$eval('body',el=>el.innerText);assert.match(adminText,/5\s*\/\s*5|5 of 5/);assert.ok(adminText.includes('1m'));
  assert.deepEqual(errors,[]);
  return {actualApp:true,canonicalBearer:true,dashboard:true,detail:true,progressRedirect:true,adminFamilyCard:true,adminStudentProgress:true,allFiveSolutionControls:true,masterToggleParity:true,objectiveToggleParity:true,independentHintSolutionGates:true,timeParity:true};
 }finally{if(browser)await browser.close();if(vite)await vite.close();if(pid){let alive=false;try{process.kill(pid,0);alive=true;}catch(e){if(e.code!=='ESRCH')throw e;}assert.equal(alive,false);}}
}
module.exports={mountLegacyParityRoutes,qualifyLegacyFullAppParity};
