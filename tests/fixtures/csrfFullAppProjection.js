'use strict';
const assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs'),{pathToFileURL}=require('node:url');
async function qualifyCsrfProjection({backendPort,token,adminToken,studentId,title,getObjectiveCount,runtimeRoot}){
 process.env.PORT=String(backendPort);let vite,browser,pid,learner,admin;
 try{
  const client=path.resolve('client'),{createServer}=await import(pathToFileURL(path.join(client,'node_modules/vite/dist/node/index.js')));
  vite=await createServer({root:client,configFile:path.join(client,'vite.config.mjs'),configLoader:'native',cacheDir:path.join(runtimeRoot,'csrf-vite-cache'),server:{host:'127.0.0.1',port:0,strictPort:false,fs:{allow:[client,fs.realpathSync(path.join(client,'node_modules'))]}}});await vite.listen();const origin='http://127.0.0.1:'+vite.httpServer.address().port;
  browser=await require('puppeteer').launch({headless:true});pid=browser.process().pid;
  const make=async bearer=>{const context=await browser.createBrowserContext(),page=await context.newPage();await page.setViewport({width:1440,height:1000});await page.evaluateOnNewDocument(t=>localStorage.setItem('token',t),bearer);await page.setRequestInterception(true);page.on('request',r=>r.url().startsWith(origin+'/')||/^(data|about|blob):/.test(r.url())?r.continue():r.abort());return page;};
  learner=await make(token);admin=await make(adminToken);
  for(const route of ['/workshop-dashboard','/workshop/challenges','/workshop/progress']){
   await learner.goto(origin+route);await learner.waitForFunction(title=>document.body.innerText.includes(title)&&/1\s*\/\s*12/.test(document.body.innerText),{timeout:45000},title);
   if(route==='/workshop/progress')assert.equal(new URL(learner.url()).pathname,'/workshop-dashboard');
  }
  await learner.goto(origin+'/vulnerabilities/csrf-via-ai');await learner.waitForFunction(()=>document.body.innerText.includes('Total: 1/12')&&!document.body.innerText.includes('Loading exercise'),{timeout:45000});
  await learner.bringToFront();await learner.waitForFunction(()=>{const e=Array.from(document.querySelectorAll('button')).find(e=>e.textContent.trim()==='Reset tab');if(!e)return false;for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);if(Number(s.opacity)<.99||s.visibility==='hidden'||s.display==='none')return false;}return e.getBoundingClientRect().height>0;},{timeout:15000});
  await learner.screenshot({path:path.join(runtimeRoot,'csrf-baseline-projection.png'),fullPage:true});
  await admin.goto(origin+'/admin/exercises');const card='[data-exercise-key="csrf_prompt_injection"]';await admin.waitForSelector(card,{timeout:45000});
  await admin.$eval(card,el=>Array.from(el.querySelectorAll('button')).find(b=>b.textContent.includes('Manage Objectives')).click());
  await admin.waitForSelector('[data-objective-id="csrf_g2"]');assert.equal(await admin.$$eval('[data-objective-id]',els=>els.length),12);
  await admin.$eval('[data-objective-id="csrf_g2"] [data-control="visible"]',el=>el.click());
  await learner.goto(origin+'/workshop-dashboard');await learner.waitForFunction(()=>/0\s*\/\s*11/.test(document.body.innerText),{timeout:45000});
  await admin.$eval('[data-objective-id="csrf_g2"] [data-control="visible"]',el=>el.click());
  await learner.goto(origin+'/workshop/challenges');await learner.waitForFunction(()=>/1\s*\/\s*12/.test(document.body.innerText),{timeout:45000});
  await admin.$$eval('button', buttons => buttons.find(button => button.textContent === 'Done').click());
  await admin.waitForSelector('[data-objective-id="csrf_g2"]', { hidden: true });
  assert.ok(Number.isSafeInteger(getObjectiveCount) && getObjectiveCount > 0);
  const setGate = async (field, desired) => {
    const current = await admin.evaluate(async name => (await (await fetch('/api/workshop/config/snapshot')).json()).exercises.csrf_workshop[name], field);
    if (current !== desired) await admin.$eval(card + ' [data-control="' + (field === 'showHints' ? 'hints' : 'solutions') + '"]', button => button.click());
    await admin.waitForFunction(async (name, expected) => {
      const [snapshot, status] = await Promise.all([
        fetch('/api/workshop/config/snapshot').then(response => response.json()),
        fetch('/api/solutions/csrf-workshop/status').then(response => response.json()),
      ]);
      const kind = name === 'showHints' ? 'hint' : 'solution';
      const exercise = snapshot.exercises.csrf_workshop;
      return exercise[name] === expected && exercise.objectives.csrf_g2[kind + 'Visible'] === expected
        && status.master[kind === 'hint' ? 'hints' : 'solutions'] === expected
        && status.objectives.csrf_g2[kind] === expected;
    }, { timeout: 45000 }, field, desired);
  };
  const assertContentGates = async (hint, solution) => {
    await learner.goto(origin + '/vulnerabilities/csrf-via-ai');
    await learner.waitForFunction((count, hintEnabled, solutionEnabled) => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const amount = label => buttons.filter(button => button.textContent.trim() === label).length;
      return amount('Hint') === (hintEnabled ? count : 0) && amount('Solution') === (solutionEnabled ? count : 0);
    }, { timeout: 45000 }, getObjectiveCount, hint, solution);
    const responseCodes = await learner.evaluate(async () => Promise.all([
      fetch('/api/hints/csrf_workshop/csrf_g2').then(response => response.status),
      fetch('/api/solutions/csrf-workshop/objective/csrf_g2').then(response => response.status),
    ]));
    assert.deepEqual(responseCodes, [hint ? 200 : 403, solution ? 200 : 403]);
  };
  await setGate('showSolutions', false); await setGate('showHints', true); await assertContentGates(true, false);
  await setGate('showSolutions', true); await setGate('showHints', false); await assertContentGates(false, true);
  await admin.goto(origin+'/admin/student-workshop-view?studentId='+studentId);await admin.waitForFunction(title=>document.body.innerText.includes(title)&&/1\s*\/\s*12|1 of 12/.test(document.body.innerText),{timeout:45000},title);
  await admin.bringToFront();await admin.waitForFunction(title=>{const e=Array.from(document.querySelectorAll('.title')).find(e=>e.textContent.trim()===title);if(!e)return false;for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);if(Number(s.opacity)<.99||s.visibility==='hidden'||s.display==='none')return false;}return e.getBoundingClientRect().height>0;},{timeout:15000},title);
  await admin.screenshot({path:path.join(runtimeRoot,'csrf-admin-projection.png'),fullPage:true});
  return{modelCalls:0,scope:'Controlled canonical projection paired with separate retained actual g2 evidence',baseline:true,threeStudentViews:true,adminStudentView:true,objectiveVisibilityParity:true,independentHintSolutionControls:true,contentEndpointGates:true,completed:1,total:12};
 }catch(error){for(const [name,page] of [['learner',learner],['admin',admin]])if(page){await page.screenshot({path:path.join(runtimeRoot,`csrf-${name}-failure.png`),fullPage:true}).catch(()=>{});fs.writeFileSync(path.join(runtimeRoot,`csrf-${name}-failure.txt`),await page.$eval('body',el=>el.innerText).catch(()=>'unavailable'));}throw error;}finally{await browser?.close();await vite?.close();if(pid){let absent=false;try{process.kill(pid,0);}catch(e){if(e.code==='ESRCH')absent=true;}assert.equal(absent,true);}}
}
module.exports={qualifyCsrfProjection};
