'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
async function qualifyRenderedDashboardParity({browser,origin,platformToken,pool,userId,completed,workspace,phase,objectiveId='ss_audit_instruction_followed',artifactPrefix='audit'}) {
  const headers={authorization:`Bearer ${platformToken}`};
  const read=async endpoint=>{
    const response=await fetch(`${origin}${endpoint}`,{headers});assert.equal(response.status,200);
    return response.json();
  };
  const [challengeResponse,progressResponse,stats,time]=await Promise.all([
    read('/api/workshop/challenges'),read('/api/workshop/progress'),read('/api/workshop/student/stats'),read('/api/workshop/time/summary')]);
  const key='secureshop_agent_security';
  const challenge=challengeResponse.challenges.find(row=>row.workshopKey===key);
  const progress=progressResponse.challenges.find(row=>row.workshopKey===key);
  assert.ok(challenge);assert.deepEqual(progress,challenge);
  assert.equal(challenge.objectives.find(row=>row.id===objectiveId).completed,completed);
  assert.equal(stats.completedObjectives,challenge.completedObjectiveCount);
  assert.equal(stats.totalObjectives,challenge.objectiveCount);
  assert.equal(stats.completedChallenges,challenge.completed?1:0);
  assert.equal(time.summary[key],challenge.timeSpentSeconds);
  const bulk=await require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(pool).getUsersProgress([userId]);
  const admin=bulk.get(userId).find(row=>row.workshopKey===key);
  assert.equal(admin.completedObjectiveCount,challenge.completedObjectiveCount);
  assert.equal(admin.objectiveCount,challenge.objectiveCount);
  assert.equal(admin.timeSpentSeconds,challenge.timeSpentSeconds);
  const page=await browser.newPage(),errors=[];
  try {
    await page.setViewport({width:1440,height:1000});
    page.on('pageerror',error=>errors.push(error.message));
    await page.setRequestInterception(true);
    page.on('request',request=>new URL(request.url()).origin===origin?request.continue():request.abort());
    await page.evaluateOnNewDocument(token=>localStorage.setItem('token',token),platformToken);
    const done=challenge.completedObjectiveCount,total=challenge.objectiveCount;
    for(const route of ['/workshop-dashboard','/workshop/challenges','/workshop/progress']) {
      const navigation=await page.goto(`${origin}${route}`,{waitUntil:'domcontentloaded'});
      assert.ok([200,304].includes(navigation.status()),'document may reuse its validated cached build');
      if(route==='/workshop/challenges') {
        await page.waitForFunction(expected=>document.body.textContent.includes(expected),{timeout:20000},`${done}/${total} objectives done`);
        await page.waitForFunction(label=>[...document.querySelectorAll('span')].some(node=>node.textContent===label),
          {timeout:10000},challenge.objectives.find(row=>row.id===objectiveId).text);
      } else {
        await page.waitForFunction(({done,total})=>{
          const labels=[...document.querySelectorAll('div')].filter(node=>node.textContent.trim()==='Objectives');
          return labels.some(node=>node.parentElement.textContent.replace(/\s+/g,'').includes(`Objectives${done}/${total}`));
        },{timeout:20000},{done,total});
        assert.equal(new URL(page.url()).pathname,'/workshop-dashboard','historical progress route must reach the canonical dashboard');
        const renderedMetrics=await page.evaluate(()=>Object.fromEntries(['Exercises','Time'].map(label=>{
          const node=[...document.querySelectorAll('div')].find(item=>item.textContent.trim()===label);
          return [label,node?.nextElementSibling?.textContent.replace(/\s+/g,'')];
        })));
        assert.equal(renderedMetrics.Exercises,`${stats.completedChallenges}/${challengeResponse.challenges.length}`);
        const seconds=Math.max(0,Math.floor(challenge.timeSpentSeconds));
        const minutes=Math.floor((seconds%3600)/60),hours=Math.floor(seconds/3600);
        assert.equal(renderedMetrics.Time,seconds<60?`${seconds}s`:hours>0?`${hours}h${minutes}m`:`${minutes}m`);

      }
      await page.waitForFunction(() => {
        const targets=[...document.querySelectorAll('h1,h3,span,div')].filter(node=>
          ['SecureShop Agent Security','Objectives'].includes(node.textContent.trim()));
        return targets.length>0 && targets.every(target=>{
          for(let node=target;node;node=node.parentElement) {
            if(Number(getComputedStyle(node).opacity)<0.99) return false;
          }
          return true;
        });
      },{timeout:15000});
      const screenshot=path.join(workspace,`${artifactPrefix}-${phase}-${route.split('/').filter(Boolean).join('-')}.png`);
      await page.screenshot({path:screenshot,fullPage:true});await fs.chmod(screenshot,0o600);
    }
    assert.deepEqual(errors,[]);
    await fs.writeFile(path.join(workspace,`${artifactPrefix}-${phase}-dashboard-parity.json`),JSON.stringify({
      workshopKey:key,completed:done,total,timeSeconds:challenge.timeSpentSeconds,
      completedExercises:stats.completedChallenges,routes:['/workshop-dashboard','/workshop/challenges','/workshop/progress'],
      adminScope:'native bulk projection; not rendered administrator pages',
    },null,2),{mode:0o600});
  } finally { await page.close(); }
}
module.exports={qualifyRenderedDashboardParity};
