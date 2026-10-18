'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),Module=require('node:module');
const names=['ragProgressStore','adminWorkshopResetService','workshopConfigService','workshopProgressService','changeRevisionService','emailWorkshopStore','workshopModeService','promptInjectionProgressService','workshopConfigMutationService'];
const paths=names.map(name=>path.resolve(__dirname,'../server/services',name+'.js'));

test('all nine supported service defaults select PostgreSQL without legacy fallback and retain owner/progress contracts',async()=>{
  const previous=process.env.PLATFORM_DATABASE_ENGINE,load=Module._load;
  try{
    for(const engine of [undefined,'sqlite','postgres']){
      if(engine===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=engine;
      const calls=[];
      const progress={
        getWorkshopProgress:async(owner,key)=>{calls.push(['progress',owner,key]);return {objectives:[{id:'interact',completed:true,completedAt:'controlled-time'}]};},
        resetWorkshopProgress:async(...args)=>{calls.push(['progress-reset',...args]);},
        syncObjectiveComplete:async()=>assert.fail('Controlled durable response must not synthesize credit'),
      };
      const config={getSnapshot:async()=>({exercises:{direct_prompt_injection:{isVisible:true,objectives:{interact:{isVisible:true}}}}})};
      const revisions={initialize:async()=>{},bump:async change=>{calls.push(['revision',change]);return 3;},getSnapshot:async scopes=>({revision:3,scopes})};
      const modes={initialize:async()=>{},getMode:async input=>{calls.push(['mode-read',input]);return 'fixed';},setMode:async input=>{calls.push(['mode-write',input]);}};
      const pool={query:async(sql,args)=>{calls.push(['query',sql,args]);return {rows:sql.includes('activity_count')?[{activity_count:2}]:[{user_email:'learner@example.invalid'}]};}};
      const stores={progress,config,revisions,modes,pool};
      const resets={resetStudent:async input=>{calls.push(['student-reset',input]);return {success:true};}};
      Module._load=function(request,parent,isMain){
        if(request==='sqlite3'||request==='better-sqlite3'||request.endsWith('/authDb')||request==='./changeRevisionStore'||request==='./workshopModeStore')assert.fail('Legacy default import forbidden: '+request);
        if(paths.includes(parent?.filename)){
          // Revision service logging is an external sink, not a store-selection
          // contract. The real Winston file transport opens asynchronously.
          if(request==='../utils/logger')return {error:()=>assert.fail('Unexpected controlled revision failure')};
          if(request==='./postgresPlatformStores')return {getPostgresPlatformStores:()=>stores};
          if(request==='./postgresIdentityAdapter')return {getPostgresIdentityAdapter:()=>({pool})};
          if(request==='./postgresWorkshopResetService')return {getPostgresWorkshopResetService:()=>resets};
        }
        return load.call(this,request,parent,isMain);
      };
      for(const file of paths)delete require.cache[file];
      const service=Object.fromEntries(names.map((name,i)=>[name,require(paths[i])]));
      assert.equal(service.workshopConfigService.createWorkshopConfigService(),config);
      assert.equal(service.workshopConfigMutationService.createWorkshopConfigMutationService(),config);
      assert.equal(service.workshopProgressService.createWorkshopProgressService(),progress);
      assert.equal(service.adminWorkshopResetService.getProductionStudentWorkshopResetService(),resets);
      await resets.resetStudent({userId:71,workshopKey:'direct_prompt_injection'});
      const rag=service.ragProgressStore.createDefaultRagProgressStore(['interact']);
      assert.deepEqual(await rag.get({platformUserId:71}),{interact:{completed:true,completedAt:'controlled-time'}});
      await rag.complete({platformUserId:71,objectiveId:'interact',durable:true});
      await rag.reset({platformUserId:71});
      const dpi=service.promptInjectionProgressService.createDefaultPromptInjectionProgressService();
      await assert.rejects(dpi.getProgress({userId:71,userKey:'72'}),error=>error.code==='USER_MISMATCH');
      assert.equal((await dpi.getProgress({userId:71,userKey:'71'})).completedObjectiveCount,1);
      await assert.rejects(dpi.completeObjective({userId:71,userKey:'71',objectiveId:'interact'}),error=>error.code==='JUDGED_ATTEMPT_REQUIRED');
      await dpi.resetProgress({userId:71,userKey:'71'});
      assert.equal(await service.workshopModeService.getMode({userId:71,workshopKey:'direct_prompt_injection'}),'fixed');
      await service.workshopModeService.setMode({userId:71,workshopKey:'direct_prompt_injection',mode:'vuln'});
      assert.equal(await service.changeRevisionService.bump({scopeType:'user',scopeKey:'71',category:'progress'}),3);
      assert.deepEqual(await service.changeRevisionService.getSnapshot(['71']),{revision:3,scopes:['71']});
      assert.equal(await service.emailWorkshopStore.getConfiguredEmail('student-71'),'learner@example.invalid');
      await service.emailWorkshopStore.resetProgress('student-71');
      assert(calls.some(row=>row[0]==='query'&&row[1].includes('DELETE FROM identity.email_agent_progress WHERE user_key=$1')&&row[2][0]==='student-71'));
      assert(calls.some(row=>row[0]==='progress-reset'&&row[1]===71&&row[2]==='indirect_prompt_injection'));
      assert(calls.some(row=>row[0]==='progress-reset'&&row[1]===71&&row[2]==='direct_prompt_injection'));
      assert(calls.some(row=>row[0]==='mode-write'&&row[1].userId===71&&row[1].mode==='vuln'));
    }
  }finally{
    Module._load=load;for(const file of paths)delete require.cache[file];
    if(previous===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=previous;
  }
});
