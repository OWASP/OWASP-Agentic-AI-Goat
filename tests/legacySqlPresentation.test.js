'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const presentation=require('../server/services/legacySqlPresentation');
function fixture(error=null,rows=[]) {
  const routes=new Map(),calls=[];
  const router={};for(const method of ['get','post','put','delete'])router[method]=(url,...handlers)=>routes.set(method+' '+url,handlers.at(-1));
  const stubs={express:{Router:()=>router},'../database/legacyChallengeStore':{engine:'postgres',executeAiSql:(sql,callback)=>{calls.push(sql);callback(error,rows);}},'../utils/logger':{},'../services/legacySqlPresentation':presentation,'../services/legacyPlatformMutationLifecycle':{legacyPlatformMutationMiddleware:()=>{}}};
  const file=path.resolve(__dirname,'../server/routes/ecommerce.js'),loaded=new Module(file,module);loaded.filename=file;loaded.require=id=>{assert.ok(Object.hasOwn(stubs,id),'Unexpected dependency '+id);return stubs[id];};loaded._compile(fs.readFileSync(file,'utf8'),file);
  return {calls,request(body){let status=200,result;routes.get('post /ai-query')({body},{status(code){status=code;return this;},json(value){result=value;}});return {status,body:result};}};
}
for(const attackType of ['basic','union','boolean_blind','time_blind','error_based','stacked','nosql'])test('legacy '+attackType+' reports observations without a model or Judge claim',()=>{
  const f=fixture(null,[{username:'ordinary_fixture'}]);const r=f.request({query:'fixture',sqlQuery:'SELECT * FROM users',userId:7,attackType});assert.equal(r.status,200);assert.equal(f.calls.length,1);assert.equal(r.body.sqlQuery,f.calls[0]);assert.deepEqual(r.body.results,[{username:'ordinary_fixture'}]);assert.match(r.body.aiResponse,/returned 1 row/);assert.doesNotMatch(r.body.aiResponse,/attack successful|in your account|injection executed|extracted sensitive/);assert.match(r.body.educationalNote,/no LLM decision or objective Judge/);
  if(attackType==='union')assert.match(f.calls[0],/UNION SELECT/);
  if(attackType==='stacked'){assert.match(f.calls[0],/; INSERT INTO audit_log/);assert.match(r.body.educationalNote,/extended query mode/);}
});
test('SQL errors remain visible as teaching observations and never become success',()=>{const f=fixture(new Error('cannot insert multiple commands into a prepared statement'));const r=f.request({sqlQuery:'SELECT 1',attackType:'stacked',query:'fixture',userId:7});assert.equal(r.status,500);assert.match(r.body.details,/multiple commands/);assert.equal(r.body.aiResponse,undefined);});
test('empty and ordinary rows do not imply boolean truth or account ownership',()=>{assert.match(presentation.describeLegacySqlResult('boolean_blind',[]),/not a verified TRUE\/FALSE/);assert.match(presentation.describeLegacySqlResult('basic',[]),/returned 0 row/);assert.doesNotMatch(presentation.describeLegacySqlResult('basic',[{}]),/Here.*your profile/);});
