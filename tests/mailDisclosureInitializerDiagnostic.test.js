'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('./postgres/secureshopListingsFullApp.native.js'),'utf8');
test('both diagnostic and rendered paths share exact bounded initializer subprocess sequence',async()=>{
 const start=source.indexOf('  const initializeOwned = async () => {'),end=source.indexOf("  if(process.env.MAIL_DISCLOSURE_INITIALIZE_ONLY",start);assert(start>=0&&end>start);
 for(const failure of [false,true]){const calls=[],waits=[];const run=vm.runInNewContext(source.slice(start,end)+'initializeOwned',{assert,owned:{launch:(node,args,options)=>{calls.push({node,args,options});return calls.length;}},process:{execPath:'/owned/node'},source:'/owned/source',env:{private:'not logged'},waitForChild:async(child,options)=>{waits.push(options.timeoutMs);return failure&&child===1?1:0;}});
 if(failure)await assert.rejects(run());else await run();assert.equal(calls.length,failure?1:2);assert.equal(calls[0].args[0],'server/database/sensitiveInfoFiles.js');if(!failure)assert.equal(calls[1].args[0],'db/postgres/initialize-application.js');assert(waits.every(x=>x===150000));assert(calls.every(x=>x.options.cwd==='/owned/source'));
 }
 const diagnostic=source.slice(end,source.indexOf("  const id=require('../../scripts/application-data-root')",end));assert.match(diagnostic,/await initializeOwned\(\);result.status='initializer-diagnostic-passed';save\(\);return;/);assert(!diagnostic.includes('backend'));assert.equal(source.match(/await initializeOwned\(\)/g).length,2);
});

test('diagnostic finally records and refuses controlled generation on success or failure',()=>{
 const start=source.indexOf("if(process.env.MAIL_DISCLOSURE_INITIALIZE_ONLY==='1'){result.diagnosticTransport="),end=source.indexOf('}\n})().catch',start);assert(start>=0&&end>start);const snippet=source.slice(start,end);
 for(const status of ['initializer-diagnostic-passed','failed'])for(const generation of [0,1]){const result={status};let saved=false;const work=()=>vm.runInNewContext(snippet,{process:{env:{MAIL_DISCLOSURE_INITIALIZE_ONLY:'1'}},result,modelList:{counts:()=>({generation,actualModelCalls:0})},save:()=>{saved=true;},assert});if(generation)assert.throws(work);else work();assert(saved);assert.equal(result.diagnosticTransport.generation,generation);assert.equal(result.status,status);}
});
