'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {closeSecureShopBoundResources}=require('../server/services/secureshopBoundShutdown');
test('pool closure waits for audit drain and still runs after audit filesystem failure',async()=>{
 let release;const held=new Promise(resolve=>{release=resolve;});const events=[];
 const fsError=Error('spool cleanup failed'),browserError=Error('browser cleanup failed');
 const closing=closeSecureShopBoundResources({auditSummary:{async close(){events.push('audit');await held;throw fsError;}},
  closeBrowserAssessment(){events.push('browser');throw browserError;},closeCleanup(){events.push('pools');}});
 const failure=assert.rejects(closing,error=>error instanceof AggregateError&&error.errors[0]===fsError&&error.errors[1]===browserError);
 await Promise.resolve();assert.deepEqual(events,['audit']);release();await failure;
 assert.deepEqual(events,['audit','browser','pools']);
});
test('disabled audit serving still closes browser and cleanup pools',async()=>{
 let count=0;await closeSecureShopBoundResources({closeBrowserAssessment(){count++;},closeCleanup(){count++;}});assert.equal(count,2);
});
test('Listings close failure still closes browser and database resources and preserves every failure',async()=>{
 const listingError=Object.assign(Error('active listing operation'),{code:'LISTINGS_COMPOSITION_BUSY'});
 const poolError=Error('pool close failed');const events=[];
 await assert.rejects(closeSecureShopBoundResources({
  listings:{async close(){events.push('listings');throw listingError;}},
  async closeBrowserAssessment(){events.push('browser');},
  async closeCleanup(){events.push('pools');throw poolError;}
 }),error=>error instanceof AggregateError&&error.errors.length===2&&error.errors[0]===listingError&&error.errors[1]===poolError);
 assert.deepEqual(events,['listings','browser','pools']);
});

test('inventory shutdown failure cannot skip browser or pool closure',async()=>{
 const calls=[],failure=Error('inventory close failed');
 await assert.rejects(closeSecureShopBoundResources({inventory:{async close(){calls.push('inventory');throw failure;}},closeBrowserAssessment:async()=>{calls.push('browser');},closeCleanup:async()=>{calls.push('pools');}}),error=>error instanceof AggregateError&&error.errors.includes(failure));
 assert.deepEqual(calls,['inventory','browser','pools']);
});

test('composition drains every branch after registry and mail failures and shares concurrent close',async()=>{
 const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
 const source=fs.readFileSync(path.join(__dirname,'../server/services/secureshopBoundReviewComposition.js'),'utf8');
 const start=source.indexOf('async function closeSecureShopBoundReviewComposition()');
 const end=source.indexOf('\nmodule.exports =',start);
 assert.ok(start>=0&&end>start);
 // Evaluate the unchanged production close function with controlled lexical owners.
 // No module initialization, browser, pool or subprocess is needed.
 const events=[],registryError=Error('registry close'),mailError=Error('mail close'),poolError=Error('pool close');
 let release;const held=new Promise(resolve=>{release=resolve;});
 const context={pending:undefined,closing:undefined,retainedInputs:{},retained:{value:{
  ownedMcpRegistry:{async close(){events.push('registry');await held;throw registryError;}},
  mail:{async close(){events.push('mail');throw mailError;}},
  auditSummary:{async close(){events.push('audit');}},
  listings:{async close(){events.push('listings');}},
  inventory:{async close(){events.push('inventory');}},
  async closeBrowserAssessment(){events.push('browser');}
 }},async closeSecureShopCleanupComposition(){events.push('pools');throw poolError;},
 require(request){assert.equal(request,'./secureshopBoundShutdown');return{closeSecureShopBoundResources};}};
 vm.createContext(context);vm.runInContext(source.slice(start,end),context);
 const first=context.closeSecureShopBoundReviewComposition(),second=context.closeSecureShopBoundReviewComposition();
 const settled=Promise.allSettled([first,second]);
 assert.deepEqual(events,['registry']);assert.ok(context.retained);
 release();const results=await settled;
 assert.deepEqual(events,['registry','mail','audit','listings','inventory','browser','pools']);
 assert.ok(results.every(r=>r.status==='rejected'));
 assert.equal(results[0].reason,results[1].reason);
 assert.deepEqual(results[0].reason.errors,[registryError,mailError,poolError]);
 assert.equal(context.retained,undefined);assert.equal(context.retainedInputs,undefined);
 await context.closeSecureShopBoundReviewComposition();
 assert.equal(events.length,7);
});


test('registered invocation drains before resources close and retains its cleanup failure',async()=>{
 let release;const held=new Promise(resolve=>{release=resolve;}),calls=[],failure=Error('invocation drain failed');
 const closing=closeSecureShopBoundResources({registeredInvocation:{async close(){calls.push('invocation');await held;throw failure;}},
  ownedMcpRegistry:{async close(){calls.push('registry');}},async closeBrowserAssessment(){calls.push('browser');},async closeCleanup(){calls.push('pools');}});
 const rejected=assert.rejects(closing,error=>error instanceof AggregateError&&error.errors.includes(failure));
 await Promise.resolve();assert.deepEqual(calls,['invocation']);release();await rejected;
 assert.deepEqual(calls,['invocation','registry','browser','pools']);
});


test('separate oversized audit runtime drains even when the original audit close fails',async()=>{
 const calls=[],failure=Error('original audit close failed');
 await assert.rejects(closeSecureShopBoundResources({auditSummary:{async close(){calls.push('original');throw failure;}},auditUnbounded:{async close(){calls.push('unbounded');}},closeBrowserAssessment:async()=>calls.push('browser'),closeCleanup:async()=>calls.push('pools')}),error=>error instanceof AggregateError&&error.errors.includes(failure));
 assert.deepEqual(calls,['original','unbounded','browser','pools']);
});
