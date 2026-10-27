'use strict';
// This exact source becomes tests/secureshopPricingChatLifecycle.test.js on apply.
const test=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {EventEmitter}=require('node:events');
const FIXTURE=path.join(__dirname,'postgres/secureshopStandalonePricingRendered.integration.test.js');
const source=readFileSync(FIXTURE,'utf8');
function exactBetween(start,end){const left=source.indexOf(start),right=source.indexOf(end,left+start.length);
 assert.ok(left>=0&&right>left);return source.slice(left,right);}
function controls(){const body=exactBetween('function observeV34BrowserLifecycle(', 'async function qualifyPricingChatBrowser(');
 return new Function('createHash','PRICING_CHAT',body+
  '\nreturn {observeV34BrowserLifecycle,retainV34BrowserLifecycle,retainPricingChatBrowserLifecycle};')
  (crypto.createHash,true);}
function fake(){const child=new EventEmitter();Object.assign(child,{pid:12345,exitCode:null,signalCode:null,
  spawnargs:['/private/browser','--headless','--user-data-dir=/private/secret','--password=secret']});
 const browser=new EventEmitter();browser.process=()=>child;browser.connected=true;
 const page=new EventEmitter();page.isClosed=()=>page.closed===true;page.closed=false;
 return {child,browser,page};}
test('Pricing chat actual viewport-close path preserves primary and retains bounded redacted lifecycle',async()=>{
 const {observeV34BrowserLifecycle,retainV34BrowserLifecycle,retainPricingChatBrowserLifecycle}=controls();
 assert.ok(source.includes('if(v34||PRICING_CHAT)try{browserLifecycle=observeV34BrowserLifecycle(browser);}catch{}'));
 const {child,browser,page}=fake(),lifecycle=observeV34BrowserLifecycle(browser),status={};
 const start=exactBetween("  browserLifecycle?.mark('browser-admission');",'  if(v34||v34Preflight){const mouseClick');
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 const startup=new AsyncFunction('browser','browserLifecycle','retainedAdmission','profile','require',
  'let page;\n'+start+'\nreturn page;');
 const primary=Object.assign(Error('original viewport error'),{name:'TargetCloseError'});
 browser.newPage=async()=>page;
 page.setViewport=async()=>{page.closed=true;page.emit('close');browser.connected=false;
  browser.emit('disconnected');child.exitCode=1;child.emit('exit',1,null);throw primary;};
 const catchBody=exactBetween(" }catch(error){\n  await retainV34BrowserLifecycle(v34,browserLifecycle,'failure-lifecycle');",
  '  if((v34||v34Preflight)&&page)');
 const catchRun=new AsyncFunction('error','v34','browserLifecycle','status',
  'retainV34BrowserLifecycle','retainPricingChatBrowserLifecycle',
  catchBody.slice(' }catch(error){\n'.length)+'\nthrow error;');
 await assert.rejects(startup(browser,lifecycle,null,'owned-profile',()=>assert.fail('no admission')),
  error=>error===primary);
 await assert.rejects(catchRun(primary,null,lifecycle,status,retainV34BrowserLifecycle,
  retainPricingChatBrowserLifecycle),error=>error===primary);
 assert.equal(status.browserLifecycleFailure.stage,'viewport');
 assert.deepEqual(status.browserLifecycleFailure.events.map(row=>row.kind),
  ['page-close','browser-disconnected','process-exit']);
 assert.equal(status.browserLifecycleFailure.current.pageClosed,true);
 assert.doesNotMatch(JSON.stringify(status),/secret|private\/browser|password/);
 browser.close=async()=>{child.emit('close',1,null);};
 const cleanup=exactBetween("  browserLifecycle?.mark('fixture-cleanup');",'\n }');
 const cleanupRun=new AsyncFunction('browser','browserLifecycle','cdp','v34','status',
  'retainV34BrowserLifecycle','retainPricingChatBrowserLifecycle',cleanup);
 await cleanupRun(browser,lifecycle,null,null,status,retainV34BrowserLifecycle,retainPricingChatBrowserLifecycle);
 assert.equal(status.browserLifecycleCleanup.stage,'fixture-cleanup');
 assert.equal(status.browserLifecycleCleanup.events.at(-1).kind,'process-close');
 for(const emitter of [child,browser,page])assert.equal(emitter.eventNames().length,0);
 assert.equal(status.browserLifecycleCaptureFailed,undefined);
});
test('Pricing chat observer failure cannot mask original error or fabricate completion',()=>{
 const {retainPricingChatBrowserLifecycle}=controls(),status={passed:false};
 const primary=Error('primary');
 try{retainPricingChatBrowserLifecycle(status,{snapshot(){throw Error('observer failure');}},'failure');
  throw primary;}catch(error){assert.equal(error,primary);}
 assert.equal(status.browserLifecycleCaptureFailed,true);
 assert.equal(status.browserLifecycleFailure,undefined);
 assert.equal(status.passed,false);
});
