'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function shutdown(budget,attacker,victim){
 const source=fs.readFileSync(path.join(__dirname,'../server/routes/csrfWorkshop.js'),'utf8');
 const start=source.indexOf('router.closeBrowser = async () => {'),end=source.indexOf('\nmodule.exports = router;',start);
 assert(start>=0&&end>start);
 const context={router:{},browserExecutionBudget:{close:budget},attackerBrowserExecutor:{close:attacker},victimDocumentBrowserExecutor:{close:victim},AggregateError};
 vm.runInNewContext(source.slice(start,end),context);return context.router.closeBrowser;
}
test('actual route shutdown retains rejected close and waits for the other executor',async()=>{
 const error=Error('attacker close failed'),calls=[];let release;
 const held=new Promise(resolve=>{release=resolve;});
 const close=shutdown(()=>calls.push('budget'),async()=>{calls.push('attacker');throw error;},async()=>{calls.push('victim');await held;});
 let settled=false;const result=close().finally(()=>{settled=true;});const failure=assert.rejects(result,e=>e===error);
 await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);assert.deepEqual(calls,['budget','attacker','victim']);release();await failure;
});
test('budget and synchronous executor failures cannot skip other cleanup and remain ordered',async()=>{
 const errors=[Error('budget'),Error('attacker'),Error('victim')],calls=[];
 const close=shutdown(()=>{calls.push(0);throw errors[0];},()=>{calls.push(1);throw errors[1];},async()=>{calls.push(2);throw errors[2];});
 await assert.rejects(close(),e=>e instanceof AggregateError&&e.errors.length===3&&e.errors.every((x,i)=>x===errors[i]));assert.deepEqual(calls,[0,1,2]);
});
test('successful shutdown still closes budget and both executors',async()=>{
 const calls=[];await shutdown(()=>calls.push(0),()=>calls.push(1),()=>calls.push(2))();assert.deepEqual(calls,[0,1,2]);
});
