'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {selectInboxUser}=require('./fixtures/secureshopMailDisclosureBrowser');
function browser({loseFocus=false,fallback=false}={}){
 let value='12',observing=false,checks=0,held=false,selected=false;const calls=[];let listener;
 const input={async click(){calls.push('focus');},async press(key){if(key==='End'){calls.push('end');return;}if(key==='Home'){assert(held);selected=true;calls.push('selectHome');return;}assert.equal(key,'Backspace');value=selected?'':value.slice(0,-1);calls.push('clear');if(fallback)listener({method:()=> 'GET',url:()=> 'http://lab/api/secureshop/email/inbox/1'});},async type(char){assert.equal(char.length,1);value+=char;calls.push(char);}};
 const page={keyboard:{async down(key){assert.equal(key,'Shift');held=true;},async up(key){assert.equal(key,'Shift');held=false;}},on(event,fn){assert.equal(event,'request');observing=true;listener=fn;},off(event,fn){assert.equal(fn,listener);observing=false;}};
 const frame={async waitForSelector(selector,options){assert.equal(selector,'[data-testid="inbox-userid"]');assert.deepEqual(options,{visible:true,timeout:15000});calls.push('ready');return input;},async evaluate(fn,el){if(!el)return undefined;assert.equal(el,input);checks++;return {connected:true,sameNode:true,focused:!loseFocus,...(fn.toString().includes('value:el.value')?{value}:{})};},async waitForFunction(fn,opts,text){if(text===input){assert.match(fn.toString(),/!el.disabled/);return;}assert.equal(value,text);}};
 return {page,frame,calls,get observing(){return observing;},get checks(){return checks;}};
}
test('native End and Shift Home precede clear and incremental typing',async()=>{
 const b=browser();await selectInboxUser({...b,id:123});assert.deepEqual(b.calls,['ready','focus','end','selectHome','clear','1','2','3']);assert.equal(b.checks,4);assert.equal(b.observing,false);
});
test('lost focus or fallback inbox request fails qualification with separate diagnostics',async()=>{
 for(const options of [{loseFocus:true},{fallback:true}]){const b=browser(options);await assert.rejects(selectInboxUser({...b,id:12}),error=>{assert.match(error.message,/focused selector|fallback inbox/);if(options.loseFocus)assert.deepEqual(error.actual,{connected:true,sameNode:true,focused:false,value:''});return true;});assert.equal(b.observing,false);}
});
test('waits for a mounted Inbox selector and rejects a replacement during the edit',async()=>{
 const loading=browser();let mounted=false;
 const wait=loading.frame.waitForSelector;
 loading.frame.waitForSelector=async(...args)=>{assert.equal(mounted,false);await Promise.resolve();mounted=true;return wait(...args);};
 loading.frame.$=async()=>{throw Error('premature selector lookup');};
 await selectInboxUser({...loading,id:23});
 assert.equal(mounted,true);assert.equal(loading.observing,false);
 const replaced=browser();const evaluate=replaced.frame.evaluate;let first=true;
 replaced.frame.evaluate=async(...args)=>{const value=await evaluate(...args);if(first&&args[1]){first=false;return {...value,connected:false,sameNode:false};}return value;};
 await assert.rejects(selectInboxUser({...replaced,id:23}),/Blank edit must retain focused selector/);
 assert.equal(replaced.observing,false);
});
test('invalid or lossy IDs are rejected before browser interaction',async()=>{
 for(const id of [0,-1,1.5,Number.MAX_SAFE_INTEGER+1,'01','1e2','',null])await assert.rejects(selectInboxUser({page:{},frame:{},id}),/Canonical inbox user ID required/);
 const b=browser();await selectInboxUser({...b,id:'9007199254740993'});assert.equal(b.calls.slice(5).join(''),'9007199254740993');
});
