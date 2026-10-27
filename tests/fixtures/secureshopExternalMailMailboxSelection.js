'use strict';
// Rendered mailbox selection only. No mail-list, message, storage, or SMTP access.
const assert=require('node:assert/strict');
const ORIGINS=['https://sharklasers.com','https://www.sharklasers.com'];
function editorNode({kind,wait=false}){
 if(!['https://sharklasers.com','https://www.sharklasers.com'].includes(location.origin))throw Error('MAILBOX_ORIGIN');
 const visible=n=>!n.disabled&&n.getClientRects().length>0;
 const inputs=[...document.querySelectorAll('input[type="text"]')].filter(visible);
 const sets=[...document.querySelectorAll('button,input[type="button"],input[type="submit"]')]
  .filter(n=>visible(n)&&(n.tagName==='INPUT'?n.value:n.textContent).trim()==='Set');
 const anchors=document.querySelectorAll('#inbox-id');
 if(inputs.length!==1||sets.length!==1||anchors.length!==1){if(wait)return false;throw Error('MAILBOX_EDITOR_AMBIGUOUS');}
 let region=inputs[0].parentElement;
 while(region&&region.tagName!=='BODY'&&region.tagName!=='HTML'&&!region.contains(sets[0]))region=region.parentElement;
 if(!region||['BODY','HTML'].includes(region.tagName)||!(region.contains(anchors[0])||anchors[0].contains(region))){if(wait)return false;throw Error('MAILBOX_EDITOR_ASSOCIATION');}
 return wait?true:(kind==='input'?inputs[0]:sets[0]);
}
function readMailbox(){
 const one=s=>{const ns=document.querySelectorAll(s);if(ns.length!==1)throw Error('MAILBOX_SELECTOR_UNVERIFIED');return ns[0];};
 if(!['https://sharklasers.com','https://www.sharklasers.com'].includes(location.origin))throw Error('MAILBOX_ORIGIN');
 const name=one('#inbox-id'),domain=one('#gm-host-select');
 return {local:name.textContent.trim(),domain:domain.value};
}
function selectionStructure({recipient}){
 if(!['https://sharklasers.com','https://www.sharklasers.com'].includes(location.origin))throw Error('MAILBOX_ORIGIN');
 const widgets=document.querySelectorAll('#email-widget'),names=document.querySelectorAll('#inbox-id'),domains=document.querySelectorAll('#gm-host-select');
 const widget=widgets.length===1?widgets[0]:null;
 const controls=[...document.querySelectorAll('input,select,button,[contenteditable="true"]')].slice(0,64).map(n=>({
  tag:['INPUT','SELECT','BUTTON','SPAN','DIV'].includes(n.tagName)?n.tagName:'OTHER',
  id:['email-widget','inbox-id','gm-host-select'].includes(n.id)?n.id:null,
  type:['text','button','submit','hidden','checkbox','radio'].includes(n.getAttribute('type'))?n.getAttribute('type'):null,
  inWidget:!!widget&&widget.contains(n),visible:!!(n.getClientRects().length),disabled:n.disabled===true,
  editable:n.isContentEditable===true,
  setControl:(n.tagName==='BUTTON'||(n.tagName==='INPUT'&&['button','submit'].includes(n.getAttribute('type'))))
   ?(n.tagName==='INPUT'?n.value:n.textContent).trim()==='Set':false
 }));
 return {widgetCount:widgets.length,nameCount:names.length,domainCount:domains.length,
  localMatches:names.length===1&&names[0].textContent.trim()===recipient.split('@')[0],
  domainMatches:domains.length===1&&domains[0].value==='sharklasers.com',controls};
}
async function selectMailbox(options){
 let substep='MAILBOX_ADMISSION';const original=options.step;
 options.onSubstep?.(substep);
 try{return await performSelection({...options,step:(work,cap,label)=>{substep=label;options.onSubstep?.(label);return Promise.resolve().then(()=>original(work,cap,label)).catch(e=>{e.selectionSubstep=label;throw e;});}});}
 catch(error){
  const reasons=['MAILBOX_ORIGIN','MAILBOX_ORIGIN_CHANGED','MAILBOX_SELECTOR_UNVERIFIED','MAILBOX_WIDGET','MAILBOX_SET_UNVERIFIED','MAILBOX_EDITOR_AMBIGUOUS','MAILBOX_EDITOR_ASSOCIATION','MAILBOX_INPUT_NOT_EMPTY','MAILBOX_INPUT_NOT_EXACT','MAILBOX_READBACK_MISMATCH','INSPECTION_DEADLINE'];
  const diagnostic={substep:error.selectionSubstep||substep,reason:reasons.includes(error?.message)?error.message:null,structure:null,structureAvailable:false};
  try{diagnostic.structure=await original(()=>options.page.evaluate(selectionStructure,{recipient:options.recipient}),1000,'MAILBOX_DIAGNOSTIC');diagnostic.structureAvailable=true;}catch{}
  error.selectionDiagnostic=diagnostic;throw error;
 }
}
async function performSelection({page,recipient,step,remain,armPost}){
 assert.match(recipient,/^goat-[a-f0-9]{16}@sharklasers\.com$/);
 const origin=new URL(page.url()).origin;assert(ORIGINS.includes(origin),'MAILBOX_ORIGIN');
 const check=()=>{remain(1);assert.equal(new URL(page.url()).origin,origin,'MAILBOX_ORIGIN_CHANGED');};
 const local=recipient.split('@')[0];
 check();await step(()=>page.select('#gm-host-select','sharklasers.com'),10000,'MAILBOX_DOMAIN');
 check();await step(()=>page.click('#inbox-id'),10000,'MAILBOX_EDIT');
 await step(()=>page.waitForFunction(editorNode,{timeout:remain(10000)},{kind:'input',wait:true}),10000,'MAILBOX_INPUT');
 const input=await step(()=>page.evaluateHandle(editorNode,{kind:'input'}),5000,'MAILBOX_FOCUS');
 let inputError;
 try{
  check();await step(()=>input.click({count:3}),5000,'MAILBOX_FOCUS');
  check();await step(()=>input.press('Backspace'),5000,'MAILBOX_FOCUS');
  assert.ok(await step(()=>input.evaluate(node=>node.value===''),1000,'MAILBOX_FOCUS'),'MAILBOX_INPUT_NOT_EMPTY');
  check();await step(()=>input.type(local),5000,'MAILBOX_TYPE');
  assert.ok(await step(()=>input.evaluate((node,expected)=>node.value===expected,local),1000,'MAILBOX_TYPE'),'MAILBOX_INPUT_NOT_EXACT');
 }catch(e){inputError=e;}
 try{await step(()=>input.dispose(),1000,'MAILBOX_HANDLE_DISPOSE');}catch(e){if(!inputError)inputError=e;}
 if(inputError)throw inputError;
 const handle=await step(()=>page.evaluateHandle(editorNode,{kind:'set'}),5000,'MAILBOX_SET_CONTROL');
 let clickError;
 try{check();if(armPost){const context=await step(()=>page.evaluate(()=>{
   if(location.origin!=='https://www.sharklasers.com')throw Error('MAILBOX_ORIGIN');
   const nodes=document.querySelectorAll('#inbox-id');if(nodes.length!==1||nodes[0].textContent.length>256)throw Error('MAILBOX_POST_CONTEXT');
   return nodes[0].textContent;
  }),1000,'MAILBOX_SET_CONTROL');armPost(context);}
  check();await step(()=>handle.click(),5000,'MAILBOX_SET');}catch(e){clickError=e;}
 try{await step(()=>handle.dispose(),1000,'MAILBOX_HANDLE_DISPOSE');}catch(e){if(!clickError)clickError=e;}
 if(clickError)throw clickError;
 await step(()=>page.waitForFunction(({local})=>{
  const names=document.querySelectorAll('#inbox-id'),domains=document.querySelectorAll('#gm-host-select');
  return names.length===1&&domains.length===1&&names[0].textContent.trim()===local&&domains[0].value==='sharklasers.com';
 },{timeout:remain(15000)},{local}),15000,'MAILBOX_READBACK');
 check();const actual=await step(()=>page.evaluate(readMailbox),5000,'MAILBOX_VERIFY');check();
 assert.ok(actual.local===local&&actual.domain==='sharklasers.com','MAILBOX_READBACK_MISMATCH');
 return {recipient,origin,mailboxSelected:true,readbackConfirmed:true,messageSelectorsVerified:false,smtpAttempted:false,deliveryConfirmed:false};
}
module.exports={selectMailbox,readMailbox,selectionStructure,editorNode};
