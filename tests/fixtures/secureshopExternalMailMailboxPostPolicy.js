'use strict';
const assert=require('node:assert/strict');
function createMailboxPostGate({recipient,deadline,now=Date.now}){
 assert.match(recipient,/^goat-[a-f0-9]{16}@sharklasers\.com$/);
 let armed=false,consumed=false,expectedIn;
 return {
  arm(value){assert(!armed&&!consumed&&now()<deadline,'MAILBOX_POST_ARM');assert(typeof value==='string'&&value.length<=256,'MAILBOX_POST_CONTEXT');expectedIn=value;armed=true;},
  allow({url,method,body,substep}){
   if(!['MAILBOX_SET','MAILBOX_HANDLE_DISPOSE','MAILBOX_READBACK'].includes(substep)||!armed||consumed||now()>=deadline||method!=='POST'||typeof body!=='string'||Buffer.byteLength(body)>1024||/%(?![a-f0-9]{2})/i.test(body))return false;
   let u;try{u=new URL(url);}catch{return false;}
   if(u.origin!=='https://www.sharklasers.com'||u.username||u.password||u.pathname!=='/ajax.php'||u.hash)return false;
   if([...u.searchParams].length!==1||u.searchParams.get('f')!=='set_email_user')return false;
   const form=new URLSearchParams(body),keys=[...form.keys()];
   if(keys.length!==4||new Set(keys).size!==4||keys.some(k=>!['email_user','lang','site','in'].includes(k)))return false;
   if(form.get('email_user')!==recipient.split('@')[0]||form.get('lang')!=='en'||form.get('site')!=='sharklasers.com'||form.get('in')!==expectedIn)return false;
   consumed=true;return true; // Authorization is consumed before continue(), including uncertain failure.
  },
  inspect({url,method,body,substep}){
   let u=null;try{u=new URL(url);}catch{}
   const bodyType=typeof body==='string',bodyBound=bodyType&&Buffer.byteLength(body)<=1024;
   const form=bodyBound?new URLSearchParams(body):null,keys=form?[...form.keys()]:[];
   return {path:u?.pathname==='/ajax.php'?'/ajax.php':'OTHER',action:u?.searchParams.get('f')==='set_email_user'?'set_email_user':'OTHER',
    formKeys:keys.slice(0,8).map(k=>['email_user','lang','site','in'].includes(k)?k:'OTHER'),
    checks:{armed,unconsumed:!consumed,beforeDeadline:now()<deadline,phase:['MAILBOX_SET','MAILBOX_HANDLE_DISPOSE','MAILBOX_READBACK'].includes(substep),
     method:method==='POST',bodyType,bodyBound,encoding:bodyBound&&!/%(?![a-f0-9]{2})/i.test(body),
     origin:u?.origin==='https://www.sharklasers.com',noCredentials:!!u&&!u.username&&!u.password,path:u?.pathname==='/ajax.php',noFragment:!!u&&!u.hash,
     oneAction:!!u&&[...u.searchParams].length===1&&u.searchParams.get('f')==='set_email_user',
     exactKeys:keys.length===4&&new Set(keys).size===4&&keys.every(k=>['email_user','lang','site','in'].includes(k)),
     expectedLocal:form?.get('email_user')===recipient.split('@')[0],language:form?.get('lang')==='en',site:form?.get('site')==='sharklasers.com',renderedContext:!!form&&form.get('in')===expectedIn}}
  },
  status(){return {armed,consumed};}
 };
}
module.exports={createMailboxPostGate};
