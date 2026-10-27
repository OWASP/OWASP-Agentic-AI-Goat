'use strict';
// Fixed inherited socket protocol. The public constructor requires live local
// capabilities; neither request JSON nor endpoint strings mint ownership.
const CAP=16384;
const fail=code=>Object.assign(new Error(code),{code});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
const REQUEST_OPS=new Set(['start','claim-cohort','pg-create-intent','pg-bind','attach-browser','finish-work']);
const REQUEST_CODES=new Set(['V03_PARENT_REQUEST','V03_PARENT_WORK_EXPIRED',
 'V03_PARENT_START_ORDER','V03_PARENT_NOT_PREPARED','V03_PARENT_CLAIM_ORDER',
 'V03_PARENT_PG_ORDER','V03_PARENT_ATTACH_ORDER','V03_PARENT_FINISH_ORDER',
 'V03_PARENT_OPERATION','V03_PARENT_CHANNEL_REVOKED','V03_PARENT_RESPONSE_BOUND']);
const safeRequestFailure=(request,error)=>{
 let op='invalid',code='V03_PARENT_DEPENDENCY_FAILURE';
 try{const candidate=request?.op;if(REQUEST_OPS.has(candidate))op=candidate;}catch{}
 try{const candidate=error?.code;if(REQUEST_CODES.has(candidate))code=candidate;}catch{}
 return Object.freeze({op,code});
};
function protocol(controller,main,channel,watchdog,postgres,postWork){
 const binding=controller.owner.binding();
 let sequence=0,state='ready',buffer=Buffer.alloc(0),busy=false,poisoned=false,terminal=null,requestFailure=null;
 let resolveDone;const done=new Promise(resolve=>{resolveDone=resolve;});
 const stop=reason=>{
  if(terminal)return terminal;
  poisoned=true;channel.pause();
  terminal=(async()=>{
   let finalization=null;const errors=[];
   // The fixed watchdog owns the entire child -> producers -> PG ordering.
   // A work-complete response never waits for this post-MAIN path.
   try{finalization=await watchdog.close(reason);}catch(error){errors.push(error.code||'V03_PARENT_RETIREMENT');}
   const receipt=Object.freeze({closed:true,qualificationComplete:false,independentFullRequired:true,
    cleanupVerified:errors.length===0&&finalization?.publicationVerified===true
     &&finalization?.candidate?.cleanupVerified===true,finalization,errors,requestFailure});
   resolveDone(receipt);return receipt;
  })();return terminal;
 };
 async function dispatch(request){
  if(poisoned||!exact(request,'version,runId,planSha256,sequence,op,payload')
    ||request.version!==1||request.runId!==binding.runId||request.planSha256!==binding.planSha256
    ||!Number.isSafeInteger(request.sequence)||request.sequence!==sequence)throw fail('V03_PARENT_REQUEST');
  const remainingAtAdmission=controller.owner.remainingMs();
  const workRemainingAtAdmission=controller.owner.wrapperWindow().deadlineMs-controller.owner.nowMs();
  if(workRemainingAtAdmission<=0)throw fail('V03_PARENT_WORK_EXPIRED');
  await main.assertCurrent();
  let result;
  if(request.op==='start'){
   if(state!=='ready'||!exact(request.payload,''))throw fail('V03_PARENT_START_ORDER');
   // Preparation already finished before MAIN's original wrapper began.
   if(controller.status().stage!=='ready')throw fail('V03_PARENT_NOT_PREPARED');
   result={ready:true,parentRemainingMsAtAdmission:remainingAtAdmission,workRemainingMsAtAdmission:workRemainingAtAdmission};state='started';
  }else if(request.op==='claim-cohort'){
   if(state!=='started'||!exact(request.payload,''))throw fail('V03_PARENT_CLAIM_ORDER');
   postgres.requireBound();
   state='claiming';result=await controller.claimCohort();watchdog.armCohort();state='claimed';
  }else if(request.op==='pg-create-intent'){
   if(state!=='started'||!exact(request.payload,''))throw fail('V03_PARENT_PG_ORDER');
   result=await postgres.createIntent();
  }else if(request.op==='pg-bind'){
   if(state!=='started'||!exact(request.payload,'capturedId'))throw fail('V03_PARENT_PG_ORDER');
   result=await postgres.bind(request.payload.capturedId);
  }else if(request.op==='attach-browser'){
   if(state!=='claimed'||!exact(request.payload,'birth'))throw fail('V03_PARENT_ATTACH_ORDER');
   await main.attachBrowser(request.payload.birth);state='attached';result={attached:true};
  }else if(request.op==='finish-work'){
   if(!['started','claimed','attached'].includes(state)||!exact(request.payload,'browserAbsent,primaryFailed')
     ||typeof request.payload.browserAbsent!=='boolean'||typeof request.payload.primaryFailed!=='boolean')throw fail('V03_PARENT_FINISH_ORDER');
   // A child assertion never establishes absence. The fixed owner independently
   // inspects/join its recorded browser before releasing either producer.
   await main.requireBrowserAbsent();
   postWork.noteWorkHandoff(request.payload.primaryFailed);
   result={accepted:true,cleanupPending:true,qualificationComplete:false};state='work-finished';
  }else throw fail('V03_PARENT_OPERATION');
  if(poisoned)throw fail('V03_PARENT_CHANNEL_REVOKED');
  await main.assertCurrent();
  const response={version:1,runId:binding.runId,planSha256:binding.planSha256,sequence,op:request.op,result};
  const raw=Buffer.from(JSON.stringify(response)+'\n');if(raw.length>CAP)throw fail('V03_PARENT_RESPONSE_BOUND');
  sequence++;
  await new Promise((resolve,reject)=>channel.write(raw,error=>error?reject(error):resolve()));
 }
 const onData=chunk=>{
  if(poisoned)return;
  if(busy){void stop('pipelined-request');return;}
  buffer=Buffer.concat([buffer,chunk]);
  if(buffer.length>CAP){void stop('request-bound');return;}
  const newline=buffer.indexOf(10);if(newline<0)return;
  if(newline!==buffer.length-1){void stop('pipelined-request');return;}
  let request;try{
   const text=buffer.toString('utf8');request=JSON.parse(text);
   if(JSON.stringify(request)+'\n'!==text)throw fail('V03_NONCANONICAL_REQUEST');
  }catch{void stop('invalid-json');return;}
  buffer=Buffer.alloc(0);busy=true;
  dispatch(request).catch(error=>{
   requestFailure=safeRequestFailure(request,error);
   // This bounded diagnostic precedes child/producer retirement; terminal publication may miss its deadline.
   try{process.stderr.write(JSON.stringify({event:'v03-parent-request-failure',...requestFailure})+'\n',()=>{});}catch{}
   return stop('request-failure');
  }).finally(()=>{busy=false;});
 };
 channel.on('data',onData);
 channel.once('end',()=>{void stop('main-eof');});
 channel.once('error',()=>{void stop('main-channel-error');});
 channel.once('close',()=>{void stop('main-channel-close');});
 return Object.freeze({done,close:stop});
}
function serveParent(controller,main,channel,postgres){
 require('./ownedV03PrivateExecutors').assertPrivateExecutors(controller);
 require('./ownedV03MainProcess').assertMainProcess(main,controller.owner);
 require('./ownedV03PostgresOwner').assertPostgresOwner(postgres,controller.owner);
 if(controller.status().stage!=='ready'||main.channel()!==channel)throw fail('V03_PARENT_CAPABILITY');
 // watchOwnerChannel is supplied only by the fixed combined controller module,
 // never from an RPC or an options bag. Integration remains closed until export.
 // The expiry/EOF watcher must use the same child-first retirement ordering,
 // rather than racing producer deletion against a still-running MAIN child.
 const postWork=require('./ownedV03PostWork').createPostWork(controller,main,postgres);
 let retirement;
 const guarded=Object.freeze({owner:controller.owner,retire(reason){
  if(retirement)return retirement;
  retirement=(async()=>{
   let processError=null;
   // A genuine bounded work handoff lets MAIN publish/exit under its original
   // wrapper. Unexpected EOF/expiry is failed work and first retires MAIN.
   const expectedExit=postWork.status().handoff!==null&&[
    'inherited-fd-eof','main-eof','main-channel-close','main-terminal'].includes(reason);
   if(!expectedExit&&reason!=='original-wrapper-expiry')try{
    const proof=await main.retire();
    if(proof?.groupAbsent!==true)throw fail('V03_MAIN_RETIREMENT_UNPROVEN');
   }catch(error){processError=error;}
   if(processError)throw Object.assign(fail('V03_PARENT_MAIN_ABSENCE_UNPROVEN'),{cleanupDebt:true,cause:processError});
   return postgres.finalize(postWork);
  })();return retirement;
 }});
 const watchdog=require('./ownedV03PrivateExecutors').watchOwnerChannel(guarded,channel);
 const server=protocol(controller,main,channel,watchdog,postgres,postWork);
 const wrapper=controller.owner.wrapperWindow(),remaining=wrapper.deadlineMs-controller.owner.nowMs();
 if(remaining<=0){void server.close('original-wrapper-expiry');return server;}
 const workTimer=setTimeout(()=>{void server.close('original-wrapper-expiry');},remaining);
 server.done.finally(()=>clearTimeout(workTimer));
 // Even if a descendant keeps the socket open, actual MAIN terminal triggers
 // this same once-only parent finalizer rather than waiting for FD EOF.
 main.terminal().then(()=>server.close('main-terminal'),()=>server.close('main-terminal-error'));
 return server;
}
module.exports={serveParent};
