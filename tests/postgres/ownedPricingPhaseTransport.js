'use strict';
// Pricing-only transport; no live capability is minted by this module.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const fail=code=>Object.assign(new Error(code),{code});
const MAX_EXPORT=145*1024**2;
function createExecutor({launch=require('node:child_process').spawn,now=()=>Number(process.hrtime.bigint())/1e6,
 randomToken=()=>crypto.randomBytes(32).toString('hex'),
 setTimer=setTimeout,clearTimer=clearTimeout}={}){
 return async(plan,name,{input,sink,diagnosticSink,signal,deadline}={})=>{
  const start=now(),remaining=deadline-start,seconds=Math.floor((remaining-6000)/1000)-10;
  if(!Number.isFinite(deadline)||seconds<1||!Object.hasOwn(plan.commands,name))throw fail('PRICING_TRANSPORT_BUDGET');
  signal?.throwIfAborted();
  const spec=plan.spec;
  return new Promise((resolve,reject)=>{
   let child,failure,closed=false,ioPending=0,total=0,diagnostic=0,settled=false,ack=null,stderr='';
   const token=randomToken();if(!/^[a-f0-9]{64}$/.test(token))return reject(fail('PRICING_ACK_TOKEN'));
   const chunks=[],diagnostics=[],timers=[];const decoder=new (require('node:string_decoder').StringDecoder)('utf8');let remoteUntil=start+(seconds+10)*1000;
   const done=()=>{
    if(settled||!closed||ioPending)return;
    if(failure&&now()<remoteUntil)return;
    settled=true;timers.forEach(clearTimer);signal?.removeEventListener('abort',abort);
    if(failure)reject(failure);else resolve(Buffer.concat(chunks).toString());
   };
   const stop=e=>{if(!failure){failure=e;remoteUntil=now()+(seconds+10)*1000;}failure.retirementUnproven=true;input?.destroy();
    if(child?.pid&&!closed)try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')failure.killFailure=error.code;}
   };
   const abort=()=>stop(fail('PRICING_TRANSPORT_ABORTED'));
   const enqueue=(stream,fn,bytes)=>{
    stream.pause();ioPending++;
    Promise.resolve().then(()=>fn(bytes)).catch(stop).finally(()=>{ioPending--;if(!closed&&!failure)stream.resume();done();});
   };
   const line=(value,terminated=true)=>{
    const prefix='OWASP_AI_GOAT_PRICING_DONE:'+token+':';
    if(value.startsWith(prefix)){
     const code=value.slice(prefix.length);
     if(ack!==null||!/^\d{1,3}$/.test(code)||Number(code)>255){stop(fail('PRICING_REMOTE_ACK'));return;}
     ack=Number(code);return;
    }
    if(value.startsWith('OWASP_AI_GOAT_PRICING_DONE:')){stop(fail('PRICING_REMOTE_ACK'));return;}
    diagnostics.push(Buffer.from(value+(terminated?'\n':'')));
   };
   try{
    const wrapper='timeout --signal=TERM --kill-after=10 "$1" /bin/sh -c "$2" owned-pricing-build "$3" "$4" "$5"; code=$?; printf "\\nOWASP_AI_GOAT_PRICING_DONE:%s:%s\\n" "$6" "$code" >&2; exit "$code"';
    child=launch(spec.lima,['shell','--workdir','/','colima-goat-q','sudo','-n','/bin/sh','-c',wrapper,'owned-pricing-envelope',String(seconds),plan.commands[name],spec.guest,spec.runId,name==='metadataFetch'?plan.binding.base:'',token],
     {cwd:spec.root,detached:true,stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',HOME:path.join(spec.root,'tasks/runtime/home'),TMPDIR:path.join(spec.root,'tasks/tmp'),LIMA_HOME:spec.limaHome}});
    child.on('error',stop);child.stdin.on('error',stop);
    child.stdout.on('data',b=>{total+=b.length;if(total>(name==='retainedExport'?MAX_EXPORT:2*1024**2))return stop(fail('PRICING_OUTPUT_LIMIT'));if(sink)enqueue(child.stdout,sink,b);else chunks.push(b);});
    child.stderr.on('data',b=>{diagnostic+=b.length;if(diagnostic>2*1024**2)return stop(fail('PRICING_OUTPUT_LIMIT'));stderr+=decoder.write(b);let n;while((n=stderr.indexOf('\n'))>=0){line(stderr.slice(0,n));stderr=stderr.slice(n+1);}});
    child.once('close',(code,sig)=>{closed=true;input?.destroy();stderr+=decoder.end();if(stderr){line(stderr,false);stderr='';}
     if(diagnosticSink&&diagnostics.length)enqueue(child.stderr,diagnosticSink,Buffer.concat(diagnostics));
     const complete=!sig&&ack===code&&![124,137].includes(code)&&!failure;
     if(complete){remoteUntil=now();if(code!==0)failure=fail('PRICING_REMOTE_PHASE_FAILED');}
     else stop(fail(ack===null?'PRICING_REMOTE_ACK_MISSING':'PRICING_REMOTE_PHASE_FAILED'));
     done();});
    signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
    timers.push(setTimer(()=>{if(!closed)stop(fail('PRICING_PHASE_TIMEOUT'));done();},Math.max(0,remoteUntil-now())));
    timers.push(setTimer(()=>{
     stop(fail('PRICING_TRANSPORT_RETIREMENT_DEBT'));
     if(!settled){settled=true;signal?.removeEventListener('abort',abort);timers.forEach(clearTimer);
      failure.retirementUnproven=failure.retirementUnproven===true||!closed||ioPending>0||now()<remoteUntil;reject(failure);}
    },Math.max(0,deadline-now())));
    if(input){input.on('error',stop);input.pipe(child.stdin);}else child.stdin.end();
   }catch(error){stop(error);if(!child){closed=true;remoteUntil=start;}done();}
  });
 };
}
// An exclusive, bounded export is retained even on failure. No rename/overwrite
// and no cleanup authority until successful write/fsync/close + inode readback.
function createExport(root,runId,{io=fs}={}){
 if(!/^[a-f0-9]{32}$/.test(runId))throw fail('PRICING_EXPORT_ID');
 const directory=path.join(root,'tasks/tmp');
 if(io.realpathSync(directory)!==directory)throw fail('PRICING_EXPORT_PATH');
 const file=path.join(directory,'pricing-retained-'+runId+'.tar');
 let fd=io.openSync(file,'wx',0o600),bytes=0,failed=false,complete=false;const identity=io.fstatSync(fd),digest=crypto.createHash('sha256');
 const sink=async data=>{
  if(failed||complete||fd===null)throw fail('PRICING_EXPORT_CLOSED');
  try{if(!Buffer.isBuffer(data)||bytes+data.length>MAX_EXPORT)throw fail('PRICING_EXPORT_LIMIT');
   let offset=0;while(offset<data.length){const n=io.writeSync(fd,data,offset,data.length-offset);if(n<=0)throw fail('PRICING_EXPORT_WRITE');offset+=n;}
   bytes+=data.length;digest.update(data);
  }catch(e){failed=true;throw e;}
 };
 return Object.freeze({sink,
  finish(){if(failed||complete||fd===null||!bytes)throw fail('PRICING_EXPORT_INCOMPLETE');
   try{io.fsyncSync(fd);const held=fd;fd=null;io.closeSync(held);
    const stat=io.lstatSync(file);if(!stat.isFile()||stat.dev!==identity.dev||stat.ino!==identity.ino||stat.uid!==identity.uid||stat.nlink!==1||stat.size!==bytes||(stat.mode&0o777)!==0o600)throw fail('PRICING_EXPORT_IDENTITY');
    const dir=io.openSync(directory,'r');try{io.fsyncSync(dir);}finally{io.closeSync(dir);}
    complete=true;return Object.freeze({version:1,file,bytes,sha256:digest.digest('hex'),durable:true});
   }catch(e){failed=true;throw e;}
  },
  close(){if(fd!==null){const held=fd;fd=null;io.closeSync(held);}},
 });
}
module.exports={createExecutor,createExport,MAX_EXPORT};
