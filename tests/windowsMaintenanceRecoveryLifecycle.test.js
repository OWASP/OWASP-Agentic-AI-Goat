'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const recovery=require('../scripts/application-maintenance-recovery');
const {superviseWindows}=require('../scripts/application-journal-bound-maintenance');
const activation=require('../scripts/lib/windows-maintenance-activation');
const tick=()=>new Promise(r=>setImmediate(r));
test('Windows parent binds installation and selects only fixed recovery supervisor mode',async()=>{
 const installation={installationRoot:'C:\\owned',assertCurrent(){checked++;}};let checked=0;
 const result={completed:true,recovery:true,epoch:'9'};
 assert.equal(await recovery.runWindowsRecovery('C:\\owned',{resolve:p=>{assert.equal(p,installation.installationRoot);return installation;},supervise:async options=>{assert.deepEqual(options,{recovery:true,installation});return result;}}),result);assert.equal(checked,1);
});
test('Windows worker activation precedes existing recovery authorization and outcome approval',async()=>{
 const events=[],result={completed:true,recovery:true,observed:true,epoch:'9223372036854775807'};
 const runtime={connected:true,send(){},env:{}};
 assert.equal(await recovery.runWindowsRecoveryChild('C:\\owned',{platform:'win32',runtime,activation:{async awaitWindowsMaintenanceActivation(){events.push('admit');},async completeWindowsMaintenance(options){assert.equal(options.result,result);events.push('approve');}},execute:async options=>{assert.equal(options.configurationRoot,'C:\\owned');events.push('authorize-and-close-lease');return result;}}),result);
 assert.deepEqual(events,['admit','authorize-and-close-lease','approve']);
});
test('denied activation and denied recovery never emit success approval',async()=>{
 for(const denied of ['activation','execute']){let called=0,approved=0;await assert.rejects(recovery.runWindowsRecoveryChild('C:\\owned',{platform:'win32',runtime:{connected:true,send(){},env:{}},activation:{async awaitWindowsMaintenanceActivation(){if(denied==='activation')throw Error('denied');},async completeWindowsMaintenance(){approved++;}},execute:async()=>{called++;throw Error('denied');}}));assert.equal(called,denied==='execute'?1:0);assert.equal(approved,0);}
 await assert.rejects(recovery.runWindowsRecoveryChild('/owned',{platform:'darwin',runtime:{connected:true,send(){},env:{}}}),{code:'APPLICATION_MAINTENANCE_RECOVERY_UNAVAILABLE'});
});
test('recovery IPC result preserves real string epochs and excludes false or extra authority fields',()=>{
 for(const observed of [false,true]){const value={completed:true,recovery:true,epoch:'9',...(observed?{observed:true}:{})};assert.deepEqual(activation.validateRecoveryResult(value),value);}
 for(const value of [{completed:true,recovery:true,epoch:9},{completed:true,recovery:true,epoch:'0'},{completed:true,recovery:true,epoch:'01'},{completed:true,recovery:true,epoch:'9223372036854775808'},{completed:true,recovery:false,epoch:'9'},{completed:true,recovery:true,epoch:'9',observed:false},{completed:true,recovery:true,epoch:'9',recoveryAuthorized:true},{completed:true,recovery:true,epoch:'9',secret:'hidden'}])assert.throws(()=>activation.validateRecoveryResult(value),{code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});
});
function composition({invalid=false,descendants=false,drainFails=false}={}){
 const events=[],child=new EventEmitter(),runtime=new EventEmitter(),installation={installationRoot:'C:\\owned',assertCurrent(){events.push('installation');}};
 Object.assign(runtime,{pid:4242,connected:true,env:{},send(message,callback){setImmediate(()=>{child.emit('message',message);callback?.();});}});
 Object.assign(child,{pid:4242,connected:true,send(message,callback){setImmediate(()=>{runtime.emit('message',message);callback?.();});},disconnect(){child.connected=false;runtime.connected=false;runtime.emit('disconnect');}});
 let worker;
 const exchange=(send,expected)=>new Promise((resolve,reject)=>{const listener=message=>{if(message.type!==expected)return;child.removeListener('message',listener);resolve(message);};child.on('message',listener);child.send(send);});
 const job={failure:new Promise(()=>{}),async admitGuardian(){const ready=await exchange({type:'owasp-ai-goat-owned-guardian-hello'},'owasp-ai-goat-owned-guardian-ready');const nonce='e'.repeat(64);await exchange({type:'owasp-ai-goat-owned-guardian-probe',challenge:ready.challenge,nonce},'owasp-ai-goat-owned-guardian-proof');await exchange({type:'owasp-ai-goat-owned-guardian-activate',challenge:ready.challenge,nonce},'owasp-ai-goat-owned-guardian-active');events.push('admitted');},async assertGuardianOnly(){events.push('only');if(descendants)throw Error('descendants remain');},expectGuardianExit(){events.push('expected');},async stop(){events.push('stop');child.emit('exit',1,null);child.emit('close',1);},async waitForDrain(){events.push('drain');if(drainFails)throw Error('uncertain');},async close(){events.push('close');}};
 const spawn=(node,args,options)=>{assert.match(args[0],/application-maintenance-recovery\.js$/);assert.equal(args[1],'--owned-windows-recovery');assert.equal(args[2],installation.installationRoot);assert.equal(options.detached,false);
  worker=recovery.runWindowsRecoveryChild(installation.installationRoot,{platform:'win32',runtime,execute:async()=>{events.push('recovery-authorized-lease-closed');return{completed:true,recovery:true,epoch:'9',...(invalid?{extra:'forbidden'}:{})};}}).then(()=>{child.emit('exit',0,null);child.emit('close',0);},()=>{child.emit('message',{type:'journal-bound-failed',code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});child.emit('exit',1,null);child.emit('close',1);});return child;};
 const run=()=>superviseWindows({recovery:true,installation,spawn,environment:{},createJob:async()=>job,joinMs:100,timeoutMs:1000});return{events,run,join:()=>worker};
}
test('actual cooperative helper and supervisor compose recovery without lifecycle authority substitution',async()=>{
 const f=composition();const result=await f.run();await f.join();assert.deepEqual(result,{completed:true,recovery:true,epoch:'9'});assert(f.events.indexOf('recovery-authorized-lease-closed')<f.events.indexOf('only'));assert.deepEqual(f.events.slice(-4),['expected','drain','close','installation']);
});
test('composed malformed result, native remaining descendants and drain uncertainty fail closed',async()=>{
 for(const options of [{invalid:true},{descendants:true},{drainFails:true}]){const f=composition(options);await assert.rejects(f.run(),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});await f.join();assert(f.events.includes('close'));if(!options.drainFails)assert(!f.events.includes('expected'));}
});
test('existing direct recovery service and read-only plan are not replaced by the lifecycle',()=>{
 const fs=require('node:fs'),source=fs.readFileSync(require.resolve('../scripts/application-maintenance-recovery'),'utf8');
 assert(source.includes("arg==='--plan'){maintenanceInspectionPlan"));assert(source.includes("process.platform==='win32'?runWindowsRecovery(configurationRoot):maintenanceRecoveryExecute"));assert(source.includes('await lease.readRecoveryOutcome()'));assert(source.includes('await lease.close();return result;'));
});
test('actual Windows CLI plan never creates a job, execute selects owned recovery, and reserved child rejects off-platform',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),source=fs.readFileSync(require.resolve('../scripts/application-maintenance-recovery'),'utf8').replace(/^#!.*\n/,'');
 for(const mode of ['plan','execute','reserved']){
  const calls=[],output=[],processMock=new EventEmitter(),module={exports:{}};
  Object.assign(processMock,{platform:mode==='reserved'?'darwin':'win32',argv:['node','C:\\source\\scripts\\application-maintenance-recovery.js',mode==='plan'?'--plan':mode==='execute'?'--execute':'--owned-windows-recovery',...(mode==='execute'?['--configuration-root=C:\\owned']:mode==='reserved'?['C:\\owned']:[])],env:{},execArgv:[],stdout:{write(text,done){output.push(text);done?.();}},stderr:{write(text,done){output.push(text);done?.();}},exit(code){calls.push(['exit',code]);}});
  const req=name=>{
   if(name==='node:path')return path.win32;
   if(name==='./lib/application-maintenance-installation')return{resolveMaintenanceInstallation:p=>({installationRoot:p,assertCurrent(){calls.push('installation');}})};
   if(name==='./application-journal-bound-maintenance')return{superviseWindows:async options=>{calls.push(['owned',options.recovery]);return{completed:true,recovery:true,epoch:'9'};}};
   if(name==='./lib/application-maintenance-plan-configuration')return{loadMaintenancePlanConfiguration:()=>({environment:{}})};
   if(name==='../server/services/applicationMaintenanceLease')return{acquireApplicationMaintenanceLease:async()=>({maintenancePlan:async()=>({state:'clean'}),assertHeld(){},close:async()=>{calls.push('lease-close');}})};
   if(name==='../server/database/postgres/applicationMaintenanceStoreInspection')return{createApplicationMaintenanceStoreInspection:()=>({inspect:async()=>({stores:[],observedAt:'now'})})};
   throw Error('Unexpected CLI import '+name);
  };req.main=module;
  vm.runInNewContext(source,{require:req,module,__dirname:'C:\\source\\scripts',process:processMock,console:{log:v=>output.push(v),error:v=>output.push(v)},setTimeout,clearTimeout});await tick();
  if(mode==='plan'){assert(!calls.some(c=>Array.isArray(c)&&c[0]==='owned'));assert(calls.includes('lease-close'));assert(output.some(s=>s.includes('recoveryAuthorized')));}
  else if(mode==='execute')assert(calls.some(c=>Array.isArray(c)&&c[0]==='owned'&&c[1]===true));
  else assert.deepEqual(calls,[['exit',1]]);
 }
});
