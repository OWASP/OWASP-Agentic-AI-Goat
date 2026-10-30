'use strict';
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module'),{monitorEventLoopDelay}=require('node:perf_hooks');
const {instrument,createRecorder,SYMBOL}=require('./applicationCapacityCoordinatorObserver.cjs');
const root=fs.realpathSync(process.env.OWASP_AI_GOAT_CAPACITY_ROOT),file=path.join(root,'capacity-private.json');
if(root!==process.env.OWASP_AI_GOAT_CAPACITY_ROOT||fs.statSync(root).uid!==process.getuid())throw Error('Owned capacity root required');
const input=JSON.parse(fs.readFileSync(file));const recorder=createRecorder(input.users.map(x=>String(x.id)));globalThis[Symbol.for(SYMBOL)]=recorder.record;
const target=require.resolve('../../server/agent-runtime/runCoordinator'),compile=Module._extensions['.js'];let installed=false;
Module._extensions['.js']=function(module,filename){if(filename!==target)return compile(module,filename);installed=true;const source=instrument(fs.readFileSync(filename,'utf8'),input.coordinatorSha256);module._compile(source,filename);};
// Validate exact transform before backend startup, even if a route loads lazily.
instrument(fs.readFileSync(target,'utf8'),input.coordinatorSha256);
const scheduler=require('../../server/agent-runtime/providers/modelScheduler'),original=scheduler.sharedModelScheduler,instances=new Set();
scheduler.sharedModelScheduler=function(...args){const value=original.apply(this,args);instances.add(value);return value;};
const leaseAdmission=require('../../server/agent-runtime/graphLeaseAdmission'),originalAdmission=leaseAdmission.admissionFor,admissions=new Set(),observedAdmissions=new WeakMap();
const ownerIds=new Set(input.users.map(u=>String(u.id)));
leaseAdmission.admissionFor=function(...args){const value=originalAdmission.apply(this,args);if(observedAdmissions.has(value))return observedAdmissions.get(value);const wrapped=require('./applicationCapacityCoordinatorObserver.cjs').observeLeaseAdmission(value,ownerIds);observedAdmissions.set(value,wrapped);admissions.add(wrapped);return wrapped;};
const pg=require('pg'),Pool=pg.Pool,pools=[];pg.Pool=class CapacityObservedPool extends Pool{constructor(...args){super(...args);if(pools.length<80)pools.push(this);else recorder.invalidate();}};
const managed=require('../../server/database/postgres'),createPool=managed.createPool;managed.createPool=function(...args){const pool=createPool.apply(this,args);if(!pools.includes(pool)){if(pools.length<80)pools.push(pool);else recorder.invalidate();}return pool;};
const delay=monitorEventLoopDelay({resolution:20});delay.enable();let valid=true,samples=0,rssPeak=0;
function sample(){try{samples++;if(samples>12000)throw Error();rssPeak=Math.max(rssPeak,process.memoryUsage().rss);const state={valid,installed,pid:process.pid,sampledAt:Date.now(),samples,rss:process.memoryUsage().rss,rssPeak,eventLoopMaxMs:delay.max/1e6,coordinator:recorder.snapshot(),pools:{total:pools.reduce((n,p)=>n+p.totalCount,0),idle:pools.reduce((n,p)=>n+p.idleCount,0),waiting:pools.reduce((n,p)=>n+p.waitingCount,0),managedReserved:managed.getPoolBudgetSnapshot().reserved},leaseAdmissions:[...admissions].map(x=>x.snapshot()),schedulers:[...instances].map(x=>x.snapshot())};const dest=path.join(root,'capacity-backend.json'),temp=dest+'.tmp';fs.writeFileSync(temp,JSON.stringify(state),{mode:0o600});fs.renameSync(temp,dest);}catch{valid=false;recorder.invalidate();}}
const timer=setInterval(sample,100);timer.unref();process.on('exit',sample);sample();
