'use strict';
// Read-only telemetry for owned qualification children. Never expose URLs,
// SQL, identity rows, tokens, prompts or response bodies.
const fs=require('node:fs'),path=require('node:path');
const directory=process.env.OWASP_AI_GOAT_CAPACITY_METRICS;
if(!directory||!path.isAbsolute(directory)||!fs.statSync(directory).isDirectory())throw Error('Owned metric directory required');
const pg=require('pg'),Original=pg.Pool,pools=[];
pg.Pool=class ObservedPool extends Original{constructor(options){super(options);pools.push(this);}};
const value={pid:process.pid,role:process.argv[1]?.includes('agent-host')?'agent-host':process.argv[1]?.endsWith('/server/index.js')?'backend':'initializer',rssPeak:0,connectionsPeak:0,waitingPeak:0,reservedPeak:0,samples:0,managedReservedPeak:0,managedReservedFinal:0,dedicatedActive:0,dedicatedPeak:0,allocationFailures:0,managedEvents:0};
const managed=require('../../server/database/postgres');
function sample(){const snapshot=managed.getPoolBudgetSnapshot();value.managedReservedFinal=snapshot.reserved;value.managedReservedPeak=Math.max(value.managedReservedPeak,snapshot.reserved);value.samples++;value.rssPeak=Math.max(value.rssPeak,process.memoryUsage().rss);value.connectionsPeak=Math.max(value.connectionsPeak,pools.reduce((n,p)=>n+p.totalCount,0));value.waitingPeak=Math.max(value.waitingPeak,pools.reduce((n,p)=>n+p.waitingCount,0));value.reservedPeak=Math.max(value.reservedPeak,pools.filter(p=>!p.ended).reduce((n,p)=>n+(p.options.max||10),0));fs.writeFileSync(path.join(directory,process.pid+'.json'),JSON.stringify(value),{mode:0o600});}
const create=managed.createPool,reserve=managed.reserveDedicatedConnection;
managed.createPool=function(...args){let pool;try{pool=create.apply(this,args);}catch(error){value.allocationFailures++;sample();throw error;}value.managedEvents++;sample();const end=pool.end.bind(pool);let observed;pool.end=(...endArgs)=>{const result=end(...endArgs);if(result!==observed){observed=result;Promise.resolve(result).then(sample,sample);}return result;};return pool;};
managed.reserveDedicatedConnection=function(...args){let release;try{release=reserve.apply(this,args);}catch(error){value.allocationFailures++;sample();throw error;}value.dedicatedActive++;value.dedicatedPeak=Math.max(value.dedicatedPeak,value.dedicatedActive);value.managedEvents++;sample();let done=false;return()=>{release();if(!done){done=true;value.dedicatedActive--;value.managedEvents++;sample();}};};
const timer=setInterval(sample,25);timer.unref();process.on('exit',sample);sample();
