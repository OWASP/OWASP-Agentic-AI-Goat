'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module');
const pg=require('pg'),prepareValue=require('pg/lib/utils').prepareValue;
const exact='2026-09-27 22:46:59.123456+00';
// Reuse existing controlled state fixtures. Actual control modules execute unchanged;
// only simulated database row decoding uses the real pg text/timestamptz parsers.
function harness(name,exports){
 const file=path.resolve(__dirname,name),req=createRequire(file),module={exports:{}},queries=[];
 let source=fs.readFileSync(file,'utf8').replaceAll('calls.push(sql);','calls.push(sql); queries.push({sql,args:typeof args!=="undefined"?args:typeof a!=="undefined"?a:undefined});').replaceAll("finished_at:'now'",'finished_at:decode(sql)').replaceAll("finished_at:'time'",'finished_at:decode(sql)').replaceAll("value:'now'",'value:exact');
 const decode=sql=>pg.types.getTypeParser(sql.includes('RETURNING finished_at::text AS finished_at')?25:1184)(exact);
 vm.runInNewContext('(function(require,module,exports,__dirname){'+source+'\nmodule.exports={'+exports+'};})',{process,Buffer,console,setTimeout,clearTimeout,AbortController,structuredClone,queries,decode,exact})(n=>n==='node:test'?()=>{}:req(n),module,module.exports,path.dirname(file));
 return {...module.exports,queries};
}
test('real pg default timestamptz parser loses microseconds while text preserves exact parameter',()=>{const date=pg.types.getTypeParser(1184)(exact);assert(date instanceof Date);assert(!prepareValue(date).includes('.123456'));assert.equal(prepareValue(pg.types.getTypeParser(25)(exact)),exact);});
for(const kind of ['ordinary','prepared','recovery'])test(kind+' actual finish path propagates exact database text and retains void API',async()=>{
 let h,result;
 if(kind==='ordinary'){h=harness('applicationMaintenanceControl.test.js','fixture');const f=h.fixture();const t=await f.control.begin();result=await f.control.finish(t);}
 if(kind==='prepared'){h=harness('applicationMaintenanceInprocess.test.js','controlFixture');const f=h.controlFixture();const t=await f.c.beginPrepared(f.prepared);result=await f.c.finishPrepared(t,f.completion);}
 if(kind==='recovery'){h=harness('applicationMaintenanceRecoveryControl.test.js','fixture,input');const f=h.fixture({allowProof:true});const t=await f.c.beginRecoveryEligible(h.input());const r=await f.c.claimRecovery(t,f.proof);await f.c.advanceRecovery(r,'reconciled',f.proof);await f.c.advanceRecovery(r,'published',f.proof);result=await f.c.finishRecovery(r,f.proof);}
 assert.equal(result,undefined);
 const propagation=h.queries.filter(x=>x.sql.startsWith('UPDATE dvaia_maintenance.epochs SET finished_at')||x.sql.startsWith('INSERT INTO dvaia_maintenance.epoch_finish_receipts')||kind==='recovery'&&x.sql.startsWith("UPDATE dvaia_maintenance.control SET state='clean'"));
 assert.equal(propagation.length,kind==='ordinary'?1:kind==='recovery'?3:2);
 for(const q of propagation){assert.equal(q.args.at(-1),exact);assert.equal(prepareValue(q.args.at(-1)),exact);}
});
