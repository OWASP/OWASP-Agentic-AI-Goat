'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
const {fork}=require('node:child_process');
const operator=require('../scripts/export-installed-legacy-ram-rag');
const executable=process.execPath,operatorTest=process.platform==='darwin'?test:test.skip;
function bounded(promise,label,ms=10000){let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(label+' deadline')),ms);})]).finally(()=>clearTimeout(timer));}
function childEvent(child,event){return new Promise((resolve,reject)=>{const done=value=>{clear();resolve(value);},error=value=>{clear();reject(value);},early=(code,signal)=>error(Error(`Child exited before ${event}: ${code}/${signal}`));function clear(){child.off(event,done);child.off('error',error);if(event!=='exit')child.off('exit',early);}child.once(event,done);child.once('error',error);if(event!=='exit')child.once('exit',early);});}
async function stopChild(child){if(child.exitCode!==null||child.signalCode!==null)return;const exited=childEvent(child,'exit');if(child.connected)child.send('stop',error=>{if(error&&child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');});else child.kill('SIGTERM');try{await bounded(exited,'child graceful exit',3000);return;}catch{}if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');try{await bounded(exited,'child termination',2000);return;}catch{}if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await bounded(exited,'child forced exit',2000);}
async function port(){const server=net.createServer();try{await bounded(new Promise((resolve,reject)=>server.listen(0,'127.0.0.1',resolve).once('error',reject)),'port listen');return server.address().port;}finally{await bounded(new Promise((resolve,reject)=>server.close(error=>error&&error.code!=='ERR_SERVER_NOT_RUNNING'?reject(error):resolve())),'port close');}}
async function ready(url){for(let attempt=0;attempt<100;attempt++){try{await operator.health(url);return;}catch{}await new Promise(resolve=>setTimeout(resolve,20));}throw Error('Fixture health timeout');}
operatorTest('operator binds exact process identity, captures once, closes inspector and writes private receipt', async t => {
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-rag-operator-')));fs.chmodSync(root,0o700);let child;
  t.after(async()=>{if(child)await stopChild(child);if(!child||child.exitCode!==null||child.signalCode!==null)fs.rmSync(root,{recursive:true,force:true});});
  const healthPort=await port(),inspectorPort=await port();
  child=fork(path.join(__dirname,'fixtures/legacyRamRagOperatorTarget.js'),[],{execPath:executable,execArgv:[`--inspect-port=127.0.0.1:${inspectorPort}`],cwd:path.resolve(__dirname,'..'),stdio:['ignore','ignore','ignore','ipc'],env:{PATH:path.dirname(executable),HOME:root,TMPDIR:root,LOGS_DIR:root,OWNED_HEALTH_PORT:String(healthPort)}});
  const healthUrl=`http://127.0.0.1:${healthPort}/api/monitoring/health`;await bounded(ready(healthUrl),'fixture health',10000);
  const seed={pid:child.pid,expectedUid:process.getuid(),expectedStartTime:'pending',expectedCwd:path.resolve(__dirname,'..'),expectedExecutable:executable};
  const actualStart=String(require('node:child_process').execFileSync('/bin/ps',['-p',String(child.pid),'-o','lstart='],{encoding:'utf8',timeout:5000})).trim();
  const options={...seed,expectedStartTime:actualStart,expectedModule:path.join(__dirname,'../server/services/ragVectorStore.js'),inspectorPort,healthUrl,output:path.join(root,'snapshot')};
  await assert.rejects(operator.run({...options,expectedStartTime:'Thu Jan  1 00:00:00 1970'}),/identity mismatch/);fs.rmSync(options.output,{recursive:true,force:true});
  const result=await operator.run(options);assert.equal(result.status,'passed');assert.deepEqual(fs.readdirSync(options.output).sort(),['legacy-rag-origin.json','receipt.json']);
  for(const name of fs.readdirSync(options.output))assert.equal(fs.statSync(path.join(options.output,name)).mode&0o777,0o600);
  const receipt=JSON.parse(fs.readFileSync(path.join(options.output,'receipt.json')));assert.equal(receipt.sameProcessAfter,true);assert.equal(receipt.inspectorClosed,true);assert.equal(receipt.archive.pid,child.pid);assert.equal(receipt.health.before.statusCode,200);assert.equal(receipt.health.after.statusCode,200);assert.equal(await require('./fixtures/legacyRamRagInspectorLifecycle').tcpOpen(inspectorPort),false);
});
test('CLI requires the complete explicit identity and normalized private output arguments',()=>{assert.throws(()=>operator.parse([]));assert.throws(()=>operator.parse(['--pid','1','--pid','1']));assert.throws(()=>operator.parse(['--pid','1','--uid','1','--start-time','x','--cwd','relative','--executable','/x','--module','/m','--inspector-port','9','--health-url','http://127.0.0.1:1/','--output','/o']));});
