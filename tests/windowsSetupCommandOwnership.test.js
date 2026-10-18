'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {EventEmitter}=require('node:events');
const tick=()=>new Promise(setImmediate);

function harness(){
 const children=[],spawns=[],messages=[],kills=[],controller=new AbortController();
 const childProcess={};
 const spawn=(...args)=>{
  const child=new EventEmitter();child.pid=500+children.length;
  child.kill=signal=>{kills.push([child,signal]);return true;};children.push(child);spawns.push(args);return child;
 };
 Object.assign(childProcess,{spawn,execFile:spawn,fork:spawn});
 const fakeProcess={platform:'win32',versions:process.versions,env:{},kill(){assert.fail('Windows local ownership must never signal an adopted PID');}};
 function load(relative){
  const file=path.resolve(__dirname,'..',relative),module={exports:{}};
  vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,process:fakeProcess,setTimeout,clearTimeout,require(name){
   if(name==='node:child_process')return childProcess;
   return require(name.startsWith('.')?path.resolve(path.dirname(file),name):name);
  }});
  return module.exports;
 }
 const owner=load('scripts/lib/setup-child-ownership.js').installSetupChildOwnership({childProcess,signal:controller.signal,notify:message=>messages.push(message)});
 // Real phase order: install ownership before command captures spawn.
 const command=load('scripts/lib/setup-command.js');
 return{children,spawns,messages,kills,controller,owner,command,childProcess};
}

test('controlled Windows setup command is tracked and direct close drains only local children',async()=>{
 const h=harness();try{
  const pending=h.command.runSetupCommand('npm.cmd',['ci'],'C:\\Code',{CONTROLLED:'yes'});
  const child=h.children[0];child.emit('spawn');assert.equal(h.messages[0].grouped,false);
  assert.equal(h.spawns[0][2].detached,false);assert.equal(h.spawns[0][2].shell,true);
  child.emit('close',0);await pending;await h.owner.drain();assert.equal(h.messages.at(-1).type,'child-closed');
  // This direct-child drain is deliberately not a job-wide membership proof.
  // The phase must still ask its parent assertGuardianOnly before publication.
  assert.equal(h.owner.assertGuardianOnly,undefined);assert.deepEqual(h.kills,[]);
 }finally{h.owner.restore();}
});

test('controlled Windows timeout waits actual child close and signals only its owned handle',async()=>{
 const h=harness();try{
  let settled=false;const pending=h.command.runSetupCommand('controlled.exe',[],'C:\\Code',{}, {timeoutMs:5,killGraceMs:5}).catch(error=>{settled=true;return error;});
  const child=h.children[0];child.emit('spawn');const deadline=Date.now()+1000;
  while(h.kills.length<2){assert(Date.now()<deadline,'owned timeout escalation deadline');await new Promise(resolve=>setTimeout(resolve,5));}
  assert.equal(settled,false);assert.deepEqual(h.kills.map(([value,signal])=>[value===child,signal]),[[true,'SIGTERM'],[true,'SIGKILL']]);
  child.emit('close',1);assert.match((await pending).message,/timed out/);await h.owner.drain();
 }finally{h.owner.restore();}
});

test('controlled Windows phase cancellation prevents new children and joins close after direct escalation',async()=>{
 const h=harness();try{
  const child=h.childProcess.spawn('controlled.exe',[],{detached:true});child.emit('spawn');assert.equal(h.messages[0].grouped,false);
  h.controller.abort();assert.deepEqual(h.kills.map(([,signal])=>signal),['SIGTERM']);
  assert.throws(()=>h.childProcess.spawn('later.exe'),{code:'SETUP_CANCELLED'});
  let drained=false;const pending=h.owner.drain().then(()=>{drained=true;});await tick();assert.equal(drained,false);assert(h.kills.some(([,signal])=>signal==='SIGKILL'));
  child.emit('close',1);await pending;assert.equal(drained,true);assert.equal(h.messages.at(-1).type,'child-closed');
 }finally{h.owner.restore();}
});

test('controlled Windows spawn error retires missing handle without PID termination',async()=>{
 const h=harness();try{
  const pending=h.command.runSetupCommand('missing.exe',[],'C:\\Code',{}).catch(error=>error),child=h.children[0];
  delete child.pid;const error=Object.assign(Error('controlled missing executable'),{code:'ENOENT'});child.emit('error',error);child.emit('close',null);
  assert.equal((await pending).code,'ENOENT');await h.owner.drain();assert.deepEqual(h.kills,[]);
 }finally{h.owner.restore();}
});
