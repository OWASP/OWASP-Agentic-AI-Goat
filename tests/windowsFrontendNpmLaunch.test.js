'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs/promises'),os=require('node:os');
const {EventEmitter}=require('node:events');
const {createApplicationSupervisor}=require('../scripts/start-application');
const {admitSetupNpm}=require('../scripts/lib/setup-npm-admission');
const nodeWithSpaces='C:\\Program Files\\Dvaia Node\\node.exe',cliWithSpaces='C:\\Users\\Learner\\Private npm\\node_modules\\npm\\bin\\npm-cli.js';
function harness(overrides={}){
 const calls=[],spawns=[],environment={PATH:'controlled-empty-path',npm_execpath:cliWithSpaces,PORT:'8081',DVAIA_CLIENT_PORT:'3000'};
 const options={platform:'win32',environment,stdout:{write(){}},stderr:{write(){}},
  admitNpm:async input=>{calls.push(['admit-npm',input]);return{command:nodeWithSpaces,prefix:[cliWithSpaces]};},
  executeNpm:async()=>assert.fail('controlled admission does not execute native programs'),
  createJob:async()=>({failure:new Promise(()=>{}),async admitGuardian(child){calls.push(['job-admit',child.pid]);const spec=spawns.find(value=>value.child===child);if(spawns.length===1)child.emit('message',{type:'dvaia-backend-ready',token:spec.options.env.DVAIA_LAUNCH_READINESS_TOKEN,pid:child.pid,port:8081});else child.stdout.emit('data',Buffer.from('➜  Local: http://localhost:3000/\n'));},async stop(){calls.push(['job-stop']);},async close(){calls.push(['job-close']);}}),
  spawnProcess(command,args,options){calls.push(['spawn']);const child=new EventEmitter();Object.assign(child,{pid:1000+spawns.length,connected:true,exitCode:null,signalCode:null,stdout:new EventEmitter(),stderr:new EventEmitter()});spawns.push({command,args,options,child});return child;},
 };
 const supervisor=createApplicationSupervisor({...options,...overrides});return{calls,spawns,environment,options,supervisor};
}

test('controlled Windows default frontend admits private npm before any launch and preserves paths with spaces as direct arguments',async()=>{
 const h=harness();await h.supervisor.start();
 assert.equal(h.calls[0][0],'admit-npm');const admission=h.calls[0][1];assert.equal(admission.environment,h.environment);assert.equal(admission.node,process.execPath);assert.equal(admission.execute,h.options.executeNpm);assert.equal(admission.platform,'win32');
 const frontend=h.spawns[1];assert.equal(frontend.command,process.execPath);assert.equal(frontend.options.shell,false);assert.equal(frontend.args[1],nodeWithSpaces);
 assert.equal(frontend.options.env.Path,'C:\\Program Files\\Dvaia Node;controlled-empty-path');assert.equal(frontend.options.env.PATH,undefined);assert.equal(h.spawns[0].options.env.PATH,'controlled-empty-path');
 assert.deepEqual(JSON.parse(frontend.args[2]),[cliWithSpaces,'--prefix','client','start','--','--port','3000','--strictPort']);assert.equal(frontend.args[4],'direct');assert.equal(h.environment.PATH,'controlled-empty-path');
 await h.supervisor.stop();
});

test('controlled Windows frontend binds admitted Node directory with one PATH key and leaves caller/global untouched',async()=>{
 const globalBefore={...process.env};
 for(const paths of [{},{PATH:''},{Path:'C:\\Windows\\System32'},{PATH:'C:\\Existing tools'},{pAtH:'C:\\Mixed case'},{PATH:'C:\\Upper',Path:'C:\\Title',pAtH:'C:\\Mixed'}]){
  const environment={...paths,npm_execpath:cliWithSpaces,CUSTOM:'preserved'},before={...environment};
  const h=harness({environment});await h.supervisor.start();
  const frontend=h.spawns[1],childEnvironment=frontend.options.env,expected=[path.win32.dirname(frontend.args[1]),...Object.values(paths).flatMap(value=>value.split(';')).filter(Boolean)].join(';');
  assert.deepEqual(Object.keys(childEnvironment).filter(key=>key.toLowerCase()==='path'),['Path']);assert.equal(childEnvironment.Path,expected);assert.equal(childEnvironment.CUSTOM,'preserved');assert.deepEqual(environment,before);assert.deepEqual({...process.env},globalBefore);
  assert.deepEqual(h.spawns[0].options.env,{...environment,DVAIA_LAUNCH_READINESS_TOKEN:h.spawns[0].options.env.DVAIA_LAUNCH_READINESS_TOKEN});await h.supervisor.stop();
 }
});

test('controlled Windows explicit frontend arguments retain admitted CLI prefix',async()=>{
 const h=harness({frontendArgs:['--prefix','alternate client','run','custom-task']});await h.supervisor.start();
 assert.deepEqual(JSON.parse(h.spawns[1].args[2]),[cliWithSpaces,'--prefix','alternate client','run','custom-task']);assert.equal(h.spawns[1].args[4],'direct');await h.supervisor.stop();
});

test('controlled Windows custom frontend command retains override and bypasses default npm admission',async()=>{
 const h=harness({frontendCommand:'controlled.cmd',frontendArgs:['custom argument'],admitNpm:async()=>assert.fail('custom command must bypass npm admission')});await h.supervisor.start();
 assert.equal(h.spawns[1].args[1],'controlled.cmd');assert.deepEqual(JSON.parse(h.spawns[1].args[2]),['custom argument']);assert.equal(h.spawns[1].args[4],'shell');await h.supervisor.stop();
});

test('controlled Windows incompatible npm rejects before backend/job/workload launch',async()=>{
 const h=harness({admitNpm:async()=>{throw Object.assign(Error('controlled npm unavailable'),{code:'SETUP_NPM_UNAVAILABLE'});}});
 await assert.rejects(h.supervisor.start(),{code:'SETUP_NPM_UNAVAILABLE'});assert.equal(h.spawns.length,0);assert.equal(h.calls.some(([name])=>name==='job-admit'),false);
});

test('controlled Windows stop during read-only admission launches no application children',async()=>{
 let admit,entered;const pending=new Promise(resolve=>{admit=resolve;}),started=new Promise(resolve=>{entered=resolve;});
 const h=harness({admitNpm:()=>{entered();return pending;}}),starting=h.supervisor.start();await started;await h.supervisor.stop();admit({command:nodeWithSpaces,prefix:[cliWithSpaces]});await starting;assert.equal(h.spawns.length,0);
});

test('real admission contract reads private CLI path and probes only version through an injected bounded executor',async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia npm admission '));try{
  const cli=path.join(directory,'npm-cli.js');await fs.writeFile(cli,'controlled fixture, never executed');let probes=0;
  const h=harness({environment:{npm_execpath:cli,PATH:'no-path-dependency'},admitNpm:admitSetupNpm,executeNpm:async(command,args,options)=>{probes++;assert.equal(command,process.execPath);assert.deepEqual(args,[await fs.realpath(cli),'--version']);assert.equal(options.timeout,10000);assert.equal(options.maxBuffer,4096);assert.equal(options.env.PATH,'no-path-dependency');return{stdout:'99.0.0\n'};}});
  await h.supervisor.start();assert.equal(probes,1);assert.equal(h.spawns[1].args[1],process.execPath);assert.equal(JSON.parse(h.spawns[1].args[2])[0],await fs.realpath(cli));assert.equal(h.spawns[1].args[4],'direct');await h.supervisor.stop();
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
