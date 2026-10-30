'use strict';
// Actual service + authority modules, controlled branded guest and native bytes.
// No host processes, forwarding sockets, VM, Docker or PostgreSQL are executed.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module'),{createHash}=require('node:crypto'),{EventEmitter}=require('node:events');
const root=path.resolve(__dirname,'..'),directory='C:\\Users\\Synthetic\\private',id='abcdef123456';
function load(relative,overrides){const filename=path.join(root,relative),module={exports:{}},real=createRequire(filename);vm.runInThisContext(`(function(require,module,exports,__filename,__dirname){${fs.readFileSync(filename,'utf8')}\n})`,{filename})(name=>overrides[name]||real(name),module,module.exports,filename,path.dirname(filename));return module.exports;}
function harness(){
 const files=new Map(),events=[],docker=[],descriptors=new WeakMap();let volume=false,pgContainer=false,mailContainer=false,forwardFailure=false;
 const binding={kind:'owned-windows-lab',workspaceId:id,installationId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',vmId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',bindingSha256:'c'.repeat(64),daemonId:'controlled-owned-daemon',host:'owned-hyperv:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'};
 const describe={describeOwnedLab(session){if(!descriptors.has(session))throw Error('unbranded');return descriptors.get(session);}};
 const lab={async bindDaemon(){events.push('bind');return binding;},async assertCurrent(){events.push('current');},async stagePrivateEnvironment({bytes,sha256}){assert.equal(sha256,createHash('sha256').update(bytes).digest('hex'));events.push(['password-stage',Buffer.from(bytes)]);return'/var/lib/owasp-ai-goat/owned/private/env-'+sha256;},async openLoopbackForwards(ports,{ownChild}){events.push(['forwards',ports]);if(forwardFailure)throw Error('controlled forwarding admission failed');const owner=await ownChild({executable:'controlled admitted ssh',args:[]});if(typeof owner?.stopAndJoin!=='function')throw Error('controlled child owner denied');},async executeDocker(args){docker.push(args);events.push(['docker',args[0]]);assert(!args.some(arg=>/^[A-Za-z]:\\/.test(arg)));if(args[0]==='info')return JSON.stringify(binding.daemonId);
  if(args[0]==='image')return JSON.stringify([{Id:mail.MAILPIT_IMAGE_DIGEST,RepoDigests:[mail.MAILPIT_IMAGE]}]);
  if(args[0]==='volume'){if(args[1]==='create'){volume=true;return'';}if(!volume)throw Object.assign(Error('absent'),{code:1});return JSON.stringify([{Labels:{'org.owasp-ai-goat.workspace':id}}]);}
  if(args[0]==='run'){if(args.includes('owasp-ai-goat-postgres-'+id))pgContainer=true;else mailContainer=true;return'';}
  if(args[0]==='inspect'){
   const pg=args[1]==='owasp-ai-goat-postgres-'+id;if(pg&&!pgContainer||!pg&&!mailContainer)throw Object.assign(Error('absent'),{code:1});
   if(pg){const s=JSON.parse(files.get(directory+'\\local-postgres.json'));return JSON.stringify([{Config:{Labels:{'org.owasp-ai-goat.workspace':id}},State:{Running:true},Mounts:[{Type:'volume',Name:s.name,Destination:'/var/lib/postgresql'}],HostConfig:{PortBindings:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(s.port)}]}},NetworkSettings:{Ports:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(s.port)}]}}}]);}
   const s=JSON.parse(files.get(directory+'\\mailpit.json'));return JSON.stringify([{Id:'d'.repeat(64),Config:{Image:mail.MAILPIT_IMAGE,Labels:{'org.owasp-ai-goat.workspace':id,'org.owasp-ai-goat.mailpit.nonce':s.nonce}},Image:mail.MAILPIT_IMAGE_DIGEST,State:{Running:true},HostConfig:{PortBindings:{'1025/tcp':[{HostIp:'127.0.0.1',HostPort:String(s.smtpPort)}],'8025/tcp':[{HostIp:'127.0.0.1',HostPort:String(s.apiPort)}]}}}]);
  }
  if(args[0]==='exec'){assert(events.some(event=>Array.isArray(event)&&event[0]==='forwards'),'forward admission must precede PostgreSQL readiness');return'ready';}
  throw Error('unexpected Docker action '+args[0]);
 }};descriptors.set(lab,binding);
 const native={inspectPrivateDirectory(){return{};},readPrivateFile(file){if(!files.has(file))throw Error('denied');return Buffer.from(files.get(file));}};
 const fileSystem={async lstat(file){if(!files.has(file))throw Object.assign(Error('missing'),{code:'ENOENT'});return{};}};
 const journal={inspectDestination(){},readJournal({filePath}){return native.readPrivateFile(filePath);},createJournal({filePath,bytes}){assert(!files.has(filePath));events.push(['create',filePath]);files.set(filePath,Buffer.from(bytes));},updateJournal({filePath,originalBytes,resultBytes}){assert(files.get(filePath).equals(originalBytes));events.push(['update',filePath]);files.set(filePath,Buffer.from(resultBytes));}};
 const authority=load('scripts/local-docker-authority.js',{'./lib/windows-owned-lab':describe});
 const authorityStorage=authority.createLocalDockerAuthorityStorage({filesystemPlatform:'win32',privateState:native,journal,fileSystem});
 const tools={...authority,resolveDockerAuthority:options=>authority.resolveDockerAuthority({...options,storage:authorityStorage}),writeLocalDockerAuthority:authorityStorage.writeLocalDockerAuthority};
 const setup=load('scripts/setup-application.js',{'./lib/windows-owned-lab':describe,'./local-docker-authority':tools});
 const mail=load('scripts/local-mailpit.js',{'./lib/windows-owned-lab':describe,'./local-docker-authority':tools});
 const pg=setup.createLocalPostgresSetup({filesystemPlatform:'win32',fileSystem,privateState:native,privateJournal:journal,authorityTools:tools,findAvailablePort:async()=>55432}).localPostgres;
 const ownLabChild=async()=>({async stopAndJoin(){}}),base={directory,id,platform:'win32',environment:{},ownedLabSession:lab,ownLabChild,execute:()=>assert.fail('host process forbidden')};
 const request=(_url,callback)=>{assert(events.some(event=>Array.isArray(event)&&event[0]==='forwards'));events.push('api-ready');const response=new EventEmitter();response.statusCode=200;process.nextTick(()=>{callback(response);response.emit('end');});return Object.assign(new EventEmitter(),{destroy(){}});};
 const connect=()=>{assert(events.some(event=>Array.isArray(event)&&event[0]==='forwards'));events.push('smtp-ready');const socket=new EventEmitter();socket.setTimeout=()=>{};socket.destroy=()=>{};process.nextTick(()=>socket.emit('data',Buffer.from('220 controlled SMTP\r\n')));return socket;};
 let port=41024;
 const mailOptions={...base,resolveAuthority:tools.resolveDockerAuthority,writeAuthority:tools.writeLocalDockerAuthority,stateStorage:mail.createMailpitStateStorage({filesystemPlatform:'win32',journal,exists:file=>files.has(file)}),request,connect,allocatePort:async()=>++port,readinessAttempts:1,pullImage:false};
 return{pg,mail,base,mailOptions,files,events,docker,lab,binding,descriptors,failForward(){forwardFailure=true;}};
}
test('Windows PostgreSQL stages exact password bytes and forwards before readiness without exposing host path',async()=>{
 const h=harness();await h.pg(h.base);const state=JSON.parse(h.files.get(directory+'\\local-postgres.json')),staged=h.events.find(event=>Array.isArray(event)&&event[0]==='password-stage')[1];assert(staged.equals(Buffer.from('POSTGRES_PASSWORD='+state.password+'\n')));
 const run=h.docker.find(args=>args[0]==='run');assert.match(run[run.indexOf('--env-file')+1],/^\/var\/lib\/owasp-ai-goat\/owned\/private\/env-/);assert(!run.join(' ').includes(state.password));assert(run.includes('127.0.0.1:55432:5432'));
 assert.deepEqual(h.events.find(event=>Array.isArray(event)&&event[0]==='forwards')[1],[{local:55432,guest:55432}]);
 const original=Buffer.from(h.files.get(directory+'\\local-postgres.json')),writes=h.events.filter(e=>Array.isArray(e)&&['create','update'].includes(e[0])).length,runCount=h.docker.filter(args=>args[0]==='run').length;
 await h.pg({...h.base,existingOnly:true});assert(h.files.get(directory+'\\local-postgres.json').equals(original));assert.equal(h.events.filter(e=>Array.isArray(e)&&['create','update'].includes(e[0])).length,writes);assert.equal(h.docker.filter(args=>args[0]==='run').length,runCount);assert.equal(h.events.filter(e=>Array.isArray(e)&&e[0]==='password-stage').length,1);
});
test('Windows service mismatch and absent forwarding owner deny before storage or Docker',async()=>{
 for(const kind of ['pg','mail'])for(const change of [{ownedLabSession:{}},{id:'ffffffffffff'},{ownLabChild:undefined},{platform:'linux'}]){const h=harness();const options={...(kind==='pg'?h.base:h.mailOptions),...change};await assert.rejects(kind==='pg'?h.pg(options):h.mail.ensureLocalMailpit(options));assert.equal(h.files.size,0);assert.equal(h.docker.length,0);}
});
test('Windows PostgreSQL forwarding failure prevents readiness',async()=>{const h=harness();h.failForward();await assert.rejects(h.pg(h.base),/forwarding/);assert(!h.docker.some(args=>args[0]==='exec'));});
test('Windows PostgreSQL awaits forwarding owner admission and rejects unusable child owners',async()=>{
 const h=harness();let release,entered;const ownerEntered=new Promise(resolve=>{entered=resolve;}),ownerReady=new Promise(resolve=>{release=resolve;});
 const operation=h.pg({...h.base,ownLabChild:async()=>{entered();await ownerReady;return{async stopAndJoin(){}};}});await ownerEntered;assert(!h.docker.some(args=>args[0]==='exec'));release();await operation;
 const g=harness();await assert.rejects(g.pg({...g.base,ownLabChild:async()=>({})}),/owner denied/);assert(!g.docker.some(args=>args[0]==='exec'));
});
test('Windows Mailpit forwards both exact loopback ports and retained runtime reuses container/state',async()=>{
 const h=harness(),state=await h.mail.ensureLocalMailpit(h.mailOptions);assert.deepEqual(h.events.find(e=>Array.isArray(e)&&e[0]==='forwards')[1],[{local:state.smtpPort,guest:state.smtpPort},{local:state.apiPort,guest:state.apiPort}]);assert(h.events.indexOf('api-ready')>h.events.findIndex(e=>Array.isArray(e)&&e[0]==='forwards'));
 const original=Buffer.from(h.files.get(state.statePath)),runCount=h.docker.filter(args=>args[0]==='run').length,writes=h.events.filter(e=>Array.isArray(e)&&['create','update'].includes(e[0])).length;
 await h.mail.ensureLocalMailpit({...h.mailOptions,existingOnly:true});
 const runtime=await h.mail.assertLocalMailpitReady({...h.mailOptions,statePath:state.statePath});assert.equal(runtime.containerId,state.containerId);assert(h.files.get(state.statePath).equals(original));assert.equal(h.docker.filter(args=>args[0]==='run').length,runCount);assert.equal(h.events.filter(e=>Array.isArray(e)&&['create','update'].includes(e[0])).length,writes);assert.equal(h.events.filter(e=>Array.isArray(e)&&e[0]==='forwards').length,3);
});
test('Windows Mailpit runtime rejects foreign session/broken forwarding before HTTP/SMTP readiness',async()=>{
 const h=harness(),state=await h.mail.ensureLocalMailpit(h.mailOptions);const probes=h.events.filter(e=>e==='api-ready'||e==='smtp-ready').length;
 await assert.rejects(h.mail.assertLocalMailpitReady({...h.mailOptions,statePath:state.statePath,ownedLabSession:{}}));
 h.failForward();await assert.rejects(h.mail.assertLocalMailpitReady({...h.mailOptions,statePath:state.statePath}),/forwarding/);assert.equal(h.events.filter(e=>e==='api-ready'||e==='smtp-ready').length,probes);
});
