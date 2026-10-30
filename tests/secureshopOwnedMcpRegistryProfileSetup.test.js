'use strict';
// Exercise the real registry provision -> platform profile helpers without sudo,
// Docker, SSH, or external filesystem mutations. No installProfile override.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{createHash}=require('node:crypto');
const {provision,plan}=require('../scripts/install/secureshop-owned-mcp-registry');
const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(platform){const home=await fs.mkdtemp(path.join(os.tmpdir(),'registry-profile-'));const options={root:process.cwd(),home,platform,imageId:'sha256:'+'a'.repeat(64),environment:{},...(platform==='darwin'?{colimaProfile:'colima-registry-control'}:{})};const p=plan(options),events=[];let probe=null,installed=null,verified=false,conflict=false,missing=false,trust=false;
 const ok=stdout=>({exitCode:0,stdout:typeof stdout==='string'?stdout:JSON.stringify(stdout)}),absent=()=>({exitCode:1,stdout:''});
 options.run=async(file,args,o)=>{assert(o.timeoutMs>0&&o.timeoutMs<=30000);assert(o.maxOutputBytes>0&&o.maxOutputBytes<=1048576);events.push(o.stage);if(file==='docker'){
  assert.deepEqual(args.slice(0,2),['--host',p.dockerHost]);const a=args.slice(2);if(a[0]==='image')return ok([{Id:p.imageId,Architecture:'arm64',Os:'linux',Config:{User:'10001:10001',Entrypoint:['node','sidecars/sandbox-runner/owned-mcp-registry/http-listener.js']}}]);if(a[0]==='info')return ok('"arm64"');
  if(a[1]==='inspect'){if(probe&&[probe.Id,probe.Name.slice(1)].includes(a[2]))return ok([probe]);return{exitCode:1,stderr:a[0]==='network'?`Error response from daemon: network ${a[2]} not found`:`Error: No such container: ${a[2]}`};}
  if(a[0]==='create'){assert(a.includes('--entrypoint'),'Service create before profile verification');probe={Id:'1'.repeat(64),Name:'/'+a[a.indexOf('--name')+1],Image:p.imageId,Config:{Labels:{'owasp-ai-goat.registry.probe':p.workspace}},HostConfig:{NetworkMode:'none'},State:{Running:false,ExitCode:0}};return ok(probe.Id);}
  if(a[0]==='start'&&a[1]==='--attach')return ok('f'.repeat(64));if(a[0]==='rm'&&probe?.Id===a[1]){probe=null;return ok('');}
  if(o.stage==='network-create'){assert(verified,'Network created before enforced profile');throw Object.assign(Error('controlled stop after profile'),{code:'CONTROL_STOP'});}throw Error('Unexpected Docker command '+o.stage);
 }
 assert(platform==='linux'?file==='sudo':['ssh','scp'].includes(file));if(platform==='linux')assert.equal(args[0],'--non-interactive');else{assert.deepEqual(args.slice(0,2),['-F',p.sshConfig]);if(file==='ssh')assert.equal(args[2],p.sshHost);}
 if(o.stage==='remote-preflight')return absent();
 if(o.stage==='profile-parse'){const renderedFile=platform==='linux'?args.at(-1):null;if(renderedFile){const bytes=await fs.readFile(renderedFile);assert(bytes.includes(Buffer.from(`profile "${p.profile}"`)));assert(!bytes.includes(Buffer.from('@@SUPERVISOR_PROFILE@@')));assert.equal((await fs.stat(renderedFile)).mode&0o777,0o600);}}
 if(o.stage==='remote-copy'){assert.equal(file,'scp');const bytes=await fs.readFile(args[2]);assert(bytes.includes(Buffer.from(`profile "${p.profile}"`)));}
 if(o.stage==='profile-existing-state')return installed?ok(''):absent();
 if(['profile-existing-digest','profile-published-digest'].includes(o.stage))return ok((conflict?'0'.repeat(64):installed)+'  '+p.destination);
 if(o.stage==='profile-install'){assert(args.join(' ').includes(p.destination));const rendered=(await fs.readFile(path.join(options.root,'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in'),'utf8')).replaceAll('@@SUPERVISOR_PROFILE@@',p.profile);installed=sha(rendered);}
 if(o.stage==='profile-trust')return ok(trust?'1000:1000:644:regular file':'0:0:600:regular file');
 if(o.stage==='profile-verify'){verified=!missing;return ok(missing?'owasp-ai-goat-mcp-sandbox (enforce)\n':p.profile+' (enforce)\n');}
 return ok('');};
 return{options,p,events,close:()=>fs.rm(home,{recursive:true,force:true}),setConflict:()=>{conflict=true;},setMissing:()=>{missing=true;},setTrust:()=>{trust=true;}};
}
for(const platform of ['linux','darwin']){
 test(`${platform}: real provision installs exact registry profile before service resources and reuses matching profile`,async()=>{const f=await fixture(platform);try{await assert.rejects(provision(f.options),{code:'CONTROL_STOP'});assert(f.events.indexOf('profile-install')<f.events.indexOf('profile-load'));assert(f.events.indexOf('profile-verify')<f.events.indexOf('network-create'));const first=f.events.filter(x=>x==='profile-install').length;await assert.rejects(provision(f.options),{code:'CONTROL_STOP'});assert.equal(f.events.filter(x=>x==='profile-install').length,first);assert(f.events.includes('profile-existing-digest'));if(platform==='darwin')assert.equal(f.events.filter(x=>x==='remote-cleanup').length,2);}finally{await f.close();}});
 test(`${platform}: missing fresh profile enforcement fails before network/service creation`,async()=>{const f=await fixture(platform);f.setMissing();try{await assert.rejects(provision(f.options),{code:'MCP_INSTALL_PROFILE_RECOVERY_REQUIRED'});assert(!f.events.includes('network-create'));assert(f.events.includes('profile-install'));if(platform==='darwin')assert(f.events.includes('remote-cleanup'));}finally{await f.close();}});
 test(`${platform}: conflicting preexisting profile is not overwritten or loaded`,async()=>{const f=await fixture(platform);try{await assert.rejects(provision(f.options),{code:'CONTROL_STOP'});const n=f.events.length;f.setConflict();await assert.rejects(provision(f.options),{code:'MCP_INSTALL_PROFILE_CONFLICT'});assert(!f.events.slice(n).includes('profile-install'));assert(!f.events.slice(n).includes('profile-load'));assert(!f.events.slice(n).includes('network-create'));}finally{await f.close();}});
 test(`${platform}: untrusted installed profile ownership/mode blocks load and service creation`,async()=>{const f=await fixture(platform);f.setTrust();try{await assert.rejects(provision(f.options),{code:'MCP_INSTALL_PROFILE_TRUST_INVALID'});assert(!f.events.includes('profile-load'));assert(!f.events.includes('network-create'));}finally{await f.close();}});
}
