'use strict';
// Explicit prerequisite gate only: no build, source mount, image deletion, or
// model success claim. Outer seccomp is unconfined; packaged child BPF is used.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {constants}=require('node:fs'),{Readable}=require('node:stream'),{spawn}=require('node:child_process');
const {EXPORT,_internals:admission}=require('./ownedMcpImageAdmission');
const {PINS}=require('./ownedMcpBoundedBuild');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
const TEMPLATE='sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in';
const TEMPLATE_SHA='89d2b2194d05f55b86bc3bb0582365f707a9de7aa090a8f2eecfa9f2ca937a25';
const DOCKER_SHA='8a55fc0cf28b70ebfb3d90f660fbd3a856640e657436ae6887ef53f533276025';
const RUNTIME_IMAGE='sha256:1e68c6ad6fc836fed6bef48032f472787b2e9fa7cde7aa6fb005c30bec333d82';
const RUNTIME_DIGEST='d88092cd25f6dd885f1fbb319c53a844dc9873649657341c578e0467d9e81381';
function specification(root,nonce,runtimeDigest){
  const base=admission.specification(root);
  if(!/^[a-f0-9]{12}$/.test(nonce||'')||runtimeDigest!==RUNTIME_DIGEST)throw fail('RUNTIME_INVALID_IDENTITY');
  const name='owasp-ai-goat-owned-mcp-registry-'+nonce;
  return Object.freeze({...base,nonce,runtimeDigest,name,profile:name,guest:'/var/tmp/owasp-ai-goat-v23-runtime-'+nonce,
    directory:path.join(root,'tasks/tmp/v23-runtime-'+nonce),lima:path.join(root,'tasks/runtime/container/bin/limactl'),limaHome:path.join(root,'tasks/l')});
}
async function journal(spec,name,value){
  const fd=await fs.open(path.join(spec.directory,name+'.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await fd.writeFile(JSON.stringify(value));await fd.sync();}finally{await fd.close();}
  const dir=await fs.open(spec.directory,constants.O_RDONLY|constants.O_NOFOLLOW);try{await dir.sync();}finally{await dir.close();}
}
const guard=`set -eu
umask 077
root="$1"; nonce="$2"; profile="$3"; digest="$4"
[ "$root" = "/var/tmp/owasp-ai-goat-v23-runtime-$nonce" ]
[ "$profile" = "owasp-ai-goat-owned-mcp-registry-$nonce" ]
[ "\${#nonce}" = 12 ]; case "$nonce" in *[!0-9a-f]*) exit 80;; esac
[ "\${#digest}" = 64 ]; case "$digest" in *[!0-9a-f]*) exit 80;; esac
labels() { cat /sys/kernel/security/apparmor/profiles; }
refresh() { listing=$(labels) || exit 81; }
present() { printf '%s\\n' "$listing" | awk -v p="$profile" '$1==p || index($1,p"//")==1 { found=1 } END { exit !found }'; }
owned() { [ -d "$root" ] && [ ! -L "$root" ] && [ -f "$root/owner" ] && [ ! -L "$root/owner" ] && [ "$(cat "$root/owner")" = "$nonce" ]; }
policy() { [ -f "$root/policy" ] && [ ! -L "$root/policy" ] && [ "$(sha256sum "$root/policy" | cut -d' ' -f1)" = "$digest" ]; }
`;
const scripts=Object.freeze({
  install:guard+`[ ! -e "$root" ]; [ ! -L "$root" ]; refresh; ! present
mkdir -m 0700 "$root"
(set -C; printf '%s\\n' "$nonce" > "$root/owner")
(set -C; cat > "$root/policy")
owned; policy
apparmor_parser --skip-kernel-load "$root/policy"
refresh; ! present
apparmor_parser -a "$root/policy"
(set -C; printf '%s %s\\n' "$nonce" "$digest" > "$root/loaded")
refresh
printf '%s\\n' "$listing" | awk -v p="$profile" '$0==p" (enforce)" { found=1 } END { exit !found }'
`,
  cleanup:guard+`refresh
if [ ! -e "$root" ] && [ ! -L "$root" ]; then ! present; exit 0; fi
owned; policy
if present; then
 [ -f "$root/loaded" ]; [ ! -L "$root/loaded" ]; [ "$(cat "$root/loaded")" = "$nonce $digest" ]
 apparmor_parser -R "$root/policy"
fi
refresh; ! present
if [ -e "$root/loaded" ] || [ -L "$root/loaded" ]; then
 [ -f "$root/loaded" ]; [ ! -L "$root/loaded" ]; [ "$(cat "$root/loaded")" = "$nonce $digest" ]; rm -- "$root/loaded"
fi
rm -- "$root/policy" "$root/owner"
rmdir -- "$root"
[ ! -e "$root" ]; [ ! -L "$root" ]; refresh; ! present
`,
});
function createGuest({launch=spawn,delay=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
  return async(spec,operation,policy)=>{
    if(!Object.hasOwn(scripts,operation))throw fail('RUNTIME_UNKNOWN_GUEST_OPERATION');
    return new Promise((resolve,reject)=>{
      const child=launch(spec.lima,['shell','--workdir','/','colima-goat-q','sudo','-n','timeout','--signal=TERM','--kill-after=5','25','/bin/sh','-c',scripts[operation],'owned-runtime',spec.guest,spec.nonce,spec.profile,sha(policy)],
        {cwd:spec.root,env:{PATH:process.env.PATH,HOME:spec.limaHome,TMPDIR:path.join(spec.root,'tasks/tmp'),LIMA_HOME:spec.limaHome},detached:true,stdio:['pipe','pipe','pipe']});
      let error,count=0,stderr=Buffer.alloc(0);
      const stop=e=>{error ||= e;if(child.pid)try{process.kill(-child.pid,'SIGKILL');}catch(cause){if(cause.code!=='ESRCH')error.signalError=cause.code;}};
      const timer=setTimeout(()=>stop(fail('RUNTIME_GUEST_TIMEOUT')),40000);
      child.on('error',stop);child.stdin.on('error',stop);
      for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{count+=chunk.length;if(stream===child.stderr)stderr=Buffer.concat([stderr,chunk]).subarray(-16384);if(count>65536)stop(fail('RUNTIME_GUEST_OUTPUT_LIMIT'));});
      child.on('close',async code=>{clearTimeout(timer);if(error||code!==0){
        // Local SSH death does not join remote policy mutation. Wait the full
        // remote deadline before any cleanup; exact absence is still checked.
        if(child.pid)await delay(45000);
        const e=error||fail('RUNTIME_GUEST_FAILED');e.diagnostic={code,stderr:stderr.toString('utf8')};reject(e);
      }else resolve();});
      child.stdin.end(operation==='install'?policy:undefined);
    });
  };
}
const guest=createGuest();
function createArgs(spec){return ['create','--name',spec.name,'--label','owasp-ai-goat.runtime='+spec.nonce,'--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--memory','512m','--cpus','1','--pids-limit','128','--log-driver','none','--cap-drop','ALL','--security-opt','apparmor='+spec.profile,'--security-opt','seccomp=unconfined','--user','10001:10001','--env','SECURESHOP_MCP_REGISTRY_PROFILE='+spec.profile,'--entrypoint','node','-i',RUNTIME_IMAGE,'-'];}
function verifyContainer(spec,id,row){
  if(row?.Id!==id||row.Name!=='/'+spec.name||row.Image!==RUNTIME_IMAGE||row.Config?.Labels?.['owasp-ai-goat.runtime']!==spec.nonce)throw fail('RUNTIME_CONTAINER_IDENTITY');
}
function verifyBoundary(spec,row){
  const h=row.HostConfig,c=row.Config;
  if(h?.NetworkMode!=='none'||h.ReadonlyRootfs!==true||h.Privileged!==false||JSON.stringify(h.CapDrop)!=='["ALL"]'||(h.CapAdd||[]).length||
    h.Memory!==536870912||h.NanoCpus!==1000000000||h.PidsLimit!==128||h.LogConfig?.Type!=='none'||JSON.stringify(h.SecurityOpt)!==JSON.stringify(['apparmor='+spec.profile,'seccomp=unconfined'])||
    JSON.stringify(h.Tmpfs)!==JSON.stringify({'/tmp':'rw,nosuid,nodev,noexec,size=16m'})||(h.Binds||[]).length||(h.Mounts||[]).length||
    !Array.isArray(row.Mounts)||row.Mounts.some(x=>x.Type!=='tmpfs'||x.Destination!=='/tmp')||row.Mounts.length>1||
    c.User!=='10001:10001'||c.OpenStdin!==true||JSON.stringify(c.Entrypoint)!=='["node"]'||JSON.stringify(c.Cmd)!=='["-"]'||!c.Env?.includes('SECURESHOP_MCP_REGISTRY_PROFILE='+spec.profile))throw fail('RUNTIME_CONTAINER_BOUNDARY');
}
// This function is serialized into stdin; it imports only existing image assets.
async function registrationFixture(expectedDigest){
  const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises');
  const packaged=await require('/app/tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs').main();
  assert.equal(packaged.status,'passed');assert.equal(packaged.modelCalls,0);assert.equal(packaged.runtimeDigest,expectedDigest);
  const {createOwnedMcpRegistryListener}=require('/app/sidecars/sandbox-runner/owned-mcp-registry/http-listener');
  const {registryRequestDigest}=require('/app/server/services/secureshopMcpRegistryContract');
  const token=crypto.randomBytes(32).toString('base64url'),listener=createOwnedMcpRegistryListener({enabled:true,token,host:'127.0.0.1',port:0,expectedProfile:process.env.SECURESHOP_MCP_REGISTRY_PROFILE});
  const before=(await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim();
  const request=async(method,route,body)=>{const response=await fetch('http://127.0.0.1:'+listener.address().port+'/secureshop/mcp-registry/registration'+route,{method,headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(25000)});return {status:response.status,value:await response.json()};};
  let receipt;
  try{
    await listener.start();const health=await request('GET','/health');assert.equal(health.status,200);assert.equal(health.value.registrationCapability,'owned-mcp-registration-v1');assert.equal(health.value.runtimeDigest,expectedDigest);
    const command="printf 'owned-stdio-effect' > /owned-mcp-files/stdio-effect; exec /usr/local/bin/node /usr/local/libexec/owasp-ai-goat-owned-mcp-registry-worker.js --stdio-peer";
    const q={version:1,action:'register',operationId:crypto.randomUUID(),expectedVersion:'0',name:'tracked-stdio',transport:'stdio',url:'',stdio_cmd:command};
    const identity={instanceId:health.value.instanceId,operationId:q.operationId,requestSha256:registryRequestDigest(q)};
    const input={version:1,...identity,mode:'vuln',request:q,activeEntries:[]};
    const response=await request('POST','',input);assert.equal(response.status,200);receipt=response.value;
    assert.equal(receipt.state,'completed');assert.equal(receipt.drained,true);for(const key of Object.keys(identity))assert.equal(receipt[key],identity[key]);
    assert.equal(receipt.changes[0].endpoint,command);assert.equal(receipt.changes[0].effect.stdioEffect.text,'owned-stdio-effect');
    for(const route of ['/status','/drain']){const r=await request('POST',route,identity);assert.equal(r.status,200);assert.equal(r.value.state,'completed');assert.equal(r.value.drained,true);}
    assert.equal((await request('POST','',input)).status,409);
    const stale=await request('POST','/status',{...identity,instanceId:crypto.randomUUID()});assert.equal(stale.value.state,'unknown');assert.equal(stale.value.drained,false);
    await assert.rejects(fs.access('/owned-mcp-files/stdio-effect'),{code:'ENOENT'});
  }finally{await listener.close();}
  assert.equal((await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim(),before);
  return {status:'passed',modelCalls:0,runtimeDigest:expectedDigest,packaged,trackedRegistration:receipt,qualificationComplete:false,outerSeccomp:'unconfined',childSeccomp:'packaged executor BPF'};
}
function fixture(runtimeDigest){return '('+registrationFixture.toString()+')('+JSON.stringify(runtimeDigest)+').then(x=>console.log(JSON.stringify(x))).catch(e=>{console.error(e.stack);process.exitCode=1;});';}
async function qualify({root,nonce=crypto.randomBytes(6).toString('hex'),runtimeDigest=RUNTIME_DIGEST,docker=admission.command,remote=guest,verifyHost=true,readTemplate=()=>fs.readFile(path.join(root,TEMPLATE),'utf8')}={}){
  const spec=specification(root,nonce,runtimeDigest);
  if(await fs.realpath(root)!==root||await fs.realpath(path.dirname(spec.directory))!==path.dirname(spec.directory))throw fail('RUNTIME_PATH_ALIAS');
  if(verifyHost)for(const [file,digest]of [[spec.docker,DOCKER_SHA],[spec.lima,PINS.lima]])if(await fs.realpath(file)!==file||sha(await fs.readFile(file))!==digest)throw fail('RUNTIME_TOOL_PIN');
  const template=await readTemplate();if(sha(template)!==TEMPLATE_SHA)throw fail('RUNTIME_PROFILE_PIN');
  const policy=template.replaceAll('@@SUPERVISOR_PROFILE@@',spec.profile),script=fixture(runtimeDigest),argv=createArgs(spec);
  const before=await admission.inventory(spec,docker);
  if(!before.images.includes(RUNTIME_IMAGE+' <none>:<none>'))throw fail('RUNTIME_IMAGE_MISSING');
  await fs.mkdir(spec.directory,{mode:0o700});
  await journal(spec,'intent',{version:1,nonce,name:spec.name,profile:spec.profile,guest:spec.guest,configImageId:EXPORT.imageId,runtimeImageId:RUNTIME_IMAGE,runtimeDigest,daemon:before.daemon,before,policySha256:sha(policy),fixtureSha256:sha(script),argv,automaticRetry:false});
  let id,result,primary,cleanupError,profileAttempted=false,createAttempted=false,containerAbsent=true;
  const inspect=async()=>{const rows=JSON.parse(await docker(spec,['container','inspect',id]));if(rows.length!==1)throw fail('RUNTIME_CONTAINER_IDENTITY');verifyContainer(spec,id,rows[0]);return rows[0];};
  try{
    profileAttempted=true;await remote(spec,'install',policy);await journal(spec,'profile',{loaded:true,policySha256:sha(policy)});
    createAttempted=true;containerAbsent=false;id=(await docker(spec,argv)).trim();if(!/^[a-f0-9]{64}$/.test(id))throw fail('RUNTIME_CREATE_UNCERTAIN');
    await journal(spec,'created',{id});verifyBoundary(spec,await inspect());
    const output=await docker(spec,['start','--attach','--interactive',id],{input:Readable.from([script]),timeoutMs:180000});
    const ended=await inspect();if(ended.State?.Running||ended.State?.ExitCode!==0)throw fail('RUNTIME_FIXTURE_FAILED');
    result=JSON.parse(output.trim());if(result.status!=='passed'||result.modelCalls!==0||result.runtimeDigest!==runtimeDigest||result.qualificationComplete!==false)throw fail('RUNTIME_FIXTURE_RECEIPT');
  }catch(error){primary=error;}
  try{
    if(createAttempted){
      if(!/^[a-f0-9]{64}$/.test(id||''))throw fail('RUNTIME_CONTAINER_CLEANUP_UNCERTAIN');
      if((await inspect()).State?.Running)await docker(spec,['stop','--time','5',id]);
      if((await inspect()).State?.Running)throw fail('RUNTIME_CONTAINER_NOT_JOINED');
      await docker(spec,['rm',id]);const ids=(await docker(spec,['ps','-a','--no-trunc','--quiet'])).trim().split('\n');if(ids.includes(id))throw fail('RUNTIME_CONTAINER_REMAINS');containerAbsent=true;
    }
    if(profileAttempted)await remote(spec,'cleanup',policy);
  }catch(error){cleanupError=error;}
  try{if(JSON.stringify(await admission.inventory(spec,docker))!==JSON.stringify(before))throw fail('RUNTIME_SHARED_STATE_CHANGED');}catch(error){cleanupError=new AggregateError([cleanupError,error].filter(Boolean),'Runtime preservation failed');}
  await journal(spec,'result',{result:primary||cleanupError?null:result,error:primary?.code||primary?.message||null,diagnostic:primary?.diagnostic||null,cleanupError:cleanupError?.code||cleanupError?.message||null,containerId:id||null,containerAbsent,cleanupVerified:!cleanupError,automaticRetry:false,qualificationComplete:false});
  if(primary||cleanupError)throw new AggregateError([primary,cleanupError].filter(Boolean),'Runtime prerequisite failed; inspect durable intent, no automatic retry');
  return {directory:spec.directory,...result,cleanupVerified:true};
}
module.exports={qualify,RUNTIME_IMAGE,RUNTIME_DIGEST,_internals:{specification,journal,scripts,createGuest,createArgs,verifyBoundary,fixture,TEMPLATE,TEMPLATE_SHA}};
