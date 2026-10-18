'use strict';
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto'),{promisify}=require('node:util');
function createPinnedDockerExecution(environment,{execute=promisify(require('node:child_process').execFile),read=filename=>fs.readFileSync(filename),real=filename=>fs.realpathSync(filename)}={}){
 const binary=environment.ANALYTICS_DOCKER_BINARY,sha=environment.ANALYTICS_DOCKER_SHA256,host=environment.DOCKER_HOST,daemon=environment.ANALYTICS_DOCKER_DAEMON,image=environment.ANALYTICS_POSTGRES_IMAGE;
 const deny=()=>{throw Error('Analytics pinned Docker admission unavailable');};
 if(typeof binary!=='string'||!path.isAbsolute(binary)||!/^[a-f0-9]{64}$/.test(sha)||typeof host!=='string'||!host.startsWith('unix:///')||typeof daemon!=='string'||!daemon||!/^sha256:[a-f0-9]{64}$/.test(image))deny();
 return async(file,args,options={})=>{
  if(file!=='docker'||!Array.isArray(args)||args[0]!=='--host'||args[1]!==host||real(binary)!==binary||createHash('sha256').update(read(binary)).digest('hex')!==sha)deny();
  const bounded={...options,timeout:Math.min(options.timeout||30000,30000),maxBuffer:Math.min(options.maxBuffer||2097152,2097152)};
  const observed=await execute(binary,['--host',host,'info','--format','{{json .ID}}'],bounded);
  if(JSON.parse(observed.stdout)!==daemon)deny();
  const tagged=await execute(binary,['--host',host,'image','inspect','postgres:18','--format','{{json .Id}}'],bounded);
  if(JSON.parse(tagged.stdout)!==image)deny();
  // Installer may inspect or start its exact owned image, but never fetch a mutable tag.
  if(args[2]==='pull')deny();
  return execute(binary,args,bounded);
 };
}
module.exports={createPinnedDockerExecution};
