'use strict';
// Resource boundary for the reviewed pure suite only, not a hostile-code sandbox.
function installGuard({fs,Module,net,tls,http,https,dgram,dns,cp,workers,globalObject=globalThis}) {
 const deny=()=>{throw Object.assign(Error('Main platform pure tests deny resources'),{code:'MAIN_PLATFORM_RESOURCE_DENIED'});};
 const load=Module._load;Module._load=function(id,...args){if(/^(?:node:)?(?:sqlite|sqlite3|better-sqlite3|pg)$/.test(id)||/ollamaService|multiProviderAIService|\/database\/authDb$/.test(id))return deny();return load.call(this,id,...args);};
 for(const [object,keys]of [[cp,['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']],[net,['connect','createConnection','createServer']],[net.Socket?.prototype,['connect']],[net.Server?.prototype,['listen']],[tls,['connect','createServer']],[http,['request','get','createServer']],[https,['request','get','createServer']],[dgram,['createSocket']],[dns,['lookup','resolve','resolve4','resolve6']]])for(const k of keys)if(object?.[k])object[k]=deny;
 if(workers.Worker)workers.Worker=class{constructor(){deny();}};globalObject.fetch=deny;
 const writes=['writeFile','appendFile','mkdir','mkdtemp','rm','rmdir','unlink','rename','copyFile','cp','chmod','chown','truncate','symlink','link','fchmod','fchown','ftruncate'];
 for(const name of writes)for(const key of [name,name+'Sync'])if(fs[key])fs[key]=deny;
 for(const name of [...writes,'open'])if(fs.promises?.[name])fs.promises[name]=name==='open'?readOpen(fs.promises[name],fs.promises):deny;
 function readOpen(original,receiver){return function(file,flags,...args){if(typeof flags==='number'?(flags&(fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND))!==0:flags!==undefined&&flags!=='r'&&flags!=='rs')return deny();return original.call(receiver,file,flags,...args);};}
 for(const key of ['open','openSync'])fs[key]=readOpen(fs[key],fs);
 for(const key of ['write','writeSync','writev','writevSync'])if(fs[key]){const original=fs[key];fs[key]=function(fd,...args){if(fd!==1&&fd!==2)return deny();return original.call(fs,fd,...args);};}
 if(fs.createWriteStream)fs.createWriteStream=deny;
}
if(process.env.OWASP_AI_GOAT_MAIN_PLATFORM_PURE==='1')installGuard({fs:require('node:fs'),Module:require('node:module'),net:require('node:net'),tls:require('node:tls'),http:require('node:http'),https:require('node:https'),dgram:require('node:dgram'),dns:require('node:dns'),cp:require('node:child_process'),workers:require('node:worker_threads')});
module.exports={installGuard};
