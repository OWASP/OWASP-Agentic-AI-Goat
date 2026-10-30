'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),http=require('node:http');
const {openPrivateChannel}=require('./invocation-private-lease');
const {createInvocationSupervisorChannel}=require('../../../server/services/secureshopOwnedMcpInvocationSupervisorChannel');
const {createInvocationManager}=require('./invocation-manager');
const {createInvocationSigner}=require('../../../server/services/secureshopOwnedMcpInvocationWire');
const {createInvocationHttpHandler}=require('../../../server/services/secureshopOwnedMcpInvocationTransport');
function privateFile(path,max){const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==10001||s.nlink!==1||(s.mode&0o777)!==0o600||s.size>max)throw Error('Private configuration unavailable');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
async function main(){
 const boot=JSON.parse(fs.readFileSync(3,'utf8'));fs.closeSync(3);
 if(Object.keys(boot).sort().join()!=='managerInstanceId,runtimeSha256,secret,supervisorEpoch,volumeId'||typeof boot.secret!=='string'||!/^[a-f0-9]{64}$/.test(boot.secret))throw Error('Supervisor bootstrap invalid');
 const {secret,...base}=boot,identity={...base,peerUid:10001,peerPid:1};
 const channel=await openPrivateChannel({identity,secret:Buffer.from(secret,'hex')});
 // No manager access precedes verified kernel peer and inherited flock.
 const config=JSON.parse(privateFile('/run/secrets/owasp-ai-goat-invocation.json',4096));
 if(Object.keys(config).sort().join()!==['keyId','keySha256','managerInstanceId','runtimeSha256','volumeId',...(Object.hasOwn(config,'qualificationEpochProbe')?['qualificationEpochProbe']:[])].sort().join()||Object.hasOwn(config,'qualificationEpochProbe')&&config.qualificationEpochProbe!==true||['managerInstanceId','runtimeSha256','volumeId'].some(k=>config[k]!==base[k]))throw Error('Private identity mismatch');
 if(config.qualificationEpochProbe===true){if(await channel.qualificationEpochProbe()!==true)throw Error('Epoch qualification denied');process.stdout.write('INVOCATION_QUALIFICATION_EPOCH_REJECTED\n');}
 const key=privateFile('/var/lib/owasp-ai-goat-invocation/signing.key',32);if(key.length!==32||crypto.createHash('sha256').update(key).digest('hex')!==config.keySha256)throw Error('Signing key mismatch');
 const token=privateFile('/run/secrets/owasp-ai-goat-invocation.token',128).toString('ascii');
 const assets=require('./invocation-build-assets').verify();if(assets.runtimeSha256!==base.runtimeSha256)throw Error('Invocation runtime mismatch');
 const supervisor=createInvocationSupervisorChannel({identity,channel:channel.channel});
 const manager=createInvocationManager({stateRoot:'/var/lib/owasp-ai-goat-invocation',managerInstanceId:base.managerInstanceId,runtimeSha256:base.runtimeSha256,supervisor,stateLease:channel.lease,assets:{'synthetic-catalog-read':{authorize:q=>q.assetId==='synthetic-catalog-read'}},initialize:false});
 // Reconnecting listener may observe a still-running containment. Status is
 // nonmutating; retry only readiness readback, never start/claim, for12seconds.
 const readyUntil=Date.now()+12000;for(;;){try{await manager.ready();break;}catch(error){if(Date.now()>=readyUntil)throw error;await new Promise(resolve=>setTimeout(resolve,250));}}
 const signer=createInvocationSigner({key,keyId:config.keyId});key.fill(0);
 const handler=createInvocationHttpHandler({token,signer,manager,maxConcurrent:2});
 const server=http.createServer((req,res)=>{handler.handle(req,res).then(handled=>{if(!handled){res.writeHead(404);res.end();}}).catch(()=>{res.destroy();});});server.requestTimeout=15000;server.headersTimeout=5000;server.maxHeadersCount=32;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(8095,'0.0.0.0',resolve);});
 let closing;const close=()=>closing||=(async()=>{server.close();await manager.close();channel.close();})();process.on('SIGTERM',()=>close().then(()=>process.exit(0),()=>process.exit(70)));process.on('SIGINT',()=>close().then(()=>process.exit(0),()=>process.exit(70)));
}
if(require.main===module)main().catch(()=>{process.stderr.write('Invocation listener unavailable\n');process.exitCode=70;});
module.exports={main};
