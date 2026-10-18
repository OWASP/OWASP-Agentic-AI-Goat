'use strict';
// Explicit offline provisioning only. Never imported by the listener/restart.
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const C=require('../../../server/services/secureshopOwnedMcpInvocationContract');
function provision({root,managerInstanceId,volumeId,runtimeSha256,keyId,key}={}){
 const id=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
 if(typeof root!=='string'||!path.isAbsolute(root)||![managerInstanceId,volumeId].every(v=>typeof v==='string'&&id.test(v))||typeof runtimeSha256!=='string'||!/^[a-f0-9]{64}$/.test(runtimeSha256)||typeof keyId!=='string'||!/^[A-Za-z0-9_-]{1,32}$/.test(keyId)||!Buffer.isBuffer(key)||key.length!==32)throw Error('Explicit private identity required');
 const s=fs.lstatSync(root);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700||fs.readdirSync(root).length)throw Error('Empty owned private volume required');
 for(const [name,bytes]of Object.entries({'supervisor.lock':'','identity':`${managerInstanceId}\n${volumeId}\n${runtimeSha256}\n`,'signing.key':key,'state.json':JSON.stringify(C.bounded({version:1,managerInstanceId,runtimeSha256,claims:{},fences:{}},4194304))+'\n'})){const fd=fs.openSync(path.join(root,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 const fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}return Object.freeze({managerInstanceId,volumeId,runtimeSha256,keyId,keySha256:crypto.createHash('sha256').update(key).digest('hex')});
}
module.exports={provision};
