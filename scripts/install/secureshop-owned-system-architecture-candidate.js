'use strict';
// Unmounted planning leaf. AMD64 activation remains unavailable.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const arm=require('./secureshop-owned-system');
const AMD64_BASE='sha256:0e6e6feab3409d135561b2dac7f75dad902ceb5e14c35de4521155779ae70cee';
const FILES=Object.freeze(["Dockerfile.local.amd64.candidate", "config-reader.js", "contract.js", "diagnostic-contract.js", "diagnostic-executor.js", "diagnostic-http-handler.js", "diagnostic-http-listener.js", "diagnostic-init.c", "diagnostic-receipt.js", "diagnostic-result.js", "diagnostic-supervisor.c", "diagnostic-wire.js", "executor.js", "health-contract.js", "health-metrics.js", "http-handler.js", "http-listener.js", "local-listener-entry.js", "process-supervisor.c", "receipt.js", "restart-command-executor.js", "restart-contract.js", "restart-http-handler.js", "restart-http-listener.js", "restart-init.c", "restart-manager.js", "restart-service-child.c", "restart-supervisor.c", "restart-systemctl", "restart-target.js", "restart-wire.js", "system-init.c", "worker.js", "upload-preview-contract.js", "upload-preview-dependencies.js", "upload-preview-executor.js", "upload-preview-http-handler.js", "upload-preview-http-listener.js", "upload-preview-init.c", "upload-preview-runtime/package-lock.json", "upload-preview-runtime/package.json", "upload-preview-worker.js"].sort());
const fail=code=>Object.assign(new Error('Owned System architecture candidate unavailable'),{code});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function read(file,limit){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>limit)throw fail('SYSTEM_PACKAGE_SOURCE_INVALID');const b=Buffer.alloc(limit+1),n=fs.readSync(fd,b,0,b.length,0);if(n!==stat.size||n>limit)throw fail('SYSTEM_PACKAGE_SOURCE_INVALID');return b.subarray(0,n);}finally{fs.closeSync(fd);}}
function architecture({hostArchitecture,daemonArchitecture,daemonOs}) {
 const hosts={x64:'amd64',arm64:'arm64'},daemons={amd64:'amd64',x86_64:'amd64',arm64:'arm64',aarch64:'arm64'};
 if(daemonOs!=='linux'||!Object.hasOwn(hosts,hostArchitecture)||!Object.hasOwn(daemons,daemonArchitecture))throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
 if(hosts[hostArchitecture]!==daemons[daemonArchitecture])throw fail('SYSTEM_INSTALL_ARCHITECTURE_CONFLICT');
 return hosts[hostArchitecture];
}
function amd64Manifest(root) {
 const directory=path.join(root,'sidecars/sandbox-runner/owned-system'),bytes=read(path.join(directory,'local-package-amd64.candidate.json'),16384);let value;
 try{value=JSON.parse(bytes);}catch{throw fail('SYSTEM_PACKAGE_MANIFEST_INVALID');}
 if(!value||Object.keys(value).sort().join()!=='architecture,baseImage,files,qualification,status,version'||value.version!==2||value.architecture!=='amd64'||value.baseImage!==AMD64_BASE||value.status!=='unqualified_candidate'||value.qualification!==null||!value.files||Object.keys(value.files).sort().join()!==FILES.join())throw fail('SYSTEM_PACKAGE_MANIFEST_INVALID');
 for(const file of FILES)if(!/^[a-f0-9]{64}$/.test(value.files[file])||sha(read(path.join(directory,file),1048576))!==value.files[file])throw fail('SYSTEM_PACKAGE_SOURCE_CHANGED');
 return Object.freeze({architecture:'amd64',baseImage:AMD64_BASE,sha256:sha(bytes),qualification:null,status:'unqualified_candidate',files:Object.freeze(Object.fromEntries(FILES.map(f=>[f,value.files[f]])))});
}
function select({root,hostArchitecture,daemonArchitecture,daemonOs}) {
 const selected=architecture({hostArchitecture,daemonArchitecture,daemonOs});
 return selected==='arm64'?Object.freeze({...arm.sourceManifest(root),status:'qualified_arm64',managedVersion:1}):Object.freeze({...amd64Manifest(root),managedVersion:2});
}
function assertImage(selected,image) {
 if(!selected||!['arm64','amd64'].includes(selected.architecture)||!image||image.Os!=='linux'||image.Architecture!==selected.architecture||!/^sha256:[a-f0-9]{64}$/.test(image.Id||''))throw fail('SYSTEM_INSTALL_IMAGE_ARCHITECTURE');
 return true;
}
function assertRecordArchitecture(selected,record) {
 // Architecture binding only; not a replacement for the full private-record validator.
 if(!selected||!record||record.architecture!==selected.architecture||record.version!==selected.managedVersion||record.sourceManifestSha256!==selected.sha256)throw fail('SYSTEM_MANAGED_ARCHITECTURE_CONFLICT');
 return true;
}
function assertActivatable(input) {
 const selected=select(input);
 if(selected.architecture!=='arm64'||selected.status!=='qualified_arm64')throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
 return selected;
}
module.exports={architecture,select,assertImage,assertRecordArchitecture,assertActivatable};
