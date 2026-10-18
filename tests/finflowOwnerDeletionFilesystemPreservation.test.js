'use strict';
// Real synthetic file-store composition only; repository is controlled, never a database.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto');
const {createFinflowBackupFileStore}=require('../server/services/finflowDurableResources');
const {createFinflowOwnerResourceDeletion}=require('../server/services/finflowOwnerResourceDeletion');
const {verifyFinflowOwnerDeletionReceipt}=require('../server/services/finflowOwnerDeletionReceipt');
const os=require('node:os');
const A='11111111-1111-4111-8111-111111111111',B='22222222-2222-4222-8222-222222222222',JOB='33333333-3333-4333-8333-333333333333',LEASE='44444444-4444-4444-8444-444444444444';
async function owned(t){
 const base=await fs.realpath(os.tmpdir());
 const root=await fs.mkdtemp(path.join(base,'finflow-owner-file-control-'));await fs.chmod(root,0o700);const original=await fs.lstat(root);assert(original.isDirectory()&&!original.isSymbolicLink()&&original.uid===process.getuid()&&(original.mode&511)===448);assert.equal(await fs.realpath(root),root);
 t.after(async()=>{const current=await fs.lstat(root);assert.equal(current.dev,original.dev);assert.equal(current.ino,original.ino);assert.equal(await fs.realpath(root),root);let entries=0,bytes=0;
  async function inspect(dir){for(const name of await fs.readdir(dir)){assert(++entries<=24);const p=path.join(dir,name),s=await fs.lstat(p);assert(!s.isSymbolicLink()&&s.uid===process.getuid());if(s.isDirectory())await inspect(p);else{assert(s.isFile()&&s.nlink===1);bytes+=s.size;assert(bytes<=65536);}}}
  await inspect(root);await fs.rm(root,{recursive:true,force:false});await assert.rejects(fs.lstat(root),{code:'ENOENT'});
 });return root;
}
test('actual owner file cleanup preserves sibling bytes and same-job replay rechecks physical absence',{timeout:10000},async t=>{
 const root=await owned(t),files=createFinflowBackupFileStore({root:path.join(root,'store')});
 for(const[fileToken,text]of [[A,'synthetic owner bytes'],[B,'synthetic sibling bytes']]){const bytes=Buffer.from(text);await files.write({fileToken,bytes,contentSha256:createHash('sha256').update(bytes).digest('hex')});}
 const sibling=await files.read(B),checked=[];let completeCalls=0;
 const repository={async beginOwnerDeletion(scope){assert.equal(scope.ownerId,41);assert.equal(scope.jobId,JOB);return{ownerId:41,jobId:JOB,status:completeCalls?'completed':'pending',fileTokens:[A],artifactCount:1,datasetCount:2};},async completeOwnerDeletion(scope){assert.deepEqual(scope.fileTokens,[A]);assert.equal(await files.absent(A),true);assert.equal(scope.ownerId,41);assert.equal(scope.jobId,JOB);completeCalls++;return{ownerId:41,jobId:JOB,status:'completed',fileTokens:[A],artifactCount:1,datasetCount:2,completedAt:'2026-09-14T00:00:00.000Z'};}};
 const cleanup=createFinflowOwnerResourceDeletion({repository,files:{remove:tokens=>files.remove(tokens),absent:async token=>{checked.push(token);return files.absent(token);}}});
 for(let i=0;i<2;i++){const receipt=await cleanup({subjectId:41,jobId:JOB,leaseToken:LEASE,check:async()=>{},signal:new AbortController().signal});assert(verifyFinflowOwnerDeletionReceipt(receipt,{ownerId:41,jobId:JOB}));assert.equal(await files.absent(A),true);assert.equal(await files.absent(B),false);assert.deepEqual(await files.read(B),sibling);}
 assert.equal(completeCalls,2);assert.deepEqual(checked,[A,A]);
});
