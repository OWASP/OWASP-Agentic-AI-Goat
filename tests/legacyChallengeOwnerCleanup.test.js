'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createLegacyChallengeOwnerCleanup}=require('../server/services/legacyChallengeOwnerCleanup');

test('legacy upload cleanup removes only regular files in the managed root and forwards exact owner',async()=>{
 const root=path.resolve('/owned/uploads'),events=[];
 const cleanup=createLegacyChallengeOwnerCleanup({uploadRoot:root,
  store:{destroyOwner:async(owner,{removeFile})=>{events.push(['owner',owner]);assert.equal(await removeFile(path.join(root,'owned.txt')),true);assert.equal(await removeFile(path.join(root,'missing.txt')),false);return{removed:3,filesRemoved:1};}},
  fileSystem:{lstat:async file=>{if(file.endsWith('missing.txt'))throw Object.assign(Error('missing'),{code:'ENOENT'});return{isFile:()=>true,isSymbolicLink:()=>false};},unlink:async file=>events.push(['unlink',file])}});
 assert.deepEqual(await cleanup.destroyOwner('17'),{removed:3,filesRemoved:1});
 assert.deepEqual(events,[['owner','17'],['unlink',path.join(root,'owned.txt')]]);
});

test('legacy upload cleanup refuses traversal, symlinks, and non-regular leaves before unlink',async()=>{
 let unlinked=false;
 const make=stat=>createLegacyChallengeOwnerCleanup({uploadRoot:'/owned/uploads',store:{destroyOwner:(_owner,{removeFile})=>removeFile(stat.path)},
  fileSystem:{lstat:async()=>stat.value,unlink:async()=>{unlinked=true;}}});
 await assert.rejects(make({path:'/private/host',value:{isFile:()=>true,isSymbolicLink:()=>false}}).destroyOwner(1),/escaped/);
 await assert.rejects(make({path:'/owned/uploads/link',value:{isFile:()=>true,isSymbolicLink:()=>true}}).destroyOwner(1),/regular/);
 await assert.rejects(make({path:'/owned/uploads/fifo',value:{isFile:()=>false,isSymbolicLink:()=>false}}).destroyOwner(1),/regular/);
 assert.equal(unlinked,false);
});
