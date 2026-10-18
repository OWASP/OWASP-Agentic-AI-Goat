'use strict';
const {withCtfTransaction}=require('../database/postgres/ctfLifecycleRepository');
const {projectCtfDeletion}=require('../database/postgres/ctfDeletionProjectionAdapter');
function createCtfDeletionService({identity,ctfPool}){if(typeof identity?.admit!=='function'||typeof identity?.acknowledge!=='function'||typeof ctfPool?.connect!=='function')throw TypeError('CTF deletion dependencies required');return async scope=>{
 if(typeof scope?.check!=='function')throw TypeError('Canonical deletion lease check required');
 scope.signal?.throwIfAborted();await scope.check();
 const event=await identity.admit(scope,{signal:scope.signal});
 // Admission is durable. A later lease loss does not undo the command; only
 // exact same command replay can recover an uncertain CTF commit.
 scope.signal?.throwIfAborted();await scope.check();
 const receipt=await withCtfTransaction(ctfPool,c=>projectCtfDeletion(c,event),{signal:scope.signal});
 scope.signal?.throwIfAborted();await scope.check();
 return identity.acknowledge(scope,event,receipt,{signal:scope.signal});
};}
module.exports={createCtfDeletionService};
