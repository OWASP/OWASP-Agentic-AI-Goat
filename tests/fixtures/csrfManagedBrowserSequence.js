'use strict';
function createSequence(limit=1){
 if(![1,2].includes(limit))throw TypeError('Owned browser limit must be one or two');
 let used=0,active=false;
 return Object.freeze({reserve(){if(active)throw Error('Owned browser still active');if(used>=limit)throw Error('Owned browser launch budget exhausted');active=true;const index=++used;let released=false;return Object.freeze({index,release(){if(released)throw Error('Owned browser lease already released');released=true;active=false;}});}});
}
module.exports={createSequence};
