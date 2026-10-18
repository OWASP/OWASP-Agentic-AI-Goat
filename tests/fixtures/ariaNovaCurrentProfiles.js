'use strict';
const assert=require('node:assert/strict');
const definitions={
 current:{cases:['aria_boundary_error','aria_boundary_success','nova_operator','nova_literal_negative'],chats:[16,8,8,0],generate:36,chat:32,external:69,deadlineMs:600000},
 'aria-remaining':{cases:[1,2,4,5,6,7,8,9,10].map(n=>`sqli_${n}`),chats:[8,8,16,8,8,8,16,16,8],generate:81,chat:96,external:178,deadlineMs:1260000},
 'nova-remaining':{cases:[1,3,4,5,6,7,8,9,10].map(n=>`nosqli_${n}`),chats:[8,8,8,8,8,8,8,16,16],generate:81,chat:88,external:170,deadlineMs:1260000},
};
for(const value of Object.values(definitions)){Object.freeze(value.cases);Object.freeze(value.chats);Object.freeze(value);}
function profileFor(name='current'){assert(Object.hasOwn(definitions,name),'Closed ARIA/NOVA profile');return definitions[name];}
module.exports={profileFor};
