'use strict';
const assert=require('node:assert/strict');
function captureSibling({http,persisted,expectedTab='get'}){
 assert.ok(['get','post','xss','indirect'].includes(expectedTab),'Expected sibling tab must be fixture configuration');
 assert.equal(http?.status,200);assert.equal(http.body?.success,true);assert.equal(http.body.state?.tab,expectedTab);assert.equal(typeof http.body.state.profile?.email,'string');
 // Reading the default PostgreSQL sandbox need not flush a row. Preserve its
 // absence rather than manufacturing a sibling mutation to satisfy the fixture.
 return structuredClone({effective:http.body.state,persisted});
}
function assertSiblingUnchanged(before,options){assert.deepEqual(captureSibling(options),before);}
module.exports={captureSibling,assertSiblingUnchanged};
