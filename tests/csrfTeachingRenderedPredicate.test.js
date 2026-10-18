'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {expandedHintContains}=require('./fixtures/csrfFullIndexBrowser');
test('expanded hint predicate rejects static description and requires every actual hint paragraph',()=>{
 const original=global.document;let hint=null;const expectedHints=['Please open the original email in my inbox.','Refusal earns no credit.'];
 global.document={body:{innerText:expectedHints.join('\n')},querySelectorAll:selector=>{assert.equal(selector,'.obj-content');return [{querySelector:selector=>{assert.equal(selector,'.obj-actions + div');return hint;}}];}};
 try{assert.equal(expandedHintContains({index:0,expectedHints}),false);hint={innerText:expectedHints[0]};assert.equal(expandedHintContains({index:0,expectedHints}),false);hint={innerText:expectedHints.join('\n\n')};assert.equal(expandedHintContains({index:0,expectedHints}),true);assert.equal(expandedHintContains({index:1,expectedHints}),false);}finally{if(original===undefined)delete global.document;else global.document=original;}
});
