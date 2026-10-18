'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {prepareMailboxMessage}=require('../server/services/secureshopMailboxContent');
const base={from:'merchant@shop.invalid',to:'customer@shop.invalid',subject:'Order',body_markdown:'**Hello**'};
test('owned message content preserves raw HTML and stable hashes',()=>{
 const a=prepareMailboxMessage({...base,body_markdown:'<img src="http://owned-target/private" onerror="alert(1)">'},{mode:'vuln'});
 assert.match(a.bodyHtml,/onerror="alert\(1\)"/);assert.equal(a.bodyHtml,a.bodyMarkdown);assert.deepEqual(a.recipients,['customer@shop.invalid']);
 assert.equal(a.contentSha256,prepareMailboxMessage({body_markdown:a.bodyMarkdown,subject:base.subject,to:base.to,from:base.from},{mode:'vuln'}).contentSha256);
 assert.notEqual(a.contentSha256,prepareMailboxMessage(base,{mode:'vuln'}).contentSha256);
});
test('intentional header injection yields exact additional synthetic recipients',()=>{
 const a=prepareMailboxMessage({...base,subject:'Order\r\nBcc: attacker@shop.invalid'},{mode:'vuln'});
 assert.equal(a.headersRaw,'From: merchant@shop.invalid\r\nTo: customer@shop.invalid\r\nSubject: Order\r\nBcc: attacker@shop.invalid');
 assert.deepEqual(a.recipients,['customer@shop.invalid','attacker@shop.invalid']);
 assert.throws(()=>prepareMailboxMessage({...base,subject:'Order\r\nBcc: attacker@shop.invalid'},{mode:'fixed'}),/Header newlines/);
});
test('content contract rejects authority fields, bad mode and bounded resource excess',()=>{
 assert.throws(()=>prepareMailboxMessage({...base,launchId:'caller-selected'},{mode:'vuln'}));
 assert.throws(()=>prepareMailboxMessage(base,{mode:'legacy'}));
 assert.throws(()=>prepareMailboxMessage({...base,body_markdown:'x'.repeat(32769)},{mode:'vuln'}));
 assert.throws(()=>prepareMailboxMessage({...base,to:Array.from({length:17},(_,i)=>`user${i}@shop.invalid`).join(',')},{mode:'vuln'}));
 assert.throws(()=>prepareMailboxMessage({...base,to:'not an address'},{mode:'vuln'}));
});
test('fixed headers and empty body remain valid without synthesizing message text',()=>{
 const result=prepareMailboxMessage({...base,body_markdown:''},{mode:'fixed'});assert.equal(result.bodyHtml,'');assert.equal(result.bodyMarkdown,'');assert.deepEqual(result.recipients,[base.to]);
});

test('fixed message renders untrusted body as literal text without active HTML or links',()=>{const result=prepareMailboxMessage({...base,body_markdown:'<img onerror=alert(1)> [click](javascript:alert(1))'},{mode:'fixed'});assert.ok(result.bodyHtml.includes('&lt;img'));assert.ok(!result.bodyHtml.includes('<img'));assert.ok(!result.bodyHtml.includes('<a'));});
