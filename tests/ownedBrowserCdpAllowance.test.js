'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{EventEmitter}=require('node:events');
const {install}=require('./fixtures/ownedBrowserCdpAllowance');
test('only exact executable and owned profile learn one CDP endpoint, revoked on exact exit',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'owned-cdp-')),browser=path.join(dir,'browser'),profile=path.join(dir,'profile');fs.writeFileSync(browser,'fixture');fs.mkdirSync(profile);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const endpoints=[],children=[],cp={spawn:()=>{const c=new EventEmitter();c.pid=123+children.length;c.stderr=new EventEmitter();children.push(c);return c;}};
 const restore=install({browserExecutable:browser,ownedRoot:dir,childProcess:cp,addEndpoint:e=>endpoints.push(e),removeEndpoint:e=>endpoints.splice(endpoints.indexOf(e),1)});t.after(restore);
 const line='DevTools listening on ws://127.0.0.1:45000/devtools/browser/12345678-1234-1234-1234-123456789abc\n';
 cp.spawn('/other',[`--user-data-dir=${profile}`]).stderr.emit('data',line);assert.equal(endpoints.length,0);
 cp.spawn(browser,[`--user-data-dir=${os.tmpdir()}`]).stderr.emit('data',line);assert.equal(endpoints.length,0);
 const c=cp.spawn(browser,[`--user-data-dir=${profile}`]);c.stderr.emit('data',line.replace('127.0.0.1','example.invalid'));assert.equal(endpoints.length,0);c.stderr.emit('data',line);assert.equal(endpoints.length,1);c.emit('exit');assert.equal(endpoints.length,0);c.stderr.emit('data',line);assert.equal(endpoints.length,0);
});
