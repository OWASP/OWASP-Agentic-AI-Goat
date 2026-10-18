'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{execFileSync}=require('node:child_process');
const {isolatedRuntimePath}=require('../scripts/lib/isolated-runtime-path');
test('POSIX pinned Node does not shadow separately selected npm', {skip:process.platform==='win32'}, t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'isolated-runtime-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const selected=path.join(root,'selected');fs.mkdirSync(selected);
 fs.writeFileSync(path.join(selected,'npm'),'#!/bin/sh\nprintf "selected-npm"\n',{mode:0o700});
 fs.writeFileSync(path.join(selected,'node'),'#!/bin/sh\nexit 99\n',{mode:0o700});
 const PATH=isolatedRuntimePath(root,selected+path.delimiter+path.dirname(process.execPath));
 assert.equal(execFileSync('/bin/sh',['-c','npm --version'],{env:{PATH},encoding:'utf8'}),'selected-npm');
 assert.equal(execFileSync('/bin/sh',['-c','node -p process.execPath'],{env:{PATH},encoding:'utf8'}).trim(),fs.realpathSync(process.execPath));
 assert.deepEqual(fs.readdirSync(path.join(root,'.isolated-runtime-bin')),['node']);
});
