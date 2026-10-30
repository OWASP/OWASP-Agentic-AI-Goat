'use strict';
// Controlled adapter and source-contract checks only. This suite never starts
// PowerShell, invokes native Windows APIs, or qualifies an installation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createWindowsPrivateState, normalizePrivatePath, MAX_FILE_BYTES, MAX_DELETE_BYTES } = require('../scripts/lib/windows-private-state');
const privateDirectory = 'C:\\Users\\learner\\private';
const privateFile = privateDirectory + '\\state.json';
const identity = { volumeSerial: 0xffffffff, fileId: '00112233aabbccdd' };
const denial = { code: 'WINDOWS_PRIVATE_STATE_DENIED', message: 'Windows private state operation denied.' };

function controlled(transform) {
  const calls = [];
  const adapter = createWindowsPrivateState({ platform: 'win32', systemRoot: 'C:\\Windows', execute(executable, args, options) {
    calls.push({ executable, args, options });
    const request = JSON.parse(options.input);
    const directory = /Directory$/.test(request.operation);
    const bytes = ['createPrivateFile', 'deleteMatchingPrivateFile'].includes(request.operation) ? Buffer.from(request.bytesBase64, 'base64') : Buffer.from('controlled state');
    const response = { version: 1, ok: true, operation: request.operation, path: request.path, size: directory ? null : bytes.length, identity: { ...identity } };
    if (['readPrivateFile', 'readPrivateWorkspaceFile', 'readAndFlushPrivateFile', 'readAndFlushPrivateWorkspaceFile'].includes(request.operation)) response.bytesBase64 = bytes.toString('base64');
    if (request.operation === 'deleteMatchingPrivateFile') response.deleted = true;
    return transform ? transform(response, request) : JSON.stringify(response);
  } });
  return { adapter, calls };
}

test('controlled executor binds each operation, exact response, immutable identity and pipe-only secret transport', () => {
  const { adapter, calls } = controlled();
  const directory = adapter.ensurePrivateDirectory(privateDirectory);
  assert.deepEqual(directory, { path: privateDirectory, size: null, identity });
  assert(Object.isFrozen(directory)); assert(Object.isFrozen(directory.identity));
  assert.deepEqual(adapter.inspectPrivateDirectory(privateDirectory), directory);
  assert.equal(adapter.readPrivateFile(privateFile).toString(), 'controlled state');
  const secret = Buffer.from('synthetic-secret-only');
  assert.equal(adapter.createPrivateFile(privateFile, secret).size, secret.length);
  for (const call of calls) {
    assert.equal(call.executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.deepEqual(call.args.slice(0, 5), ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', path.resolve(__dirname, '../scripts/windows/windows-private-state.ps1')]);
    assert.equal(call.args.length, 5);
    assert.deepEqual(call.options.stdio, ['pipe', 'pipe', 'pipe']);
    assert.equal(call.options.windowsHide, true); assert.equal(call.options.encoding, 'utf8');
    assert.equal(call.options.timeout, 30000); assert.equal(call.options.maxBuffer, 1500000);
    assert(!JSON.stringify(call.args).includes(secret.toString())); assert(!JSON.stringify(call.args).includes(secret.toString('base64')));
    assert.equal(Object.hasOwn(call.options, 'shell'), false);
  }
  assert.equal(JSON.parse(calls[3].options.input).bytesBase64, secret.toString('base64'));
});

test('drive paths normalize narrowly and reject every escape before executor allocation', () => {
  assert.equal(normalizePrivatePath('c:\\Users\\one\\literal $().json'), 'C:\\Users\\one\\literal $().json');
  const { adapter, calls } = controlled();
  const rejected = [null, {}, '', 'C:', 'C:\\', 'relative', '/tmp/private', 'C:/private', '\\\\host\\share\\private', '\\\\?\\C:\\private', '\\\\.\\C:\\private', 'C:\\private\\', 'C:\\private\\\\file', 'C:\\private\\..\\file', 'C:\\private\\.\\file', 'C:\\private\\file:secret', 'C:\\private\\file.', 'C:\\private\\file ', 'C:\\private\\CON', 'C:\\private\\aux.json', 'C:\\private\\NUL.txt', 'C:\\private\\LPT9.ini', 'C:\\private\\COM¹.log', 'C:\\private\\CONIN$', 'C:\\private\\CONOUT$', 'C:\\private\\CLOCK$', 'C:\\private\\wild*card', 'C:\\private\\question?', 'C:\\private\\nul\0', 'C:\\private\\line\n', 'C:\\private\\delete\x7f', 'C:\\' + 'a'.repeat(238)];
  for (const input of rejected) assert.throws(() => adapter.inspectPrivateDirectory(input), denial);
  assert.equal(calls.length, 0);
});

test('bounded create accepts zero and exact 1 MiB, rejecting oversized and ambiguous byte values', () => {
  const { adapter, calls } = controlled();
  assert.equal(adapter.createPrivateFile(privateFile, Buffer.alloc(0)).size, 0);
  assert.equal(adapter.createPrivateFile(privateFile, Buffer.alloc(MAX_FILE_BYTES)).size, MAX_FILE_BYTES);
  const allocated = calls.length;
  for (const bytes of [Buffer.alloc(MAX_FILE_BYTES + 1), 'secret', new Uint8Array(1), null]) assert.throws(() => adapter.createPrivateFile(privateFile, bytes), denial);
  assert.equal(calls.length, allocated);
});

test('non-Windows hosts and invalid Windows installation paths cannot silently fall back', () => {
  let calls = 0;
  for (const options of [{ platform: 'linux', systemRoot: 'C:\\Windows' }, { platform: 'win32' }, { platform: 'win32', systemRoot: 'C:\\Windows\\..\\other' }, { platform: 'win32', systemRoot: '\\\\host\\share' }]) {
    const adapter = createWindowsPrivateState({ ...options, execute() { calls++; return ''; } });
    assert.throws(() => adapter.ensurePrivateDirectory(privateDirectory), denial);
  }
  assert.equal(calls, 0);
});

test('controlled native denials and process failures discard all potentially sensitive diagnostics', () => {
  const secret = 'synthetic diagnostic secret';
  const failures = [() => JSON.stringify({ version: 1, ok: false, code: 'WINDOWS_PRIVATE_STATE_DENIED' }), () => { throw Object.assign(Error(secret), { stdout: secret, stderr: secret, output: [null, secret], cause: Error(secret) }); }, () => 'not json ' + secret, () => '', () => Buffer.from('{}'), () => ' '.repeat(1500001)];
  for (const transform of failures) {
    const { adapter } = controlled(transform);
    for (const action of [() => adapter.ensurePrivateDirectory(privateDirectory), () => adapter.inspectPrivateDirectory(privateDirectory), () => adapter.readPrivateFile(privateFile), () => adapter.readPrivateFileSnapshot(privateFile), () => adapter.readPrivateWorkspaceFile('C:\\workspace\\.env'), () => adapter.createPrivateFile(privateFile, Buffer.from(secret)), () => adapter.deleteMatchingPrivateFile(privateFile, Buffer.from(secret), identity)]) {
      assert.throws(action, error => {
        assert.equal(error.code, denial.code); assert.equal(error.message, denial.message);
        assert.deepEqual(Object.keys(error), ['code']); assert(!String(error.stack).includes(secret)); return true;
      });
    }
  }
});

test('response admission rejects mismatched operation/path, extra keys, size and identity confusion', () => {
  const mutations = [r => ({ ...r, version: 2 }), r => ({ ...r, ok: 1 }), r => ({ ...r, operation: 'createPrivateFile' }), r => ({ ...r, path: 'C:\\elsewhere\\state' }), r => ({ ...r, extra: 'unexpected' }), r => ({ ...r, size: -1 }), r => ({ ...r, size: MAX_FILE_BYTES + 1 }), r => ({ ...r, size: '16' }), r => ({ ...r, identity: { ...r.identity, extra: true } }), r => ({ ...r, identity: { volumeSerial: -1, fileId: r.identity.fileId } }), r => ({ ...r, identity: { volumeSerial: 0x100000000, fileId: r.identity.fileId } }), r => ({ ...r, identity: { volumeSerial: 1, fileId: 'BAD' } }), r => ({ ...r, identity: null })];
  for (const mutate of mutations) {
    const { adapter } = controlled(r => JSON.stringify(mutate(r)));
    assert.throws(() => adapter.readPrivateFile(privateFile), denial);
  }
  assert.throws(() => controlled(r => JSON.stringify({ ...r, size: 0 })).adapter.inspectPrivateDirectory(privateDirectory), denial);
  assert.throws(() => controlled(r => JSON.stringify({ ...r, size: r.size + 1 })).adapter.createPrivateFile(privateFile, Buffer.from('synthetic')), denial);
});

test('read admission rejects noncanonical, oversized, mismatched and missing encoded bytes', () => {
  for (const encoded of ['', 'Zg=', 'Zh==', ' Zg==', 'Zg==\n', {}, null, Buffer.alloc(MAX_FILE_BYTES + 1).toString('base64')]) {
    const { adapter } = controlled(r => JSON.stringify({ ...r, bytesBase64: encoded }));
    assert.throws(() => adapter.readPrivateFile(privateFile), denial);
  }
  const empty = controlled(r => JSON.stringify({ ...r, size: 0, bytesBase64: '' }));
  assert.equal(empty.adapter.readPrivateFile(privateFile).length, 0);
  const boundary = controlled(r => JSON.stringify({ ...r, size: MAX_FILE_BYTES, bytesBase64: Buffer.alloc(MAX_FILE_BYTES).toString('base64') }));
  assert.equal(boundary.adapter.readPrivateFile(privateFile).length, MAX_FILE_BYTES);
});

test('literal path metacharacters are transported as JSON rather than executable PowerShell text', () => {
  const { adapter, calls } = controlled();
  const literal = privateDirectory + '\\$(`tick`) ; literal.json';
  adapter.inspectPrivateDirectory(literal);
  assert.equal(JSON.parse(calls[0].options.input).path, literal);
  assert(!calls[0].args.some(arg => arg.includes('$(')));
});

test('native source pins creation-time protected DACL, handle inspection and conservative ancestor trust', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.cs'), 'utf8');
  for (const api of ['CreateFileW', 'CreateDirectoryW', 'GetSecurityInfo', 'GetFileInformationByHandle', 'GetFinalPathNameByHandleW', 'ConvertStringSecurityDescriptorToSecurityDescriptorW', 'ReadFile', 'WriteFile', 'FlushFileBuffers', 'LocalFree']) assert(source.includes(api), api);
  assert(source.includes('D:P(A;')); assert(source.includes('InheritHandle=false'));
  assert(source.includes('ref attributes,CreateNew')); assert(source.includes('CreateDirectoryW(path,ref attributes)'));
  assert(source.includes('security.Owner.Value == user')); assert(source.includes('ControlFlags.DiscretionaryAclProtected'));
  assert(source.includes('AceFlags.Inherited | AceFlags.InheritOnly')); assert(source.includes('ace.SecurityIdentifier.Value == user || ace.SecurityIdentifier.Value == SystemSid'));
  assert(source.includes('trusted.Contains(security.Owner.Value)')); assert(source.includes('Require(AncestorAclIsSafe(security,trusted))'));
  assert(source.includes('DangerousWrite = 0x000d0150'));
  assert(source.includes('rights & ~(prior | everyoneDenied)'));
  assert(source.includes('if ((ace.AceFlags & AceFlags.InheritOnly)!=0) continue'));
  assert(source.includes('operation=="ensurePrivateDirectory" && i==parents-1'));
  assert(source.includes('ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint | BackupSemantics'));
  assert(source.includes('(info.Attributes & ReparseAttribute) == 0')); assert(source.includes('info.Links == 1'));
  assert(source.includes('StringComparison.OrdinalIgnoreCase')); assert(source.includes('a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow'));
  assert(source.includes('info.SizeHigh == 0 && info.SizeLow <= MaxBytes'));
  assert(source.includes('String.Equals(filesystem.ToString(),"NTFS"'));
  assert(source.includes('new byte[(int)file.Before.SizeLow]')); assert(source.includes('new byte[1]'));
  assert(source.includes('file.Recheck(user,trusted)')); assert(source.includes('foreach (Opened item in chain) item.Recheck'));
  assert(source.includes('Equal(content,Read(reopened,user,trusted))'));
  assert(!/File\.ReadAllBytes|File\.WriteAllBytes|SetAccessControl|icacls|chmod|MoveFile|ReplaceFile|CreateHardLink/.test(source));
});

test('PowerShell helper bounds stdin and stdout, has fixed failure DTO, and avoids dynamic interpretation', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.ps1'), 'utf8');
  assert(source.includes('$limit = 1500000')); assert(source.includes('[Console]::In.Read('));
  assert(source.includes('GetByteCount($wire) -gt $limit')); assert(source.includes('GetByteCount($json) -gt $limit'));
  assert(source.includes("Add-Type -Path (Join-Path $PSScriptRoot 'windows-private-state.cs')"));
  assert(source.includes('[OwaspAiGoat.WindowsPrivateState]::Invoke('));
  assert(source.includes('"code":"WINDOWS_PRIVATE_STATE_DENIED"')); assert(source.includes('exit 1'));
  assert(!/Invoke-Expression|Write-Error|Write-Host|Write-Verbose|Out-File|\.ReadToEnd\(|-Command/.test(source));
  assert(source.includes('same identity')); assert(!source.includes('Set-Acl'));
});

// Source-contract assertion only: no native Windows call is executed here.
test('native creation requests documented GENERIC_WRITE before FlushFileBuffers', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.cs'), 'utf8');
  assert(source.includes('GenericWrite = 0x40000000'));
  assert(source.includes('CreatePrivateFileW(path,ReadControl|ReadAttributes|ReadData|GenericWrite,0,ref attributes,CreateNew,OpenReparsePoint,IntPtr.Zero)'));
  assert(!source.includes('ReadData|WriteData,0,ref attributes'));
  const createStart = source.indexOf('static Opened CreateFile(');
  const createEnd = source.indexOf('static byte[] Read(', createStart);
  const create = source.slice(createStart, createEnd);
  assert(create.indexOf('ReadData|GenericWrite') < create.indexOf('FlushFileBuffers(created.Handle)'));
  assert(create.includes('CreationDescriptor(user,false)'));
  assert(create.includes('Equal(content,Read(reopened,user,trusted))'));
});

test('workspace reader binds its separate operation and returns bounded bytes solely over the native protocol',()=>{
 const {adapter,calls}=controlled(),workspaceFile='c:\\workspace\\.env';
 assert.equal(adapter.readPrivateWorkspaceFile(workspaceFile).toString(),'controlled state');
 assert.deepEqual(JSON.parse(calls[0].options.input),{version:1,operation:'readPrivateWorkspaceFile',path:'C:\\workspace\\.env'});
 for(const size of [0,MAX_FILE_BYTES]){
  const value=controlled(r=>JSON.stringify({...r,size,bytesBase64:Buffer.alloc(size,9).toString('base64')}));
  assert.equal(value.adapter.readPrivateWorkspaceFile('C:\\workspace\\.env').length,size);
 }
 const {adapter:unsafe,calls:attempts}=controlled();
 for(const file of ['\\\\host\\share\\.env','C:\\workspace\\..\\.env','C:\\workspace\\.env:stream','C:\\workspace\\.env.'])assert.throws(()=>unsafe.readPrivateWorkspaceFile(file),denial);
 assert.equal(attempts.length,0);
});

test('workspace reader refuses ordinary-reader response substitution, unbounded and malformed payloads',()=>{
 for(const mutate of [r=>({...r,operation:'readPrivateFile'}),r=>({...r,path:'C:\\other\\.env'}),r=>({...r,size:MAX_FILE_BYTES+1}),r=>({...r,bytesBase64:'Zh=='}),r=>({...r,bytesBase64:null}),r=>({...r,identity:{volumeSerial:1,fileId:'bad'}}),r=>{const {bytesBase64,...other}=r;return other;},r=>({...r,secret:'unexpected'})]){
  assert.throws(()=>controlled(r=>JSON.stringify(mutate(r))).adapter.readPrivateWorkspaceFile('C:\\workspace\\.env'),denial);
 }
 const noPlatform=createWindowsPrivateState({platform:'linux',systemRoot:'C:\\Windows',execute(){throw Error('must not invoke');}});
 assert.throws(()=>noPlatform.readPrivateWorkspaceFile('C:\\workspace\\.env'),denial);
});

test('workspace native read changes only ancestor privacy selection and retains the same held private leaf checks',()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../scripts/windows/windows-private-state.cs'),'utf8');
 const publication=fs.readFileSync(path.resolve(__dirname,'../scripts/windows/windows-private-publication.cs'),'utf8');
 assert(source.includes('bool workspaceFile=operation=="readPrivateWorkspaceFile"'));
 assert(source.includes('bool reading=operation=="readPrivateFile" || workspaceFile'));
 assert(source.includes('chain.Add(Open(cursor,true,!workspaceFile && !workspaceDirectory && i==parents-1,user,trusted))'));
 assert(source.includes('operation=="ensurePrivateDirectory" && i==parents-1'));
 assert(source.includes('Open(path,false,true,user,trusted); chain.Add(leaf)'));
 assert(source.includes('byte[] readBytes=reading ? Read(leaf,user,trusted) : null'));
 assert(source.includes('foreach (Opened item in chain) item.Recheck(user,trusted)'));
 assert(source.includes('Require(Equal(Acl, Security(Handle, Private, Directory, user, trusted)))'));
 assert(source.includes('Require(info.Links == 1 && info.SizeHigh == 0 && info.SizeLow <= MaxBytes)'));
 // Both native implementations evaluate the same mutating ancestor mask and
 // conservative ACE-order deny coverage. These are source checks, not ACL execution.
 assert(source.includes('DangerousWrite = 0x000d0150'));assert(publication.includes('DangerousWrite=0xd0150'));
 assert(source.includes('rights & ~(prior | everyoneDenied)'));assert(publication.includes('rights&~(prior|everyoneDenied)'));
 assert(source.includes('if ((ace.AceFlags & AceFlags.InheritOnly)!=0) continue'));assert(publication.includes('if((ace.AceFlags&AceFlags.InheritOnly)!=0)continue'));
 assert(source.includes('trusted.Contains(security.Owner.Value)'));assert(publication.includes('trusted.Contains(security.Owner.Value)'));
 for(const [flag,mask] of [[0x40000000,0x120116],[0x80000000,0x120089],[0x20000000,0x1200a0]]){
  for(const native of [source,publication]){
   const mappings=[...native.matchAll(/if\s*\(\(mask\s*&\s*(0x[0-9a-f]+)\)\s*!=\s*0\)\s*mask\s*\|=\s*(0x[0-9a-f]+)/gi)].map(match=>match.slice(1).map(value=>Number(value)));
   assert(mappings.some(([generic,expanded])=>generic===flag&&expanded===mask));
  }
 }
 const powershell=fs.readFileSync(path.resolve(__dirname,'../scripts/windows/windows-private-state.ps1'),'utf8');
 assert(powershell.includes("'readPrivateFile', 'readPrivateWorkspaceFile', 'createPrivateFile'"));
});

test('snapshot binds bytes and native identity from one read and isolates every returned byte copy', () => {
  const { adapter, calls } = controlled();
  const snapshot = adapter.readPrivateFileSnapshot(privateFile);
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].options.input), { version: 1, operation: 'readPrivateFile', path: privateFile });
  assert(Object.isFrozen(snapshot)); assert(Object.isFrozen(snapshot.identity));
  assert.deepEqual(snapshot.identity, identity); assert.equal(snapshot.path, privateFile);
  assert.equal(snapshot.size, Buffer.byteLength('controlled state'));
  const first = snapshot.bytes, second = snapshot.bytes;
  assert.notEqual(first, second); assert.equal(first.toString(), 'controlled state');
  first.fill(0); second[0] = 0;
  assert.equal(snapshot.bytes.toString(), 'controlled state');
  assert.throws(() => { snapshot.bytes = Buffer.from('replacement'); }, TypeError);
  assert.throws(() => { snapshot.identity.fileId = 'ffffffffffffffff'; }, TypeError);
  assert.equal(adapter.readPrivateFile(privateFile).toString(), 'controlled state');
});

test('matching-delete transports exact bounded bytes and identity only in stdin, acknowledging immutable metadata', () => {
  const { adapter, calls } = controlled();
  for (const length of [0, MAX_DELETE_BYTES]) {
    const bytes = Buffer.alloc(length, 9), result = adapter.deleteMatchingPrivateFile(privateFile, bytes, identity);
    assert.deepEqual(result, { path: privateFile, size: length, identity, deleted: true });
    assert(Object.isFrozen(result)); assert(Object.isFrozen(result.identity));
    const call = calls[calls.length - 1];
    assert.deepEqual(JSON.parse(call.options.input), { version: 1, operation: 'deleteMatchingPrivateFile',
      path: privateFile, bytesBase64: bytes.toString('base64'), expectedIdentity: identity });
    assert.equal(call.args.length, 5); assert(!call.args.includes(bytes.toString('base64')));
    assert.deepEqual(call.options.stdio, ['pipe', 'pipe', 'pipe']);
  }
});

test('matching-delete denies unbounded bytes, ambiguous identities and unsafe paths before native invocation', () => {
  const { adapter, calls } = controlled();
  for (const bytes of [Buffer.alloc(MAX_DELETE_BYTES + 1), 'state', new Uint8Array(1), null]) {
    assert.throws(() => adapter.deleteMatchingPrivateFile(privateFile, bytes, identity), denial);
  }
  for (const expected of [null, {}, { ...identity, extra: true }, { ...identity, volumeSerial: -1 },
    { ...identity, volumeSerial: 0x100000000 }, { ...identity, volumeSerial: 1.5 }, { ...identity, volumeSerial: '1' },
    { ...identity, fileId: '00112233AABBCCDD' }, { ...identity, fileId: ['00112233aabbccdd'] },
    { ...identity, fileId: 'bad' }]) assert.throws(() => adapter.deleteMatchingPrivateFile(privateFile, Buffer.from('state'), expected), denial);
  for (const unsafe of ['C:\\private\\..\\state.json', 'C:\\private\\state.json:stream', '\\\\host\\share\\state.json']) {
    assert.throws(() => adapter.deleteMatchingPrivateFile(unsafe, Buffer.from('state'), identity), denial);
  }
  assert.equal(calls.length, 0);
});

test('matching-delete native denial and mismatched acknowledgments never trigger a fallback operation', () => {
  const bytes = Buffer.from('state');
  for (const transform of [r => JSON.stringify({ ...r, deleted: false }), r => JSON.stringify({ ...r, deleted: 1 }),
    r => { const { deleted, ...rest } = r; return JSON.stringify(rest); },
    r => JSON.stringify({ ...r, identity: { ...identity, volumeSerial: 1 } }),
    r => JSON.stringify({ ...r, identity: { ...identity, fileId: 'ffffffffffffffff' } }),
    r => JSON.stringify({ ...r, size: r.size + 1 }), r => JSON.stringify({ ...r, operation: 'createPrivateFile' }),
    r => JSON.stringify({ ...r, bytesBase64: bytes.toString('base64') }),
    () => JSON.stringify({ version: 1, ok: false, code: 'WINDOWS_PRIVATE_STATE_DENIED' }),
    () => { throw Error('synthetic private native diagnostic'); }]) {
    const { adapter, calls } = controlled(transform);
    assert.throws(() => adapter.deleteMatchingPrivateFile(privateFile, bytes, identity), denial);
    assert.equal(calls.length, 1); assert.equal(JSON.parse(calls[0].options.input).operation, 'deleteMatchingPrivateFile');
  }
});

test('matching-delete source pins exclusive handle admission and identity/bytes/ACL checks before disposition', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.cs'), 'utf8');
  const deletion = source.slice(source.indexOf('static Opened OpenForDeletion('), source.indexOf('static IntPtr CreationDescriptor('));
  assert.match(deletion, /CreateFileW\(path,ReadControl\|ReadAttributes\|ReadData\|DeleteAccess,0,IntPtr.Zero,OpenExisting,OpenReparsePoint,IntPtr.Zero\)/);
  assert.match(deletion, /new Opened\(handle,path,false,true,user,trusted\)/);
  assert.match(source, /DeleteAccess = 0x00010000/); assert.match(source, /MaxDeleteBytes = 4096/);
  assert.match(source, /struct FileDisposition \{ public byte DeleteFile; \}/);
  const native = source.slice(source.indexOf('public static Dictionary<string,object> Invoke('));
  const identityCheck = native.indexOf('leaf.Before.VolumeSerial==expectedVolumeSerial');
  const sizeCheck = native.indexOf('leaf.Before.SizeLow==content.Length && leaf.Before.SizeLow<=MaxDeleteBytes');
  const bytesCheck = native.indexOf('Equal(content,Read(leaf,user,trusted))');
  const chainCheck = native.indexOf('foreach (Opened item in chain) item.Recheck(user,trusted)');
  const disposeCheck = native.indexOf('SetFileInformationByHandle(leaf.Handle,4,ref disposition');
  assert(identityCheck > 0 && sizeCheck > identityCheck && bytesCheck > sizeCheck && chainCheck > bytesCheck && disposeCheck > chainCheck);
  assert.match(native, /leaf.Before.IndexHigh.ToString\("x8"\)\+leaf.Before.IndexLow.ToString\("x8"\)==expectedFileId/);
  assert.match(native, /finally \{ for \(int i=chain.Count-1;i>=0;i--\) chain\[i\]\.Dispose\(\); \}/);
  assert.match(native, /chain.Add\(Open\(cursor,true,!workspaceFile && !workspaceDirectory && i==parents-1,user,trusted\)\)/);
  assert.match(source, /Require\(info.Links == 1/); assert.match(source, /\(info.Attributes & ReparseAttribute\) == 0/);
  assert.doesNotMatch(source.replace(/\/\/.*$/gm, ''), /File\.Delete|DeleteFileW\(|DeleteFileA\(|FILE_FLAG_DELETE_ON_CLOSE|0x04000000|Remove-Item|unlink|MoveFile|ReplaceFile/);
  const helper = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.ps1'), 'utf8');
  assert.match(helper, /'bytesBase64', 'expectedIdentity', 'operation', 'path', 'version'/);
  assert.match(helper, /identityKeys -join ','\) -cne 'fileId,volumeSerial'/);
  assert.match(helper, /volumeSerial -isnot \[int\].*volumeSerial -isnot \[long\]/);
  assert.match(helper, /bytesBase64.Length -gt 5464/);
  assert.match(helper, /\[uint32\]\$request.expectedIdentity.volumeSerial/);
});

test('workspace directory inspection returns immutable null-size metadata bound to its exact normalized path',()=>{
 const {adapter,calls}=controlled(),input='c:\\Users\\learner\\workspace';
 const first=adapter.inspectWorkspaceDirectory(input),second=adapter.inspectWorkspaceDirectory(input);
 assert.deepEqual(first,{path:'C:\\Users\\learner\\workspace',size:null,identity});assert.deepEqual(first,second);assert(Object.isFrozen(first));assert(Object.isFrozen(first.identity));
 assert.deepEqual(JSON.parse(calls[0].options.input),{version:1,operation:'inspectWorkspaceDirectory',path:'C:\\Users\\learner\\workspace'});
 assert.equal(calls[0].args.length,5);assert.deepEqual(calls[0].options.stdio,['pipe','pipe','pipe']);
});

test('workspace directory inspection rejects drive roots, unsafe paths and non-Windows execution before invocation',()=>{
 const {adapter,calls}=controlled();for(const input of ['C:\\','\\\\host\\share\\workspace','C:\\Users\\learner\\..\\workspace','C:\\Users\\workspace:stream','C:\\Users\\workspace.','C:\\Users\\NUL'])assert.throws(()=>adapter.inspectWorkspaceDirectory(input),denial);
 assert.equal(calls.length,0);
 const unavailable=createWindowsPrivateState({platform:'linux',systemRoot:'C:\\Windows',execute(){throw Error('must not call');}});assert.throws(()=>unavailable.inspectWorkspaceDirectory('C:\\workspace'),denial);
});

test('workspace directory inspection denies substituted metadata, native failures and unexpected payload authority',()=>{
 for(const mutate of [r=>({...r,size:0}),r=>({...r,operation:'inspectPrivateDirectory'}),r=>({...r,path:'C:\\other'}),r=>({...r,bytesBase64:'c2VjcmV0'}),r=>({...r,deleted:true}),r=>({...r,identity:{volumeSerial:1,fileId:'bad'}}),()=>({version:1,ok:false,code:'WINDOWS_PRIVATE_STATE_DENIED'})]){
  const {adapter,calls}=controlled(r=>JSON.stringify(mutate(r)));assert.throws(()=>adapter.inspectWorkspaceDirectory('C:\\workspace'),denial);assert.equal(calls.length,1);
 }
 const failed=controlled(()=>{throw Object.assign(Error('synthetic workspace secret'),{stderr:'synthetic workspace secret',code:'ENOENT'});});assert.throws(()=>failed.adapter.inspectWorkspaceDirectory('C:\\workspace'),e=>e.code===denial.code&&!String(e.stack).includes('synthetic workspace secret'));assert.equal(failed.calls.length,1);
});

test('workspace native inspection requires current target owner and safe ACL under held read-only handles without private-DACL changes',()=>{
 const source=fs.readFileSync(path.resolve(__dirname,'../scripts/windows/windows-private-state.cs'),'utf8');
 const invoke=source.slice(source.indexOf('public static Dictionary<string,object> Invoke('));
 assert(invoke.includes('bool workspaceDirectory=operation=="inspectWorkspaceDirectory"'));
 assert(invoke.includes('bool directory=operation=="ensurePrivateDirectory" || operation=="inspectPrivateDirectory" || workspaceDirectory'));
 assert(invoke.includes('Open(cursor,true,!workspaceFile && !workspaceDirectory && i==parents-1,user,trusted)'));
 const owned=invoke.indexOf('if(workspaceDirectory)Require(new RawSecurityDescriptor(leaf.Acl,0).Owner.Value==user)'),recheck=invoke.indexOf('foreach (Opened item in chain) item.Recheck(user,trusted)');assert(owned>0&&recheck>owned);
 assert(invoke.includes('if (operation=="ensurePrivateDirectory" && i==parents-1) CreateDirectory(cursor,user)'));
 assert(source.includes('Require(AncestorAclIsSafe(security,trusted))'));assert(source.includes('DangerousWrite = 0x000d0150'));
 assert(source.includes('ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint | BackupSemantics'));
 assert(source.includes('Same(Before, Information(Handle, Path, Directory), Directory)'));assert(source.includes('Require(Equal(Acl, Security(Handle, Private, Directory, user, trusted)))'));
 assert(source.includes('(info.Attributes & ReparseAttribute) == 0'));assert(source.includes('String.Equals(filesystem.ToString(),"NTFS"'));
 const powershell=fs.readFileSync(path.resolve(__dirname,'../scripts/windows/windows-private-state.ps1'),'utf8');assert(powershell.includes("'inspectPrivateDirectory', 'inspectWorkspaceDirectory', 'readPrivateFile'"));
});

const flushedReads = ['readAndFlushPrivateFile', 'readAndFlushPrivateWorkspaceFile'];
test('held read-and-flush APIs bind distinct operations and bounded private bytes through stdin/stdout', () => {
  for (const operation of flushedReads) {
    const file = operation === 'readAndFlushPrivateFile' ? privateFile : 'C:\\workspace\\.env';
    for (const size of [0, 16, MAX_FILE_BYTES]) {
      const bytes = Buffer.alloc(size, 9), { adapter, calls } = controlled(r => JSON.stringify({ ...r, size, bytesBase64: bytes.toString('base64') }));
      assert.deepEqual(adapter[operation](file), bytes);
      assert.equal(calls.length, 1);
      assert.deepEqual(JSON.parse(calls[0].options.input), { version: 1, operation, path: file });
      assert.equal(calls[0].args.length, 5); assert.deepEqual(calls[0].options.stdio, ['pipe', 'pipe', 'pipe']);
      assert(!calls[0].args.includes(bytes.toString('base64')));
    }
  }
});

test('read-and-flush APIs reject unsafe paths and unavailable platforms before native allocation', () => {
  for (const operation of flushedReads) {
    const { adapter, calls } = controlled();
    for (const file of ['C:\\', '\\\\host\\share\\state', 'C:\\workspace\\..\\state', 'C:\\workspace\\state:stream', 'C:\\workspace\\state.', 'C:\\workspace\\CON']) assert.throws(() => adapter[operation](file), denial);
    assert.equal(calls.length, 0);
    const unavailable = createWindowsPrivateState({ platform: 'linux', systemRoot: 'C:\\Windows', execute() { throw Error('must not invoke'); } });
    assert.throws(() => unavailable[operation](privateFile), denial);
  }
});

test('read-and-flush requires its exact acknowledgment and rejects read-only substitution or malformed bytes', () => {
  for (const operation of flushedReads) {
    for (const mutate of [r => ({ ...r, operation: 'readPrivateFile' }), r => ({ ...r, operation: 'readPrivateWorkspaceFile' }),
      r => ({ ...r, operation: operation === flushedReads[0] ? flushedReads[1] : flushedReads[0] }),
      r => ({ ...r, path: 'C:\\elsewhere\\state' }), r => ({ ...r, size: MAX_FILE_BYTES + 1 }),
      r => ({ ...r, size: r.size + 1 }), r => ({ ...r, bytesBase64: 'Zh==' }),
      r => ({ ...r, bytesBase64: Buffer.alloc(MAX_FILE_BYTES + 1).toString('base64') }),
      r => { const { bytesBase64, ...rest } = r; return rest; },
      r => ({ ...r, identity: { volumeSerial: 1, fileId: 'invalid' } }), r => ({ ...r, flushed: true })]) {
      const { adapter, calls } = controlled(r => JSON.stringify(mutate(r)));
      assert.throws(() => adapter[operation](privateFile), denial); assert.equal(calls.length, 1);
    }
  }
});

test('read-and-flush failure returns no bytes, scrubs diagnostics and never falls back to an ordinary read', () => {
  const secret = 'synthetic flush diagnostic';
  for (const operation of flushedReads) {
    for (const failure of [() => JSON.stringify({ version: 1, ok: false, code: 'WINDOWS_PRIVATE_STATE_DENIED' }),
      () => { throw Object.assign(Error(secret), { code: 'ENOENT', stderr: secret, stdout: secret, cause: Error(secret) }); }]) {
      const { adapter, calls } = controlled(failure);
      assert.throws(() => adapter[operation](privateFile), error => {
        assert.equal(error.code, denial.code); assert.equal(error.message, denial.message);
        assert.deepEqual(Object.keys(error), ['code']); assert(!String(error.stack).includes(secret)); return true;
      });
      assert.equal(calls.length, 1); assert.equal(JSON.parse(calls[0].options.input).operation, operation);
    }
  }
});

// Static native contract only: these controls do not execute FlushFileBuffers.
test('native read-and-flush keeps exact existing private leaf held through bounded read, flush and final checks', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.cs'), 'utf8');
  const opener = source.slice(source.indexOf('static Opened OpenForReadAndFlush('), source.indexOf('static IntPtr CreationDescriptor('));
  assert(opener.includes('CreateFileW(path,ReadControl|ReadAttributes|ReadData|GenericWrite,ShareRead,IntPtr.Zero,OpenExisting,OpenReparsePoint,IntPtr.Zero)'));
  assert(opener.includes('new Opened(handle,path,false,true,user,trusted)'));
  assert.doesNotMatch(opener.replace(/\/\/.*$/gm, ''), /WriteFile|CreateNew|CreateDirectory|DeleteAccess|ShareWrite|ShareDelete/);
  const ordinary = source.slice(source.indexOf('static Opened Open('), source.indexOf('static Opened OpenForDeletion('));
  assert.doesNotMatch(ordinary.replace(/\/\/.*$/gm, ''), /GenericWrite|FlushFileBuffers/);
  const invoke = source.slice(source.indexOf('public static Dictionary<string,object> Invoke('));
  assert(invoke.includes('bool flushing=operation=="readAndFlushPrivateFile" || operation=="readAndFlushPrivateWorkspaceFile"'));
  assert(invoke.includes('bool workspaceFile=operation=="readPrivateWorkspaceFile" || operation=="readAndFlushPrivateWorkspaceFile"'));
  assert(invoke.includes('flushing ? OpenForReadAndFlush(path,user,trusted) : Open(path,false,true,user,trusted)'));
  assert(invoke.includes('chain.Add(Open(cursor,true,!workspaceFile && !workspaceDirectory && i==parents-1,user,trusted))'));
  const read = invoke.indexOf('byte[] readBytes=reading ? Read(leaf,user,trusted) : null');
  const flush = invoke.indexOf('if (flushing) Require(FlushFileBuffers(leaf.Handle))');
  const checked = invoke.indexOf('foreach (Opened item in chain) item.Recheck(user,trusted)');
  const result = invoke.indexOf('if (readBytes!=null) result.Add("bytesBase64"');
  assert(read > 0 && flush > read && checked > flush && result > checked);
  const boundedRead = source.slice(source.indexOf('static byte[] Read('), source.indexOf('public static Dictionary<string,object> Invoke('));
  assert(boundedRead.includes('new byte[(int)file.Before.SizeLow]')); assert(boundedRead.includes('new byte[1]'));
  assert(boundedRead.includes('read==bytes.Length')); assert(boundedRead.includes('read==0')); assert(boundedRead.includes('file.Recheck(user,trusted)'));
  const helper = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-state.ps1'), 'utf8');
  assert(helper.includes("'readAndFlushPrivateFile', 'readAndFlushPrivateWorkspaceFile'"));
  assert(helper.includes("$expected = @('operation', 'path', 'version')"));
});

test('read-and-flush snapshot binds flushed bytes and identity in one operation and clones byte access', () => {
  const { adapter, calls } = controlled();
  const snapshot = adapter.readAndFlushPrivateFileSnapshot(privateFile);
  assert(Object.isFrozen(snapshot)); assert(Object.isFrozen(snapshot.identity));
  assert.deepEqual(snapshot.identity, identity); assert.equal(snapshot.path, privateFile);
  assert.equal(snapshot.size, Buffer.byteLength('controlled state'));
  const first = snapshot.bytes; first.fill(0);
  assert.equal(snapshot.bytes.toString(), 'controlled state');
  assert.deepEqual(JSON.parse(calls[0].options.input), { version: 1, operation: 'readAndFlushPrivateFile', path: privateFile });
  assert.equal(calls.length, 1);
  assert.throws(() => controlled(() => { throw Error('synthetic flush secret'); }).adapter.readAndFlushPrivateFileSnapshot(privateFile), denial);
});
