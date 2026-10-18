'use strict';
// Controlled executor/protocol fixtures plus static native-source contracts.
// No PowerShell, native Windows APIs, filesystem, database or installer runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createWindowsPrivatePublication, MAX_FILE_BYTES } = require('../scripts/lib/windows-private-publication');
const targetPath = 'C:\\workspace\\.env';
const intentPath = 'C:\\Users\\learner\\private\\publication.json';
const operationId = '11111111-2222-4333-8444-555555555555';
const base = { targetPath, intentPath, operationId };
const stagePath = `${targetPath}.dvaia-${operationId}.stage`;
const denied = { code: 'WINDOWS_PRIVATE_PUBLICATION_DENIED', message: 'Windows private publication denied.' };
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const clone = value => JSON.parse(JSON.stringify(value));

// Explicit test double of the protocol's retained states. These cases exercise
// the JS adapter's native boundary and recovery requests, not the C# algorithm.
function controlled(initial) {
  const files = new Map(); const calls = []; let sequence = 1; let fault = null; let locked = false;
  const file = bytes => ({ bytes: Buffer.from(bytes), identity: { volumeSerial: 19, fileId: (++sequence).toString(16).padStart(16, '0') } });
  if (initial !== null) files.set(targetPath, file(initial));
  const read = name => files.get(name);
  const writeNew = (name, bytes) => { if (files.has(name)) throw Error('controlled exclusive collision'); const item = file(bytes); files.set(name, item); return item; };
  const same = (item, record) => Boolean(item && record && item.bytes.length === record.size && hash(item.bytes) === record.sha256 && item.identity.fileId === record.identity.fileId && item.identity.volumeSerial === record.identity.volumeSerial);
  const record = item => ({ size: item.bytes.length, sha256: hash(item.bytes), identity: { ...item.identity } });
  const executor = (executable, args, options) => {
    calls.push({ executable, args, options });
    if (locked) throw Error('controlled cooperating writer locked');
    locked = true;
    try {
      const request = JSON.parse(options.input), prepare = request.operation === 'preparePrivatePublication';
      const stageName = `${request.targetPath}.dvaia-${request.operationId}.stage`, originalName = `${request.intentPath}.original`, resultName = `${request.intentPath}.result`;
      let intentFile = read(request.intentPath), intent, current = read(request.targetPath), stage = read(stageName), original = read(originalName), proposed = read(resultName);
      const expectedOriginal = request.originalBytesBase64 === null ? null : prepare ? Buffer.from(request.originalBytesBase64, 'base64') : null;
      const expectedResult = prepare ? Buffer.from(request.resultBytesBase64, 'base64') : null;
      if (!intentFile) {
        if (!prepare || (current ? !expectedOriginal || !current.bytes.equals(expectedOriginal) : expectedOriginal !== null)) throw Error('controlled prior-byte mismatch');
        if (!current && original) throw Error('controlled unexpected backup');
        if (current) {
          if (!original) original = writeNew(originalName, current.bytes);
          else if (!original.bytes.equals(current.bytes)) throw Error('controlled backup mismatch');
        }
        if (!proposed) proposed = writeNew(resultName, expectedResult);
        else if (!proposed.bytes.equals(expectedResult)) throw Error('controlled result backup mismatch');
        if (!stage) stage = writeNew(stageName, expectedResult);
        else if (!stage.bytes.equals(expectedResult)) throw Error('controlled retained stage mismatch');
        if (fault === 'before-intent') { fault = null; throw Error('synthetic secret interruption'); }
        intent = { targetPath: request.targetPath, intentPath: request.intentPath, operationId: request.operationId, original: current ? record(current) : null, originalBackup: original ? record(original) : null, result: record(stage), resultBackup: record(proposed) };
        intentFile = writeNew(request.intentPath, Buffer.from(JSON.stringify(intent)));
      } else intent = JSON.parse(intentFile.bytes.toString());
      if (intent.targetPath !== request.targetPath || intent.intentPath !== request.intentPath || intent.operationId !== request.operationId || !same(proposed, intent.resultBackup) || intent.original && !same(original, intent.originalBackup) || !intent.original && original) throw Error('controlled immutable intent mismatch');
      let state;
      if (same(current, intent.result) && current.bytes.equals(proposed.bytes)) {
        if (stage) throw Error('controlled unexpected committed stage');
        state = 'committed';
      } else {
        if (intent.original ? !same(current, intent.original) || !current.bytes.equals(original.bytes) : current !== undefined) throw Error('controlled changed original');
        if (!same(stage, intent.result) || !stage.bytes.equals(proposed.bytes)) throw Error('controlled changed stage');
        state = 'prepared';
      }
      if (prepare && (!proposed.bytes.equals(expectedResult) || (intent.original ? !expectedOriginal || !original.bytes.equals(expectedOriginal) : expectedOriginal !== null))) throw Error('controlled changed payload');
      if (request.operation === 'publishPrivatePublication' && state === 'prepared') {
        files.set(request.targetPath, stage); files.delete(stageName); current = stage; state = 'committed';
        if (fault === 'after-promotion') { fault = null; throw Error('synthetic secret interruption'); }
      }
      return JSON.stringify({ version: 1, ok: true, operation: request.operation, targetPath: request.targetPath, intentPath: request.intentPath, operationId: request.operationId, state, intentSha256: hash(intentFile.bytes), size: intent.result.size, identity: { ...intent.result.identity } });
    } finally { locked = false; }
  };
  const adapter = createWindowsPrivatePublication({ platform: 'win32', systemRoot: 'C:\\Windows', execute: executor });
  return { adapter, files, calls, setFault(value) { fault = value; }, replace(name, bytes) { files.set(name, file(bytes)); }, executor };
}
const prepareOptions = (originalBytes, resultBytes) => ({ ...base, originalBytes, resultBytes });

test('controlled replacement binds exact originals, retains byte backups and immutable intent, and returns identity', () => {
  const original = Buffer.from('synthetic original'), result = Buffer.from('synthetic replacement');
  const f = controlled(original), prepared = f.adapter.preparePrivatePublication(prepareOptions(original, result));
  assert.equal(prepared.state, 'prepared'); assert(f.files.get(targetPath).bytes.equals(original));
  assert(f.files.get(`${intentPath}.original`).bytes.equals(original)); assert(f.files.get(`${intentPath}.result`).bytes.equals(result));
  const intentBytes = Buffer.from(f.files.get(intentPath).bytes);
  const committed = f.adapter.publishPrivatePublication(base);
  assert.equal(committed.state, 'committed'); assert.deepEqual(committed.identity, prepared.identity);
  assert.equal(committed.intentSha256, prepared.intentSha256); assert(f.files.get(intentPath).bytes.equals(intentBytes));
  assert(f.files.get(targetPath).bytes.equals(result)); assert(!f.files.has(stagePath));
  assert.equal(f.adapter.inspectPrivatePublication(base).state, 'committed');
  assert(Object.isFrozen(committed)); assert(Object.isFrozen(committed.identity));
});

test('controlled fresh publication never overwrites an existing target', () => {
  const result = Buffer.from('synthetic new'); const f = controlled(null);
  f.adapter.preparePrivatePublication(prepareOptions(null, result)); f.adapter.publishPrivatePublication(base);
  assert(f.files.get(targetPath).bytes.equals(result)); assert(!f.files.has(`${intentPath}.original`));
  const collision = controlled(Buffer.from('operator bytes'));
  assert.throws(() => collision.adapter.preparePrivatePublication(prepareOptions(null, result)), denied);
  assert.equal(collision.files.size, 1); assert.equal(collision.files.get(targetPath).bytes.toString(), 'operator bytes');
});

test('controlled interruption after durable staging retains the same bytes for prepare retry', () => {
  const original = Buffer.from('before'), result = Buffer.from('after'); const f = controlled(original);
  f.setFault('before-intent'); assert.throws(() => f.adapter.preparePrivatePublication(prepareOptions(original, result)), denied);
  assert(!f.files.has(intentPath)); const stage = f.files.get(stagePath);
  f.adapter.preparePrivatePublication(prepareOptions(original, result)); assert.equal(f.files.get(stagePath), stage);
  f.adapter.publishPrivatePublication(base); assert(f.files.get(targetPath).bytes.equals(result));
});

test('controlled lost promotion acknowledgement resolves committed state without rewriting or rotating bytes', () => {
  const original = Buffer.from('before'), result = Buffer.from('after'); const f = controlled(original);
  const prepared = f.adapter.preparePrivatePublication(prepareOptions(original, result)); const journal = f.files.get(intentPath);
  f.setFault('after-promotion'); assert.throws(() => f.adapter.publishPrivatePublication(base), denied);
  const promoted = f.files.get(targetPath); assert(promoted.bytes.equals(result));
  const recovered = f.adapter.publishPrivatePublication(base);
  assert.equal(recovered.state, 'committed'); assert.deepEqual(recovered.identity, prepared.identity);
  assert.equal(f.files.get(targetPath), promoted); assert.equal(f.files.get(intentPath), journal);
});

test('controlled changed byte/identity, missing original and damaged artifacts fail without publication', () => {
  for (const mutate of [
    f => f.replace(targetPath, Buffer.from('other bytes')),
    f => f.replace(targetPath, Buffer.from('before')),
    f => f.files.delete(targetPath),
    f => f.replace(stagePath, Buffer.from('changed proposed')),
    f => f.replace(`${intentPath}.original`, Buffer.from('changed original')),
    f => f.replace(`${intentPath}.result`, Buffer.from('changed result')),
    f => { const doc = JSON.parse(f.files.get(intentPath).bytes); doc.operationId = 'unbound'; f.files.get(intentPath).bytes = Buffer.from(JSON.stringify(doc)); },
  ]) {
    const f = controlled(Buffer.from('before')); f.adapter.preparePrivatePublication(prepareOptions(Buffer.from('before'), Buffer.from('after')));
    mutate(f); const bytes = f.files.get(targetPath)?.bytes;
    assert.throws(() => f.adapter.publishPrivatePublication(base), denied);
    assert.equal(f.files.get(targetPath)?.bytes, bytes); assert(f.files.has(intentPath));
  }
});

test('controlled separately prepared cooperative publications cannot replace a newer committed target', () => {
  const original = Buffer.from('before'); const f = controlled(original);
  f.adapter.preparePrivatePublication(prepareOptions(original, Buffer.from('first')));
  const second = { targetPath, intentPath: intentPath + '.second', operationId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' };
  f.adapter.preparePrivatePublication({ ...second, originalBytes: original, resultBytes: Buffer.from('second') });
  f.adapter.publishPrivatePublication(base); const first = f.files.get(targetPath);
  assert.throws(() => f.adapter.publishPrivatePublication(second), denied);
  assert.equal(f.files.get(targetPath), first); assert.equal(first.bytes.toString(), 'first');
});

test('adapter transports two bounded payloads solely over JSON stdin with no shell', () => {
  const f = controlled(Buffer.alloc(MAX_FILE_BYTES)); const bytes = Buffer.alloc(MAX_FILE_BYTES, 1);
  f.adapter.preparePrivatePublication(prepareOptions(Buffer.alloc(MAX_FILE_BYTES), bytes));
  const call = f.calls[0]; assert.equal(call.executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(call.args, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', path.resolve(__dirname, '../scripts/windows/windows-private-publication.ps1')]);
  assert.equal(call.options.maxBuffer, 4096); assert.equal(call.options.timeout, 30000); assert.equal(call.options.windowsHide, true);
  assert.deepEqual(call.options.stdio, ['pipe', 'pipe', 'pipe']); assert(!Object.hasOwn(call.options, 'shell'));
  assert(Buffer.byteLength(call.options.input) < 3000000);
  const request = JSON.parse(call.options.input); assert.equal(Buffer.from(request.resultBytesBase64, 'base64').length, MAX_FILE_BYTES);
  assert(!call.args.some(arg => arg.includes(request.resultBytesBase64)));
  f.adapter.publishPrivatePublication(base); const publish = JSON.parse(f.calls.at(-1).options.input);
  assert.deepEqual(Object.keys(publish).sort(), ['intentPath', 'operation', 'operationId', 'targetPath', 'version']);
});

test('adapter rejects oversized/ambiguous bodies, unsafe paths, collisions and unbound operations before execution', () => {
  const f = controlled(null), valid = prepareOptions(null, Buffer.from('new'));
  const invalid = [
    { ...valid, resultBytes: Buffer.alloc(MAX_FILE_BYTES + 1) }, { ...valid, originalBytes: Buffer.alloc(MAX_FILE_BYTES + 1) },
    { ...valid, resultBytes: 'new' }, { ...valid, originalBytes: undefined }, { ...valid, extra: true },
    { ...valid, targetPath: '\\\\host\\share\\.env' }, { ...valid, targetPath: 'C:\\work\\..\\.env' },
    { ...valid, targetPath: 'C:\\work\\.env:other' }, { ...valid, intentPath: 'C:\\private\\CON.json' },
    { ...valid, targetPath: 'C:\\' + 'a'.repeat(205) }, { ...valid, intentPath: targetPath },
    { ...valid, intentPath: stagePath }, { ...valid, intentPath: 'C:\\private\\invalid\ud800.json' }, { ...valid, operationId: 'not an operation' }, { ...valid, operationId: operationId.toUpperCase() },
  ];
  // The numeric-only UUID above is case-invariant; use one with letters here.
  invalid.pop(); invalid.push({ ...valid, operationId: 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE' });
  for (const options of invalid) assert.throws(() => f.adapter.preparePrivatePublication(options), denied);
  assert.throws(() => f.adapter.publishPrivatePublication({ ...base, resultBytes: Buffer.alloc(0) }), denied);
  assert.equal(f.calls.length, 0);
});

test('adapter refuses non-Windows execution and strips secret-bearing process failures', () => {
  let calls = 0; const secret = 'synthetic secret diagnostic';
  const unavailable = createWindowsPrivatePublication({ platform: 'linux', systemRoot: 'C:\\Windows', execute() { calls++; } });
  assert.throws(() => unavailable.inspectPrivatePublication(base), denied); assert.equal(calls, 0);
  const failed = createWindowsPrivatePublication({ platform: 'win32', systemRoot: 'C:\\Windows', execute() { throw Object.assign(Error(secret), { stdout: secret, stderr: secret, cause: Error(secret) }); } });
  assert.throws(() => failed.publishPrivatePublication(base), error => {
    assert.equal(error.code, denied.code); assert.equal(error.message, denied.message); assert.deepEqual(Object.keys(error), ['code']); assert(!String(error.stack).includes(secret)); return true;
  });
});

test('adapter rejects wrong response binding, secret/extra fields, invalid identity and premature publish state', () => {
  const response = { version: 1, ok: true, operation: 'publishPrivatePublication', ...base, state: 'committed', intentSha256: 'a'.repeat(64), size: 3, identity: { volumeSerial: 1, fileId: '1234567812345678' } };
  const mutations = [r => ({ ...r, state: 'prepared' }), r => ({ ...r, operationId: 'wrong' }), r => ({ ...r, targetPath: 'C:\\other\\.env' }), r => ({ ...r, intentPath: 'C:\\other\\intent' }), r => ({ ...r, operation: 'preparePrivatePublication' }), r => ({ ...r, intentSha256: 'bad' }), r => ({ ...r, size: MAX_FILE_BYTES + 1 }), r => ({ ...r, secret: 'should not be returned' }), r => ({ ...r, identity: { ...r.identity, fileId: 'bad' } }), r => ({ ...r, identity: { ...r.identity, volumeSerial: -1 } }), () => ({ version: 1, ok: false, code: denied.code })];
  for (const mutate of mutations) {
    const adapter = createWindowsPrivatePublication({ platform: 'win32', systemRoot: 'C:\\Windows', execute: () => JSON.stringify(mutate(clone(response))) });
    assert.throws(() => adapter.publishPrivatePublication(base), denied);
  }
  for (const output of [' '.repeat(4097), '{} trailing', Buffer.from('{}')]) {
    const adapter = createWindowsPrivatePublication({ platform: 'win32', systemRoot: 'C:\\Windows', execute: () => output });
    assert.throws(() => adapter.publishPrivatePublication(base), denied);
  }
});

test('native source contracts retain cross-session lock, private artifacts and exact byte/identity recovery', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-publication.cs'), 'utf8');
  assert(source.includes('Global\\\\Dvaia.PrivatePublication.')); assert(!source.includes('Local\\\\Dvaia.PrivatePublication.'));
  assert(source.includes('security.SetOwner(owner);security.SetAccessRuleProtection(true,false)'));
  assert(source.includes('actual.AreAccessRulesProtected')); assert(source.includes('mutex.WaitOne(5000)'));
  assert(source.includes('catch(AbandonedMutexException){held=true;}')); assert(source.includes('finally {mutex.ReleaseMutex();}'));
  assert(source.includes('D:P(A;;FA;;;')); assert(source.includes('GenericRead|GenericWrite|Delete,ShareRead|ShareDelete,ref attributes,CreateNew,OpenReparsePoint|WriteThrough'));
  assert(source.includes('intentBytes=Encode(intent)')); assert(source.includes('retained=scope.Create(intentPath,intentBytes)'));
  assert(source.includes('Equal(Encode(intent),bytes)')); assert(source.includes('Fixed field order avoids relying on reflection')); assert(source.includes('intent.userSid==user'));
  assert(source.includes('original=scope.Read(backup)')); assert(source.includes('expectedResult=scope.Read(resultBackup)'));
  assert(source.includes('Equal(current,original)')); assert(source.includes('Equal(current,expectedResult)')); assert(source.includes('Equal(resultBytes,expectedResult)'));
  assert(source.includes('actual.creationTime==expected.creationTime')); assert(source.includes('actual.fileId==expected.fileId'));
  assert(source.includes('if(!opened.Handle.IsClosed)opened.Check')); assert(source.includes('scope.Check();stage.Dispose();if(target!=null)target.Dispose()'));
  const rename = source.indexOf('Require(MoveFileExW(stagePath,targetPath');
  assert(rename > source.indexOf('scope.Check();stage.Dispose()'));
  assert(source.slice(rename).includes('target=scope.Maybe(targetPath)'));
  assert(source.includes('MoveWriteThrough|(intent.originalTarget==null?0:MoveReplaceExisting)'));
  assert(source.includes('Require(stage.Before.Volume==')); assert(source.includes('Require(FlushFileBuffers(target.Handle))'));
  const durability=source.indexOf('Require(FlushFileBuffers(resultBackup.Handle))');
  assert(durability>source.indexOf('string state=State(scope,intent'));
  assert(source.slice(durability,source.indexOf('if(operation=="publishPrivatePublication")')).includes('Require(FlushFileBuffers((state=="prepared"?stage:target).Handle))'));
  assert(source.slice(durability).includes('if(backup!=null)Require(FlushFileBuffers(backup.Handle))'));
  assert(source.slice(durability).includes('Require(FlushFileBuffers(retained.Handle))'));
  assert(source.includes('GenericRead|GenericWrite|Delete,ShareRead|ShareDelete,IntPtr.Zero,OpenExisting'));
  assert(source.includes('info.Links==1 && info.SizeHigh==0 && info.SizeLow<=MaxBytes'));
  assert(source.includes('new byte[(int)opened.Before.SizeLow]')); assert(source.includes('byte[] sentinel=new byte[1]'));
  assert(!/MoveCopyAllowed|MOVEFILE_COPY_ALLOWED|ReplaceFileW|DeleteFileW|File\.ReadAllBytes|File\.WriteAllBytes|SetEndOfFile|truncate|chmod|icacls/.test(source));
  assert(source.includes('No POSIX directory-fsync equivalence is asserted'));
});

test('PowerShell source bounds wire data and avoids argument interpolation and diagnostics', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/windows/windows-private-publication.ps1'), 'utf8');
  assert(source.includes('$limit = 3000000')); assert(source.includes('[Console]::In.Read('));
  assert(source.includes('GetByteCount($wire) -gt $limit')); assert(source.includes('GetByteCount($json) -gt 4096'));
  assert(source.includes('System.Web.Extensions.dll')); assert(source.includes('[Dvaia.WindowsPrivatePublication]::Invoke('));
  assert(source.includes('"code":"WINDOWS_PRIVATE_PUBLICATION_DENIED"'));
  assert(!/Invoke-Expression|Write-Error|Write-Host|Write-Verbose|Out-File|\.ReadToEnd\(|-Command/.test(source));
});

test('controlled retained preparation rejects different same-length requested payload without rewriting artifacts', () => {
  const original = Buffer.from('before'), proposed = Buffer.from('after'); const f = controlled(original);
  f.adapter.preparePrivatePublication(prepareOptions(original, proposed));
  const stage = f.files.get(stagePath), intent = f.files.get(intentPath);
  assert.throws(() => f.adapter.preparePrivatePublication(prepareOptions(original, Buffer.from('other'))), denied);
  assert.equal(f.files.get(stagePath), stage); assert.equal(f.files.get(intentPath), intent);
  assert(f.files.get(targetPath).bytes.equals(original));
});
