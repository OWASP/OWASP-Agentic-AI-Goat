'use strict';

// Closed source-bound plan factory only. No runner, image capability or runtime
// admission. The eventual combined owner must validate and execute this plan.
const fs = require('node:fs/promises'), native = require('node:fs');
const path = require('node:path'), Module = require('node:module');
const { isDeepStrictEqual: same } = require('node:util');
const inputs = require('./ownedSystemDiagnosticBuildInputs');
const system = require('./ownedSystemConfigBuildAdapter')._internals;
const derivation = require('./ownedV03DiagnosticDerivation');
const metadata = require('./ownedPolicySystemMetadata');
const { ROOT, BASE, sha } = inputs._internals;
const TARGET = 'original-v03-diagnostic';
const METADATA_TARGET = 'v03-diagnostic';
const SOURCE_SHA = 'ab71e0fb17929f9323e1ff92f452b96b1b813641e4f70c1f3c6a555873a37c22';
const fail = code => Object.assign(new Error(code), { code });
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function replaceOnce(source, before, after) {
  if (source.split(before).length !== 2) throw fail('DIAGNOSTIC_DERIVATION_ANCHOR');
  return source.replace(before, after);
}
function deriveSource(source) {
  if (sha(source) !== SOURCE_SHA) throw fail('DIAGNOSTIC_DERIVATION_SOURCE');
  // The fixed V03 holder consumes parent-remaining time from private input;
  // neither the original System900s cohort nor a new11096s timer is borrowed.
  let text = derivation.deriveSource(source);
  text = replaceOnce(text, "return closedMetadataQualificationPlan(root,runId,'v24-system');",
    "return closedMetadataQualificationPlan(root,runId,'v03-diagnostic');");
  text = replaceOnce(text,
    "if(!['v23-registry','v24-system','v33-pricing','v24-policy','listings-package'].includes(targetName))",
    "if(!['v03-diagnostic','v23-registry','v24-system','v33-pricing','v24-policy','listings-package'].includes(targetName))");
  text = replaceOnce(text, "const base=targetName==='v24-system'?",
    "const base=['v24-system','v03-diagnostic'].includes(targetName)?");
  text = replaceOnce(text, "kind:targetName==='listings-package'?",
    "kind:targetName==='v03-diagnostic'?'private-v03-diagnostic-metadata':targetName==='listings-package'?");
  text = replaceOnce(text, "+(metadataOnly?metadataAdmissionAudit.replace(\"variant='metadata-admission-audit-v3'\",\"variant='metadata-idle-barrier-v4'\"):transportAudit)", "+(metadataOnly?metadataAdmissionAudit.replace(\"variant='metadata-admission-audit-v3'\",\"variant='metadata-idle-barrier-v4'\").replace('activeWorkers=threading.active_count()-1,','v03Connections=V03_BUDGET.connections,activeWorkers=threading.active_count()-1,')+\"\\nV03_BUDGET=None\\nV03_GRANT=None\\ndef v03_grant():\\n    global V03_GRANT\\n    path='/var/tmp/owasp-ai-goat-v23-relay-'+TRANSPORT_RUN+'/v03-credit.json'\\n    try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\\n    except FileNotFoundError:\\n        if V03_GRANT is not None: raise Denied('v03-credit-lost')\\n        return None\\n    try:\\n        a=os.fstat(fd)\\n        if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1 or stat.S_IMODE(a.st_mode)!=0o444 or not 0<a.st_size<=1024: raise Denied('v03-credit-file')\\n        data=os.read(fd,1025);z=os.fstat(fd)\\n        if len(data)!=a.st_size or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns): raise Denied('v03-credit-changed')\\n        row=json.loads(data)\\n    finally:os.close(fd)\\n    if type(row) is not dict or set(row)!={'version','runId','artifactLimit','attemptsPerArtifact','starts'} or type(row['version']) is not int or row['version']!=1 or row['runId']!=TRANSPORT_RUN or type(row['artifactLimit']) is not int or row['artifactLimit']!=35 or type(row['attemptsPerArtifact']) is not int or row['attemptsPerArtifact']!=2: raise Denied('v03-credit-binding')\\n    if type(row['starts']) is not dict or set(row['starts'])!={'adapter','connector'} or any(type(n) is not int or not 0<=n<=32 for n in row['starts'].values()): raise Denied('v03-credit-starts')\\n    if V03_GRANT is None:\\n        if row['starts'][TRANSPORT_MODE]!=V03_BUDGET.connections: raise Denied('v03-credit-race')\\n        V03_GRANT=row\\n    elif row!=V03_GRANT: raise Denied('v03-credit-rewrite')\\n    return row\\n_v03_init=Budget.__init__\\ndef v03_init(self):\\n    global V03_BUDGET\\n    _v03_init(self);V03_BUDGET=self\\ndef v03_admit(self):\\n    with self.lock:\\n        grant=v03_grant();cap=32 if grant is None else grant['starts'][TRANSPORT_MODE]+70\\n        if self.connections>=cap or self.connections>=102: raise Denied('connections')\\n        self.connections+=1\\nBudget.__init__=v03_init\\nBudget.admit=v03_admit\\n\":transportAudit)");
  text = replaceOnce(text, "+metadataIdleProgram:transportCheckpointProgram;", "+metadataIdleProgram+\"\\ndef v03_credit():\\n    authority();remaining(read(ROOT+'/acquisition.deadline'))\\n    packet=checkpoint();starts={}\\n    for mode in ('adapter','connector'):\\n        row=packet['rows'][mode]\\n        require(row['activeWorkers']==0 and type(row['v03Connections']) is int and 0<=row['v03Connections']<=32)\\n        identity=json.loads(read(ROOT+'/fs/relay.'+mode+'.process'))\\n        check_child(identity,proc(identity['pid']))\\n        require(os.listdir('/proc/'+str(identity['pid'])+'/task')==[str(identity['pid'])])\\n        starts[mode]=row['v03Connections']\\n    row=dict(version=1,runId=RUN,artifactLimit=35,attemptsPerArtifact=2,starts=starts)\\n    remaining(read(ROOT+'/acquisition.deadline'))\\n    fd=os.open(RELAY+'/v03-credit.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)\\n    with os.fdopen(fd,'wb') as f:\\n        data=json.dumps(row,sort_keys=True).encode();require(f.write(data)==len(data));f.flush()\\n        before=os.fstat(f.fileno());require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1)\\n        os.fchmod(f.fileno(),0o444)\\n        os.fsync(f.fileno())\\n        after=os.fstat(f.fileno());require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino) and stat.S_IMODE(after.st_mode)==0o444 and after.st_nlink==1)\\n    fd=os.open(RELAY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\\n    try:os.fsync(fd)\\n    finally:os.close(fd)\\n    remaining(read(ROOT+'/acquisition.deadline'))\\n\":transportCheckpointProgram;");
  text = replaceOnce(text, "('start','authority','cleanup','evidence','checkpoint','idle')", "('start','authority','cleanup','evidence','checkpoint','idle','v03_credit')");
  text = replaceOnce(text, "authority|cleanup|evidence|checkpoint|idle)", "authority|cleanup|evidence|checkpoint|idle|v03_credit)");
  text = replaceOnce(text, "        require(not os.listdir(RELAY))", "        if os.path.lexists(RELAY+'/v03-credit.json'):\n            st=os.lstat(RELAY+'/v03-credit.json');require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o444 and st.st_size<=1024)\n            require(time.monotonic()<end);os.unlink(RELAY+'/v03-credit.json')\n        require(not os.listdir(RELAY))");
  return text;
}
async function loadMetadataFactory() {
  const filename = path.join(ROOT, 'tests/postgres/ownedMcpBoundedBuild.js');
  if (await fs.realpath(filename) !== filename) throw fail('DIAGNOSTIC_DERIVATION_PATH');
  const fd = await fs.open(filename, native.constants.O_RDONLY | native.constants.O_NOFOLLOW | native.constants.O_NONBLOCK);
  let source;
  try {
    const before = await fd.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > 1024 ** 2) throw fail('DIAGNOSTIC_DERIVATION_FILE');
    const bytes = Buffer.alloc(before.size + 1); let offset = 0;
    while (offset < bytes.length) { const row = await fd.read(bytes, offset, bytes.length - offset, offset); if (!row.bytesRead) break; offset += row.bytesRead; }
    const after = await fd.stat();
    if (offset !== before.size || ['dev','ino','size','mtimeMs','ctimeMs'].some(key => before[key] !== after[key])) throw fail('DIAGNOSTIC_DERIVATION_CHANGED');
    source = bytes.subarray(0, offset).toString('utf8');
  } finally { await fd.close(); }
  const text = deriveSource(source), derived = new Module(filename, module);
  derived.filename = filename; derived.paths = Module._nodeModulePaths(__dirname);
  derived._compile(text, filename);
  return { plan: derived.exports._internals.systemMetadataQualificationPlan,
    specification: derived.exports.specification, sourceSha256: SOURCE_SHA, derivedSha256: sha(text) };
}
async function diagnosticBuildPlan(root, runId) {
  if (arguments.length !== 2 || root !== ROOT || !/^[a-f0-9]{32}$/.test(runId || '')) throw fail('DIAGNOSTIC_PLAN_BINDING');
  const captured = await inputs.captureDiagnosticBuildInputs(root);
  const derived = await loadMetadataFactory(), meta = await derived.plan(root, runId);
  if (meta.binding.target !== METADATA_TARGET || meta.binding.base !== BASE) throw fail('DIAGNOSTIC_METADATA_BINDING');
  const spec = derived.specification(root, runId), guest = await system.guestSource(root, meta.binding);
  const metadataGuestSource = metadata.guestMetadataSource(meta.binding, { retention: meta.metadataRetention.mode });
  if (sha(metadataGuestSource) !== meta.guestSourceSha256) throw fail('DIAGNOSTIC_METADATA_SOURCE');
  const helperHashes = { ...guest.hashes };
  for (const name of ['ownedSystemDiagnosticBuildAdapter','ownedSystemDiagnosticBuildInputs',
    'ownedSystemConfigPrivateBuild','ownedSystemConfigBuildAdapter','ownedV03DiagnosticDerivation','ownedV03CombinedLease','ownedMcpBoundedBuild',
    'ownedSystemDiagnosticRuntime','ownedSystemPrivateHttpConsumer','ownedSystemRuntimeTransport','ownedSystemConfigPhaseDriver','ownedV03PrivateExecutors','ownedV03GuestClock','ownedSystemDiagnosticProducer']) {
    const relative = 'tests/postgres/' + name + '.js';
    helperHashes[relative] = sha(await fs.readFile(path.join(root, relative)));
  }
  helperHashes['tests/postgres/owned_system_private_http_channel.py']=sha(await fs.readFile(path.join(root,'tests/postgres/owned_system_private_http_channel.py')));
  Object.assign(meta.buildSources, { [captured.recipeProvider.path]: captured.recipeProvider.sha256 },
    Object.fromEntries(captured.context.files.map(row => [captured.context.sourceRoot + '/' + row.name, row.sha256])));
  return freeze({ version: 1, target: TARGET, runId, binding: meta.binding, spec, captured, metadata: meta,
    boundedDerivation: { sourceSha256: derived.sourceSha256, derivedSha256: derived.derivedSha256,
      buildOnly: true, runtimeAdmitted: false }, helperHashes, guestSource: guest.text, metadataGuestSource,
    commands: system.commandsFor(meta, spec, captured, guest), limits: system.LIMITS,
    executionApproved: false, runtimeAvailable: false,
    pending: ['diagnostic-build-owner-admission', 'combined-v03-lifetime', 'diagnostic-runtime-and-retirement'] });
}
const planDigest = plan => sha(JSON.stringify(plan));
async function verifyDiagnosticBuildPlan(plan) {
  if (!plan || plan.target !== TARGET || plan.executionApproved !== false || plan.runtimeAvailable !== false)
    throw fail('DIAGNOSTIC_PLAN_NOT_AUTHORITY');
  if (!same(plan, await diagnosticBuildPlan(plan.spec?.root, plan.runId))) throw fail('DIAGNOSTIC_PLAN_CHANGED');
  return true;
}
async function withPrivateDiagnosticImage() { throw fail('DIAGNOSTIC_BUILD_NOT_ADMITTED'); }
module.exports = { diagnosticBuildPlan, verifyDiagnosticBuildPlan, planDigest, withPrivateDiagnosticImage,
  _internals: { ROOT, TARGET, METADATA_TARGET, SOURCE_SHA, deriveSource, replaceOnce, loadMetadataFactory } };
