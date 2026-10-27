"""Post-terminal admission checks for the prospective original V39 atomic pair.

This is not a launcher: the caller must supply its observed child wait result and
its previously admitted source/model pins. A saved receipt cannot establish either.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SCOPE = 'mcp-description-v39-atomic-pair-current-main-v1'
RESULT_SCOPE = 'V39-atomic-pair-standalone'
TAP = 'standalone admin compares clean and treatment registered descriptions with independent physical Judge evidence'
MODEL = 'llama3.1:8b'
MODEL_SHA256 = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
PAIR_HELPER = 'tests/fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification.js'
REQUIRED_SOURCE = (
    'tests/postgres/secureshopOwnedMcpRegistryRendered.native.js',
    'tests/postgres/secureshopMailActualTransport.js',
    'tests/fixtures/secureshopMcpDescriptionRenderedQualification.js',
    PAIR_HELPER,
    'server/services/secureshopMcpDescriptionEvidence.js',
    'server/services/secureshopModelQualification.js',
    'server/agent-runtime/objectiveJudge.js',
    'server/agent-runtime/judgeExecutionTranscript.js',
    'server/services/secureshop/providers/ollamaProvider.js',
)
FLAGS = ('standaloneAdminRendered', 'ownedNamespaceRegistration',
         'renderedToolsAndHistory', 'exactSavedOperationReadback',
         'renderedRemovalHistoryRetained', 'siblingDenied', 'cleanupComplete',
         'renderedManifestImportSaved')
ARTIFACTS = tuple(f'mcp-description-atomic-{arm}-{kind}.json'
                  for arm in ('control', 'treatment')
                  for kind in ('wire', 'model', 'qualification'))
LIMITS = {'wire': 128 * 1024 * 1024, 'model': 32 * 1024 * 1024,
          'qualification': 8 * 1024 * 1024}
HEX = re.compile(r'^[a-f0-9]{64}$')


def _exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _private_json(directory, name, maximum):
    if Path(name).name != name:
        raise RuntimeError('V39 atomic artifact name changed')
    path = directory / name
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= maximum):
        raise RuntimeError('Private V39 atomic artifact required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise RuntimeError('V39 atomic artifact changed before read')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(maximum + 1)
        after = path.lstat()
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
        if (len(body) != before.st_size or identity(before) != identity(after)
                or identity(before) != identity(os.fstat(descriptor))):
            raise RuntimeError('V39 atomic artifact changed during read')
        return json.loads(body)
    finally:
        os.close(descriptor)


def _wire(wire, arm, model_digest):
    if not _exact(wire, ('modelDigest', 'calls')) or wire['modelDigest'] != model_digest:
        raise RuntimeError('V39 atomic physical model digest mismatch')
    calls = wire['calls']
    if type(calls) is not list or not 8 <= len(calls) <= 14:
        raise RuntimeError('V39 atomic physical arm bounds failed')
    kinds = []
    for index, row in enumerate(calls, 1):
        if (type(row) is not dict or row.get('arm') != arm or row.get('kind') not in ('actor', 'judge')
                or type(row.get('index')) is not int or row['index'] != index
                or row.get('model') != MODEL or row.get('status') != 200
                or row.get('error') is not None or row.get('responseComplete') is not True
                or row.get('responseCaptureTruncated') is not False
                or row.get('terminalReason') != 'end'):
            raise RuntimeError('V39 atomic physical call identity failed')
        kinds.append(row['kind'])
        for field, limit in (('request', 262144), ('response', 4194304)):
            body = row.get(field)
            if type(body) is not str:
                raise RuntimeError('V39 atomic physical body missing')
            encoded = body.encode('utf-8')
            if (not 0 < len(encoded) <= limit or type(row.get(field + 'Bytes')) is not int
                    or row[field + 'Bytes'] != len(encoded)
                    or row.get(field + 'Sha256') != hashlib.sha256(encoded).hexdigest()
                    or row.get(field + 'ObservedBytes', len(encoded)) != len(encoded)):
                raise RuntimeError('V39 atomic physical body digest mismatch')
        if (row.get('responseObservedBytes') != row['responseBytes']
                or json.loads(row['request']).get('model') != MODEL):
            raise RuntimeError('V39 atomic physical request/response mismatch')
    actor = kinds.count('actor')
    judge = kinds.count('judge')
    if not 7 <= actor <= 13 or not 1 <= judge <= 4:
        raise RuntimeError('V39 atomic per-arm actor/Judge bounds failed')
    return actor, judge


def _model(model, wire, actor, judge):
    if (not _exact(model, ('providerCalls', 'transcripts'))
            or type(model['providerCalls']) is not list or not model['providerCalls']
            or type(model['transcripts']) is not list or len(model['transcripts']) != 1):
        raise RuntimeError('V39 atomic original model recorder missing')
    transcript = model['transcripts'][0]
    if (type(transcript) is not dict or transcript.get('complete') is not True
            or type(transcript.get('calls')) is not list or len(transcript['calls']) != judge):
        raise RuntimeError('V39 atomic Judge transcript incomplete')
    positions = []
    for row in model['providerCalls']:
        if (type(row) is not dict or row.get('method') not in ('chat', 'finalResponse')
                or type(row.get('wireStart')) is not int or type(row.get('wireEnd')) is not int
                or not 0 <= row['wireStart'] < row['wireEnd'] <= len(wire['calls'])
                or row['wireEnd'] - row['wireStart'] > 2
                or type(row.get('input')) is not dict or type(row.get('result')) is not dict):
            raise RuntimeError('V39 atomic model recorder call invalid')
        positions.extend(range(row['wireStart'], row['wireEnd']))
    if positions != [i for i, call in enumerate(wire['calls']) if call['kind'] == 'actor']:
        raise RuntimeError('V39 atomic model recorder/physical actor mismatch')


def _source_pins(source_root, source_pins):
    if type(source_pins) is not dict or not all(name in source_pins for name in REQUIRED_SOURCE):
        raise RuntimeError('V39 atomic frozen source closure missing')
    for name, expected in source_pins.items():
        if type(name) is not str or Path(name).is_absolute() or '..' in Path(name).parts:
            raise RuntimeError('V39 atomic frozen source path invalid')
        path = source_root / name
        if (type(expected) is not str or not HEX.fullmatch(expected)
                or path.is_symlink() or path.resolve() != path
                or not stat.S_ISREG(path.lstat().st_mode)
                or _digest(path) != expected):
            raise RuntimeError('V39 atomic frozen source changed')


# This exact core is emitted by admission and exercised with the real canonical
# dispatcher in controlled tests. It has no network transport or credit writer.
JUDGE_REPLAY_JS = r'''
const {createHash}=require('node:crypto');
const {createObjectiveJudge,prepareJudgeInput}=require(root+'/server/agent-runtime/objectiveJudge');
const evidence=require(root+'/server/services/secureshopMcpDescriptionEvidence');
const hash=value=>createHash('sha256').update(value).digest('hex');
const json=value=>JSON.parse(JSON.stringify(value));
// Only wall-clock durations vary on replay; every semantic field is retained.
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'
  ?Object.fromEntries(Object.entries(value).filter(([key])=>!['durationMs','attemptDurationsMs'].includes(key))
    .map(([key,item])=>[key,stable(item)])):value;
function checkTranscriptDigest(transcript){
  const {transcriptSha256,...body}=transcript;
  assert.equal(transcriptSha256,hash(JSON.stringify(body)));
  assert.equal(transcript.complete,true);assert.equal(transcript.failure,null);
  assert.equal(transcript.outcome.bytes,JSON.stringify(transcript.outcome.value));
  assert.equal(transcript.outcome.sha256,hash(transcript.outcome.bytes));
}
async function replayCanonicalJudge(input,expected,transcript,wires){
  assert.ok(wires.length>=1&&wires.length<=4);
  checkTranscriptDigest(transcript);
  assert.deepStrictEqual(transcript.outcome.value,expected);
  const prepared=prepareJudgeInput(input);
  assert.equal(prepared.evidenceError,undefined);
  assert.equal(transcript.header.packet,prepared.packet);
  assert.equal(transcript.header.evidenceDigest,prepared.evidenceDigest);
  assert.equal(transcript.header.runId,input.execution.runId);
  let cursor=0,replayedTranscript;
  const replay=await createObjectiveJudge({contextTokens:32768,
    observeExecutionTranscript:value=>{replayedTranscript=value;},
    model:{async chat(messages,tools,options){
      const wire=wires[cursor],saved=transcript.calls[cursor++];
      assert.ok(wire&&saved,'Canonical Judge requested an unrecorded call');
      assert.equal(wire.kind,'judge');
      assert.equal(wire.requestSha256,hash(wire.request));
      assert.equal(wire.responseSha256,hash(wire.response));
      const request=JSON.parse(wire.request),frames=wire.response.trim().split('\n').map(line=>JSON.parse(line));
      assert.ok(frames.length>0);const terminal=frames.at(-1);
      assert.equal(terminal.done,true);
      const text=frames.map(frame=>frame.message?.content||'').join('');
      const sdk=new(require('@langchain/ollama').ChatOllama)({model,temperature:options.temperature,
        numPredict:options.num_predict??options.max_tokens??1024,numCtx:options.num_ctx??8192,
        maxRetries:0,format:options.format});
      const params=json(sdk.invocationParams({tools}));
      const expectedRequest={model,messages,format:options.format,options:params.options,stream:true,
        ...(Object.hasOwn(params,'tools')?{tools:params.tools}:{})};
      assert.deepStrictEqual(request,expectedRequest,'Physical Judge request differs from canonical request');
      assert.deepStrictEqual(saved.request,json({method:'chat',input:messages,tools,
        schema:options.format??null,options:{temperature:options.temperature,num_ctx:options.num_ctx,
          max_tokens:options.max_tokens,num_predict:options.num_predict,timeout:options.timeout}}));
      assert.equal(saved.requestSha256,hash(JSON.stringify(saved.request)));
      assert.equal(saved.response,text);assert.equal(saved.responseSha256,hash(text));
      return {provider:'ollama',model,mocked:false,fallback:false,tokens:terminal.eval_count||0,
        metadata:{eval_count:terminal.eval_count??null},response:text};
    }}})(input);
  assert.equal(cursor,wires.length);assert.equal(cursor,transcript.calls.length);
  assert.deepStrictEqual(stable(replay),stable(expected),'Saved Judge outcome differs from canonical replay');
  assert.equal(replayedTranscript.complete,true);
  const body=value=>{const {evaluationId,transcriptSha256,outcome,...rest}=value;return stable(rest);};
  assert.deepStrictEqual(body(replayedTranscript),body(transcript),
    'Saved Judge transcript differs from canonical replay');
  assert.deepStrictEqual(stable(replayedTranscript.outcome.value),stable(expected));
  return replay;
}
async function replayArmJudge(arm){
  const captured=arm.qualification,transcript=arm.model.transcripts[0];
  let input,expected;
  if(captured.arm==='control'){
    const execution=captured.diagnostic.input.execution;
    const rebuilt=evidence.buildMcpDescriptionDiagnosticCandidate({source:captured.original,
      assessmentExecution:execution,qualifyModelTrace:qualify});
    assert.ok(rebuilt);assert.equal(rebuilt.canonicalCredit,false);
    input={rubric:evidence.RUBRIC,...rebuilt.candidate,execution};
    assert.deepStrictEqual(input,captured.diagnostic.input);
    expected=captured.diagnostic.outcome;assert.equal(expected.verdict,'fail');
  }else{
    assert.equal(captured.arm,'treatment');const saved=captured.judgment;
    const execution={runId:saved.run_id,ownerKey:saved.owner_key,durableGeneration:String(saved.owner_generation)};
    const candidate=evidence.buildMcpDescriptionCandidate({source:captured.original,
      assessmentExecution:execution,qualifyModelTrace:qualify});
    assert.ok(candidate);input={rubric:evidence.RUBRIC,...candidate,execution};
    const prepared=prepareJudgeInput(input);
    assert.equal(saved.packet,prepared.packet);assert.equal(saved.evidence_digest,prepared.evidenceDigest);
    expected=JSON.parse(saved.judge_result_json);
    assert.equal(saved.verdict,expected.verdict);assert.equal(expected.verdict,'pass');
    assert.equal(captured.assessment.judgment.verdict,expected.verdict);
  }
  return replayCanonicalJudge(input,expected,transcript,arm.calls.filter(wire=>wire.kind==='judge'));
}
'''


def admit_atomic_pair(directory, *, fixture_returncode, tap_text, source_root,
                      source_pins, model_before, model_after, node_path):
    """Validate retained evidence after the caller's actual child.wait(0).

    The caller must independently own process birth/reap, exact model installation
    checks, source snapshot, and outer resource cleanup. This does not promote a run.
    """
    if type(fixture_returncode) is not int or fixture_returncode != 0:
        raise RuntimeError('V39 atomic fixture did not exit successfully')
    names = re.findall(r'^ok \d+ - (.+)$', tap_text, re.M) if type(tap_text) is str else []
    if names != [TAP] or re.search(r'^(?:not ok |# (?:fail|cancelled|skipped) [1-9])', tap_text, re.M):
        raise RuntimeError('Exact V39 atomic TAP required')
    if (model_before != {'baseURL': 'http://127.0.0.1:11434', 'model': MODEL, 'sha256': MODEL_SHA256}
            or model_after != model_before):
        raise RuntimeError('V39 atomic pinned model changed')
    source_root = Path(source_root)
    if (not source_root.is_absolute() or source_root.is_symlink()
            or source_root.resolve() != source_root
            or not stat.S_ISDIR(source_root.lstat().st_mode)):
        raise RuntimeError('Exact V39 atomic source root required')
    _source_pins(source_root, source_pins)
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or directory.resolve() != directory:
        raise RuntimeError('Exact private V39 atomic evidence directory required')
    parent = directory.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise RuntimeError('Private V39 atomic evidence directory required')
    result = _private_json(directory, 'candidate-result.json', 8192)
    keys = set(FLAGS) | {'status', 'scope', 'modelCalls', 'browserCalls', 'cleanupErrors',
                         'actorCalls', 'judgeCalls', 'descriptionQualification', 'browserApi'}
    if (not _exact(result, keys) or result['status'] != 'passed'
            or result['scope'] != RESULT_SCOPE or result['cleanupErrors'] != []
            or result['cleanupComplete'] is not True
            or result['descriptionQualification'] is not True
            or type(result['browserCalls']) is not int or result['browserCalls'] != 1
            or any(result[key] is not False for key in FLAGS if key != 'cleanupComplete')):
        raise RuntimeError('V39 atomic fixture terminal result incomplete')
    receipt = _private_json(directory, 'mcp-description-atomic-pair-receipt.json', 8192)
    browser_api = result['browserApi']
    if (not _exact(browser_api, ('total', 'apiRequests', 'denied', 'interceptionErrors'))
            or type(browser_api['total']) is not int or not 0 < browser_api['total'] <= 1200
            or type(browser_api['apiRequests']) is not int
            or not 0 < browser_api['apiRequests'] <= browser_api['total']
            or browser_api['denied'] != []
            or type(browser_api['interceptionErrors']) is not int
            or browser_api['interceptionErrors'] != 0
            or receipt.get('browserApi') != browser_api):
        raise RuntimeError('V39 atomic terminal/browser audit receipt mismatch')
    pairs = {}
    for arm in ('control', 'treatment'):
        wire = _private_json(directory, f'mcp-description-atomic-{arm}-wire.json', LIMITS['wire'])
        model = _private_json(directory, f'mcp-description-atomic-{arm}-model.json', LIMITS['model'])
        qualification = _private_json(directory, f'mcp-description-atomic-{arm}-qualification.json', LIMITS['qualification'])
        actor, judge = _wire(wire, arm, MODEL_SHA256)
        _model(model, wire, actor, judge)
        if (type(qualification) is not dict or qualification.get('version') != 2
                or qualification.get('arm') != arm or qualification.get('model') != model):
            raise RuntimeError('V39 atomic persisted qualification/model mismatch')
        pairs[arm] = {'actor': actor, 'judge': judge}
    actors = sum(row['actor'] for row in pairs.values())
    judges = sum(row['judge'] for row in pairs.values())
    if (not 16 <= actors + judges <= 28 or type(result['actorCalls']) is not int
            or type(result['judgeCalls']) is not int or type(result['modelCalls']) is not int
            or (result['actorCalls'], result['judgeCalls'], result['modelCalls'])
            != (actors, judges, actors + judges)):
        raise RuntimeError('V39 atomic aggregate physical counters mismatch')
    if (not _exact(receipt, ('version', 'scope', 'pairVersion', 'control', 'treatment',
                            'physicalCalls', 'sameTaskCatalogSchemaResult', 'controlNoCredit',
                            'treatmentCanonicalCredit', 'fixedAndLifecycle', 'cleanupComplete',
                            'relayRetired', 'browserApi', 'errors'))
            or receipt['version'] != 2 or receipt['scope'] != SCOPE
            or receipt['cleanupComplete'] is not True or receipt['relayRetired'] is not True
            or receipt['errors'] != [] or receipt['physicalCalls'] != actors + judges
            or any((receipt[arm].get('actorCalls'), receipt[arm].get('judgeCalls'))
                   != (pairs[arm]['actor'], pairs[arm]['judge']) for arm in pairs)):
        raise RuntimeError('V39 atomic receipt/physical evidence mismatch')
    script = r'''const fs=require('node:fs'); const assert=require('node:assert/strict');
const root=process.argv[1],dir=process.argv[2],model=process.argv[3];
const pair=require(root+'/tests/fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification');
const original=require(root+'/tests/fixtures/secureshopMcpDescriptionRenderedQualification');
const {OllamaProvider}=require(root+'/server/services/secureshop/providers/ollamaProvider');
const read=n=>JSON.parse(fs.readFileSync(dir+'/'+n,'utf8'));
const arms=Object.fromEntries(['control','treatment'].map(a=>[a,{
  qualification:read(`mcp-description-atomic-${a}-qualification.json`),
  calls:read(`mcp-description-atomic-${a}-wire.json`).calls,
  model:read(`mcp-description-atomic-${a}-model.json`)}]));
const qualify=i=>i&&i.provider==='ollama'&&i.model===model&&i.mocked===false&&i.fallback!==true;
''' + JUDGE_REPLAY_JS + r'''
(async()=>{
for(const arm of Object.values(arms)){
  for(const call of arm.model.providerCalls){
    const wires=arm.calls.slice(call.wireStart,call.wireEnd);
    await original.assertExactProviderWire(call,wires,model);
    const provider=new OllamaProvider({model}); let used=0;
    provider.transport={chat:async()=>{const w=wires[used++]; const frames=w.response.trim()
      .split('\n').map(line=>JSON.parse(line));
      return {response:frames.map(frame=>frame.message?.content||'').join(''),metadata:frames.at(-1)};}};
    const result=await provider[call.method](call.input);
    assert.equal(used,wires.length);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(result)),call.result);
  }
  await replayArmJudge(arm);
}
const captured=pair.assertPairCaptured({control:arms.control.qualification,
  treatment:arms.treatment.qualification,controlCalls:arms.control.calls,
  treatmentCalls:arms.treatment.calls,qualifyModelTrace:qualify});
const saved=read('mcp-description-atomic-pair-receipt.json');
assert.deepStrictEqual(pair.finalizePairReceipt(captured,{cleanupComplete:true,relayRetired:true,
  browserApi:saved.browserApi}),saved);
})().catch(error=>{process.stderr.write(String(error));process.exitCode=1});'''
    node_path = Path(node_path)
    if (node_path != source_root / 'tasks/runtime/node/node_modules/node/bin/node'
            or node_path.is_symlink() or node_path.resolve() != node_path
            or not stat.S_ISREG(node_path.lstat().st_mode)):
        raise RuntimeError('Exact V39 atomic Node verifier required')
    checked = subprocess.run([str(node_path), '-e', script, str(source_root), str(directory), MODEL],
                             cwd=source_root, capture_output=True, text=True, timeout=30,
                             env={'NODE_ENV': 'test', 'OLLAMA_CONTEXT_WINDOW': '8192'})
    if checked.returncode:
        raise RuntimeError('V39 atomic persisted original source/Judge proof failed')
    return {'result': result, 'receipt': receipt,
            'artifactSha256': {name: _digest(directory / name)
                               for name in ('candidate-result.json',
                                            'mcp-description-atomic-pair-receipt.json', *ARTIFACTS)}}
