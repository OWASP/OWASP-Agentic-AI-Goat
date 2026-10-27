'use strict';
// Permanent generated-program regression: actual builder bytes, no patching.
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const {relayLifecycleProgram}=require('./postgres/ownedMcpBoundedBuild')._internals;
const root=path.resolve(__dirname,'..');

test('generated relay cleanup only rescans tagged transient link loss, never re-signals or deletes uncertain groups', () => {
  const program = relayLifecycleProgram + String.raw`
ROOT='/controlled';RUN='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';RELAY='/controlled-relay';SOURCE_SHA='pinned';DNS_CODE='fixed-resolver';HOSTS=['deb.debian.org'];CHILDREN={'connector':'source','adapter':'source'}
ADMISSION={'account':'fixture','uid':501,'gid':502,'python':'/usr/bin/python3.13','pythonSha256':'a'*64,'setprivSha256':'b'*64}
from unittest.mock import patch
import io
def stat_record(start):
 fields=['S']+['0']*23;fields[19]=str(start)
 return '101 (relay) '+' '.join(fields)
for starts,expected_site in (([11,11],'proc_link'),([11,12],'proc_recheck_stat')):
 stats=iter(starts)
 def fake_open(p,mode='r',*args,**kwargs):
  if p.endswith('/stat'):return io.StringIO(stat_record(next(stats)))
  if p.endswith('/cmdline'):return io.BytesIO(b'/usr/bin/python3.13\0')
  if p.endswith('/status'):return io.StringIO('Uid:\t501 501 501 501\nGid:\t502 502 502 502\nGroups:\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n')
  raise AssertionError('unexpected open')
 with patch('builtins.open',side_effect=fake_open),patch.object(os,'readlink',side_effect=FileNotFoundError('controlled')):
  try:proc(101);raise AssertionError('missing fail-closed lookup')
  except (FileNotFoundError,RelayFailure) as error:assert getattr(error,'lookupSite',None)==expected_site
def uncertain(site):
 error=FileNotFoundError('controlled lookup');error.lookupSite=site;return error
for scenario in ('transient-proc-link','persistent-proc-link','other-lookup','identity-change','inaccessible'):
 row={'mode':'connector','pid':101,'start':11,'deadline':'1234.5','net':'net:[1]'}
 records={ROOT+'/fs/relay.controller':'{"pid":300,"start":99}',ROOT+'/fs/relay.connector.intent':'intent',ROOT+'/fs/relay.connector.process':json.dumps(row),ROOT+'/fs/relay.directory':'[1,2]',ROOT+'/fs/relay.socket':'[3,4]'}
 clock=[1000.0];events=[];calls=[0];directory=[True]
 def check(_row):
  calls[0]+=1
  if calls[0]==1:return [row] # ownership proved before one SIGTERM
  if scenario=='transient-proc-link':return [] if calls[0]>2 else (_ for _ in ()).throw(uncertain('proc_link'))
  if scenario=='persistent-proc-link':raise uncertain('proc_link')
  if scenario=='other-lookup':raise uncertain('proc_stat')
  if scenario=='identity-change':
   error=RelayFailure('controlled');error.reason='birth_group_session';error.lookupSite='proc_recheck_stat';raise error
  raise PermissionError('controlled inaccessible')
 def reader(p):return records[p]
 def exists(_pid):return True
 def lexists(p):return p in records or directory[0] and p in (RELAY,RELAY+'/connector.sock')
 def pause(value):clock[0]+=value
 def remove(_p):events.append(('rmdir',calls[0]));directory[0]=False
 def unlink(_p):events.append(('unlink',calls[0]))
 stderr=io.StringIO();stdout=io.StringIO()
 with patch('__main__.context'),patch('__main__.journal'),patch('__main__.read',side_effect=reader),patch('__main__.check_group',side_effect=check),patch('__main__.check_child'),patch('__main__.exists',side_effect=exists),patch('__main__.proc',return_value={'start':12}),patch('__main__.directory_record',return_value=[1,2]),patch('__main__.socket_record',return_value=[3,4]),patch.object(os.path,'lexists',side_effect=lexists),patch.object(os,'killpg',side_effect=lambda pid,sig:events.append(('signal',pid))),patch.object(os,'unlink',side_effect=unlink),patch.object(os,'listdir',return_value=[]),patch.object(os,'rmdir',side_effect=remove),patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.object(time,'sleep',side_effect=pause),patch.object(sys,'stderr',stderr),patch.object(sys,'stdout',stdout):
  try:cleanup();ok=True
  except RelayFailure:ok=False
 assert ok==(scenario=='transient-proc-link'),scenario
 assert [event for event in events if event[0]=='signal']==[('signal',101)],scenario
 if ok:
  assert calls[0]>=3 and events[-2:]==[('unlink',calls[0]),('rmdir',calls[0])]
  assert directory[0] is False and stdout.getvalue()=='relay-absent\n'
 else:
  assert directory[0] is True and not any(event[0] in ('unlink','rmdir') for event in events)
  if scenario=='persistent-proc-link':assert 1010<=clock[0]<1010.1
  assert stdout.getvalue()==''
`;
  const result = spawnSync('/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python', ['-I','-S','-B','-'], {cwd: root, input: program, encoding: 'utf8', timeout: 10000, maxBuffer: 131072});
  assert.equal(result.status, 0, result.stderr);
});
