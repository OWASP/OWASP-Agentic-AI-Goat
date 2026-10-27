'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const {HOSTS,LIMITS,guestProgram,_internals:{program}}=require('./postgres/ownedMcpPrivateEgress');
function python(body){const result=spawnSync('/opt/homebrew/bin/python3',['-I','-B','-c',program+'\n'+body],{encoding:'utf8',timeout:10000,maxBuffer:65536});assert.equal(result.status,0,result.stderr);return result.stdout;}
test('closed specification stays disconnected from builder and accepts no arbitrary origin',()=>{
 assert.deepEqual(HOSTS,['registry-1.docker.io','auth.docker.io','deb.debian.org']);
 assert.equal(LIMITS.wholeSeconds,300);assert.equal(LIMITS.concurrency,4);
 for(const spec of [{runId:'../escape',uid:501,mode:'connector'},{runId:'a'.repeat(32),uid:0,mode:'connector'},{runId:'a'.repeat(32),uid:501,mode:'proxy'}])assert.throws(()=>guestProgram(spec));
 assert.match(guestProgram({runId:'a'.repeat(32),uid:501,mode:'adapter',deadlineFromArgv:true}),/dvaia-v23-relay-aaaaaaaa/);
 assert.throws(()=>guestProgram({runId:'a'.repeat(32),uid:501,mode:'adapter'}));
 assert.doesNotMatch(program,/CERT_NONE|check_hostname\s*=\s*False|iptables|ip link|docker.sock/);
});
test('CONNECT grammar rejects alternate destinations, credentials, bodies and header confusion',()=>python(String.raw`
def denied(callback):
    try: callback()
    except Denied: return
    raise AssertionError('accepted')
for host in HOST_LIMITS:
    assert authority(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode())==host
for raw in [b'CONNECT localhost:443 HTTP/1.1\r\n\r\n',b'CONNECT registry-1.docker.io:80 HTTP/1.1\r\n\r\n',b'CONNECT registry-1.docker.io.:443 HTTP/1.1\r\n\r\n',b'CONNECT 8.8.8.8:443 HTTP/1.1\r\n\r\n',b'GET https://registry-1.docker.io HTTP/1.1\r\n\r\n',b'CONNECT auth.docker.io:443 HTTP/1.1\r\nHost: deb.debian.org:443\r\n\r\n',b'CONNECT auth.docker.io:443 HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n',b'CONNECT auth.docker.io:443 HTTP/1.1\r\nHost: auth.docker.io:443\r\nHost: auth.docker.io:443\r\n\r\n',b'x'*8193]: denied(lambda:authority(raw))
`));
test('independent numeric CRLF bytes and actual HTTP/1.1 socketpair response',()=>python(String.raw`
crlf=bytes([13,10]);request=b'CONNECT auth.docker.io:443 HTTP/1.1'+crlf+b'Host: auth.docker.io:443'+crlf+crlf
assert authority(request)=='auth.docker.io'
left,right=socket.socketpair()
try:
    left.settimeout(1);right.settimeout(1);left.sendall(request)
    received=header(right,time.monotonic()+1);assert received==request;assert authority(received)=='auth.docker.io'
    established(right)
    assert left.recv(100)==b'HTTP/1.1 200 Connection Established'+bytes([13,10,13,10])
    literal=request.replace(bytes([13,10]),bytes([92,114,92,110]))
    try: authority(literal)
    except Denied: pass
    else: raise AssertionError('literal escapes admitted')
finally: left.close();right.close()
`));
test('cancellation during DNS or immediately before connect cannot start external connection',()=>python(String.raw`
from unittest.mock import patch,Mock
for phase in ('before','dns','connect'):
    stop=threading.Event();remote=Mock()
    if phase=='before': stop.set()
    def resolved(*args):
        if phase=='dns': stop.set()
        return ['8.8.8.8']
    def tracked(sock):
        if phase=='connect': stop.set()
    with patch('__main__.resolve',side_effect=resolved) as lookup,patch.object(socket,'socket',return_value=remote) as factory:
        try: connect_public('auth.docker.io',time.monotonic()+3,stop,tracked)
        except Denied: pass
        else: raise AssertionError('cancelled connection')
        remote.connect.assert_not_called()
        if phase=='before': lookup.assert_not_called()
        if phase in ('before','dns'): factory.assert_not_called()
        else: remote.close.assert_called_once()
`));
test('resolver reap is bounded and reports unresolved ownership instead of silently hanging',()=>python(String.raw`
from unittest.mock import patch,Mock
read,write=os.pipe();os.write(write,b'["8.8.8.8"]');os.close(write)
child=Mock();child.stdout=os.fdopen(read,'rb');child.poll.return_value=None
child.wait.side_effect=subprocess.TimeoutExpired('controlled',.5);debt=[]
with patch.object(subprocess,'Popen',return_value=child):
    try: resolve('auth.docker.io',time.monotonic()+1,threading.Event(),debt)
    except Denied: pass
    else: raise AssertionError('unreaped accepted')
assert debt==[child];child.kill.assert_called_once()
assert all(call.kwargs.get('timeout',0)>0 for call in child.wait.call_args_list)
assert child.wait.call_args.kwargs['timeout']==.5
`));
test('resolver ownership survives selector allocation and all unexpected cleanup failures',()=>python(String.raw`
from unittest.mock import patch,Mock
for failure in ('allocation','selector-close','stdout-close','kill','wait'):
    debt=[];child=Mock();child.stdout=Mock();child.poll.return_value=None;child.wait.return_value=0
    selector=Mock();selector.register.side_effect=RuntimeError('stop before reading')
    if failure=='selector-close': selector.close.side_effect=OSError('controlled')
    if failure=='stdout-close': child.stdout.close.side_effect=OSError('controlled')
    if failure=='kill': child.kill.side_effect=OSError('controlled')
    if failure=='wait': child.wait.side_effect=OSError('controlled')
    def allocate():
        assert debt==[child], 'spawn must be recorded before selector allocation'
        if failure=='allocation': raise RuntimeError('controlled')
        return selector
    with patch.object(subprocess,'Popen',return_value=child),patch.object(selectors,'DefaultSelector',side_effect=allocate):
        try: resolve('auth.docker.io',time.monotonic()+1,threading.Event(),debt)
        except (Denied,RuntimeError): pass
        else: raise AssertionError('failure swallowed')
    child.stdout.close.assert_called_once();child.kill.assert_called_once();child.wait.assert_called_once_with(timeout=.5)
    assert debt==([] if failure=='allocation' else [child])
`));
test('thread startup failure closes accepted client without joining an unstarted worker',()=>python(String.raw`
from unittest.mock import patch,Mock
listener=Mock();client=Mock();listener.accept.return_value=(client,None);thread=Mock();thread.start.side_effect=RuntimeError('controlled')
with patch('__main__.private_directory'),patch('__main__.socket_identity',return_value=(1,2)),patch('__main__.remove_owned_socket'),patch.object(os.path,'lexists',return_value=False),patch.object(socket,'socket',return_value=listener),patch.object(threading,'Thread',return_value=thread):
    try: serve('connector','/owned',501,time.monotonic()+30)
    except RuntimeError: pass
    else: raise AssertionError('startup error lost')
client.close.assert_called();listener.close.assert_called();thread.join.assert_not_called()
`));
test('both relay modes require one original guest-monotonic deadline before any effects',()=>python(String.raw`
from unittest.mock import patch,Mock
with patch.object(time,'monotonic',return_value=100):
    assert deadline_from_argv(['-', '350.25'])==350.25
    assert validate_deadline(400)==400
    for argv in [[],['-'],['-','350','extra'],['-','nan'],['-','inf'],['-','1e3'],['-','+350'],['-','100'],['-','400.01'],['-','0']]:
        try: deadline_from_argv(argv)
        except Denied: pass
        else: raise AssertionError(argv)
    for mode in ('connector','adapter'):
        for invalid in (True,float('nan'),float('inf'),100,401):
            with patch('__main__.private_directory') as admission,patch.object(socket,'socket') as socket_factory:
                try: serve(mode,'/owned',501,invalid)
                except Denied: pass
                else: raise AssertionError('invalid deadline')
                admission.assert_not_called();socket_factory.assert_not_called()
with patch.object(time,'monotonic',return_value=349):
    assert deadline_from_argv(['-','350.25'])==350.25 # Later adapter does not renew deadline.
with patch.object(time,'monotonic',return_value=351):
    try: deadline_from_argv(['-','350.25'])
    except Denied: pass
    else: raise AssertionError('expired shared deadline')
`));
test('public numeric addresses only and a single resolved destination are bound before connect',()=>python(String.raw`
from unittest.mock import patch,Mock
for value in ['127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1','0.0.0.0','224.0.0.1','::1','fc00::1','fe80::1','::ffff:8.8.8.8','64:ff9b::808:808','example.com']:
    try: public_address(value)
    except Denied: pass
    else: raise AssertionError(value)
assert public_address('8.8.8.8')=='8.8.8.8'
fake=Mock();fake.getpeername.return_value=('8.8.8.8',443)
with patch('__main__.resolve',return_value=['8.8.8.8']) as resolver,patch.object(socket,'socket',return_value=fake):
    assert connect_public('auth.docker.io',time.monotonic()+10) is fake
    resolver.assert_called_once();fake.connect.assert_called_once_with(('8.8.8.8',443))
fake.getpeername.return_value=('127.0.0.1',443)
with patch('__main__.resolve',return_value=['8.8.8.8']),patch.object(socket,'socket',return_value=fake):
    try: connect_public('auth.docker.io',time.monotonic()+10)
    except Denied: pass
    else: raise AssertionError('peer drift')
assert fake.close.called
`));
test('byte and lifetime connection accounting deny before exceeding immutable limits',()=>python(String.raw`
b=Budget()
for i in range(32): b.admit()
try: b.admit()
except Denied: pass
else: raise AssertionError('connections')
b.charge('auth.docker.io',1048576)
try: b.charge('auth.docker.io',1)
except Denied: pass
else: raise AssertionError('host cap')
assert b.total==1048576
b.total=TOTAL
try: b.charge('deb.debian.org',1)
except Denied: pass
else: raise AssertionError('aggregate cap')
`));
test('opaque duplex transport preserves bytes and cancellation without external sockets',()=>python(String.raw`
a,left=socket.socketpair();right,b=socket.socketpair();stop=threading.Event();budget=Budget();failures=[]
def run():
    try: pump(left,right,'auth.docker.io',budget,time.monotonic()+3,stop)
    except Denied: failures.append('stopped')
thread=threading.Thread(target=run);thread.start()
try:
    a.settimeout(2);b.settimeout(2)
    a.sendall(b'opaque TLS client bytes');assert b.recv(100)==b'opaque TLS client bytes'
    b.sendall(b'opaque TLS server bytes');assert a.recv(100)==b'opaque TLS server bytes'
    stop.set();thread.join(2);assert not thread.is_alive();assert budget.total==46
finally:
    stop.set()
    for sock in (a,left,right,b): sock.close()
assert failures==['stopped']
`));
test('owned directory/socket and Linux peer credentials reject wrong identity',()=>python(String.raw`
import tempfile
from unittest.mock import patch,Mock
with tempfile.TemporaryDirectory() as directory:
    os.chmod(directory,0o700);uid=os.getuid()
    if uid>0: private_directory(os.path.realpath(directory),uid)
    path=os.path.join(directory,'connector.sock')
    info=Mock(st_mode=stat.S_IFSOCK|0o600,st_uid=uid,st_dev=1,st_ino=2)
    with patch.object(os,'lstat',return_value=info):
        assert socket_identity(path,uid)==(1,2)
        info.st_mode=stat.S_IFSOCK|0o666
        try: socket_identity(path,uid)
        except Denied: pass
        else: raise AssertionError('mode')
fake=Mock();fake.getsockopt.return_value=struct.pack('3i',123,501,501)
with patch.object(socket,'SO_PEERCRED',17,create=True):
    peer_uid(fake,501)
    try: peer_uid(fake,502)
    except Denied: pass
    else: raise AssertionError('foreign peer')
`));
test('DNS result admission rejects mixed private answers and joins its exact owned resolver',()=>python(String.raw`
from unittest.mock import patch,Mock
for answer,accepted in [(['8.8.8.8'],True),(['8.8.8.8','127.0.0.1'],False),([],False)]:
    read,write=os.pipe();os.write(write,json.dumps(answer).encode());os.close(write)
    child=Mock();child.stdout=os.fdopen(read,'rb');child.wait.return_value=0;child.poll.return_value=0
    with patch.object(subprocess,'Popen',return_value=child) as launch:
        try: result=resolve('auth.docker.io',time.monotonic()+2)
        except Denied: assert not accepted
        else: assert accepted and result==answer
        assert child.wait.called
        args=launch.call_args.args[0];assert args[-1]=='auth.docker.io';assert args[1:3]==['-I','-S']
with patch.object(subprocess,'Popen') as launch:
    try: resolve('auth.docker.io',time.monotonic()-1)
    except Denied: pass
    else: raise AssertionError('expired')
    launch.assert_not_called()
`));
test('expired relay performs no read and cleanup denies changed socket or ancestors before unlink',()=>python(String.raw`
from unittest.mock import patch,Mock
left,right=socket.socketpair()
try:
    try: pump(left,right,'auth.docker.io',Budget(),time.monotonic()-1,threading.Event())
    except Denied: pass
    else: raise AssertionError('deadline')
finally: left.close();right.close()
for changed in (False,True):
    with patch('__main__.private_directory'),patch('__main__.socket_identity',return_value=(1,3) if changed else (1,2)),patch.object(os,'unlink') as unlink:
        try: remove_owned_socket('/owned','/owned/connector.sock',501,(1,2))
        except Denied: assert changed
        else: assert not changed
        assert unlink.called is (not changed)
with patch('__main__.private_directory',side_effect=Denied('path')),patch.object(os,'unlink') as unlink:
    try: remove_owned_socket('/owned','/owned/connector.sock',501,(1,2))
    except Denied: pass
    else: raise AssertionError('ancestor')
    unlink.assert_not_called()
`));
