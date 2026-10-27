"""Real local socket framing with controlled peers; no producer/build/model."""
import json,socket,threading,time,unittest,pathlib,subprocess
from listings_phase_client import ListingsPhaseClient,ListingsPhaseDebt

RUN='a'*32; PLAN='b'*64

class PhaseClientTests(unittest.TestCase):
    def test_actual_python_fd_to_node_endpoint_and_original_listings_lifetime(self):
        root=pathlib.Path(__file__).resolve().parents[2]
        script=r'''
const net=require('node:net');
const {serveListingsPhases}=require('./tests/postgres/listingsPhaseEndpoint');
const adapter=require('./tests/postgres/ownedMcpOriginalBuildAdapter');
const {performance}=require('node:perf_hooks');let clockOffset=0;
const runId='a'.repeat(32),planSha256='b'.repeat(64),mode=process.argv[2];
let confirmed=0,cancelled=0;const effects=[];
const base={assertOpen(){},assertActive(){},assertRetirementAdmission(){if(mode==='confirm-expired'&&effects.length===6)clockOffset=2000000;},joinPhase:fn=>fn(),
 confirmRetired(){confirmed++;},expireWork(){cancelled++;},signal:new AbortController().signal,retirementSignal:new AbortController().signal};
const plan={spec:{runId},listingsConsumer:{mode:'manager',name:'controlled'}};
const lifetime=adapter._internals.listingsLifetime(base,plan,async name=>{
 effects.push(name);if(mode==='stall')return new Promise(()=>{});
 return name==='listingsManagerChannels'?JSON.stringify({version:1,runId,remoteChannelsAbsent:true,channels:[]}):name.includes('Retire')?'absent':'controlled';
});
serveListingsPhases(new net.Socket({fd:Number(process.argv[1]),readable:true,writable:true}),{runId,planSha256},lifetime,{now:()=>performance.now()+clockOffset})
 .then(()=>process.stdout.write(JSON.stringify({confirmed,cancelled,effects,passed:true})),error=>process.stdout.write(JSON.stringify({confirmed,cancelled,effects,passed:false,code:error.code})));
'''
        for mode in ('normal','order','stall','confirm-expired'):
            local,remote=socket.socketpair()
            child=subprocess.Popen([str(root/'tasks/runtime/node/node_modules/node/bin/node'),'-e',script,str(remote.fileno()),mode],
                cwd=root,pass_fds=(remote.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            remote.close();client=ListingsPhaseClient(local,RUN,PLAN,time.monotonic()+3)
            try:
                client.admit()
                if mode=='order':
                    with self.assertRaises(ListingsPhaseDebt):client.run_phase('listingsManagerStart')
                elif mode=='stall':
                    client.work_deadline=time.monotonic()+.1
                    with self.assertRaises(ListingsPhaseDebt):client.run_phase('listingsProfileInstall')
                else:
                    client.run_phase('listingsProfileInstall')
                    client.run_phase('listingsManagerCreate',dict(origin='http://127.0.0.1:1234',token='x'*48))
                    client.run_phase('listingsManagerStart');client.begin_retirement(time.monotonic()+1)
                    client.run_phase('listingsManagerChannels',dict(channelIds=[],listenerClosed=True,localChannelsRetired=True))
                    client.run_phase('listingsManagerRetire');client.run_phase('listingsProfileRetire')
                    if mode=='confirm-expired':
                        with self.assertRaises(ListingsPhaseDebt):client.confirm_retired()
                    else:client.confirm_retired()
                out,err=child.communicate(timeout=4);self.assertEqual(child.returncode,0,err)
                result=json.loads(out)
                self.assertEqual(result['confirmed'],1 if mode=='normal' else 0)
                self.assertEqual(result['passed'],mode=='normal')
                if mode=='order':self.assertEqual(result['effects'],[])
                if mode=='stall':self.assertGreater(result['cancelled'],0)
            finally:
                client.close()
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=1)
                    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=1)
                child.stdout.close();child.stderr.close()
    def test_actual_nonstream_socket_is_rejected(self):
        for kind in (socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
            try: local,remote=socket.socketpair(socket.AF_UNIX,kind)
            except OSError:
                if kind==socket.SOCK_SEQPACKET:continue  # Unsupported OS transport, never admitted.
                raise
            try:
                with self.assertRaises(ValueError):ListingsPhaseClient(local,RUN,PLAN,time.monotonic()+1)
            finally:local.close();remote.close()
    def peer(self, mode='normal', duration=2):
        local,remote=socket.socketpair();frames=[];errors=[]
        client=ListingsPhaseClient(local,RUN,PLAN,time.monotonic()+duration)
        def send(op,sequence,**payload):
            frame=dict(version=1,op=op,runId=RUN,planSha256=PLAN,sequence=sequence,**payload)
            if mode=='wrong-plan':frame['planSha256']='c'*64
            if mode=='wrong-sequence':frame['sequence']+=1
            if mode=='duplicate-key':
                remote.sendall((json.dumps(frame)[:-1]+',"version":1}\n').encode());return
            if mode=='oversize':
                remote.sendall(b'x'*65537+b'\n');return
            remote.sendall((json.dumps(frame)+'\n').encode())
        def work():
            try:
                remote.settimeout(3)
                send('hello',0)
                stream=remote.makefile('rb')
                try:
                    for raw in stream:
                        row=json.loads(raw);frames.append(row)
                        if mode=='stall':continue
                        op=row['op'];seq=row['sequence']
                        if op=='admit':send('admitted',seq)
                        elif op=='retirement':send('retirement-admitted',seq)
                        elif op=='phase':send('result',seq,name=row['name'],output='absent')
                        elif op=='confirm':send('retired',seq)
                finally:stream.close()
            except (OSError,ValueError) as error:errors.append(type(error).__name__)
            finally:remote.close()
        thread=threading.Thread(target=work);thread.start()
        self.addCleanup(lambda: self.finish(client,thread))
        return client,frames,thread

    def finish(self,client,thread):
        client.close();thread.join(3);self.assertFalse(thread.is_alive())

    def test_real_frames_bind_run_plan_sequence_and_single_cleanup_window(self):
        client,frames,thread=self.peer();client.admit()
        client.run_phase('listingsProfileInstall')
        end=time.monotonic()+1;client.begin_retirement(end)
        for name in ('listingsManagerChannels','listingsManagerRetire','listingsProfileRetire'):client.run_phase(name)
        client.confirm_retired();self.assertTrue(client.confirmed)
        self.assertEqual([r['sequence'] for r in frames],list(range(len(frames))))
        with self.assertRaises(ValueError):client.begin_retirement(end+.1)
        with self.assertRaises(ValueError):client.confirm_retired()

    def test_stalled_peer_is_bounded_poisoned_and_local_socket_closed(self):
        client,frames,thread=self.peer('stall',.05);started=time.monotonic()
        with self.assertRaises(ListingsPhaseDebt):client.admit()
        self.assertLess(time.monotonic()-started,.5)
        self.assertTrue(client.debt and client.closed);self.assertFalse(client.confirmed)

    def test_wrong_plan_is_debt_without_dispatch(self):
        client,frames,thread=self.peer('wrong-plan')
        with self.assertRaises(ListingsPhaseDebt):client.admit()
        self.assertEqual(frames,[])

    def test_expired_confirmation_never_sent(self):
        client,frames,thread=self.peer();client.admit();client.begin_retirement(time.monotonic()+1)
        for name in ('listingsManagerChannels','listingsManagerRetire','listingsProfileRetire'):client.run_phase(name)
        client.now=lambda:client.cleanup_deadline+1
        with self.assertRaises(ListingsPhaseDebt):client.confirm_retired()
        self.assertNotIn('confirm',[r['op'] for r in frames])

    def test_unknown_duplicate_and_wrong_window_never_dispatch(self):
        client,frames,thread=self.peer();client.admit()
        with self.assertRaises(ValueError):client.run_phase('arbitrary-command')
        with self.assertRaises(ValueError):client.run_phase('listingsManagerRetire')
        client.run_phase('listingsProfileInstall')
        with self.assertRaises(ValueError):client.run_phase('listingsProfileInstall')

    def test_malformed_oversize_and_wrong_sequence_poison_before_dispatch(self):
        for mode in ('duplicate-key','oversize','wrong-sequence'):
            client,frames,thread=self.peer(mode)
            with self.subTest(mode=mode),self.assertRaises(ListingsPhaseDebt):client.admit()
            self.assertEqual(frames,[]);self.assertTrue(client.closed and client.debt)

if __name__=='__main__':unittest.main()
