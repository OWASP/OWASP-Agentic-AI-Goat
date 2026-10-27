"""Fixed host state-machine controls; bridge/socket/process effects mocked."""
import unittest
from unittest.mock import patch
import v03_listings_bridge_host as subject

class Bridge:
    def __init__(self,*args):self.args=args;self.claims=[];self.closes=0
    def open(self):return 'http://127.0.0.1:1234'
    def claim(self,*args,**kwargs):self.claims.append((args,kwargs))
    def close(self,deadline):
        self.closes+=1
        return dict(listenerClosed=True,localChannelsRetired=True,remoteChannelsVerified=False,
            channelIds=['c'*32],channelStates=[{'channelId':'c'*32,'state':'spawn_attempted'}],failures=[])

class Controls(unittest.TestCase):
    def setUp(self):
        self.now=100
        p=patch.object(subject.time,'monotonic',side_effect=lambda:self.now);p.start();self.addCleanup(p.stop)
        p=patch.object(subject,'V03ListingsBridge',Bridge);p.start();self.addCleanup(p.stop)
        self.host=subject.Host('/synthetic','a'*32,'b'*32,'d'*64,'e'*64)
    def request(self,op,payload,sequence=None):
        return dict(version=1,runId='a'*32,planSha256='d'*64,sequence=self.host.sequence if sequence is None else sequence,op=op,payload=payload)
    def test_start_claim_close_exact_once(self):
        result=self.host.dispatch(self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000}))
        self.assertEqual(result['result']['origin'],'http://127.0.0.1:1234')
        self.host.dispatch(self.request('claim',dict(handoff={},hostDeadlineMs=1310000,activationDeadlineMs=110000,guestRecord={})))
        receipt=self.host.dispatch(self.request('close',{}))['result']
        self.assertFalse(receipt['remoteChannelsVerified']);self.assertEqual(receipt['channelIds'],['c'*32])
        self.assertEqual(self.host.close(),receipt);self.assertEqual(self.host.bridge.closes,1)
    def test_expired_request_never_constructs_bridge(self):
        self.now=111
        with self.assertRaises(ValueError):self.host.dispatch(self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000}))
        self.assertIsNone(self.host.bridge)
    def test_foreign_sequence_and_duplicate_start_denied(self):
        with self.assertRaises(ValueError):self.host.dispatch(self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000},1))
        self.host.dispatch(self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000}))
        with self.assertRaises(ValueError):self.host.dispatch(self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000}))
    def test_close_after_expiry_still_retires_actual_local_bridge(self):
        self.host.dispatch(self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000}));self.now=12000
        self.assertTrue(self.host.close()['localChannelsRetired']);self.assertEqual(self.host.bridge.closes,1)
    def test_duplicate_keys_denied(self):
        with self.assertRaises(ValueError):subject.unique([('a',1),('a',2)])
    def test_actual_main_loop_eof_closes_bridge_and_preserves_terminal_channels(self):
        request=self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000})
        writes=[]
        with patch.object(subject.sys,'platform','darwin'),\
                patch.object(subject.sys,'argv',['host','/synthetic','a'*32,'b'*32,'d'*64,'e'*64]),\
                patch.object(subject.os,'set_blocking'),patch.object(subject,'read_frame',side_effect=[request,EOFError('lost parent')]),\
                patch.object(subject,'write_frame',side_effect=lambda fd,row:writes.append(row)):
            with self.assertRaises(EOFError):subject.main()
        self.assertEqual(writes[-1]['stage'],'terminal')
        self.assertEqual(writes[-1]['failure'],'EOFError')
        self.assertEqual(writes[-1]['local']['channelIds'],['c'*32])
        self.assertFalse(writes[-1]['local']['remoteChannelsVerified'])
        self.assertTrue(writes[-1]['cleanupDebt'])
    def test_constructor_source_close_debt_survives_no_bridge_terminal(self):
        request=self.request('start',{'startupDeadlineMs':160000,'parentDeadlineMs':11000000})
        primary=ValueError('source primary');primary.cleanupDebt=True;primary.leaseSourceCloseUnproven=True
        writes=[]
        with patch.object(subject.sys,'platform','darwin'),\
                patch.object(subject.sys,'argv',['host','/synthetic','a'*32,'b'*32,'d'*64,'e'*64]),\
                patch.object(subject.os,'set_blocking'),patch.object(subject,'read_frame',return_value=request),\
                patch.object(subject,'V03ListingsBridge',side_effect=primary),\
                patch.object(subject,'write_frame',side_effect=lambda fd,row:writes.append(row)):
            with self.assertRaises(ValueError) as caught:subject.main()
        self.assertIs(caught.exception,primary)
        self.assertTrue(writes[-1]['cleanupDebt']);self.assertTrue(writes[-1]['leaseSourceCloseUnproven'])

if __name__=='__main__':unittest.main()
