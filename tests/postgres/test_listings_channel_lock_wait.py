"""Actual emitted-block controls; root identity/network prerequisites mocked explicitly."""
import ast,fcntl,importlib.util,json,os,stat,tempfile,threading,time,types,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
import listings_native_resources as resource
CODE=resource._PRIVATE_CHANNEL
BLOCK=CODE[CODE.index("lock=os.open(root/'listings-channel.lock'"):CODE.index('sock=None;complete=False;sent=received=0')].replace('ls.st_uid==0','ls.st_uid==os.getuid()')
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='emitted-lock-',dir=HERE.parents[1]/'tasks/tmp');self.root=Path(self.tmp.name);self.opened=set()
  def op(*a):fd=os.open(*a);self.opened.add(fd);return fd
  def close(fd):self.assertIn(fd,self.opened);self.opened.remove(fd);os.close(fd)
  self.ops=types.SimpleNamespace(**{n:getattr(os,n) for n in dir(os) if not n.startswith('__')});self.ops.open=op;self.ops.close=close
 def tearDown(self):
  self.assertEqual(self.opened,set());self.tmp.cleanup()
 def runblock(self,deadline,flock=fcntl.flock):
  def need(ok):
   if not ok:raise RuntimeError('denied')
  ns=dict(root=self.root,CHANNEL='a'*32,end=deadline,os=self.ops,stat=stat,fcntl=types.SimpleNamespace(flock=flock,LOCK_EX=fcntl.LOCK_EX,LOCK_NB=fcntl.LOCK_NB),time=time,json=json,need=need,H={'runId':'b'*32,'namespaceInode':1},birth=lambda pid:1)
  try:exec(BLOCK,ns)
  finally:
   if ns.get('admitted'):self.ops.close(ns['journal'])
  return ns
 def test_expired_entry(self):
  with self.assertRaises(RuntimeError):self.runblock(time.monotonic()-1)
 def test_actual_emitters_retirement_prefix_unchanged(self):
  module=types.SimpleNamespace(private_channel_program=resource.private_channel_program,private_channels_retirement_program=resource.private_channels_retirement_program)
  original=resource.private_handoff;resource.private_handoff=lambda h:h
  self.addCleanup(setattr,resource,'private_handoff',original)
  retirement=module.private_channels_retirement_program({'runId':'b'*32},[])
  channel=module.private_channel_program({'runId':'b'*32},'a'*32,1)
  ast.parse(retirement);ast.parse(channel)
  prefix=CODE[:CODE.index('child=subprocess.Popen')]
  self.assertEqual(__import__('hashlib').sha256(prefix.encode()).hexdigest(),'633626e3e5de004ec79b4e689ad7667a282ccd2c1121b1fc03438510e8d76339')
  self.assertEqual(CODE[:CODE.index('child=subprocess.Popen')],prefix)
  self.assertIn(prefix,retirement)
  self.assertNotIn('SECONDS',retirement)
  self.assertEqual(channel.count('end=__import__("time").monotonic()+SECONDS'),1)
  # Execute actual retirement prefix with filesystem/identity guard calls mocked.
  # Keep assignments/imports/functions: a new deadline assignment would execute.
  tree=ast.parse(prefix)
  class MockGuards(ast.NodeTransformer):
   def visit_Expr(self,node):return ast.Pass()
   def visit_For(self,node):return ast.Pass()
  tree=MockGuards().visit(tree)
  # Root stat is the sole top-level physical filesystem read in this prefix.
  for node in tree.body:
   if isinstance(node,ast.Assign) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and node.value.func.attr=='stat':node.value=ast.Constant(None)
  exec(compile(ast.fix_missing_locations(tree),'actual-retirement-prefix','exec'),{'H':{'root':str(self.root)}})
 def test_late_acquisition(self):
  def late(*args):fcntl.flock(*args);time.sleep(.03)
  with self.assertRaises(RuntimeError):self.runblock(time.monotonic()+.01,late)
  self.assertFalse((self.root/('listings-channel-'+'a'*32+'.jsonl')).exists())
 def test_unexpected_error(self):
  def fail(*args):raise PermissionError('test')
  with self.assertRaises(PermissionError):self.runblock(time.monotonic()+1,fail)
 def test_fence(self):
  (self.root/'listings-channel-admission-closed').touch()
  with self.assertRaises(RuntimeError):self.runblock(time.monotonic()+1)
 def test_duplicate_journal(self):
  (self.root/('listings-channel-'+'a'*32+'.jsonl')).touch()
  with self.assertRaises(FileExistsError):self.runblock(time.monotonic()+1)
 def test_release_and_shared_connect_budget(self):
  path=self.root/'listings-channel.lock';path.touch(mode=0o600);held=os.open(path,os.O_RDWR);fcntl.flock(held,fcntl.LOCK_EX)
  t=threading.Thread(target=lambda:(time.sleep(.03),os.close(held)));t.start();deadline=time.monotonic()+.3
  try:ns=self.runblock(deadline)
  finally:t.join()
  calls=[]
  sock=types.SimpleNamespace(settimeout=lambda x:calls.append(x),connect=lambda target:None,setblocking=lambda value:None)
  ns['socket']=types.SimpleNamespace(socket=lambda:sock)
  start=CODE.index(' remaining=end-time.monotonic();need(remaining>0)',CODE.index('sock=None;'))
  fragment=CODE[start:CODE.index(' os.set_blocking',start)]
  exec('\n'.join(line[1:] for line in fragment.splitlines()),ns)
  self.assertGreater(calls[0],0);self.assertLess(calls[0],.28);self.assertEqual(ns['end'],deadline)
  self.assertNotIn('end=',CODE[CODE.index(' incoming=bytearray()'):]);self.assertIn('while time.monotonic()<end:',CODE)
 def test_sustained_contention(self):
  path=self.root/'listings-channel.lock';path.touch(mode=0o600);held=os.open(path,os.O_RDWR);fcntl.flock(held,fcntl.LOCK_EX)
  try:
   with self.assertRaises(RuntimeError):self.runblock(time.monotonic()+.03)
  finally:os.close(held)
 def test_fence_while_waiting(self):
  path=self.root/'listings-channel.lock';path.touch(mode=0o600);held=os.open(path,os.O_RDWR);fcntl.flock(held,fcntl.LOCK_EX)
  def release():time.sleep(.03);(self.root/'listings-channel-admission-closed').touch();os.close(held)
  t=threading.Thread(target=release);t.start()
  try:
   with self.assertRaises(RuntimeError):self.runblock(time.monotonic()+.3)
  finally:t.join()
if __name__=='__main__':unittest.main()
