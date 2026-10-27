"""Real filesystem regression for the currently generated V03 grant writer."""
import os,stat,tempfile,unittest,json,types,ast
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def current_block():
 source=(ROOT/'tests/postgres/ownedSystemDiagnosticBuildAdapter.js').read_text()
 # Decode the actual JS replacement strings, then its embedded Python literal.
 line=next(x for x in source.splitlines() if x.startswith('  text = replaceOnce(text, "+metadataIdleProgram:'))
 decoder=json.JSONDecoder();args=line.split('replaceOnce(text, ',1)[1]
 _,end=decoder.raw_decode(args);replacement,_=decoder.raw_decode(args[end+2:])
 prefix='+metadataIdleProgram+';assert replacement.startswith(prefix)
 controller,_=decoder.raw_decode(replacement[len(prefix):])
 fn=next(n for n in ast.parse(controller).body if isinstance(n,ast.FunctionDef) and n.name=='v03_credit')
 blocks=[n for n in fn.body if isinstance(n,ast.With)]
 assert len(blocks)==1
 # Preserve the generated writer; no historical proposal or hash dependency.
 block='\n'.join('    '+line for line in ast.unparse(blocks[0]).splitlines())
 return source,block
class Mode(unittest.TestCase):
 def test_real_umask_descriptor_mode_and_cleanup_predicate(self):
  transformed,body=current_block();self.assertIn('os.fchmod',transformed)
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp',prefix='v03-credit-mode-') as directory:
   path=Path(directory)/'credit.json';mask=os.umask(0o077)
   try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
   finally:os.umask(mask)
   self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o400)
   # Execute exact proposed block with only root-UID expectation mapped to
   # current test UID; production identity checks remain byte-for-byte intact.
   program='if True:\n'+body.replace('before.st_uid == 0','before.st_uid == os.getuid()')
   def require(v):self.assertTrue(v)
   exec(program,dict(os=os,stat=stat,json=json,fd=fd,row={'version':1},require=require))
   info=path.lstat();self.assertTrue(stat.S_ISREG(info.st_mode));self.assertEqual(info.st_nlink,1);self.assertEqual(stat.S_IMODE(info.st_mode),0o444)
   self.assertEqual(json.loads(path.read_bytes()),{'version':1})
   with self.assertRaises(FileExistsError):os.open(path,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o444)
 def test_no_follow_and_failure_before_publication(self):
  _,body=current_block();self.assertLess(body.index('os.fchmod'),body.index('os.fsync'));self.assertLess(body.index('os.fsync'),body.index('after = os.fstat'))
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp',prefix='v03-credit-mode-') as directory:
   target=Path(directory)/'target';target.touch();link=Path(directory)/'credit';link.symlink_to(target)
   with self.assertRaises(FileExistsError):os.open(link,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
 def test_generated_body_failure_paths_close_descriptor(self):
  _,body=current_block();program='if True:\n'+body.replace('before.st_uid == 0','before.st_uid == os.getuid()')+'\ncompleted=True'
  for mode in ['hardlink','chmod','sync','postmode','postinode','postlinks']:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp',prefix='v03-credit-mode-') as directory:
    p=Path(directory)/'credit';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    if mode=='hardlink':os.link(p,Path(directory)/'second')
    calls=[];sentinel=OSError('controlled');count=0
    def chmod(f,m):
     calls.append('chmod');self.assertEqual(json.loads(p.read_bytes()),{'version':1})
     if mode=='chmod':raise sentinel
     return os.fchmod(f,m)
    def sync(f):
     calls.append('sync')
     if mode=='sync':raise sentinel
     return os.fsync(f)
    def fstat(f):
     nonlocal count
     count+=1;r=os.fstat(f)
     if count==2 and mode.startswith('post'):
      fields={k:getattr(r,k) for k in ['st_mode','st_uid','st_nlink','st_dev','st_ino']}
      fields[{'postmode':'st_mode','postinode':'st_ino','postlinks':'st_nlink'}[mode]]={'postmode':stat.S_IFREG|0o400,'postinode':r.st_ino+1,'postlinks':2}[mode]
      return types.SimpleNamespace(**fields)
     return r
    proxy=types.SimpleNamespace(fdopen=os.fdopen,getuid=os.getuid,fchmod=chmod,fsync=sync,fstat=fstat)
    env=dict(os=proxy,stat=stat,json=json,fd=fd,row={'version':1},require=lambda v:self.assertTrue(v))
    with self.assertRaises((OSError,AssertionError)) as caught:exec(program,env)
    if mode in ['chmod','sync']:self.assertIs(caught.exception,sentinel)
    if mode=='hardlink':self.assertEqual(calls,[])
    self.assertNotIn('completed',env)
    with self.assertRaises(OSError):os.fstat(fd)
if __name__=='__main__':unittest.main()

