import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin/node')
NODEMON=ROOT/'node_modules/nodemon/bin/nodemon.js'

def alive(pid):
    try: os.kill(pid,0);return True
    except ProcessLookupError: return False

def wait_until(predicate,seconds=10):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=predicate()
        if value:return value
        time.sleep(.05)
    raise TimeoutError('disposable nodemon condition was not observed')

class NodemonRestartIntegrationTest(unittest.TestCase):
    def test_clean_child_exit_waits_then_sighup_restarts_distinct_child(self):
        with tempfile.TemporaryDirectory(prefix='dvaia-nodemon-restart-') as directory:
            root=Path(directory);pid_file=root/'child.pid'
            (root/'child.js').write_text("require('fs').writeFileSync(process.env.PID_FILE,String(process.pid));setInterval(()=>{},1000);\n")
            (root/'nodemon.json').write_text('{"watch":["."],"ext":"js","delay":"50"}\n')
            env=dict(os.environ,PID_FILE=str(pid_file))
            watcher=subprocess.Popen([str(NODE),str(NODEMON),'--quiet','--config',str(root/'nodemon.json'),'child.js'],
              cwd=root,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            try:
                first=int(wait_until(lambda:int(pid_file.read_text()) if pid_file.exists() else 0))
                os.kill(first,signal.SIGTERM)
                wait_until(lambda:not alive(first))
                time.sleep(.35)
                self.assertEqual(int(pid_file.read_text()),first)
                os.kill(watcher.pid,signal.SIGHUP)
                second=int(wait_until(lambda:(lambda value:value if value!=first else 0)(int(pid_file.read_text()))))
                self.assertNotEqual(second,first);self.assertTrue(alive(second))
            finally:
                try: os.killpg(watcher.pid,signal.SIGTERM)
                except ProcessLookupError: pass
                try: watcher.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(watcher.pid,signal.SIGKILL);watcher.wait(timeout=5)

if __name__=='__main__': unittest.main()
