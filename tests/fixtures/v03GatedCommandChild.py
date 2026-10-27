#!/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python
import subprocess,sys,time
mode=sys.argv[-1]
if mode=='slow':time.sleep(.15)
elif mode=='descendant':
 child=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(.15)'])
 child.wait()
elif mode=='error':raise SystemExit(7)
print('controlled-command-complete')
