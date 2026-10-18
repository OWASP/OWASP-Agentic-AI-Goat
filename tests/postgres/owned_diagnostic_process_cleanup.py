"""Import-safe owned diagnostic cleanup; no launch side effects."""
import os,signal,time
def stop_directive_child(child,members,cleanup):
 if members(cleanup):
  try:os.killpg(child.pid,signal.SIGTERM)
  except ProcessLookupError:pass
 end=time.monotonic()+min(5,cleanup.remaining())
 while members(cleanup) and time.monotonic()<end:
  child.poll();time.sleep(min(.05,cleanup.remaining()))
 if members(cleanup):
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
 if child is not None:child.wait(timeout=min(5,cleanup.remaining()))
 end=time.monotonic()+min(5,cleanup.remaining())
 while members(cleanup) and time.monotonic()<end:time.sleep(min(.05,cleanup.remaining()))
 absent=not members(cleanup)
 if not absent:raise RuntimeError('Owned process group remains')
 return absent
