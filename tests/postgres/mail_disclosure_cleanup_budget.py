"""One monotonic budget shared by all disclosure cleanup phases."""
import signal,time
class CleanupBudget:
 def __init__(self,seconds,clock=time.monotonic):self.clock=clock;self.deadline=clock()+seconds
 def remaining(self):
  value=self.deadline-self.clock()
  if value<=0:raise TimeoutError('Disclosure cleanup budget exhausted')
  return value
 def run(self,work):
  remaining=self.remaining();previous=signal.getsignal(signal.SIGALRM)
  def expired(signum,frame):raise TimeoutError('Disclosure cleanup budget exhausted')
  signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,remaining)
  try:
   result=work();self.remaining();return result
  finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
