"""Model-only source/dependency gates and bounded cleanup; no import effects."""
import os,signal,subprocess,time
from pathlib import Path
from owned_mcp_assembly_freeze import dependencies,digest,sha
ROOTS=('server','shared','db/postgres','tests','scripts/lib')
def source_inventory(root):
 root=Path(root);rows={}
 for name in ROOTS:
  for p in sorted((root/name).rglob('*')):
   if '__pycache__' in p.parts or p.suffix=='.pyc':continue
   if p.is_symlink():rows[str(p.relative_to(root))]={'symlink':os.readlink(p)}
   elif p.is_file():rows[str(p.relative_to(root))]=sha(p)
 for name in ('package.json','package-lock.json'):rows[name]=sha(root/name)
 return rows
def verify(root,source_expected,dependency_expected):
 if source_inventory(root)!=source_expected:raise RuntimeError('Exact source membership/bytes changed')
 rows=dependencies(Path(root))
 if digest(rows)!=dependency_expected:raise RuntimeError('Dependency membership/bytes changed')
 return len(rows)
def cleanup(child,pgid):
 signal.alarm(0)
 for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
 out={'wholeProcessGroupAbsent':False,'errors':[]}
 def members():
  if not pgid:return []
  text=subprocess.check_output(['ps','-axo','pid=,pgid=,uid='],text=True,timeout=3)
  rows=[tuple(map(int,l.split())) for l in text.splitlines() if len(l.split())==3 and int(l.split()[1])==pgid]
  if any(r[2]!=os.getuid() for r in rows):raise RuntimeError('Foreign group process')
  return rows
 try:
  if members():
   os.killpg(pgid,signal.SIGTERM);deadline=time.monotonic()+5
   while members() and time.monotonic()<deadline:child.poll();time.sleep(.05)
   if members():os.killpg(pgid,signal.SIGKILL)
  if child:child.wait(timeout=5)
  out['wholeProcessGroupAbsent']=not members()
 except BaseException as error:out['errors'].append(type(error).__name__+': '+str(error)[:300])
 return out
