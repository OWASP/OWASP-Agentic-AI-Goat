"""Coupon-only dependency identity and full-byte admission; no import side effects."""
import re
from pathlib import Path
from owned_mcp_assembly_freeze import dependencies,digest,sha
IDENTITIES=('package.json','package-lock.json','node_modules/.package-lock.json','client/package.json','client/package-lock.json','client/node_modules/.package-lock.json')
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER_SHA='95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
DAEMON_ID='2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
def inventory(root):
 root=Path(root)
 return {**dependencies(root),**{'client/'+k:v for k,v in dependencies(root/'client').items()}}
def verify(root,identities,expected):
 if not re.fullmatch('[a-f0-9]{64}',expected or ''):raise RuntimeError('Reviewed coupon dependency byte digest required')
 if set(identities)!=set(IDENTITIES):raise RuntimeError('Exact six coupon dependency identities required')
 root=Path(root)
 if {p:sha(root/p) for p in IDENTITIES}!=identities:raise RuntimeError('Coupon dependency identity drift')
 rows=inventory(root)
 if digest(rows)!=expected:raise RuntimeError('Coupon dependency byte drift')
 return {'digest':expected,'count':len(rows),'identities':identities}
def pins(node,docker,daemon_id):
 if sha(node)!=NODE_SHA or sha(docker)!=DOCKER_SHA or daemon_id!=DAEMON_ID:raise RuntimeError('Coupon executable or daemon mismatch')
