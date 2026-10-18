"""Closed mounted indirect cohort admission; no installed model discovery."""
import hashlib,json,re
from full_backend_auth_contract import EMBEDDING_ASSETS

def validate(args):
 if getattr(args,'csrf_full_app',None)!='actual-indirect-chain':
  if getattr(args,'csrf_indirect_dependency_byte_sha256',None):raise ValueError('Indirect digest requires its closed selector')
  return
 conflicting=('actual8b','saved_evidence','production_assembly','actual_grading','actual_grading_browser','catalog_candidate','rendered_catalog','full_app','full_app_retry','dpi_rendered','dpi_containment_rendered','dpi_containment_visual','inventory_rendered','inventory_catalog','inventory_grading','mail_header_rendered','mail_header_catalog','mail_header_readiness','mail_reply_rendered','mail_reply_seed_only','coupon_rendered','mail_disclosure_rendered','mail_disclosure_catalog','mail_disclosure_initialize_only')
 if any(getattr(args,k,False) for k in conflicting):raise ValueError('Indirect CSRF selector must be exclusive')
 if not all(getattr(args,k,None) for k in ('node_binary','node_sha256','node_version','dependency_root','dependency_hashes','csrf_indirect_dependency_byte_sha256')):raise ValueError('Indirect CSRF requires explicit runtime/dependency pins')
 if args.node_version!='v26.10.0':raise ValueError('Qualified Node version required')
 if not re.fullmatch('[a-f0-9]{64}',args.csrf_indirect_dependency_byte_sha256):raise ValueError('Indirect CSRF requires full dependency byte digest')
 identities=json.loads(args.dependency_hashes)
 expected={'package.json','package-lock.json','node_modules/.package-lock.json','client/package.json','client/package-lock.json','client/node_modules/.package-lock.json'}
 if set(identities)!=expected or any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{64}',v) for v in identities.values()):raise ValueError('Six exact dependency identities required')

def verify_cache(source):
 result={}
 for name,expected in EMBEDDING_ASSETS.items():
  path=source/name
  if not path.is_file() or path.is_symlink() or path.resolve()!=path.absolute():raise ValueError('Owned regular embedding asset required')
  actual=hashlib.sha256(path.read_bytes()).hexdigest()
  if actual!=expected:raise ValueError('Qualified embedding asset mismatch')
  result[name]=actual
 if len(result)!=4:raise ValueError('Exact four-asset cache required')
 return result

def verify_dependencies(args,source):
 if getattr(args,'csrf_full_app',None)!='actual-indirect-chain':return None
 from pathlib import Path
 from coupon_dependency_integrity import verify
 root=Path(args.dependency_root)
 if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True)!=root or root==source.resolve():raise ValueError('Separate canonical dependency donor required')
 return verify(root,json.loads(args.dependency_hashes),args.csrf_indirect_dependency_byte_sha256)
