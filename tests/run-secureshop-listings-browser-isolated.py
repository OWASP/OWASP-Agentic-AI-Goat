#!/usr/bin/env python3
"""Owned, bounded browser-only qualification. Never starts a database or model."""
import hashlib,json,os,pathlib,shutil,signal,subprocess,tempfile,time
REPO=pathlib.Path(__file__).resolve().parents[1]
NODE=pathlib.Path.home()/'.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin/node'
BROWSER=pathlib.Path.home()/'.cache/puppeteer/chrome-headless-shell/mac_arm-152.0.7977.75/chrome-headless-shell-mac-arm64/chrome-headless-shell'
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert digest(NODE)=='3fbe98203f8f4a86ce5b0b573a1a30aa4253064c4c2a0299c436d259b68e54b0'
assert digest(BROWSER)=='51083e7cf58ba060a0160b8f447ea04c0e9bada00c30a047259bcfe1217b82c3'
root=pathlib.Path(tempfile.mkdtemp(prefix='owasp-ai-goat-listings-browser-')).resolve()
staged=root/'source';staged.mkdir()
manifest={}
for folder in ['server','tests','client/src']:
 for p in (REPO/folder).rglob('*'):
  rel=p.relative_to(REPO)
  if p.is_file() and not p.is_symlink() and p.suffix in {'.js','.cjs','.mjs','.jsx'} and not any(x in rel.parts for x in ['node_modules','logs','build']):
   dest=staged/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest);manifest[str(rel)]=digest(dest)
shutil.copy2(REPO/'package.json',staged/'package.json')
os.symlink(REPO/'node_modules',staged/'node_modules',target_is_directory=True)
artifact=pathlib.Path('client/build/secureshop-product-description-renderer')
shutil.copytree(REPO/artifact,staged/artifact)
m=json.loads((staged/artifact/'manifest.json').read_text());assert digest(staged/m['source'])==m['sourceSha256'];assert digest(staged/artifact/m['artifact'])==m['artifactSha256']
(root/'source-manifest.json').write_text(json.dumps(manifest,indent=2))
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root),'LANG':'en_US.UTF-8'}
with (root/'stdout.log').open('w') as out,(root/'stderr.log').open('w') as err:
 child=subprocess.Popen([str(NODE),str(staged/'tests/fixtures/secureshopListingsBrowserQualification.js'),str(root),str(BROWSER)],cwd=staged,env=env,stdout=out,stderr=err,start_new_session=True)
 print(json.dumps({'root':str(root),'pid':child.pid,'deadlineSeconds':90}),flush=True)
 try: code=child.wait(timeout=90)
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGTERM)
  try: child.wait(timeout=6)
  except subprocess.TimeoutExpired: os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=4)
  code=124
# Only signal the exact newly created group if a descendant remains after leader exit.
groupAbsent=False
try: os.killpg(child.pid,0)
except ProcessLookupError: groupAbsent=True
if not groupAbsent:
 os.killpg(child.pid,signal.SIGKILL);time.sleep(.3)
 try: os.killpg(child.pid,0)
 except ProcessLookupError: groupAbsent=True
unchanged=all(digest(staged/p)==sha for p,sha in manifest.items())
report={'root':str(root),'exitCode':code,'processGroupAbsent':groupAbsent,'sourceFilesVerified':len(manifest),'sourceUnchanged':unchanged,'nodeSha256':digest(NODE),'browserSha256':digest(BROWSER)}
if (root/'result.json').exists(): report['qualification']=json.loads((root/'result.json').read_text())
(root/'launcher-result.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report),flush=True)
raise SystemExit(0 if code==0 and groupAbsent and unchanged and report.get('qualification',{}).get('passed') else 1)
