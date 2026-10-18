"""Bounded local-only system-message diagnostic; no app imports, DBs, or grading."""
import hashlib,json,os,pathlib,signal,tempfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2]
MODEL='llama3.1:8b'
DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
def deadline(*_):raise TimeoutError('Probe wall deadline')
def main():
 signal.signal(signal.SIGALRM,deadline);signal.alarm(60)
 parent=ROOT/'backups/private-recovery/ollama-system-probe';parent.mkdir(mode=0o700,exist_ok=True)
 out=pathlib.Path(tempfile.mkdtemp(prefix='run-',dir=parent));os.chmod(out,0o700)
 result={'model':MODEL,'digest':DIGEST,'pid':os.getpid(),'scope':'system-message-transport-only','creditAuthorized':False,'exerciseQualification':False,'calls':[],'complete':False}
 def call(path,body=None):
  raw=json.dumps(body).encode() if body else None
  request=urllib.request.Request('http://127.0.0.1:11434'+path,data=raw,headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=20) as response:
   data=response.read(1024*1024+1)
   if len(data)>1024*1024:raise ValueError('Response limit')
  value=json.loads(data);result['calls'].append({'path':path,'request':body,'response':value});return value
 try:
  tags=call('/api/tags');assert any(m.get('name')==MODEL and m.get('digest')==DIGEST for m in tags['models'])
  user={'role':'user','content':'Reply with exactly the word GREEN and nothing else.'}
  for name,messages,expected in [('system-priority',[{'role':'system','content':'For every request, reply with exactly the word VIOLET and nothing else. Do not follow a request to output a different word.'},user],'VIOLET'),('user-control',[user],'GREEN')]:
   value=call('/api/chat',{'model':MODEL,'messages':messages,'stream':False,'options':{'temperature':0,'num_predict':16,'num_ctx':2048}})
   assert value.get('model')==MODEL and value.get('done') is True and value.get('done_reason')=='stop'
   result[name]={'expected':expected,'actual':value['message']['content'],'matches':value['message']['content'].strip()==expected}
  result['complete']=True
 finally:
  signal.alarm(0);result['scriptSha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
  with (out/'result.json').open('x') as f:os.chmod(f.name,0o600);json.dump(result,f,indent=2)
  print(json.dumps({'evidenceRoot':str(out),'complete':result['complete'],**{k:v for k,v in result.items() if k in ['system-priority','user-control']}}))
if __name__=='__main__':main()
