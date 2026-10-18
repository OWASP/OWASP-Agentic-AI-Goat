"""Inert owned-container public host-key reader; caller owns pinned local Docker runner.

The reviewed readonly /etc/ssh directory view is necessary: a single-file bind
dereferences a host symlink before the reader can lstat it. The fixed program
does not enumerate the directory or accept a filename and never opens private
keys. It runs without network/capabilities, as UID/GID10001, with readonly root.
No SSH, keyscan, TOFU, source copy, image pull/build or remote mutation.
"""
import base64
import hashlib
import json
import re
import struct
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned, CONTAINER

SOURCE='/etc/ssh'
TARGET='/vm-ssh'
PUBLIC_FILE='ssh_host_ed25519_key.pub'
READER=r"""'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
assert.equal(process.getuid(),10001);assert.equal(process.getgid(),10001);
const directory='/vm-ssh',file='/vm-ssh/ssh_host_ed25519_key.pub';
const dir=fs.lstatSync(directory);assert(dir.isDirectory()&&!dir.isSymbolicLink());
assert.equal(dir.uid,0);assert.equal(dir.mode&0o022,0);
const before=fs.lstatSync(file);assert(before.isFile()&&!before.isSymbolicLink());
assert.equal(before.uid,0);assert.equal(before.nlink,1);assert.equal(before.mode&0o022,0);assert(before.size>0&&before.size<=4096);
const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
let bytes;try{const s=fs.fstatSync(fd);assert(s.isFile());for(const k of ['dev','ino','uid','gid','mode','nlink','size','mtimeMs','ctimeMs'])assert.equal(s[k],before[k]);
bytes=Buffer.alloc(before.size);let n=0;while(n<bytes.length){const got=fs.readSync(fd,bytes,n,bytes.length-n,null);assert(got>0);n+=got;}assert.equal(fs.readSync(fd,Buffer.alloc(1),0,1,null),0);
const after=fs.fstatSync(fd),pathAfter=fs.lstatSync(file);for(const k of ['dev','ino','uid','gid','mode','nlink','size','mtimeMs','ctimeMs']){assert.equal(after[k],before[k]);assert.equal(pathAfter[k],before[k]);}
}finally{fs.closeSync(fd);}
const text=bytes.toString('ascii');assert(bytes.every(x=>x===9||x===10||x===13||(x>=32&&x<=126)));const lines=text.trim().split(/\r?\n/);assert.equal(lines.length,1);
const fields=lines[0].trim().split(/[ \t]+/);assert(fields.length>=2&&fields[0]==='ssh-ed25519');assert(/^[A-Za-z0-9+/]+={0,2}$/.test(fields[1]));const key=Buffer.from(fields[1],'base64');assert.equal(key.toString('base64'),fields[1]);
assert.equal(key.length,51);assert.equal(key.readUInt32BE(0),11);assert.equal(key.subarray(4,15).toString(),'ssh-ed25519');assert.equal(key.readUInt32BE(15),32);
const entry={type:'regular-file',uid:before.uid,gid:before.gid,mode:before.mode&0o777,nlink:before.nlink,size:before.size,dev:before.dev,ino:before.ino};
process.stdout.write(JSON.stringify({version:1,publicKey:'ssh-ed25519 '+fields[1],source:'/etc/ssh/ssh_host_ed25519_key.pub',entry,sourceSha256:crypto.createHash('sha256').update(bytes).digest('hex'),directory:{uid:dir.uid,mode:dir.mode&0o777},noFollow:true,stableRead:true})+'\n');
"""

def plan(nonce,image):
    if not re.fullmatch('[a-f0-9]{32}',nonce) or not re.fullmatch('sha256:[a-f0-9]{64}',image):raise ValueError('Exact owner and existing image required')
    return {'name':'dvaia-vm-public-key-'+nonce,'image':image,'labels':{'dvaia.qualification':'vm-public-host-key','dvaia.owner':nonce},'readerSha256':hashlib.sha256(READER.encode()).hexdigest()}

def create_args(p):
    args=['create','--pull','never','--name',p['name']]
    for k,v in p['labels'].items():args+=['--label',k+'='+v]
    return args+['--network','none','--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','64m','--cpus','0.25','--pids-limit','32','--env','NODE_OPTIONS=','--env','NODE_PATH=','--env','LD_PRELOAD=','--env','LD_LIBRARY_PATH=','--mount','type=bind,src=/etc/ssh,dst=/vm-ssh,readonly,bind-nonrecursive=true','--entrypoint','/usr/local/bin/node',p['image'],'-e',READER]

def validate_layout(row):
    h=row['HostConfig'];c=row['Config'];mounts=row['Mounts']
    if c.get('User')!='10001:10001' or c.get('Entrypoint')!=['/usr/local/bin/node'] or c.get('Cmd')!=['-e',READER]:raise RuntimeError('Exact public reader identity required')
    for key in ('NODE_OPTIONS','NODE_PATH','LD_PRELOAD','LD_LIBRARY_PATH'):
        if [x for x in c.get('Env',[]) if x.startswith(key+'=')]!=[key+'=']:raise RuntimeError('Reader injection environment denied')
    if h.get('NetworkMode')!='none' or h.get('ReadonlyRootfs') is not True or h.get('Privileged') is not False or h.get('CapAdd') not in (None,[]) or h.get('CapDrop')!=['ALL'] or h.get('SecurityOpt')!=['no-new-privileges']:raise RuntimeError('Public reader confinement mismatch')
    if h.get('Memory')!=67108864 or h.get('NanoCpus')!=250000000 or h.get('PidsLimit')!=32 or h.get('PidMode') not in ('',None) or h.get('IpcMode') not in ('private',None) or h.get('Tmpfs') not in (None,{}):raise RuntimeError('Public reader resource mismatch')
    if len(mounts)!=1:raise RuntimeError('Only reviewed public directory view allowed')
    m=mounts[0]
    if m.get('Type')!='bind' or m.get('Source')!=SOURCE or m.get('Destination')!=TARGET or m.get('RW') is not False or m.get('Propagation')!='rprivate':raise RuntimeError('Readonly exact bind required')
    specs=h.get('Mounts') or []
    if len(specs)!=1 or specs[0].get('BindOptions',{}).get('NonRecursive') is not True:raise RuntimeError('Recursive mounts forbidden')
    if row.get('NetworkSettings',{}).get('Ports') not in (None,{}) or h.get('PortBindings') not in (None,{}):raise RuntimeError('No network publication allowed')

def parse_public_output(text):
    if not isinstance(text,str) or len(text.encode())>8192:raise ValueError('Public output limit')
    value=json.loads(text)
    if value.get('source')!='/etc/ssh/'+PUBLIC_FILE or value.get('noFollow') is not True or value.get('stableRead') is not True:raise ValueError('Exact stable public entry required')
    key=value.get('publicKey','').split(' ')
    if len(key)!=2 or key[0]!='ssh-ed25519':raise ValueError('Ed25519 public key required')
    raw=base64.b64decode(key[1],validate=True)
    if base64.b64encode(raw).decode()!=key[1] or len(raw)!=51 or raw[:4]!=struct.pack('>I',11) or raw[4:15]!=b'ssh-ed25519' or raw[15:19]!=struct.pack('>I',32):raise ValueError('Invalid SSH wire key')
    e=value.get('entry',{});d=value.get('directory',{})
    if e.get('type')!='regular-file' or e.get('uid')!=0 or e.get('nlink')!=1 or not isinstance(e.get('mode'),int) or e['mode']&0o022 or not 0<e.get('size',0)<=4096 or d.get('uid')!=0 or not isinstance(d.get('mode'),int) or d['mode']&0o022:raise ValueError('Unsafe public source permissions')
    if not re.fullmatch('[a-f0-9]{64}',value.get('sourceSha256','')):raise ValueError('Public source hash required')
    return value

def read_owned_key(*,docker,record,remaining,cleanup_remaining,daemon_id,image,nonce,ssh_host,ssh_port):
    """docker is parent's pinned CLI/socket/clean-env bounded runner, not discovery.

    record must durably fsync the parent-owned journal before returning. Independent
    cleanup_remaining must remain positive even after work deadline/cancellation.
    Receipt becomes publishable only after exact owned container absence.
    """
    p=plan(nonce,image)
    if not isinstance(ssh_host,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,100}',ssh_host) or type(ssh_port)is not int or not 1<=ssh_port<=65535:raise ValueError('Closed SSH endpoint required')
    attempted=False;identifier=None;value=None;failure=None;cleanup=None
    def command(args,cleanup_mode=False):
        timeout=min(20,(cleanup_remaining if cleanup_mode else remaining)())
        if timeout<=0:raise TimeoutError('Owned public-key deadline expired')
        out=docker(args,timeout=timeout)
        if len(out.stdout.encode())+len(out.stderr.encode())>65536:raise RuntimeError('Docker diagnostic output limit')
        return out
    try:
        verify_daemon(command,daemon_id);verify_image(command,image)
        if inspect_owned(command,name=p['name'],labels=p['labels'],image=image) is not None:raise RuntimeError('Owned name collision')
        record('public-key-create-intent',{**p,'daemonId':daemon_id,'creationAttempted':True,'sourceDirectory':SOURCE,'publicFile':PUBLIC_FILE});attempted=True
        created=command(create_args(p));candidate=created.stdout.strip()
        if created.returncode or not CONTAINER.fullmatch(candidate):raise RuntimeError('Public reader creation failed')
        identifier=candidate
        record('public-key-created',{'containerId':identifier})
        row=inspect_owned(command,name=p['name'],labels=p['labels'],image=image,captured_id=identifier);validate_layout(row)
        if row['State'].get('Status')!='created' or row['State'].get('Running') is not False:raise RuntimeError('Reader must be inspected before start')
        record('public-key-start-intent',{'containerId':identifier,'readerSha256':p['readerSha256']})
        output=command(['start','--attach',identifier])
        if output.returncode:raise RuntimeError('Public reader failed')
        value=parse_public_output(output.stdout)
        terminal=inspect_owned(command,name=p['name'],labels=p['labels'],image=image,captured_id=identifier);validate_layout(terminal)
        if terminal['State'].get('Running') is not False or terminal['State'].get('ExitCode')!=0 or terminal['State'].get('Status')!='exited':raise RuntimeError('Reader terminal state unverified')
    except BaseException as error:failure=error
    finally:
        if attempted:
            try:cleanup=cleanup_owned(lambda args:command(args,True),daemon_id=daemon_id,name=p['name'],labels=p['labels'],image=image,captured_id=identifier);record('public-key-cleanup',cleanup)
            except BaseException as error:
                if failure:raise BaseExceptionGroup('Public key read and cleanup failed',[failure,error])
                raise
    if failure:raise failure
    known=f'[127.0.0.1]:{ssh_port} {value["publicKey"]}\n'
    return {'status':'authenticated-existing-vm-host-key','method':'local-vm-control-plane','knownHostsSha256':hashlib.sha256(known.encode()).hexdigest(),'sshHost':ssh_host,'hostname':'127.0.0.1','port':ssh_port,'knownHostsContent':known,'daemonId':daemon_id,'imageId':image,'containerId':identifier,'readerSha256':p['readerSha256'],'cleanup':cleanup,'publicSource':value,'scope':'Public entry read through pinned trusted local daemon; no SSH connection attempted'}
