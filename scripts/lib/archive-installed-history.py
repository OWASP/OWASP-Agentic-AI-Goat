#!/usr/bin/env python3
"""Bounded no-dereference tar capture/readback, no extraction or source writes."""
import hashlib,json,os,stat,sys,tarfile,itertools
LIMIT=3*1024**3

def digest(stream):
    h=hashlib.sha256()
    while chunk:=stream.read(1024*1024): h.update(chunk)
    return h.hexdigest()

def entry(root,relative):
    p=os.path.join(root,relative);s=os.lstat(p)
    if s.st_uid!=os.getuid(): raise ValueError('FOREIGN_OWNER')
    row={'dev':s.st_dev,'ino':s.st_ino,'path':relative,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'size':s.st_size if stat.S_ISREG(s.st_mode) else 0}
    if stat.S_ISLNK(s.st_mode): row.update(type='symlink',link=os.readlink(p))
    elif stat.S_ISDIR(s.st_mode): row.update(type='directory')
    elif stat.S_ISREG(s.st_mode):
        if s.st_nlink!=1: raise ValueError('HARDLINK_UNSUPPORTED')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            a=os.fstat(f.fileno())
            if (a.st_dev,a.st_ino)!=(s.st_dev,s.st_ino): raise ValueError('SOURCE_REPLACED')
            row.update(type='file',sha256=digest(f))
            b=os.fstat(f.fileno())
            if (a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(b.st_size,b.st_mtime_ns,b.st_ctime_ns): raise ValueError('SOURCE_CHANGED')
    else: raise ValueError('UNSUPPORTED_SOURCE')
    return row

def walk(root,relative='.'):
    yield relative
    p=os.path.join(root,relative)
    if stat.S_ISDIR(os.lstat(p).st_mode):
        for name in sorted(os.listdir(p)): yield from walk(root,os.path.join(relative,name))

def capture(root,archive,limit=LIMIT):
    if os.path.realpath(root)!=root or not os.path.isdir(root) or os.path.islink(root): raise ValueError('ROOT_INVALID')
    inventory=archive+'.inventory.jsonl';total=count=0
    fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as output,open(inventory,'x',encoding='utf8') as index:
        os.chmod(inventory,0o600)
        with tarfile.open(fileobj=output,mode='w|',dereference=False,format=tarfile.PAX_FORMAT) as tar:
            for relative in walk(root):
                row=entry(root,relative);total+=row['size'];count+=1
                if total>limit or count>200000: raise ValueError('ARCHIVE_BOUND')
                info=tar.gettarinfo(os.path.join(root,relative),arcname=relative)
                if row['type']=='file':
                    read=os.open(os.path.join(root,relative),os.O_RDONLY|os.O_NOFOLLOW)
                    with os.fdopen(read,'rb') as source: tar.addfile(info,source)
                else: tar.addfile(info)
                if output.tell()>limit: raise ValueError('ARCHIVE_BOUND')
                index.write(json.dumps(row,separators=(',',':'))+'\n')
        output.flush();os.fsync(output.fileno());index.flush();os.fsync(index.fileno())
    verify(root,archive,inventory)
    with open(archive,'rb') as f: archive_sha=digest(f)
    with open(inventory,'rb') as f: inventory_sha=digest(f)
    return {'bytes':os.stat(archive).st_size,'sourceBytes':total,'entries':count,'sha256':archive_sha,'inventorySha256':inventory_sha,'verified':True}

def verify(root,archive,inventory):
    with open(inventory,encoding='utf8') as index,tarfile.open(archive,'r|') as tar:
        for info in tar:
            line=index.readline()
            if not line: raise ValueError('EXTRA_ARCHIVE_ENTRY')
            row=json.loads(line)
            if info.name.rstrip('/')!=row['path'].rstrip('/') or info.mode!=row['mode'] or info.uid!=row['uid'] or info.gid!=row['gid']: raise ValueError('ARCHIVE_METADATA')
            if row['type']=='file':
                if not info.isfile() or info.size!=row['size'] or digest(tar.extractfile(info))!=row['sha256']: raise ValueError('ARCHIVE_PAYLOAD')
            elif row['type']=='symlink':
                if not info.issym() or info.linkname!=row['link']: raise ValueError('ARCHIVE_LINK')
            elif not info.isdir(): raise ValueError('ARCHIVE_DIRECTORY')
            if entry(root,row['path'])!=row: raise ValueError('SOURCE_CHANGED')
        if index.readline(): raise ValueError('MISSING_ARCHIVE_ENTRY')
    with open(inventory,encoding='utf8') as index:
        expected=(json.loads(line)['path'] for line in index)
        for actual,recorded in itertools.zip_longest(walk(root),expected):
            if actual!=recorded: raise ValueError('SOURCE_MEMBERSHIP_CHANGED')

if __name__=='__main__':
    try:
        if len(sys.argv)!=4 or not 0<int(sys.argv[3])<=LIMIT: raise ValueError('ARGUMENTS')
        os.umask(0o077);print(json.dumps(capture(os.path.abspath(sys.argv[1]),os.path.abspath(sys.argv[2]),int(sys.argv[3]))))
    except Exception:
        print('HISTORICAL_ARCHIVE_FAILED',file=sys.stderr);sys.exit(1)
