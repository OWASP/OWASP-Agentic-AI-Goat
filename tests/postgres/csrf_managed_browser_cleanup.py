"""Exact detached Chromium cleanup for the owned CSRF fixture only."""
import json, os, signal, subprocess, time, shutil
from pathlib import Path

EXPECTED_EXECUTABLE = str(Path.home()/'.cache/puppeteer/chrome-headless-shell/mac_arm-152.0.7977.75/chrome-headless-shell-mac-arm64/chrome-headless-shell')

def validate_identity(identity, root, uid, current):
    profile=str(Path(root).resolve()/'csrf-managed-profile')
    if identity.get('version')!=1 or identity.get('detached') is not True:raise RuntimeError('Invalid browser ownership version')
    if any(type(identity.get(key)) is not int or identity[key]<=1 for key in ['pid','pgid','qualificationPgid','workerPid']):raise RuntimeError('Invalid process identity')
    if identity.get('uid')!=uid or identity.get('pid')!=identity.get('pgid') or identity.get('pgid')==identity.get('qualificationPgid'):raise RuntimeError('Foreign or worker browser group')
    if identity.get('profile')!=profile or identity.get('executable')!=EXPECTED_EXECUTABLE:raise RuntimeError('Invalid owned browser paths')
    if not isinstance(identity.get('startIdentity'),str) or not identity['startIdentity'].strip():raise RuntimeError('Missing start identity')
    command=identity.get('command','')
    if not isinstance(command,str) or not command.startswith(EXPECTED_EXECUTABLE+' ') or '--user-data-dir='+profile not in command:raise RuntimeError('Invalid captured command')
    if current:
        if current['pid']!=identity['pid'] or current['pgid']!=identity['pgid'] or current['uid']!=uid:raise RuntimeError('Browser identity changed')
        if current['startIdentity']!=identity['startIdentity'] or current['command']!=identity['command']:raise RuntimeError('Browser PID reused or command changed')
        if not current['command'].startswith(identity['executable']+' ') or '--user-data-dir='+profile not in current['command']:raise RuntimeError('Browser executable/profile mismatch')
    return identity['pgid']

def roster():
    return [tuple(map(int,line.split())) for line in subprocess.check_output(['/bin/ps','-axo','pid=,pgid=,uid='],text=True,timeout=3).splitlines() if line.strip()]

def cleanup_one(root):
    root=Path(root).resolve();profile=root/'csrf-managed-profile'
    if profile.is_symlink():raise RuntimeError('Refuse symlink profile')
    file=next((root/name for name in ['csrf-managed-process.json','csrf-managed-launch.json'] if (root/name).is_file()),None)
    if not file:
        # No captured process: verify exact profile is absent from all live argv;
        # never infer authority to signal an unrecorded process.
        commands=subprocess.check_output(['/bin/ps','-axo','command='],text=True,timeout=3)
        if '--user-data-dir='+str(profile) in commands:raise RuntimeError('Unrecorded browser still live')
        if profile.exists():shutil.rmtree(profile)
        return {'captured':False,'groupAbsent':True,'profileAbsent':not profile.exists()}
    identity=json.loads(file.read_text());rows=roster();pid=identity['pid'];row=next((r for r in rows if r[0]==pid),None);current=None
    if row:
        current={'pid':row[0],'pgid':row[1],'uid':row[2],'startIdentity':subprocess.check_output(['/bin/ps','-p',str(pid),'-o','lstart='],text=True,timeout=3).strip(),'command':subprocess.check_output(['/bin/ps','-p',str(pid),'-o','command='],text=True,timeout=3).strip()}
    pgid=validate_identity(identity,root,os.getuid(),current);members=[r for r in rows if r[1]==pgid]
    if any(r[2]!=os.getuid() for r in members):raise RuntimeError('Foreign browser group member')
    if members and not current:raise RuntimeError('Browser leader absent with surviving group; refuse unverified signal')
    if members:
        os.killpg(pgid,signal.SIGTERM);deadline=time.monotonic()+3
        while any(r[1]==pgid for r in roster()) and time.monotonic()<deadline:time.sleep(.05)
        remaining=[r for r in roster() if r[1]==pgid]
        if remaining:
            # Same captured live leader must still have the same start identity.
            start=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','lstart='],text=True,timeout=3).strip()
            leader=next((r for r in remaining if r[0]==pid),None)
            if not leader or any(r[2]!=os.getuid() for r in remaining):raise RuntimeError('Browser identity changed during cleanup')
            command=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','command='],text=True,timeout=3).strip()
            validate_identity(identity,root,os.getuid(),{'pid':leader[0],'pgid':leader[1],'uid':leader[2],'startIdentity':start,'command':command})
            os.killpg(pgid,signal.SIGKILL)
            deadline=time.monotonic()+3
            while any(r[1]==pgid for r in roster()) and time.monotonic()<deadline:time.sleep(.05)
    if any(r[1]==pgid for r in roster()):raise RuntimeError('Owned browser group remains')
    if profile.exists():shutil.rmtree(profile)
    return {'captured':True,'pid':pid,'pgid':pgid,'groupAbsent':True,'profileAbsent':not profile.exists()}


def cleanup(root):
    root=Path(root).resolve();manifest=root/'csrf-managed-sequence.json'
    if not manifest.exists():return cleanup_one(root)
    if manifest.is_symlink() or json.loads(manifest.read_text())!={'version':1,'limit':2}:raise RuntimeError('Invalid owned browser sequence')
    outcomes=[];errors=[]
    for index in (1,2):
        child=root/('csrf-managed-'+str(index))
        try:
            if child.is_symlink():raise RuntimeError('Refuse symlink ownership root')
            outcomes.append(dict(index=index,**cleanup_one(child)))
        except Exception as error:errors.append({'index':index,'type':type(error).__name__})
    if errors:raise RuntimeError('Owned browser sequence cleanup failed: '+json.dumps(errors))
    return {'limit':2,'launches':outcomes,'groupAbsent':all(r['groupAbsent'] for r in outcomes),'profileAbsent':all(r['profileAbsent'] for r in outcomes)}
