"""Small failure-recovery orchestration used by the SecureShop activation gate."""
import hashlib
import json
import os
import stat
from pathlib import Path

def _private_write(path, payload):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(descriptor,'wb') as output:
            output.write(payload);output.flush();os.fsync(output.fileno())
    except BaseException:
        try: os.close(descriptor)
        except OSError: pass
        raise

def persist_recovery_snapshot(*, evidence, sources, managed):
    """Persist rollback bytes before mutation without exposing their contents."""
    root=Path(evidence)/'recovery-source'
    root.mkdir(mode=0o700)
    records={}
    for name,payload in sorted(sources.items()):
        if not isinstance(name,str) or Path(name).is_absolute() or '..' in Path(name).parts:
            raise RuntimeError('recovery source name is invalid')
        if payload is None:
            records[name]={'present':False}
            continue
        if not isinstance(payload,bytes): raise RuntimeError('recovery source bytes are invalid')
        filename=f'{hashlib.sha256(name.encode()).hexdigest()}.source'
        _private_write(root/filename,payload)
        records[name]={'present':True,'file':filename,'bytes':len(payload),
          'sha256':hashlib.sha256(payload).hexdigest()}
    managed_record={'present':managed.get('present') is True}
    if managed_record['present']:
        payload=managed.get('bytes')
        if not isinstance(payload,bytes): raise RuntimeError('managed recovery bytes are invalid')
        filename='managed.env';_private_write(root/filename,payload)
        managed_record.update({'file':filename,'bytes':len(payload),
          'sha256':hashlib.sha256(payload).hexdigest()})
    manifest={'sources':records,'managed':managed_record}
    payload=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    _private_write(root/'manifest.json',payload)
    return {'directory':str(root),'manifestSha256':hashlib.sha256(payload).hexdigest(),
      'sourceCount':len(records),'managedPresent':managed_record['present']}

def load_recovery_snapshot(*, evidence, expected_sources, expected_manifest_sha256):
    root=Path(evidence)/'recovery-source';manifest_path=root/'manifest.json'
    if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode)!=0o700:
        raise RuntimeError('private recovery directory is invalid')
    if manifest_path.is_symlink() or not manifest_path.is_file() \
        or stat.S_IMODE(manifest_path.stat().st_mode)!=0o600:
        raise RuntimeError('private recovery manifest is invalid')
    manifest_payload=manifest_path.read_bytes()
    if hashlib.sha256(manifest_payload).hexdigest()!=expected_manifest_sha256:
        raise RuntimeError('private recovery manifest changed')
    manifest=json.loads(manifest_payload)
    if set(manifest.get('sources',{}))!=set(expected_sources):
        raise RuntimeError('private recovery source inventory changed')
    def read_record(record):
        if record.get('present') is not True:return None
        filename=record.get('file');path=root/filename if isinstance(filename,str) else root/'invalid'
        if path.parent!=root or path.is_symlink() or not path.is_file() \
            or stat.S_IMODE(path.stat().st_mode)!=0o600:
            raise RuntimeError('private recovery payload is invalid')
        payload=path.read_bytes()
        if len(payload)!=record.get('bytes') or hashlib.sha256(payload).hexdigest()!=record.get('sha256'):
            raise RuntimeError('private recovery payload changed')
        return payload
    sources={name:read_record(record) for name,record in manifest['sources'].items()}
    managed_record=manifest.get('managed',{})
    managed={'present':managed_record.get('present') is True,'bytes':read_record(managed_record),'mode':0o600}
    return sources,managed

def validate_application_schema_scope(*, present, allowed, public_objects):
    present=set(present);allowed=set(allowed)
    if present-allowed-{'public'}:
        raise RuntimeError('configured store contains an unreviewed application schema')
    if allowed-present:
        raise RuntimeError('configured store is missing a reviewed application schema')
    if public_objects:
        raise RuntimeError('configured store contains unreviewed public-schema objects')
    return {'reviewedSchemas':sorted(allowed),'publicUserObjects':public_objects}

def validate_generated_output_scope(*, manifest_names, builder_names):
    manifest=set(manifest_names);builder=set(builder_names)
    if not manifest or manifest!=builder:
        raise RuntimeError('generated SecureShop activation output scope changed')
    return sorted(manifest)

def stage_generated_release_sources(*, manifest_outputs, builder_names, target_root, build):
    names=validate_generated_output_scope(manifest_names=manifest_outputs,builder_names=builder_names)
    target_root.mkdir()
    build(target_root)
    actual={name:hashlib.sha256((target_root/name).read_bytes()).hexdigest() for name in names}
    if actual!=dict(manifest_outputs):
        raise RuntimeError('generated release source differs from manifest')
    return actual

def recover_after_failed_restart(*, pause_and_drain, restore, resume, health):
    stages=[]
    try:
        pause_and_drain();stages.append('paused_and_drained')
        restore();stages.append('source_config_catalog_restored')
        resume();stages.append('watcher_resumed')
        if health() is not True:
            raise RuntimeError('prior SecureShop service did not recover')
        stages.append('prior_service_healthy')
        return {'recovered':True,'stages':stages}
    except BaseException as error:
        return {'recovered':False,'stages':stages,'errorType':type(error).__name__}

def drain_optional_backend(*, resolve, terminate, wait):
    """A frozen watcher with no child is already drained; any observed child must exit."""
    pid=resolve()
    if pid is None:return {'state':'absent','pid':None}
    terminate(pid);wait(pid)
    return {'state':'confirmed_exited','pid':pid}

def recover_failed_postrestart(*, cleanup, promotion_started, recovery_available,
                               pause_and_drain, restore, resume, health):
    """Run recovery only for a resumed candidate that failed mounted readiness."""
    if not (promotion_started and recovery_available
            and cleanup.get('watcherResumed') is True
            and cleanup.get('health200') is not True):
        return None
    return recover_after_failed_restart(pause_and_drain=pause_and_drain,
      restore=restore,resume=resume,health=health)
