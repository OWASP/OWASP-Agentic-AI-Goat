#!/usr/bin/env python3
"""Read-only resource checks before releasing the IPI qualification slot."""
import sys
sys.dont_write_bytecode = True
import argparse, fcntl, importlib.util, json, os, socket, subprocess
from pathlib import Path
from full_backend_auth_contract import validate_package, digest
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned
from mcp_connected_baseline_contract import validate_docker_cli

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--control',required=True);parser.add_argument('--exit-code',type=int,required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('ipi_launcher',Path(__file__).with_name('run-ipi-email-canonical-migration-isolated.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    grant=module.private_json(args.control)
    if grant.get('status')!='consumed' or grant.get('scope')!=module.SCOPE or grant.get('owner')!='/root':
        raise RuntimeError('Consumed IPI control required')
    flags=[]
    for action in module.parser()._actions:
        if action.dest!='help':flags.extend(['--'+action.dest.replace('_','-'),str(grant[action.dest])])
    values=vars(module.parser().parse_args(flags))
    candidate=dict(grant);candidate.pop('launcherPid');candidate['status']='granted'
    module.validate_grant(candidate,values)
    root=Path(grant['evidence_root']);source=Path(grant['package'])
    if root.resolve()!=root or root.is_symlink() or root.stat().st_uid!=os.getuid() or root.stat().st_mode&0o077:
        raise RuntimeError('Private evidence root required')
    validate_package(source,grant['manifest'],grant['manifest_sha256'],grant['node'],grant['node_sha256'])
    for name in ['verify-ipi-email-canonical-migration.py','run-ipi-email-canonical-migration-isolated.py']:
        if digest(Path(__file__).with_name(name))!=digest(source/'tests/postgres'/name):raise RuntimeError('Verifier source drift')
    docker=[validate_docker_cli(grant['docker_cli'],grant['docker_cli_sha256']),'--host',grant['docker_host']]
    def command(arguments):return subprocess.run(docker+arguments,env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=30)
    verify_daemon(command,grant['docker_daemon_id']);verify_image(command,grant['postgres_image_id'])
    intent=module.private_json(root/'container-intent.json');created=module.private_json(root/'container-created.json')
    cleanup=module.private_json(root/'container-cleanup.json');owner=module.private_json(root/'ownership.json');terminal=module.private_json(root/'terminal.json')
    if intent['imageId']!=grant['postgres_image_id'] or intent['daemonId']!=grant['docker_daemon_id'] or created['labels']!=intent['labels']:
        raise RuntimeError('Resource identity mismatch')
    if cleanup['status'] not in ['absent','removed_absence_verified'] or cleanup['containerId']!=created['containerId']:
        raise RuntimeError('Cleanup receipt mismatch')
    for name in [intent['name'],created['containerId']]:
        if inspect_owned(command,name=name,labels=intent['labels'],image=intent['imageId'],captured_id=created['containerId']) is not None:
            raise RuntimeError('Owned container remains')
    with socket.socket() as connection:
        connection.settimeout(2)
        if connection.connect_ex(('127.0.0.1',created['port']))==0:raise RuntimeError('Owned PostgreSQL port remains open')
    with socket.socket() as listener:listener.bind(('127.0.0.1',created['port']))
    rows=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,check=True,timeout=5).stdout.splitlines()
    processes=[tuple(map(int,line.split())) for line in rows]
    if owner['launcherPid']!=grant['launcherPid'] or owner['ownerHandle']!=int(grant['owner_handle']) or owner['manifestSha256']!=grant['manifest_sha256']:
        raise RuntimeError('Launcher ownership mismatch')
    if any(pid==owner['launcherPid'] for pid,_group,_uid in processes):raise RuntimeError('Launcher remains')
    journals=list(root.glob('process-*.json'))
    if not journals:raise RuntimeError('Qualification process journal missing')
    for path in journals:
        process=module.private_json(path)
        if process['status']!='cleanup_verified' or any(pid==process['pid'] or group==process['pgid'] for pid,group,_uid in processes):
            raise RuntimeError('Qualification process cleanup unavailable')
    if terminal['ownerHandle']!=int(grant['owner_handle']) or terminal['manifestSha256']!=grant['manifest_sha256'] or terminal['failures']:
        raise RuntimeError('Terminal identity or cleanup mismatch')
    if terminal['resultSha256']!=digest(root/'result.tap'):raise RuntimeError('Result changed')
    passed=args.exit_code==0
    if terminal['status']!=('passed_cleaned' if passed else 'failed'):raise RuntimeError('Terminal outcome mismatch')
    if passed:
        report=(root/'result.tap').read_text()
        if any(line not in report.splitlines() for line in ['# tests 2','# pass 2','# fail 0','# skipped 0']):raise RuntimeError('Incomplete migration qualification')
    slot=Path(grant['slot'])
    with slot.with_name('native-verification.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=json.loads(slot.read_text())
        expected={'status':'consumed','scope':module.SCOPE,'owner':'/root','ownerHandle':int(grant['owner_handle']),
                  'launcherPid':grant['launcherPid'],'candidateSourceRoot':grant['package'],
                  'candidateManifestSha256':grant['manifest_sha256'],'evidenceRoot':str(root),'controlRoot':str(Path(args.control).parent),'allowedLaunches':1}
        if state!=expected:raise RuntimeError('Active slot changed')
        result={'cleanupVerified':True,'qualificationPassed':passed,'exitCode':args.exit_code,'ownerHandle':int(grant['owner_handle']),
                'manifestSha256':grant['manifest_sha256'],'resultSha256':terminal['resultSha256']}
        record=Path(args.control).with_name('postflight-result.json');module.write_json(record,result)
        state.update(status='terminal_pass_cleaned' if passed else 'terminal_fail_cleaned',cleanupVerified=True,exitCode=args.exit_code,postflight=str(record))
        module.write_json(slot,state)
        print(json.dumps(result))

if __name__=='__main__':main()
