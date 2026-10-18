"""Offline admission/layout tests; no Docker, Node, network or database."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from mcp_owned_mailpit_contract import REQUIRED, MIGRATIONS, SCOPE, validate_manifest, validate_mailpit_layout, consume_control, validate_docker_cli, digest

class Contract(unittest.TestCase):
 def test_docker_cli_identity(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory).resolve()/'docker';path.write_text('controlled fixture only');path.chmod(0o700)
   expected=digest(path)
   self.assertEqual(validate_docker_cli(str(path),expected),str(path))
   for badpath,badhash in [('relative',expected),(str(path),'a'*64),(str(path),'not-a-hash')]:
    with self.assertRaises(RuntimeError):validate_docker_cli(badpath,badhash)
   link=path.with_name('link');link.symlink_to(path)
   with self.assertRaises(RuntimeError):validate_docker_cli(str(link),expected)
   path.chmod(0o600)
   with self.assertRaises(RuntimeError):validate_docker_cli(str(path),expected)
 def test_scope_and_migrations(self):
  manifest=dict(version=1,scope=SCOPE,files={name:'a'*64 for name in REQUIRED},symlinks={},directories=[])
  self.assertIs(validate_manifest(manifest),manifest)
  for change in ['scope','missing','extra']:
   value=copy.deepcopy(manifest)
   if change=='scope':value['scope']='sql_nosql_route_actual8b'
   elif change=='missing':value['files'].pop(next(iter(MIGRATIONS)))
   else:value['files']['db/postgres/workshop-migrations/mcp/0004_reserved.sql']='b'*64
   with self.assertRaises(RuntimeError):validate_manifest(value)
 def test_every_required_file_is_mandatory(self):
  for omitted in REQUIRED:
   with self.subTest(omitted=omitted):
    manifest=dict(version=1,scope=SCOPE,files={name:'a'*64 for name in REQUIRED if name!=omitted},symlinks={},directories=[])
    with self.assertRaisesRegex(RuntimeError,'required source closure missing'):validate_manifest(manifest)
 def test_mailpit_exact_layout(self):
  row={'HostConfig':{'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,noexec,nosuid,size=16777216'}},'Mounts':[],
       'NetworkSettings':{'Ports':{key:[{'HostIp':'127.0.0.1','HostPort':str(port)}] for key,port in [('1025/tcp',30125),('8025/tcp',38025)]}}}
  self.assertEqual(validate_mailpit_layout(row),(30125,38025))
  with_pop=copy.deepcopy(row);with_pop['NetworkSettings']['Ports']['1110/tcp']=None
  self.assertEqual(validate_mailpit_layout(with_pop),(30125,38025))
  for bound in [[],[{'HostIp':'127.0.0.1','HostPort':'31110'}]]:
   with_pop['NetworkSettings']['Ports']['1110/tcp']=bound
   with self.assertRaises(RuntimeError):validate_mailpit_layout(with_pop)
  for change in ['writable','mount','host','default','extra','tmpfs']:
   value=copy.deepcopy(row)
   if change=='writable':value['HostConfig']['ReadonlyRootfs']=False
   elif change=='mount':value['Mounts']=[{'Source':'foreign'}]
   elif change=='host':value['NetworkSettings']['Ports']['1025/tcp'][0]['HostIp']='0.0.0.0'
   elif change=='default':value['NetworkSettings']['Ports']['1025/tcp'][0]['HostPort']='1025'
   elif change=='extra':value['NetworkSettings']['Ports']['443/tcp']=[]
   else:value['HostConfig']['Tmpfs']={}
   with self.assertRaises(RuntimeError):validate_mailpit_layout(value)
 def test_bound_one_use_control(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory).resolve()/'control.json';expected={'owner_handle':123,'manifest_sha256':'a'*64,'mailpit_image_id':'sha256:'+'b'*64}
   grant=dict(scope=SCOPE,status='granted',allowedLaunches=1,**expected)
   path.write_text(json.dumps(grant));path.chmod(0o600)
   with self.assertRaises(RuntimeError):consume_control(path,{**expected,'owner_handle':124})
   self.assertEqual(json.loads(path.read_text())['status'],'granted')
   consume_control(path,expected)
   self.assertEqual(json.loads(path.read_text())['status'],'consumed')
   with self.assertRaises(RuntimeError):consume_control(path,expected)
 def test_control_symlink_and_public_permissions_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory).resolve()/'control.json';path.write_text('{}');path.chmod(0o644)
   with self.assertRaises(RuntimeError):consume_control(path,{})
   path.chmod(0o600);link=path.with_name('link');link.symlink_to(path)
   with self.assertRaises(RuntimeError):consume_control(link,{})

if __name__=='__main__':unittest.main()
