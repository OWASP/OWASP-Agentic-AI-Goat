"""Closed copied-file membership for authority-only model diagnostics; no resources."""
import hashlib,os
from pathlib import Path

def verify_files(destination, reviewed_rows):
 destination=Path(destination);found={}
 for current,dirs,files in os.walk(destination,followlinks=False):
  for name in list(dirs):
   item=Path(current)/name
   if item.is_symlink():
    if item!=destination/'node_modules':raise RuntimeError('Unexpected copied directory symlink')
    dirs.remove(name)
  for name in files:
   item=Path(current)/name
   if item.is_symlink():raise RuntimeError('Unexpected copied file symlink')
   relative=item.relative_to(destination).as_posix()
   if relative not in reviewed_rows:raise RuntimeError('Copied path absent from reviewed inventory')
   data=item.read_bytes();found[relative]={'kind':'file','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
 if found!=reviewed_rows:raise RuntimeError('Copied reviewed inventory differs')
 return found

def verify_retained(path,expected):
 if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=expected:raise RuntimeError('Retained diagnostic input changed')
