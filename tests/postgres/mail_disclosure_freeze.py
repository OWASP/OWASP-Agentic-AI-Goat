"""Disclosure-only private staging; reuses reviewed inventory and pin checks."""
import hashlib
from pathlib import Path
from mail_reply_authority_freeze import inventory, copy, verify, check_pins, digest, DOCKER_SHA
CURRICULUM='server/config/secureshopCurriculum.js'
OBJECTIVE='ss_mail_cross_persona_read'
def stage_expected(rows,source):
 data=(Path(source)/CURRICULUM).read_text();lines=data.splitlines(keepends=True)
 indexes=[i for i,line in enumerate(lines) if "{ id: '"+OBJECTIVE+"'," in line]
 if len(indexes)!=1:raise RuntimeError('Exact disclosure catalog row required')
 i=indexes[0]
 if "qualification: 'pending'" not in lines[i]:raise RuntimeError('Disclosure must remain pending in reviewed source')
 lines[i]=lines[i].replace("qualification: 'pending'","qualification: 'native-model'")
 staged=''.join(lines).encode();expected=dict(rows)
 expected[CURRICULUM]={'kind':'file','bytes':len(staged),'sha256':hashlib.sha256(staged).hexdigest()}
 return expected,staged
