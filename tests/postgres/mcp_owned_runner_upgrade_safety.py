"""Pure process-pause and recovery rules for the owned runner upgrade."""
import signal

QUALIFIED_OBJECTIVES = ('mcp_cmd_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_audit_gap')

class OwnedPauseSet:
    def __init__(self): self.stopped=[]
    def stop(self,pid,send):
        send(pid,signal.SIGSTOP)
        self.stopped.append(pid)
    def resume_all(self,send):
        errors=[]
        while self.stopped:
            pid=self.stopped.pop()
            try: send(pid,signal.SIGCONT)
            except ProcessLookupError: pass
            except Exception as error: errors.append((pid,type(error).__name__))
        return errors

def validate_recovery(*,prior_pid,candidate_pid,healthy,replacement_required):
    if healthy is not True or not isinstance(candidate_pid,int) or candidate_pid<=0:
        raise RuntimeError('application recovery is not healthy')
    if replacement_required and candidate_pid==prior_pid:
        raise RuntimeError('application recovery did not replace the prior backend')
    if not replacement_required and candidate_pid!=prior_pid:
        raise RuntimeError('application recovery did not retain the resumed backend')
    return candidate_pid

def smoke_login_payload(value):
    if not isinstance(value,dict) or set(value) not in ({'username','password'},{'username','email','password'}):
        raise RuntimeError('smoke credential shape invalid')
    if not all(isinstance(value[key],str) and value[key] for key in ('username','password')):
        raise RuntimeError('smoke credential shape invalid')
    if 'email' in value and (not isinstance(value['email'],str) or not value['email']):
        raise RuntimeError('smoke credential shape invalid')
    return {'username':value['username'],'password':value['password']}

def validate_qualified_objectives(value):
    if not isinstance(value,list) or tuple(value)!=QUALIFIED_OBJECTIVES:
        raise RuntimeError('authenticated infra objective set invalid')
    return len(value)
