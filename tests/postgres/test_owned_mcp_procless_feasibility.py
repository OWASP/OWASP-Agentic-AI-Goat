import pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
class Feasibility(unittest.TestCase):
 def test_portable_closed_peer_frame_contract(self):
  header=ROOT/'sidecars/sandbox-runner/owned-mcp-registry/procless-peer-contract.h'
  code='#include <assert.h>\n#include "'+str(header)+'"\n'+r'''int main(void){unsigned char nonce[16]={1,2,3},frame[18]={'R',1,2,3};
#define CHECK(kind,n,trunc,count,pid,uid,gid) peer_frame_valid(frame,n,kind,nonce,trunc,count,pid,uid,gid,10001,10001,1)
assert(CHECK('R',17,0,1,22,10001,10001));assert(!CHECK('R',17,1,1,22,10001,10001));assert(!CHECK('R',17,0,0,22,10001,10001));assert(!CHECK('R',17,0,2,22,10001,10001));assert(!CHECK('R',17,0,1,1,10001,10001));assert(!CHECK('R',17,0,1,22,10002,10001));assert(!CHECK('R',17,0,1,22,10001,10002));assert(!CHECK('R',18,0,1,22,10001,10001));assert(!CHECK('D',17,0,1,22,10001,10001));nonce[0]=9;assert(!CHECK('R',17,0,1,22,10001,10001));nonce[0]=1;frame[0]='D';assert(CHECK('D',17,0,1,22,10001,10001));assert(!CHECK('R',17,0,1,22,10001,10001));return 0;}
'''

  with tempfile.TemporaryDirectory() as d:
   source=pathlib.Path(d)/'check.c';binary=pathlib.Path(d)/'check';source.write_text(code)
   subprocess.run(['cc','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True,capture_output=True)
   result=subprocess.run([str(binary)],check=True,capture_output=True);self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')
 def test_actual_signal_handler_interrupts_wait_and_socket_race_is_nonblocking(self):
  source=(ROOT/'sidecars/sandbox-runner/owned-mcp-registry/procless-feasibility.c').read_text()
  handlers=source[source.index('static volatile sig_atomic_t'):source.index('static long clock_ms')]
  code='#include <assert.h>\n#include <signal.h>\n#include <string.h>\n#include <errno.h>\n#include <poll.h>\n#include <unistd.h>\n#include <sys/socket.h>\n#include <sys/wait.h>\n'+handlers+r'''int main(void){
assert(!install_handlers());struct sigaction installed;assert(!sigaction(SIGTERM,NULL,&installed));assert(!(installed.sa_flags&SA_RESTART));
int pair[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,pair));pid_t child=fork();assert(child>=0);
if(!child){usleep(20000);kill(getppid(),SIGTERM);_exit(0);}
struct pollfd gate={pair[0],POLLIN,0};assert(poll(&gate,1,1000)==-1&&errno==EINTR&&cancelled);assert(waitpid(child,NULL,0)==child);
/* Readiness consumed before our receive must fail immediately, never block. */
char byte='x';assert(send(pair[1],&byte,1,0)==1);assert(poll(&gate,1,1000)==1);assert(recv(pair[0],&byte,1,0)==1);
assert(recv(pair[0],&byte,1,MSG_DONTWAIT)==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));close(pair[0]);close(pair[1]);return 0;}
'''
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'signal.c';binary=pathlib.Path(d)/'signal';path.write_text(code)
   subprocess.run(['cc','-Wall','-Wextra','-Werror',str(path),'-o',str(binary)],check=True,capture_output=True)
   subprocess.run([str(binary)],check=True,capture_output=True,timeout=3)
  self.assertIn('recvmsg(socket,&message,MSG_DONTWAIT)',source)
  self.assertNotIn('MSG_NOSIGNAL)',source)
  self.assertIn('if(now<0||now>=end)return 0',source)
 def test_probe_has_no_completion_or_policy_relaxation(self):
  source=(ROOT/'sidecars/sandbox-runner/owned-mcp-registry/procless-feasibility.c').read_text()
  for required in ['SO_PASSCRED','SCM_CREDENTIALS','SYS_pidfd_open','read_start(peer,&after)','after!=start','descendant(peer,child)','PR_GET_SECCOMP','PR_GET_NO_NEW_PRIVS','"--unshare-all"','"--seccomp","3"','"--dir","/proc"','"--tmpfs","/proc","--remount-ro","/proc"','MSG_CTRUNC','cancelled||poll','alarm(12)','drain(child)']:
   self.assertIn(required,source)
  self.assertNotIn('ptrace(',source);self.assertNotIn('setns(',source);self.assertNotIn('"--proc"',source)
  self.assertNotIn('invocation-worker.js',source);self.assertNotIn('signing.key',source)
 def test_actual_worker_requires_trusted_gate_and_diagnostic_image_separate(self):
  current=(ROOT/'sidecars/sandbox-runner/owned-mcp-registry/invocation-supervisor.c').read_text();self.assertIn('r->state=attested&&!forced',current);self.assertIn('ATTEST_BINARY,NULL',current)
  image=(ROOT/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.procless-feasibility').read_text();self.assertIn('-Wall -Wextra -Werror',image);self.assertIn('"--probe"',image)
if __name__=='__main__':unittest.main()
