import pathlib,subprocess,tempfile,unittest,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE=ROOT/'sidecars/sandbox-runner/owned-mcp-registry'
def compile_run(code):
 with tempfile.TemporaryDirectory() as d:
  p=pathlib.Path(d)/'test.c';p.write_text(code);binary=pathlib.Path(d)/'test'
  architecture=[]
  if sys.platform=='darwin':
   supported=subprocess.run(['/usr/sbin/sysctl','-n','hw.optional.arm64'],capture_output=True,text=True,timeout=3)
   if supported.returncode==0 and supported.stdout.strip()=='1':architecture=['-arch','arm64']
  compiled=subprocess.run(['cc',*architecture,'-Wall','-Wextra','-Werror',str(p),'-o',str(binary)],capture_output=True);assert compiled.returncode==0,compiled.stderr.decode()
  executed=subprocess.run([str(binary)],capture_output=True,timeout=3);assert executed.returncode==0,(executed.returncode,executed.stderr.decode())
class Attestation(unittest.TestCase):
 def test_protocol_freshness_and_dynamic_identity(self):
  compile_run('#include <assert.h>\n#include "'+str(BASE/'invocation-attestation-protocol.h')+'"\n'+r'''
int main(void){unsigned char nonce[16]={9},frame[17]={'R',9};
#define VALID(kind,n,trunc,count,pid,uid,gid) peer_frame_valid(frame,n,kind,nonce,trunc,count,pid,uid,gid,10001,10001,1)
assert(VALID('R',17,0,1,23,10001,10001));assert(!VALID('D',17,0,1,23,10001,10001));
assert(!VALID('R',16,0,1,23,10001,10001));assert(!VALID('R',17,1,1,23,10001,10001));
assert(!VALID('R',17,0,0,23,10001,10001));assert(!VALID('R',17,0,2,23,10001,10001));
assert(!VALID('R',17,0,1,1,10001,10001));assert(!VALID('R',17,0,1,23,10002,10001));assert(!VALID('R',17,0,1,23,10001,10002));
nonce[1]=1;assert(!VALID('R',17,0,1,23,10001,10001));return 0;}
''')
 def test_actual_state_machine_cancellation_timeout_and_release(self):
  source=(BASE/'invocation-attestation.h').read_text();structure=source[source.index('struct attestation {'):source.index('static void attest_close')];step=source[source.index('static int attest_step'):source.index('\n#endif')]
  preamble=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
#define SYS_pidfd_open 1
#define ATTEST_BINARY "fixed"
static int sends=0,closed=0,receive_result=0,wrong_ack=0,stale=0;
static const char *bad_namespace=NULL;
static int namespace_unavailable=0,network_failure=0;
static pid_t getpid(void){return 1;}
static int descendant(pid_t p,pid_t r){return p==23&&r==2;}
static int syscall(int n,pid_t p,int x){(void)n;(void)p;(void)x;return 42;}
static int read_start(pid_t p,unsigned long long *out){(void)p;*out=stale?8:7;return 0;}
static int namespace_fd(pid_t p,const char *n){if(p!=1&&bad_namespace&&!strcmp(n,bad_namespace))return namespace_unavailable?-1:10;return p==1?10:11;}
static int fstat(int fd,struct stat *out){memset(out,0,sizeof(*out));out->st_ino=fd;return 0;}
static int stat(const char *p,struct stat *out){(void)p;memset(out,0,sizeof(*out));out->st_ino=99;out->st_mode=S_IFREG;out->st_nlink=1;return 0;}
static int close(int fd){(void)fd;return 0;}
static int status_safe(pid_t p){(void)p;return 1;}
static int loopback_only(pid_t p){assert(p==23);return network_failure!=1;}
static int no_routes(pid_t p){assert(p==23);return network_failure!=2;}
static int ipv6_loopback_only(pid_t p){assert(p==23);return network_failure!=3;}
static int poll(struct pollfd *p,unsigned long n,int t){(void)p;(void)n;(void)t;return 0;}
'''
  # System headers declare stat/fstat/poll; use test-local names for doubles.
  for name in ['fstat','stat','poll']:
   preamble=preamble.replace('static int '+name+'(', 'static int fake_'+name+'(')
   step=re.sub(r'\b'+name+r'\(', 'fake_'+name+'(',step)
  stubs=r'''
static void attest_close(struct attestation *a){(void)a;closed++;}
static int attest_send(struct attestation *a,unsigned char kind){(void)a;assert(kind=='C'||kind=='G');sends++;return 0;}
static int attest_receive(struct attestation *a,unsigned char kind,pid_t *p,uid_t *u,gid_t *g){(void)a;(void)kind;*p=wrong_ack?24:23;*u=10001;*g=10001;return receive_result;}
'''
  body=r'''
int main(void){struct attestation a={.until=100,.socket=9,.pidfd=-1};
for(int phase=0;phase<4;phase++){a.phase=phase;assert(attest_step(&a,2,1,1)==-1);assert(attest_step(&a,2,100,0)==-1);}assert(sends==0);
a.phase=0;assert(attest_step(&a,2,1,0)==0&&a.phase==1&&sends==1);
assert(attest_step(&a,2,1,0)==0&&a.phase==1);receive_result=1;
assert(attest_step(&a,2,1,0)==0&&a.phase==2&&sends==1);
stale=1;assert(attest_step(&a,2,1,0)==-1&&sends==1);stale=0;
assert(attest_step(&a,2,1,0)==0&&a.phase==3&&sends==2);
wrong_ack=1;assert(attest_step(&a,2,1,0)==-1&&closed==0);wrong_ack=0;
assert(attest_step(&a,2,1,0)==1&&a.phase==4&&closed==1);
assert(attest_step(&a,2,1,0)==-1);
/* Run the actual phase-one gate for every same/missing namespace and each
   network predicate. No release or completion is permitted on rejection. */
const char *names[]={"user","mnt","pid","net","ipc","uts"};
for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++)for(int missing=0;missing<2;missing++){
 a=(struct attestation){.until=100,.socket=9,.pidfd=-1,.phase=1};
 sends=0;closed=0;bad_namespace=names[i];namespace_unavailable=missing;
 assert(attest_step(&a,2,1,0)==-1);assert(a.phase==1&&sends==0&&closed==0);
}
bad_namespace=NULL;namespace_unavailable=0;
for(int predicate=1;predicate<=3;predicate++){
 a=(struct attestation){.until=100,.socket=9,.pidfd=-1,.phase=1};
 sends=0;closed=0;network_failure=predicate;
 assert(attest_step(&a,2,1,0)==-1);assert(a.phase==1&&sends==0&&closed==0);
}
/* Restore all predicates: same invocation identity can reach release only
   through the complete valid handshake. */
network_failure=0;a=(struct attestation){.until=100,.socket=9,.pidfd=-1,.phase=1};
assert(attest_step(&a,2,1,0)==0&&a.phase==2&&sends==0);
assert(attest_step(&a,2,1,0)==0&&a.phase==3&&sends==1);
assert(attest_step(&a,2,1,0)==1&&a.phase==4&&closed==1);
return 0;}
'''
  compile_run(preamble+structure+stubs+step+body)
 def test_full_buffer_rights_cleanup_and_platform_truncation_characterization(self):
  source=(BASE/'invocation-attestation.h').read_text();cleanup=source[source.index('static void attest_discard_rights'):source.index('static int attest_receive')]
  compile_run(r'''
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
static int descriptors(void){int n=0;for(int fd=0;fd<1024;fd++)if(fcntl(fd,F_GETFD)>=0)n++;return n;}
'''+cleanup+r'''
int main(void){int pair[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,pair));int source=open("/dev/null",O_RDONLY);assert(source>=0);int baseline=descriptors();
for(int round=0;round<21;round++){
 char byte='x';struct iovec io={&byte,1};union{struct cmsghdr align;char bytes[CMSG_SPACE(16*sizeof(int))];}sending;
 memset(&sending,0,sizeof(sending));struct msghdr out={0};out.msg_iov=&io;out.msg_iovlen=1;out.msg_control=sending.bytes;out.msg_controllen=sizeof(sending.bytes);
 struct cmsghdr *c=CMSG_FIRSTHDR(&out);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(16*sizeof(int));
 int rights[16];for(int i=0;i<16;i++)rights[i]=source;memcpy(CMSG_DATA(c),rights,sizeof(rights));assert(sendmsg(pair[1],&out,0)==1);
 union{struct cmsghdr align;char bytes[CMSG_SPACE(16*sizeof(int))];}received;memset(&received,0,sizeof(received));
 struct msghdr in={0};in.msg_iov=&io;in.msg_iovlen=1;in.msg_control=received.bytes;in.msg_controllen=round==20?CMSG_SPACE(sizeof(int)):sizeof(received.bytes);
 int receive_flags=0;
#ifdef MSG_CMSG_CLOEXEC
 receive_flags=MSG_CMSG_CLOEXEC;
#endif
 assert(recvmsg(pair[0],&in,receive_flags)==1);if(round==20)assert(in.msg_flags&MSG_CTRUNC);
#ifdef MSG_CMSG_CLOEXEC
 for(struct cmsghdr *message=CMSG_FIRSTHDR(&in);message;message=CMSG_NXTHDR(&in,message)){
  if(message->cmsg_type==SCM_RIGHTS){int *fds=(int*)CMSG_DATA(message);size_t count=(message->cmsg_len-CMSG_LEN(0))/sizeof(int);for(size_t i=0;i<count;i++)assert(fcntl(fds[i],F_GETFD)&FD_CLOEXEC);}
 }
#endif
 attest_discard_rights(&in);
#ifdef __APPLE__
 /* Darwin exposes one descriptor but installs all16 on control truncation.
  * Record this limitation; it is NOT evidence of leak-free Linux truncation.
  * This final isolated child exits immediately, releasing inaccessible FDs. */
 if(round==20){assert(descriptors()>baseline);fprintf(stderr,"DARWIN_TRUNCATION_LIMITATION hiddenRights=%d\n",descriptors()-baseline);}
 else assert(descriptors()==baseline);
#else
 assert(descriptors()==baseline);
#endif
}close(source);close(pair[0]);close(pair[1]);return 0;}
''')
  self.assertIn('ATTEST_LINUX_MAX_RIGHTS 253',source)
  self.assertIn('CMSG_SPACE(ATTEST_LINUX_MAX_RIGHTS*sizeof(int))',source)
  self.assertIn('MSG_DONTWAIT|MSG_CMSG_CLOEXEC',source)
  self.assertLess(source.index('if(n>=0)attest_discard_rights'),source.index('if(n<0||message.msg_flags'))
 def test_bootstrap_closes_channel_before_fixed_exec_and_completion_gate(self):
  bootstrap=(BASE/'invocation-bootstrap.c').read_text();supervisor=(BASE/'invocation-supervisor.c').read_text()
  self.assertLess(bootstrap.index('SYS_close_range,3'),bootstrap.index('execve(argv[0]'))
  self.assertIn('"/usr/local/bin/node","/usr/local/libexec/dvaia-invocation-worker.js",NULL',bootstrap)
  self.assertIn('r->state=attested&&!forced&&WIFEXITED(worker_status)&&WEXITSTATUS(worker_status)==0&&r->size?1:3',supervisor)
  self.assertIn('if(!output_eof)continue',supervisor)
  self.assertLess(supervisor.index('request(fd);}',supervisor.index('while(!stopping)')),supervisor.index('attest_step(&attestation'))
if __name__=='__main__':unittest.main()
