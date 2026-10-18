#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "invocation-private-diagnostic.h"
#include "invocation-attestation.h"
#include "invocation-qualification-schedule.h"
#define HEADER 224
#define MAX_INPUT 196608
#define MAX_OUTPUT 65536
#define ROWS 64
#define STATE_ROOT "/var/lib/dvaia-invocation"
#define CONTROL "/run/dvaia-invocation/control.sock"
static volatile sig_atomic_t stopping=0;
static pid_t listener=-1,worker=-1;
static int worker_fd=-1,output_fd=-1,active=-1,start_fd=-1;
static long deadline=0,forced_at=0;static int forced=0,output_eof=0;
static unsigned char secret[32],start_header[HEADER],drain_header[HEADER];
static int drain_fd=-1;
static struct attestation attestation={.socket=-1,.pidfd=-1,.nsfds={-1,-1,-1,-1,-1,-1}};
static int attested=0;
static char epoch[37];
struct row {unsigned char ids[108];unsigned char state;size_t size,input_size;unsigned char *input;char output[MAX_OUTPUT];};
static struct row rows[ROWS];static size_t count=0;
static long now_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(70);return t.tv_sec*1000L+t.tv_nsec/1000000;}
static void stop_signal(int sig){(void)sig;stopping=1;}
static int uuid_valid(const char *s){for(int i=0;i<36;i++){if(i==8||i==13||i==18||i==23){if(s[i]!='-')return 0;}else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;}return 1;}
static int hash_valid(const char *s){if(strlen(s)!=64)return 0;for(int i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1;}
static void make_uuid(char out[37]){unsigned char b[16];if(getrandom(b,16,0)!=16)_exit(70);b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;snprintf(out,37,"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);}
static int transfer(int fd,void *bytes,size_t length,int writing,long until){size_t offset=0;while(offset<length){long left=until-now_ms();if(left<=0)return -1;struct pollfd p={fd,writing?POLLOUT:POLLIN,0};int ready=poll(&p,1,(int)left);if(ready<0&&errno==EINTR)continue;if(ready<=0)return -1;ssize_t n=writing?send(fd,(char*)bytes+offset,length-offset,MSG_NOSIGNAL):read(fd,(char*)bytes+offset,length-offset);if(n<0&&(errno==EINTR||errno==EAGAIN))continue;if(n<=0)return -1;offset+=(size_t)n;}return 0;}
static void respond(int fd,const unsigned char *request,struct row *r){unsigned char h[HEADER];memcpy(h,request,HEADER);memcpy(h,"DVO1",4);h[5]=r?r->state:5;h[6]=r?1:0;h[7]=0;memset(h+188,0,32);uint32_t n=htonl(r?(uint32_t)r->size:0);memcpy(h+220,&n,4);long until=now_ms()+500;if(!transfer(fd,h,HEADER,1,until)&&r&&r->size)transfer(fd,r->output,r->size,1,until);close(fd);}
static int open_owned(int dir,const char *name,int flags,mode_t mode){int fd=openat(dir,name,flags|O_NOFOLLOW|O_CLOEXEC,mode);struct stat st;if(fd<0)return -1;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&0777)!=0600||st.st_nlink!=1){close(fd);return -1;}return fd;}
static int descendants(void){FILE *f=fopen("/proc/self/task/1/children","r");if(!f)return -1;long pid;int found=0;while(fscanf(f,"%ld",&pid)==1)if(pid>0&&pid!=listener){found=1;if(kill((pid_t)pid,SIGKILL)&&errno!=ESRCH){fclose(f);return -1;}}fclose(f);return found;}
static void stop_worker(void){attest_close(&attestation);if(!forced)forced_at=now_ms();forced=1;if(worker_fd>=0)syscall(SYS_pidfd_send_signal,worker_fd,SIGKILL,NULL,0);}
static void read_output(void){if(active<0||output_fd<0)return;char buffer[4096];ssize_t got;
 while((got=read(output_fd,buffer,sizeof(buffer)))>0){struct row *r=&rows[active];if(r->size+(size_t)got>MAX_OUTPUT){r->state=3;stop_worker();}else{memcpy(r->output+r->size,buffer,(size_t)got);r->size+=(size_t)got;}}
 if(got==0)output_eof=1;else if(got<0&&errno!=EAGAIN&&errno!=EINTR)stop_worker();
}
static int start_worker(const unsigned char *payload,size_t length){
 int input=memfd_create("owned-invocation-input",MFD_CLOEXEC|MFD_ALLOW_SEALING),pipes[2],channel[2];
 if(input<0)return -1;
 if(write(input,payload,length)!=(ssize_t)length||lseek(input,0,SEEK_SET)<0||fcntl(input,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)||pipe2(pipes,O_CLOEXEC|O_NONBLOCK)){close(input);return -1;}
 if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel)){close(input);close(pipes[0]);close(pipes[1]);return -1;}
 int enabled=1,sendfd=fcntl(channel[1],F_DUPFD_CLOEXEC,64);
 attestation=(struct attestation){.socket=channel[0],.pidfd=-1,.nsfds={-1,-1,-1,-1,-1,-1},.until=now_ms()+5000};attested=0;
 if(sendfd<0||setsockopt(channel[0],SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled))||getrandom(attestation.nonce,16,0)!=16){if(sendfd>=0)close(sendfd);close(channel[1]);attest_close(&attestation);close(input);close(pipes[0]);close(pipes[1]);return -1;}
 pid_t pid=fork();
 if(pid<0){close(sendfd);close(channel[1]);attest_close(&attestation);close(input);close(pipes[0]);close(pipes[1]);return -1;}
 if(pid==0){
  int filter=open("/usr/share/dvaia/invocation-target.seccomp.bpf",O_RDONLY|O_NOFOLLOW);
  if(filter<0||dup2(input,0)<0||dup2(pipes[1],1)<0||dup2(pipes[1],2)<0||dup2(filter,3)<0||dup2(sendfd,4)<0)_exit(70);
  if(fcntl(1,F_SETFL,0)||fcntl(2,F_SETFL,0)||syscall(SYS_close_range,5,~0U,0))_exit(70);
  char *args[]={"/usr/bin/bwrap","--unshare-all","--die-with-parent","--new-session","--clearenv","--tmpfs","/","--ro-bind","/usr","/usr","--ro-bind","/lib","/lib","--ro-bind-try","/lib64","/lib64","--dev","/dev","--dir","/proc","--tmpfs","/proc","--remount-ro","/proc","--dir","/tmp","--chdir","/tmp","--seccomp","3",ATTEST_BINARY,NULL};
  char *env[]={"PATH=/usr/bin:/bin",NULL};execve(args[0],args,env);_exit(127);
 }
 close(sendfd);close(channel[1]);close(input);close(pipes[1]);QUALIFICATION_START();worker=pid;worker_fd=(int)syscall(SYS_pidfd_open,pid,0);output_fd=pipes[0];deadline=now_ms()+10000;
 if(worker_fd<0){kill(pid,SIGKILL);return -1;}return 0;
}
static void request(int fd){struct ucred peer;socklen_t size=sizeof(peer);unsigned char h[HEADER];long until=now_ms()+500;if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||peer.pid!=listener||peer.uid!=getuid()||transfer(fd,h,HEADER,0,until)){close(fd);return;}
 if(memcmp(h,"DVI1",4)||h[4]<1||h[4]>4||h[5]||h[6]||h[7]||memcmp(h+44,epoch,36)){close(fd);return;}unsigned char diff=0;for(int i=0;i<32;i++)diff|=h[188+i]^secret[i];if(diff){close(fd);return;}for(int i=0;i<5;i++)if(!uuid_valid((char*)h+8+i*36)){close(fd);return;}
 uint32_t n;memcpy(&n,h+220,4);n=ntohl(n);if(n>MAX_INPUT||(h[4]!=1&&n)){close(fd);return;}unsigned char *payload=n?malloc(n):NULL;if(n&&(!payload||transfer(fd,payload,n,0,until))){free(payload);close(fd);return;}
 if(h[4]==4){free(payload);struct row lease={.state=1,.size=14};memcpy(lease.output,"{\"lease\":true}",14);respond(fd,h,&lease);return;}
 int index=-1;for(size_t i=0;i<count;i++)if(!memcmp(rows[i].ids,h+80,36)){index=(int)i;break;}
 if(index>=0&&memcmp(rows[index].ids,h+80,108)){free(payload);respond(fd,h,NULL);return;}
 if(h[4]!=1){free(payload);if(index<0){respond(fd,h,NULL);return;}if(index==active){if(h[4]==2){respond(fd,h,NULL);return;}if(drain_fd>=0){respond(fd,h,NULL);return;}drain_fd=fd;memcpy(drain_header,h,HEADER);QUALIFICATION_ADMITTED(attestation.phase,attested,now_ms(),attestation.until,deadline);stop_worker();return;}respond(fd,h,&rows[index]);return;}
 if(index>=0){int same=rows[index].input_size==n&&(!n||!memcmp(rows[index].input,payload,n));free(payload);respond(fd,h,same&&index!=active?&rows[index]:NULL);return;}
 if(count==ROWS){free(payload);respond(fd,h,NULL);return;}index=(int)count++;rows[index].input_size=n;rows[index].input=n?malloc(n):NULL;if(n&&!rows[index].input){free(payload);respond(fd,h,NULL);return;}if(n)memcpy(rows[index].input,payload,n);memcpy(rows[index].ids,h+80,108);rows[index].state=2;rows[index].size=4;memcpy(rows[index].output,"null",4);
 if(active>=0){free(payload);respond(fd,h,&rows[index]);return;}
 active=index;forced=0;output_eof=0;rows[index].state=3;rows[index].size=0;memcpy(start_header,h,HEADER);start_fd=fd;
 if(start_worker(payload,n)){free(payload);stop_worker();if(worker<0){rows[index].state=2;rows[index].size=4;memcpy(rows[index].output,"null",4);respond(start_fd,start_header,&rows[index]);start_fd=-1;active=-1;}return;}free(payload);
}
static pid_t start_listener(int lockfd,const char *manager,const char *volume,const char *runtime){int bootstrap=memfd_create("invocation-bootstrap",MFD_CLOEXEC|MFD_ALLOW_SEALING);if(bootstrap<0)return -1;char hex[65],body[1024];for(int i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",secret[i]);int n=snprintf(body,sizeof(body),"{\"managerInstanceId\":\"%s\",\"volumeId\":\"%s\",\"runtimeSha256\":\"%s\",\"supervisorEpoch\":\"%s\",\"secret\":\"%s\"}",manager,volume,runtime,epoch,hex);if(write(bootstrap,body,(size_t)n)!=n||lseek(bootstrap,0,SEEK_SET)<0||fcntl(bootstrap,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)){close(bootstrap);return -1;}
 pid_t pid=fork();if(pid==0){int b=fcntl(bootstrap,F_DUPFD_CLOEXEC,10),l=fcntl(lockfd,F_DUPFD_CLOEXEC,10);if(b<0||l<0||dup2(b,3)<0||dup2(l,4)<0)_exit(70);if(syscall(SYS_close_range,5,~0U,0))_exit(70);char *argv[]={"/usr/local/bin/node","/app/sidecars/sandbox-runner/owned-mcp-registry/invocation-listener.js",NULL};char *env[]={"PATH=/usr/bin:/bin",NULL};execve(argv[0],argv,env);_exit(127);}close(bootstrap);return pid;
}
int main(int argc,char **argv){if(argc!=4||getpid()!=1||getuid()!=10001||strlen(argv[1])!=36||!uuid_valid(argv[1])||strlen(argv[2])!=36||!uuid_valid(argv[2])||!hash_valid(argv[3]))return 70;
 int dir=open(STATE_ROOT,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat st;if(dir<0||fstat(dir,&st)||st.st_uid!=getuid()||(st.st_mode&0777)!=0700)return 70;
 int lock=open_owned(dir,"supervisor.lock",O_RDWR,0600);if(lock<0||flock(lock,LOCK_EX|LOCK_NB))return 70;
 int manifest=open_owned(dir,"identity",O_RDONLY,0600);char wanted[160],actual[160];int n=snprintf(wanted,sizeof(wanted),"%s\n%s\n%s\n",argv[1],argv[2],argv[3]);if(manifest<0||read(manifest,actual,sizeof(actual))!=n||memcmp(actual,wanted,(size_t)n))return 70;close(manifest);
 // A previous supervisor epoch is never treated as proof of container death.
 int marker=open_owned(dir,"supervisor.epoch",O_WRONLY|O_CREAT|O_EXCL,0600);if(marker<0)return 70;make_uuid(epoch);if(write(marker,epoch,36)!=36||fsync(marker)||fsync(dir))return 70;close(marker);
 if(getrandom(secret,32,0)!=32||prctl(PR_SET_CHILD_SUBREAPER,1))return 70;
 signal(SIGPIPE,SIG_IGN);struct sigaction action={0};action.sa_handler=stop_signal;sigemptyset(&action.sa_mask);sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);
 int server=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path,sizeof(address.sun_path),"%s",CONTROL);if(server<0||bind(server,(struct sockaddr*)&address,sizeof(address))||chmod(CONTROL,0600)||listen(server,8))return 70;
 listener=start_listener(lock,argv[1],argv[2],argv[3]);if(listener<1)return 70;int worker_done=0,worker_status=0,restarts=0;
 while(!stopping){struct pollfd fds[2]={{server,POLLIN,0},{output_fd,POLLIN,0}};poll(fds,2,20);if(fds[0].revents&POLLIN){int fd=accept4(server,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);if(fd>=0)request(fd);}
  if(active>=0&&!forced&&!attested&&!QUALIFICATION_HOLD(attestation.phase,now_ms(),attestation.until,stopping)){int gate=attest_step(&attestation,worker,now_ms(),stopping);if(gate<0)stop_worker();else if(gate==1)attested=1;}
  read_output();if(active>=0&&now_ms()>deadline)stop_worker();
  if(active>=0&&forced&&now_ms()>forced_at+2000){stopping=1;break;}
  int status;pid_t pid;while((pid=waitpid(-1,&status,WNOHANG))>0){if(pid==listener){listener=-1;if(++restarts>2){stopping=1;break;}listener=start_listener(lock,argv[1],argv[2],argv[3]);if(listener<1)stopping=1;}else if(pid==worker){worker_done=1;worker_status=status;}}
  if(active>=0&&worker_done){int remaining=descendants();if(remaining<0){stopping=1;break;}if(!remaining){read_output();if(!output_eof)continue;struct row *r=&rows[active];r->state=attested&&!forced&&WIFEXITED(worker_status)&&WEXITSTATUS(worker_status)==0&&r->size?1:3;if(r->state!=1){const char *diagnostic=getenv("DVAIA_INVOCATION_PRIVATE_DIAGNOSTICS");if(diagnostic&&!strcmp(diagnostic,"1")){int directory=open(STATE_ROOT,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(directory>=0){(void)retain_private_failure(1,directory,r->output,r->size);close(directory);}}int phase=0;for(int candidate=1;candidate<=5;candidate++){char marker[64];int length=snprintf(marker,sizeof(marker),"DVAIA_WORKER_FAILURE phase=%d category=1\n",candidate);if(r->size>=(size_t)length&&!memcmp(r->output+r->size-length,marker,(size_t)length))phase=candidate;}fprintf(stderr,"DVAIA_SUPERVISOR_RESULT exit=%d signal=%d forced=%d outputBytes=%zu eof=%d workerPhase=%d workerCategory=%d\n",WIFEXITED(worker_status)?WEXITSTATUS(worker_status):-1,WIFSIGNALED(worker_status)?WTERMSIG(worker_status):0,forced?1:0,r->size,output_eof?1:0,phase,phase?1:0);r->size=4;memcpy(r->output,"null",4);}if(start_fd>=0)respond(start_fd,start_header,r);if(drain_fd>=0)respond(drain_fd,drain_header,r);drain_fd=-1;start_fd=-1;attest_close(&attestation);close(output_fd);close(worker_fd);output_fd=-1;worker_fd=-1;worker=-1;active=-1;worker_done=0;}}
 }
 stop_worker();if(listener>0)kill(listener,SIGTERM);long end=now_ms()+2000;while(now_ms()<end){int status;while(waitpid(-1,&status,WNOHANG)>0){}if(descendants()==0)break;usleep(10000);}close(server);unlink(CONTROL);return 70;
}
