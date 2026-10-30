#define _GNU_SOURCE
/* Qualification image only. Actual Linux ancillary receiver, no learner channel. */
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "invocation-attestation.h"
#define SELF "/usr/local/libexec/owasp-ai-goat-invocation-attestation-controls"
static int count_fds(void){DIR *d=opendir("/proc/self/fd");if(!d)return -1;int n=0;struct dirent *e;while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,".."))n++;closedir(d);return n;}
static int wait_ok(pid_t pid){int status;return waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0;}
static int channel(int pair[2]){int enabled=1;return socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)||setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled));}
static int send_frame(int fd,int rights,int split,int wrong){
 unsigned char bytes[18]={'R',1};size_t length=17;if(wrong==1)bytes[1]=2;if(wrong==2)bytes[0]='D';if(wrong==3)length=16;if(wrong==4)length=18;
 struct iovec io={bytes,length};union{struct cmsghdr align;char bytes[CMSG_SPACE(254*sizeof(int))+CMSG_SPACE(sizeof(int))];}control;
 memset(&control,0,sizeof(control));struct msghdr msg={0};msg.msg_iov=&io;msg.msg_iovlen=1;
 int source=-1;
 if(rights){source=open("/dev/null",O_RDONLY|O_CLOEXEC);if(source<0)return -1;msg.msg_control=control.bytes;int first=split?rights/2:rights;msg.msg_controllen=CMSG_SPACE(first*sizeof(int))+(split?CMSG_SPACE((rights-first)*sizeof(int)):0);struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(first*sizeof(int));for(int i=0;i<first;i++)memcpy((char*)CMSG_DATA(c)+i*sizeof(int),&source,sizeof(int));if(split){c=CMSG_NXTHDR(&msg,c);if(!c){close(source);return -1;}c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN((rights-first)*sizeof(int));for(int i=first;i<rights;i++)memcpy((char*)CMSG_DATA(c)+(i-first)*sizeof(int),&source,sizeof(int));}}
 ssize_t n=sendmsg(fd,&msg,MSG_NOSIGNAL);int saved=errno;if(source>=0)close(source);errno=saved;return n==(ssize_t)length?0:-1;
}
static int receiver_case(int rights,int split,int wrong){
 int baseline=count_fds(),pair[2];if(baseline<0||channel(pair))return 0;
 if(wrong==5){int disabled=0;if(setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&disabled,sizeof(disabled)))return 0;}
 pid_t child=fork();if(child<0)return 0;
 if(!child){close(pair[0]);int sent=send_frame(pair[1],rights,split,wrong);_exit(rights==254?(sent<0&&errno==EINVAL?0:70):(sent==0?0:70));}
 close(pair[1]);int ok=0;
 if(rights==254){ok=wait_ok(child);/* Kernel rejects send: never treat this as receiver recovery. */}
 else {struct pollfd ready={pair[0],POLLIN,0};if(poll(&ready,1,1000)==1){struct attestation a={.socket=pair[0],.nonce={1}};pid_t pid=-1;uid_t uid=0;gid_t gid=0;int received=attest_receive(&a,'R',&pid,&uid,&gid);ok=rights||wrong?received==-1:received==1&&pid==child;}ok=wait_ok(child)&&ok;}
 close(pair[0]);return ok&&count_fds()==baseline;
}
static int raw_rights_case(int truncated,int exec_check){
 int baseline=count_fds(),pair[2];if(baseline<0||channel(pair))return 0;pid_t sender=fork();if(sender<0)return 0;
 if(!sender){close(pair[0]);_exit(send_frame(pair[1],16,0,0)?70:0);}close(pair[1]);
 struct pollfd ready={pair[0],POLLIN,0};if(poll(&ready,1,1000)!=1)return 0;
 unsigned char bytes[18];struct iovec io={bytes,sizeof(bytes)};union{struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(16*sizeof(int))];}buffer;
 struct msghdr msg={0};msg.msg_iov=&io;msg.msg_iovlen=1;msg.msg_control=buffer.bytes;msg.msg_controllen=truncated?CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(sizeof(int)):sizeof(buffer.bytes);
 ssize_t received=recvmsg(pair[0],&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);int ok=received==17&&!!(msg.msg_flags&MSG_CTRUNC)==truncated;
 int descriptors[16],count=0;
 if(received>=0){for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){size_t n=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);for(size_t i=0;i<n&&count<16;i++){int fd;memcpy(&fd,(char*)CMSG_DATA(c)+i*sizeof(int),sizeof(fd));descriptors[count++]=fd;int flags=fcntl(fd,F_GETFD);if(flags<0||!(flags&FD_CLOEXEC))ok=0;}}}
 if(exec_check&&ok){
  char values[16][24];char *args[19]={SELF,"--closed"};for(int i=0;i<count;i++){snprintf(values[i],sizeof(values[i]),"%d",descriptors[i]);args[i+2]=values[i];}args[count+2]=NULL;
  pid_t child=fork();if(!child){char *env[]={"PATH=/usr/bin:/bin",NULL};execve(SELF,args,env);_exit(70);}if(child<0||!wait_ok(child))ok=0;
 }
 if(received>=0){attest_discard_rights(&msg);}
 close(pair[0]);return wait_ok(sender)&&ok&&count>0&&count_fds()==baseline;
}
int main(int argc,char **argv){
 (void)&attest_step;alarm(5);
 if(argc>=3&&argc<=18&&!strcmp(argv[1],"--closed")){for(int i=2;i<argc;i++){char *end;long fd=strtol(argv[i],&end,10);if(*end||fd<3||fd>1048576||fcntl((int)fd,F_GETFD)!=-1||errno!=EBADF)return 70;}return 0;}
 if(argc!=1)return 64;
 int passed=0;if(!receiver_case(0,0,0))goto done;passed++;
 for(int wrong=1;wrong<=5;wrong++){if(!receiver_case(0,0,wrong))goto done;}
 passed++;
 for(int i=0;i<20;i++){if(!receiver_case(i%2?253:1,i%4==1,0))goto done;}
 passed++;
 if(!receiver_case(254,0,0)||!receiver_case(254,1,0)){goto done;}
 passed++;
 if(!raw_rights_case(1,0)){goto done;}
 passed++;
 if(!raw_rights_case(0,1)){goto done;}
 passed++;
 done:printf("{\"version\":1,\"diagnosticOnly\":true,\"passedCases\":%d,\"expectedCases\":6,\"maxRights\":253}\n",passed);return passed==6?0:70;
}
