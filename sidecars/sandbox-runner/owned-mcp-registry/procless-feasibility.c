#define _GNU_SOURCE
/* Native-only feasibility. No request parser, learner effect, or completion receipt. */
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "procless-peer-contract.h"
#define BINARY "/usr/local/libexec/dvaia-procless-feasibility"
#define FILTER "/usr/share/dvaia/invocation-target.seccomp.bpf"
#define LIMIT 8192
static volatile sig_atomic_t cancelled=0;
static void cancel_probe(int sig){(void)sig;cancelled=1;}
static int install_handlers(void){struct sigaction action;memset(&action,0,sizeof(action));action.sa_handler=cancel_probe;if(sigemptyset(&action.sa_mask))return -1;return sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL)||sigaction(SIGALRM,&action,NULL)?-1:0;}
static long clock_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return t.tv_sec*1000L+t.tv_nsec/1000000;}
static int bounded_read(const char *path,char *out,size_t capacity){int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;size_t n=0;int result=-1;while(n<capacity-1){ssize_t got=read(fd,out+n,capacity-1-n);if(got<0&&errno==EINTR)continue;if(got<0)goto done;if(!got){out[n]=0;result=(int)n;goto done;}n+=(size_t)got;}char extra;if(read(fd,&extra,1)==0){out[n]=0;result=(int)n;}done:close(fd);return result;}
static int read_start(pid_t pid,unsigned long long *value){char path[80],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return -1;char *end=strrchr(text,')');if(!end||end[1]!=' ')return -1;char *save=NULL,*token=strtok_r(end+2," ",&save);for(int field=3;field<22&&token;field++)token=strtok_r(NULL," ",&save);if(!token)return -1;char *tail;errno=0;*value=strtoull(token,&tail,10);return errno||*tail||!*value?-1:0;}
static int parent_of(pid_t pid,pid_t *parent){char path[80],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return -1;char *end=strrchr(text,')');long found;char state;if(!end||sscanf(end+2,"%c %ld",&state,&found)!=2||found<1)return -1;*parent=(pid_t)found;return 0;}
static int descendant(pid_t pid,pid_t root){for(int i=0;i<8;i++){if(pid==root)return 1;pid_t parent;if(parent_of(pid,&parent)||parent==pid)return 0;pid=parent;}return 0;}
static int namespace_fd(pid_t pid,const char *name){char path[96];snprintf(path,sizeof(path),"/proc/%ld/ns/%s",(long)pid,name);return open(path,O_RDONLY|O_CLOEXEC);}
static int namespace_distinct(pid_t pid,const char *name){int a=namespace_fd(getpid(),name),b=namespace_fd(pid,name);struct stat x,y;int ok=a>=0&&b>=0&&!fstat(a,&x)&&!fstat(b,&y)&&(x.st_dev!=y.st_dev||x.st_ino!=y.st_ino);if(a>=0)close(a);if(b>=0)close(b);return ok;}
static int helper(void){
 struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0}};
 if(prctl(PR_GET_SECCOMP)!=2||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||syscall(SYS_capget,&header,caps))return 70;
 for(int i=0;i<2;i++)if(caps[i].effective||caps[i].permitted||caps[i].inheritable)return 70;
 struct statvfs procfs;if(statvfs("/proc",&procfs)||!(procfs.f_flag&ST_RDONLY))return 70;
 DIR *directory=opendir("/proc");if(!directory)return 70;struct dirent *entry;int empty=1;errno=0;while((entry=readdir(directory)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,".."))empty=0;int directory_error=errno;closedir(directory);if(!empty||directory_error)return 70;
 /* Unique per-probe challenge; never accept EOF or a truncated release. */
 unsigned char challenge[18],ready[17];struct pollfd gate={4,POLLIN,0};
 if(poll(&gate,1,5000)!=1||recv(4,challenge,sizeof(challenge),MSG_DONTWAIT)!=17||challenge[0]!='C')return 70;
 ready[0]='R';memcpy(ready+1,challenge+1,16);
 if(send(4,ready,sizeof(ready),MSG_NOSIGNAL|MSG_DONTWAIT)!=(ssize_t)sizeof(ready))return 70;
 if(poll(&gate,1,5000)!=1){return 70;}
 unsigned char release[18];
 if(recv(4,release,sizeof(release),MSG_DONTWAIT)!=17||release[0]!='G'||memcmp(release+1,challenge+1,16))return 70;
 ready[0]='D';if(send(4,ready,sizeof(ready),MSG_NOSIGNAL|MSG_DONTWAIT)!=(ssize_t)sizeof(ready))return 70;
 close(4);return 0;
}
static int receive_peer(int socket,unsigned char kind,const unsigned char nonce[16],pid_t *pid,uid_t *uid,gid_t *gid){
 unsigned char bytes[18];union{struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))];}control;
 struct iovec iov={bytes,sizeof(bytes)};struct msghdr message={0};message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=control.bytes;message.msg_controllen=sizeof(control.bytes);
 struct pollfd p={socket,POLLIN,0};if(poll(&p,1,5000)!=1)return -1;
 ssize_t n=recvmsg(socket,&message,MSG_DONTWAIT);if(n<0||message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))return -1;
 int found=0;for(struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)){
  if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_CREDENTIALS||c->cmsg_len!=CMSG_LEN(sizeof(struct ucred))||found++)return -1;
  struct ucred peer;memcpy(&peer,CMSG_DATA(c),sizeof(peer));*pid=peer.pid;*uid=peer.uid;*gid=peer.gid;
 }
 return peer_frame_valid(bytes,(size_t)n,kind,nonce,0,found,(long)*pid,(unsigned long)*uid,(unsigned long)*gid,(unsigned long)geteuid(),(unsigned long)getegid(),(long)getpid())?0:-1;
}
static int no_routes(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/net/route",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;char *newline=strchr(text,'\n');if(!newline)return 0;for(char *p=newline+1;*p;p++)if(*p!='\n'&&*p!=' '&&*p!='\t')return 0;return 1;}
static int loopback_only(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/net/dev",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;char *save=NULL,*line=strtok_r(text,"\n",&save);int row=0,seen=0;while(line){if(row++>=2){char name[32];if(sscanf(line," %31[^:]",name)!=1||strcmp(name,"lo"))return 0;seen++;}line=strtok_r(NULL,"\n",&save);}return seen==1;}
static int status_safe(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;const char *fields[]={"CapInh:","CapPrm:","CapEff:","CapBnd:","CapAmb:"};for(size_t i=0;i<5;i++){char *p=strstr(text,fields[i]);unsigned long long bits;if(!p||sscanf(p+strlen(fields[i]),"%llx",&bits)!=1||bits)return 0;}char *n=strstr(text,"NoNewPrivs:"),*f=strstr(text,"Seccomp:");int no_new=0,seccomp=0;if(!n||!f||sscanf(n+11,"%d",&no_new)!=1||sscanf(f+8,"%d",&seccomp)!=1)return 0;return no_new==1&&seccomp==2;}
static int ipv6_loopback_only(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/net/ipv6_route",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;char *save=NULL,*line=strtok_r(text,"\n",&save);while(line){char *last=strrchr(line,' ');if(!last||strcmp(last+1,"lo"))return 0;line=strtok_r(NULL,"\n",&save);}return 1;}
static int drain(pid_t root){(void)root;long begin=clock_ms();if(begin<0)return 0;long end=begin+2000;for(int attempt=0;attempt<200;attempt++){long now=clock_ms();if(now<0||now>=end)return 0;char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/self/task/%ld/children",(long)getpid());if(bounded_read(path,text,sizeof(text))<0)return 0;int count=0;char *save=NULL,*token=strtok_r(text," \n",&save);while(token){long pid=strtol(token,NULL,10);if(pid>0){count++;if(kill((pid_t)pid,SIGKILL)&&errno!=ESRCH)return 0;}token=strtok_r(NULL," \n",&save);}while(waitpid(-1,NULL,WNOHANG)>0){}if(!count)return 1;usleep(10000);}return 0;}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--child"))return helper();
 if(argc!=2||strcmp(argv[1],"--probe"))return 64;
 for(int fd=0;fd<3;fd++)if(fcntl(fd,F_GETFD)<0)return 70;
 if(install_handlers()){return 70;}
 alarm(12);
 if(prctl(PR_SET_CHILD_SUBREAPER,1))return 70;
 unsigned char nonce[16],challenge[17];if(getrandom(nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce))return 70;challenge[0]='C';memcpy(challenge+1,nonce,16);
 int channel[2],enabled=1;if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel)||setsockopt(channel[0],SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)))return 70;
 int sendfd=fcntl(channel[1],F_DUPFD_CLOEXEC,64),filter=open(FILTER,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(sendfd<0||filter<0)return 70;
 pid_t child=fork();if(child<0)return 70;
 if(!child){if(dup2(filter,3)<0||dup2(sendfd,4)<0||syscall(SYS_close_range,5,~0U,0))_exit(70);char *args[]={"/usr/bin/bwrap","--unshare-all","--die-with-parent","--new-session","--clearenv","--tmpfs","/","--ro-bind","/usr","/usr","--ro-bind","/lib","/lib","--ro-bind-try","/lib64","/lib64","--dev","/dev","--dir","/proc","--tmpfs","/proc","--remount-ro","/proc","--dir","/tmp","--chdir","/tmp","--seccomp","3",BINARY,"--child",NULL};char *env[]={"PATH=/usr/bin:/bin",NULL};execve(args[0],args,env);_exit(127);}
 close(channel[1]);close(sendfd);close(filter);int phase=1,ok=0,pidfd=-1;pid_t peer=-1;uid_t uid=0;gid_t gid=0;unsigned long long start=0,after=0;
 if(cancelled||send(channel[0],challenge,sizeof(challenge),MSG_NOSIGNAL|MSG_DONTWAIT)!=(ssize_t)sizeof(challenge)||receive_peer(channel[0],'R',nonce,&peer,&uid,&gid)||peer<=0||uid!=geteuid()||peer==getpid()||!descendant(peer,child))goto done;
 phase=2;pidfd=(int)syscall(SYS_pidfd_open,peer,0);if(pidfd<0||read_start(peer,&start))goto done;
 phase=3;const char *names[]={"user","mnt","pid","net","ipc","uts"};for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++)if(!namespace_distinct(peer,names[i]))goto done;
 phase=4;char exe[96];snprintf(exe,sizeof(exe),"/proc/%ld/exe",(long)peer);struct stat actual,expected;if(stat(exe,&actual)||stat(BINARY,&expected)||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino||expected.st_uid!=0||(expected.st_mode&0022))goto done;
 phase=5;if(!status_safe(peer)||!loopback_only(peer)||!no_routes(peer)||!ipv6_loopback_only(peer)||read_start(peer,&after)||after!=start)goto done;
 phase=6;struct pollfd alive={pidfd,POLLIN,0};challenge[0]='G';if(cancelled||poll(&alive,1,0)!=0||send(channel[0],challenge,sizeof(challenge),MSG_NOSIGNAL|MSG_DONTWAIT)!=(ssize_t)sizeof(challenge))goto done;
 pid_t ack_pid=-1;uid_t ack_uid=0;gid_t ack_gid=0;
 if(receive_peer(channel[0],'D',nonce,&ack_pid,&ack_uid,&ack_gid)||ack_pid!=peer||ack_uid!=uid||ack_gid!=gid||cancelled)goto done;
 phase=7;ok=1;
 done:alarm(0);close(channel[0]);if(pidfd>=0)close(pidfd);int clean=drain(child);printf("{\"diagnosticOnly\":true,\"phase\":%d,\"passed\":%s,\"drained\":%s}\n",phase,(ok&&!cancelled)?"true":"false",clean?"true":"false");return ok&&clean&&!cancelled?0:70;
}
