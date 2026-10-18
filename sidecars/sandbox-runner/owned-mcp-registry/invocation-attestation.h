#ifndef DVAIA_INVOCATION_ATTESTATION_H
#define DVAIA_INVOCATION_ATTESTATION_H
#include "invocation-attestation-protocol.h"
#define LIMIT 8192
/* Linux v6.8 include/net/scm.h SCM_MAX_FD; net/core/scm.c enforces
 * aggregate rights count <=253. Only SO_PASSCRED is enabled here:
 * no SO_PASSSEC or SO_PASSPIDFD, so reserve credentials + all rights. */
#define ATTEST_LINUX_MAX_RIGHTS 253
#define ATTEST_BINARY "/usr/local/libexec/dvaia-invocation-bootstrap"
static int bounded_read(const char *path,char *out,size_t capacity){int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;size_t n=0;int result=-1;while(n<capacity-1){ssize_t got=read(fd,out+n,capacity-1-n);if(got<0&&errno==EINTR)continue;if(got<0)goto done;if(!got){out[n]=0;result=(int)n;goto done;}n+=(size_t)got;}char extra;if(read(fd,&extra,1)==0){out[n]=0;result=(int)n;}done:close(fd);return result;}
static int read_start(pid_t pid,unsigned long long *value){char path[80],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return -1;char *end=strrchr(text,')');if(!end||end[1]!=' ')return -1;char *save=NULL,*token=strtok_r(end+2," ",&save);for(int field=3;field<22&&token;field++)token=strtok_r(NULL," ",&save);if(!token)return -1;char *tail;errno=0;*value=strtoull(token,&tail,10);return errno||*tail||!*value?-1:0;}
static int parent_of(pid_t pid,pid_t *parent){char path[80],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return -1;char *end=strrchr(text,')');long found;char state;if(!end||sscanf(end+2,"%c %ld",&state,&found)!=2||found<1)return -1;*parent=(pid_t)found;return 0;}
static int descendant(pid_t pid,pid_t root){for(int i=0;i<8;i++){if(pid==root)return 1;pid_t parent;if(parent_of(pid,&parent)||parent==pid)return 0;pid=parent;}return 0;}
static int namespace_fd(pid_t pid,const char *name){char path[96];snprintf(path,sizeof(path),"/proc/%ld/ns/%s",(long)pid,name);return open(path,O_RDONLY|O_CLOEXEC);}
static int no_routes(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/net/route",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;char *newline=strchr(text,'\n');if(!newline)return 0;for(char *p=newline+1;*p;p++)if(*p!='\n'&&*p!=' '&&*p!='\t')return 0;return 1;}
static int loopback_only(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/net/dev",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;char *save=NULL,*line=strtok_r(text,"\n",&save);int row=0,seen=0;while(line){if(row++>=2){char name[32];if(sscanf(line," %31[^:]",name)!=1||strcmp(name,"lo"))return 0;seen++;}line=strtok_r(NULL,"\n",&save);}return seen==1;}
static int status_safe(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;const char *fields[]={"CapInh:","CapPrm:","CapEff:","CapBnd:","CapAmb:"};for(size_t i=0;i<5;i++){char *p=strstr(text,fields[i]);unsigned long long bits;if(!p||sscanf(p+strlen(fields[i]),"%llx",&bits)!=1||bits)return 0;}char *n=strstr(text,"NoNewPrivs:"),*f=strstr(text,"Seccomp:");int no_new=0,seccomp=0;if(!n||!f||sscanf(n+11,"%d",&no_new)!=1||sscanf(f+8,"%d",&seccomp)!=1)return 0;return no_new==1&&seccomp==2;}
static int ipv6_loopback_only(pid_t pid){char path[96],text[LIMIT];snprintf(path,sizeof(path),"/proc/%ld/net/ipv6_route",(long)pid);if(bounded_read(path,text,sizeof(text))<0)return 0;char *save=NULL,*line=strtok_r(text,"\n",&save);while(line){char *last=strrchr(line,' ');if(!last||strcmp(last+1,"lo"))return 0;line=strtok_r(NULL,"\n",&save);}return 1;}

struct attestation {int socket,pidfd,phase,nsfds[6];pid_t peer;uid_t uid;gid_t gid;unsigned char nonce[16];unsigned long long start;long until;};
static void attest_close(struct attestation *a){for(int i=0;i<6;i++){if(a->nsfds[i]>=0)close(a->nsfds[i]);a->nsfds[i]=-1;}if(a->socket>=0)close(a->socket);if(a->pidfd>=0)close(a->pidfd);a->socket=-1;a->pidfd=-1;}
static int attest_send(struct attestation *a,unsigned char kind){unsigned char frame[17];frame[0]=kind;memcpy(frame+1,a->nonce,16);return send(a->socket,frame,sizeof(frame),MSG_NOSIGNAL|MSG_DONTWAIT)==(ssize_t)sizeof(frame)?0:-1;}
/* recvmsg may install rights even when ancillary data is subsequently rejected. */
static void attest_discard_rights(struct msghdr *message){
 for(struct cmsghdr *c=CMSG_FIRSTHDR(message);c;c=CMSG_NXTHDR(message,c)){
  if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS&&c->cmsg_len>=CMSG_LEN(0)){
   size_t offset=(size_t)((unsigned char*)c-(unsigned char*)message->msg_control);
   size_t available=message->msg_controllen-offset;
   size_t length=c->cmsg_len<available?c->cmsg_len:available;
   size_t count=length>=CMSG_LEN(0)?(length-CMSG_LEN(0))/sizeof(int):0;
   for(size_t i=0;i<count;i++){int fd;memcpy(&fd,(unsigned char*)CMSG_DATA(c)+i*sizeof(int),sizeof(fd));if(fd>=0)close(fd);}
  }
 }
}
static int attest_receive(struct attestation *a,unsigned char kind,pid_t *pid,uid_t *uid,gid_t *gid){
 unsigned char bytes[18];union{struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(ATTEST_LINUX_MAX_RIGHTS*sizeof(int))];}control;
 struct iovec iov={bytes,sizeof(bytes)};struct msghdr message={0};message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=control.bytes;message.msg_controllen=sizeof(control.bytes);
 ssize_t n=recvmsg(a->socket,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
 if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 0;
 if(n>=0)attest_discard_rights(&message);
 if(n<0||message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))return -1;
 int found=0;for(struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)){
  if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_CREDENTIALS||c->cmsg_len!=CMSG_LEN(sizeof(struct ucred))||found++)return -1;
  struct ucred peer;memcpy(&peer,CMSG_DATA(c),sizeof(peer));*pid=peer.pid;*uid=peer.uid;*gid=peer.gid;
 }
 return peer_frame_valid(bytes,(size_t)n,kind,a->nonce,0,found,(long)*pid,(unsigned long)*uid,(unsigned long)*gid,(unsigned long)geteuid(),(unsigned long)getegid(),(long)getpid())?1:-1;
}
/* One nonblocking state transition per supervisor turn; control requests run first. */
static int attest_step(struct attestation *a,pid_t root,long now,int cancel){
 if(cancel||now>=a->until)return -1;
 if(a->phase==0){if(attest_send(a,'C'))return -1;a->phase=1;return 0;}
 if(a->phase==1){
  pid_t pid=-1;uid_t uid=0;gid_t gid=0;int ready=attest_receive(a,'R',&pid,&uid,&gid);if(ready<=0)return ready;
  if(!descendant(pid,root))return -1;
  a->peer=pid;a->uid=uid;a->gid=gid;a->pidfd=(int)syscall(SYS_pidfd_open,pid,0);
  if(a->pidfd<0||read_start(pid,&a->start))return -1;
  const char *names[]={"user","mnt","pid","net","ipc","uts"};
  for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++){
   int own=namespace_fd(getpid(),names[i]);a->nsfds[i]=namespace_fd(pid,names[i]);struct stat x,y;
   int distinct=own>=0&&a->nsfds[i]>=0&&!fstat(own,&x)&&!fstat(a->nsfds[i],&y)&&(x.st_dev!=y.st_dev||x.st_ino!=y.st_ino);
   if(own>=0)close(own);
   if(!distinct)return -1;
  }
  char exe[96];snprintf(exe,sizeof(exe),"/proc/%ld/exe",(long)pid);struct stat actual,expected;
  if(stat(exe,&actual)||stat(ATTEST_BINARY,&expected)||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino||expected.st_uid!=0||!S_ISREG(expected.st_mode)||expected.st_nlink!=1||(expected.st_mode&0022)||!status_safe(pid)||!loopback_only(pid)||!no_routes(pid)||!ipv6_loopback_only(pid))return -1;
  a->phase=2;return 0;
 }
 if(a->phase==2){
  unsigned long long after=0;struct pollfd alive={a->pidfd,POLLIN,0};
  if(read_start(a->peer,&after)||after!=a->start||poll(&alive,1,0)!=0||attest_send(a,'G'))return -1;
  a->phase=3;return 0;
 }
 if(a->phase==3){
  pid_t pid=-1;uid_t uid=0;gid_t gid=0;int ready=attest_receive(a,'D',&pid,&uid,&gid);if(ready<=0)return ready;
  if(pid!=a->peer||uid!=a->uid||gid!=a->gid)return -1;
  a->phase=4;attest_close(a);return 1;
 }
 return -1;
}
#endif
