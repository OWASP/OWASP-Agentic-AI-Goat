#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
/* Qualification-only binary: attempt actual same-UID ptrace of trusted init. */
static int network_probe(void){
 struct ifaddrs *all=NULL;
 if(getifaddrs(&all)!=0)return 98;
 for(struct ifaddrs *item=all;item;item=item->ifa_next){
  if(!(item->ifa_flags&IFF_LOOPBACK)){freeifaddrs(all);return 99;}
 }
 freeifaddrs(all);
 int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);
 if(fd<0)return 100;
 struct sockaddr_in target={0};target.sin_family=AF_INET;target.sin_port=htons(9);
 if(inet_pton(AF_INET,"192.0.2.1",&target.sin_addr)!=1){close(fd);return 101;}
 int result=connect(fd,(struct sockaddr *)&target,sizeof(target));int code=errno;close(fd);
 return result<0&&code==ENETUNREACH?0:102;
}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--network"))return network_probe();
 if(argc!=2||getuid()!=10001||getgid()!=10001)return 91;
 char *end;long target=strtol(argv[1],&end,10);
 if(*end||target<1||target==getpid()||kill((pid_t)target,0)!=0)return 92;
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0}};
 if(syscall(SYS_capget,&h,d)!=0)return 93;
 for(int i=0;i<2;i++)if(d[i].effective||d[i].permitted||d[i].inheritable)return 94;
 if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return 95;
 errno=0;
 if(ptrace(PTRACE_ATTACH,(pid_t)target,0,0)==0){(void)ptrace(PTRACE_DETACH,(pid_t)target,0,0);return 96;}
 return errno==EPERM?0:97;
}
