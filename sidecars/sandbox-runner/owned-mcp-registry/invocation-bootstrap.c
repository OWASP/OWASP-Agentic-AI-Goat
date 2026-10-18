#define _GNU_SOURCE
/* Trusted pre-exec invocation gate: attest, close private descriptors, then
 * exec the fixed Node worker. Does not parse claims or establish completion. */
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
 if(syscall(SYS_close_range,3,~0U,0))return 70;
 char *argv[]={"/usr/local/bin/node","/usr/local/libexec/dvaia-invocation-worker.js",NULL};
 char *env[]={"PATH=/usr/bin:/bin",NULL};
 execve(argv[0],argv,env);return 70;
}
int main(int argc,char **argv){(void)argv;if(argc!=1)return 64;return helper();}
