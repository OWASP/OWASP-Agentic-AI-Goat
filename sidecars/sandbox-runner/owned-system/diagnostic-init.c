#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
/* FD3 is a private pipe to the outside supervisor, never inherited by shell.
 * The non-dumpable parent cannot be ptraced or have FDs reopened by its uid.
 * /proc is an empty directory in the fixed namespace, not a procfs mount. */
static void require(int ok){if(!ok)_exit(70);}
int main(int argc,char **argv){
 require(argc==2&&strlen(argv[1])<=16385);
 require(getuid()==10001&&geteuid()==10001&&getgid()==10001&&getegid()==10001);
 require(prctl(PR_SET_DUMPABLE,0)==0);
 for(int c=0;c<64;c++){errno=0;int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b>=0);if(b)require(prctl(PR_CAPBSET_DROP,c,0,0,0)==0);}
 require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)==0);
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0}};
 require(syscall(SYS_capset,&h,d)==0);require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0);
 int exec_status[2];require(pipe2(exec_status,O_CLOEXEC)==0);
 pid_t child=fork();require(child>=0);
 if(!child){close(3);close(exec_status[0]);for(int fd=4;fd<1024;fd++)if(fd!=exec_status[1])close(fd);char *const env[]={"PATH=/usr/bin:/bin","HOME=/work","LANG=C.UTF-8",NULL};char *const args[]={"/bin/sh","-c",argv[1],NULL};execve(args[0],args,env);char failed=1;(void)write(exec_status[1],&failed,1);_exit(127);}
 close(exec_status[1]);char failed;ssize_t got;do{got=read(exec_status[0],&failed,1);}while(got<0&&errno==EINTR);close(exec_status[0]);require(got==0);
 int status;while(waitpid(child,&status,0)<0){if(errno!=EINTR)_exit(70);}
 char result[64];int n=snprintf(result,sizeof(result),"D1 %d %d\n",WIFEXITED(status)?WEXITSTATUS(status):-1,WIFSIGNALED(status)?WTERMSIG(status):0);
 require(write(3,result,(size_t)n)==n);close(3);return 0;
}
