#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile sig_atomic_t stopped=0;static void stop(int s){(void)s;stopped=1;}
static int kill_children(void){char f[128];snprintf(f,sizeof(f),"/proc/self/task/%ld/children",(long)getpid());FILE *p=fopen(f,"r");if(!p)return -1;long id;while(fscanf(p,"%ld",&id)==1)if(id>0&&kill((pid_t)id,SIGKILL)<0&&errno!=ESRCH){fclose(p);return -1;}return fclose(p);}
int main(int argc,char **argv){
 if(argc<2||prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)<0)return 70;
 struct sigaction a={0};a.sa_handler=stop;sigemptyset(&a.sa_mask);
 if(sigaction(SIGTERM,&a,NULL)<0||sigaction(SIGINT,&a,NULL)<0)return 70;
 int channel[2];if(pipe2(channel,O_CLOEXEC)<0)return 70;pid_t child=fork();if(child<0)return 70;if(!child){close(channel[0]);if(dup2(channel[1],3)<0)_exit(70);close(channel[1]);argv[0]="/usr/bin/bwrap";execv(argv[0],argv);_exit(127);}close(channel[1]);int done=0,status=0,exit_code=70;
 for(;;){pid_t got=waitpid(-1,&status,WNOHANG);if(got>0){if(got==child){done=1;exit_code=WIFEXITED(status)?WEXITSTATUS(status):70;}continue;}if(got<0){if(errno==EINTR)continue;if(errno==ECHILD){char in[65]={0};ssize_t n=read(channel[0],in,64);close(channel[0]);int code=-2,sig=-1,used=0;if(stopped||exit_code!=0||n<=0||sscanf(in,"R1 %d %d\n%n",&code,&sig,&used)!=2||used!=n||code< -1||code>255||sig<0||sig>64||(code==-1)!=(sig>0))return 70;char out[96];int len=snprintf(out,sizeof(out),"R1 %d %d drained\n",code,sig);if(write(3,out,(size_t)len)!=len)return 70;close(3);return 0;}stopped=1;}if(stopped||done)if(kill_children()<0)stopped=1;usleep(10000);}
}
