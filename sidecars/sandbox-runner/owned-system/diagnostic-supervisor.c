#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
/* Dedicated diagnostic joiner. Outer FD3 receives status only after ECHILD.
 * Inner FD3 is a separate pipe, closed in the untrusted shell by diagnostic-init. */
static volatile sig_atomic_t stopped=0;
static void stop(int signal){(void)signal;stopped=1;}
static int kill_owned_children(void){
 char file[128];snprintf(file,sizeof(file),"/proc/self/task/%ld/children",(long)getpid());
 FILE *stream=fopen(file,"r");if(!stream)return -1;
 long pid;while(fscanf(stream,"%ld",&pid)==1){if(pid>0&&kill((pid_t)pid,SIGKILL)<0&&errno!=ESRCH){fclose(stream);return -1;}}
 return fclose(stream);
}
int main(int argc,char **argv){
 if(argc<2||prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)<0)return 70;
 struct sigaction action={0};action.sa_handler=stop;sigemptyset(&action.sa_mask);
 if(sigaction(SIGTERM,&action,NULL)<0||sigaction(SIGINT,&action,NULL)<0)return 70;
 int channel[2];if(pipe2(channel,O_CLOEXEC)<0)return 70;
 pid_t child=fork();if(child<0)return 70;
 if(child==0){close(channel[0]);if(dup2(channel[1],3)<0)_exit(70);close(channel[1]);argv[0]="/usr/bin/bwrap";execv(argv[0],argv);_exit(127);}
 close(channel[1]);int child_done=0,status=0,exit_code=70;
 for(;;){
  pid_t got=waitpid(-1,&status,WNOHANG);
  if(got>0){if(got==child){child_done=1;exit_code=WIFEXITED(status)?WEXITSTATUS(status):70;}continue;}
  if(got<0){if(errno==EINTR)continue;if(errno==ECHILD){
    char result[65]={0};ssize_t n=read(channel[0],result,64);close(channel[0]);
    int code=-2,sig=-1,used=0;
    if(stopped||exit_code!=0||n<=0||sscanf(result,"D1 %d %d\n%n",&code,&sig,&used)!=2||used!=n||code< -1||code>255||sig<0||sig>64||(code==-1)!=(sig>0))return 70;
    char receipt[96];int len=snprintf(receipt,sizeof(receipt),"D1 %d %d drained\n",code,sig);
    if(write(3,receipt,(size_t)len)!=len){return 70;}
    close(3);
    return 0;
   }stopped=1;}
  if(stopped||child_done){if(kill_owned_children()<0)stopped=1;}
  usleep(10000);
 }
}
