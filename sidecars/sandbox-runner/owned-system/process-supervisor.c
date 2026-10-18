#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
/* System config trusted process-tree joiner. No learner input becomes argv. Only the fixed
 * bubblewrap binary is executable. Subreaping is local to this process. */
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
 pid_t child=fork();if(child<0)return 70;
 if(child==0){argv[0]="/usr/bin/bwrap";execv(argv[0],argv);_exit(127);}
 close(3);int child_done=0,status=0,exit_code=70;
 for(;;){
  pid_t got=waitpid(-1,&status,WNOHANG);
  if(got>0){if(got==child){child_done=1;exit_code=WIFEXITED(status)?WEXITSTATUS(status):70;}continue;}
  if(got<0){if(errno==EINTR)continue;if(errno==ECHILD)return stopped?124:exit_code;stopped=1;}
  if(stopped||child_done){if(kill_owned_children()<0)stopped=1;}
  usleep(10000);
 }
}
