#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *stage){fprintf(stderr,"listing-template-init:%s:%d\n",stage,errno);_exit(70);}
static void require(int ok,const char *stage){if(!ok)fail(stage);}
static void clear_and_attest(void){
 require(getuid()==10001&&geteuid()==10001&&getgid()==10001&&getegid()==10001,"identity");
 for(int c=0;c<64;c++){errno=0;int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b>=0,"bounding-read");if(b)require(prctl(PR_CAPBSET_DROP,c,0,0,0)==0,"bounding-drop");}
 require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)==0,"ambient-clear");
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0}};
 require(syscall(SYS_capset,&h,d)==0,"cap-clear");require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"nnp-set");
 require(syscall(SYS_capget,&h,d)==0,"cap-read");for(int i=0;i<2;i++)require(!(d[i].effective|d[i].permitted|d[i].inheritable),"cap-retained");
 for(int c=0;c<64;c++){errno=0;int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b==0,"bounding-retained");require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,c,0,0)==0,"ambient-retained");}
 require(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1,"nnp-missing");
}
static int encoded(const char *s){size_t n=strlen(s);if(n<4||n>131072||n%4)return 0;for(size_t i=0;i<n;i++)if(!(isalnum((unsigned char)s[i])||s[i]=='+'||s[i]=='/'||s[i]=='='))return 0;return 1;}
static int marker(const char *s){const char *p="__LISTING_TEMPLATE_";size_t a=strlen(p),n=strlen(s);if(n!=a+66||strncmp(s,p,a)||strcmp(s+n-2,"__"))return 0;for(size_t i=a;i<n-2;i++)if(!isxdigit((unsigned char)s[i]))return 0;return 1;}
static void write_attestation(void){
 static const char receipt[]="listing-template-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n";
 require(write(STDOUT_FILENO,receipt,sizeof(receipt)-1)==(ssize_t)(sizeof(receipt)-1),"attestation-write");
}
int main(int argc,char **argv){
 clear_and_attest();char *const env[]={"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME=/work","USER=policy-render","LANG=C.UTF-8",NULL};
 if(argc==2&&!strcmp(argv[1],"--probe")){char *const args[]={"/usr/local/bin/node","-e","process.exit(0)",NULL};execve(args[0],args,env);fail("probe-exec");}
 require(argc==4&&!strcmp(argv[1],"--render")&&encoded(argv[2])&&marker(argv[3]),"arguments");
 write_attestation();
 char *const args[]={"/usr/local/bin/node","/opt/listing-template/worker.js",argv[2],argv[3],NULL};execve(args[0],args,env);fail("worker-exec");
}
