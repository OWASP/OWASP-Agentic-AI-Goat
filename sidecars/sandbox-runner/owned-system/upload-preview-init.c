#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
static void require(int ok){if(!ok)_exit(70);}
static void limit(int kind,rlim_t value){struct rlimit bound={value,value};require(setrlimit(kind,&bound)==0);}
int main(int argc,char **argv){
 require(argc==2||(argc==3&&!strcmp(argv[2],"--probe")));
 const char *prefix="__UPLOAD_PREVIEW_";size_t n=strlen(argv[1]),p=strlen(prefix);
 require(n==p+66&&!strncmp(argv[1],prefix,p)&&!strcmp(argv[1]+n-2,"__"));
 for(size_t i=p;i<n-2;i++)require((argv[1][i]>='0'&&argv[1][i]<='9')||(argv[1][i]>='a'&&argv[1][i]<='f'));
 require(getuid()==10001&&geteuid()==10001&&getgid()==10001&&getegid()==10001);
 require(prctl(PR_SET_DUMPABLE,0)==0);
 for(int c=0;c<64;c++){errno=0;int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b>=0);if(b)require(prctl(PR_CAPBSET_DROP,c,0,0,0)==0);}
 require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)==0);
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0}};
 require(syscall(SYS_capset,&h,d)==0);require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0);
 require(syscall(SYS_capget,&h,d)==0);for(int i=0;i<2;i++)require(!(d[i].effective|d[i].permitted|d[i].inheritable));
 for(int c=0;c<64;c++){errno=0;int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b==0);require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,c,0,0)==0);}
 require(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
 limit(RLIMIT_CORE,0);limit(RLIMIT_CPU,4);limit(RLIMIT_FSIZE,8*1024*1024);limit(RLIMIT_NOFILE,128);limit(RLIMIT_NPROC,64);
 for(int fd=3;fd<1024;fd++)close(fd);
 const char attestation[]="upload-preview-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n";
 require(write(1,attestation,sizeof(attestation)-1)==(ssize_t)(sizeof(attestation)-1));
 char *const env[]={"PATH=/usr/local/bin:/usr/bin:/bin","HOME=/work","LANG=C.UTF-8","USER=owned-upload-preview","OWASP_AI_GOAT_UPLOAD_PREVIEW_ATTESTED=upload-preview-init-v1",NULL};
 char *const args[]={"/usr/local/bin/node","--max-old-space-size=128","/opt/upload-preview/upload-preview-worker.js",argv[1],argc==3?"--probe":NULL,NULL};
 execve(args[0],args,env);return 70;
}
