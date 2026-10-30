#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/capability.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stddef.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Candidate only: never selected by ordinary CLI execution. Fixed descriptors
 * 3..6 are owned listeners; stdin is bounded operation data, stdout is result.
 * Installation must verify immutable helper/worker/Node hashes before launch. */
static const char *addresses[]={"169.254.169.254","10.0.1.100","10.0.2.10","192.0.2.10"};
static const unsigned ports[]={80,8080,80,80};
static void fail(const char *stage){fprintf(stderr,"owned-http:%s:%d\n",stage,errno);exit(70);}
static void require(int ok,const char *stage){if(!ok)fail(stage);}
static void network(void){
 struct if_nameindex *head=if_nameindex();require(head!=NULL,"interfaces");
 for(struct if_nameindex *p=head;p->if_index;p++)require(!strcmp(p->if_name,"lo"),"external-interface");
 if_freenameindex(head);
 int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);require(fd>=0,"route-socket");
 struct {struct nlmsghdr n;struct rtmsg r;} q={0};q.n.nlmsg_len=NLMSG_LENGTH(sizeof(q.r));q.n.nlmsg_type=RTM_GETROUTE;q.n.nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;q.n.nlmsg_seq=1;q.r.rtm_family=AF_UNSPEC;
 require(send(fd,&q,q.n.nlmsg_len,0)==(ssize_t)q.n.nlmsg_len,"route-query");
 int done=0;while(!done){char buf[16384];int len=recv(fd,buf,sizeof(buf),0);require(len>0,"route-receive");for(struct nlmsghdr *n=(void*)buf;NLMSG_OK(n,len);n=NLMSG_NEXT(n,len)){if(n->nlmsg_type==NLMSG_DONE){done=1;break;}require(n->nlmsg_type!=NLMSG_ERROR,"route-error");if(n->nlmsg_type==RTM_NEWROUTE){struct rtmsg *r=NLMSG_DATA(n);require(r->rtm_dst_len!=0,"default-route");}}}close(fd);
}
static void egress_denied(void){
 /* Actual UDP route probes: connect sends no packet and must find no route. */
 int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);require(fd>=0,"udp-probe-socket");
 struct sockaddr_in v4={.sin_family=AF_INET,.sin_port=htons(53)};
 require(inet_pton(AF_INET,"8.8.8.8",&v4.sin_addr)==1,"udp-probe-address");
 errno=0;require(connect(fd,(void*)&v4,sizeof(v4))==-1&&errno==ENETUNREACH,"udp-egress-denial");close(fd);
 fd=socket(AF_INET6,SOCK_DGRAM|SOCK_CLOEXEC,0);require(fd>=0,"ipv6-probe-socket");
 struct sockaddr_in6 v6={.sin6_family=AF_INET6,.sin6_port=htons(53)};
 require(inet_pton(AF_INET6,"2606:4700:4700::1111",&v6.sin6_addr)==1,"ipv6-probe-address");
 errno=0;require(connect(fd,(void*)&v6,sizeof(v6))==-1&&errno==ENETUNREACH,"ipv6-egress-denial");close(fd);
}
static void attest(void){
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0}};
 require(syscall(SYS_capget,&h,d)==0,"capget");for(int i=0;i<2;i++)require(!(d[i].effective|d[i].permitted|d[i].inheritable),"retained-capability");
 for(int c=0;c<64;c++){int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b==0,"bounding-capability");require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,c,0,0)==0,"ambient-capability");}
 require(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1,"no-new-privs");network();egress_denied();
 errno=0;require(syscall(SYS_unshare,CLONE_NEWUSER)==-1&&errno==EPERM,"unshare-denial");
 errno=0;require(syscall(SYS_setns,-1,CLONE_NEWNET)==-1&&errno==EPERM,"setns-denial");
 errno=0;long child=syscall(SYS_clone,CLONE_NEWUSER|SIGCHLD,NULL,NULL,NULL,0);if(child==0)_exit(71);if(child>0){waitpid((pid_t)child,NULL,0);fail("clone-namespace-allowed");}require(errno==EPERM,"clone-denial");
 errno=0;require(syscall(SYS_mount,"none","/tmp","tmpfs",0,NULL)==-1&&errno==EPERM,"mount-denial");
 for(int fd=7;fd<64;fd++){errno=0;require(fcntl(fd,F_GETFD)==-1&&errno==EBADF,"unexpected-descriptor");}

 for(int i=0;i<4;i++){struct sockaddr_in a={0};socklen_t n=sizeof(a);require(getsockname(i+3,(void*)&a,&n)==0,"listener-fd");struct in_addr expected;require(inet_pton(AF_INET,addresses[i],&expected)==1,"manifest");require(a.sin_family==AF_INET&&a.sin_addr.s_addr==expected.s_addr&&ntohs(a.sin_port)==ports[i],"listener-address");}
}
int main(int argc,char **argv){
 require(argc==2,"arguments");
 if(!strcmp(argv[1],"--attest")){attest();char *const args[]={"/usr/local/bin/node","/usr/local/libexec/owasp-ai-goat-owned-http-worker.js",NULL};char *const env[]={"PATH=/usr/bin:/bin","OWASP_AI_GOAT_OWNED_HTTP_ATTESTED=1",NULL};execve(args[0],args,env);fail("worker-exec");}
 require(!strcmp(argv[1],"--initialize"),"operation");network();
 int control=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);require(control>=0,"control-socket");
 for(int i=0;i<4;i++){struct ifreq r={0};snprintf(r.ifr_name,IFNAMSIZ,"lo:%d",i);struct sockaddr_in *a=(void*)&r.ifr_addr;a->sin_family=AF_INET;require(inet_pton(AF_INET,addresses[i],&a->sin_addr)==1,"address");require(ioctl(control,SIOCSIFADDR,&r)==0,"address-add");a->sin_addr.s_addr=htonl(0xffffffff);require(ioctl(control,SIOCSIFNETMASK,&r)==0,"address-mask");}
 struct ifreq flags={0};strcpy(flags.ifr_name,"lo");flags.ifr_flags=IFF_UP|IFF_LOOPBACK;require(ioctl(control,SIOCSIFFLAGS,&flags)==0,"loopback-up");close(control);
 for(int i=0;i<4;i++){int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);require(fd>=0,"listener-create");struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(ports[i])};inet_pton(AF_INET,addresses[i],&a.sin_addr);require(bind(fd,(void*)&a,sizeof(a))==0,"listener-bind");require(listen(fd,8)==0,"listener-listen");if(fd!=i+3){require(dup2(fd,i+3)==i+3,"listener-dup");close(fd);}require(fcntl(i+3,F_SETFD,0)==0,"listener-inherit");}
 for(int c=0;c<64;c++){int b=prctl(PR_CAPBSET_READ,c,0,0,0);if(b<0&&errno==EINVAL)break;require(b>=0&&prctl(PR_CAPBSET_DROP,c,0,0,0)==0,"cap-drop");}
 require(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)==0,"ambient-clear");struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0}};require(syscall(SYS_capset,&h,d)==0,"cap-clear");require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"no-new-privs-set");
 require(syscall(SYS_close_range,7u,~0u,0)==0,"descriptor-close");
 char *const args[]={"/usr/local/libexec/owasp-ai-goat-owned-http-init","--attest",NULL};char *const env[]={"PATH=/usr/bin:/bin",NULL};execve(args[0],args,env);fail("attest-exec");
}
