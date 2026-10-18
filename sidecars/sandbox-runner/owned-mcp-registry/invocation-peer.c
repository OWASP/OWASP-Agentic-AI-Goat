#define _GNU_SOURCE
#include <node_api.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
static napi_value check(napi_env env,napi_callback_info info){size_t n=2;napi_value a[2],o,v;int32_t socket_fd,lock_fd;struct ucred peer;socklen_t size=sizeof(peer);struct stat st,expected;
 if(napi_get_cb_info(env,info,&n,a,NULL,NULL)!=napi_ok||n!=2||napi_get_value_int32(env,a[0],&socket_fd)!=napi_ok||napi_get_value_int32(env,a[1],&lock_fd)!=napi_ok||getsockopt(socket_fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||size!=sizeof(peer)||peer.pid!=1||peer.uid!=getuid()||fstat(lock_fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&0777)!=0600||st.st_nlink!=1||lstat("/var/lib/dvaia-invocation/supervisor.lock",&expected)||!S_ISREG(expected.st_mode)||expected.st_dev!=st.st_dev||expected.st_ino!=st.st_ino||flock(lock_fd,LOCK_EX|LOCK_NB)){napi_throw_error(env,NULL,"Supervisor peer/lease unavailable");return NULL;}
 napi_create_object(env,&o);napi_create_int32(env,peer.pid,&v);napi_set_named_property(env,o,"pid",v);napi_create_uint32(env,peer.uid,&v);napi_set_named_property(env,o,"uid",v);return o;
}
static napi_value init(napi_env env,napi_value exports){napi_value fn;napi_create_function(env,"check",NAPI_AUTO_LENGTH,check,NULL,&fn);napi_set_named_property(env,exports,"check",fn);return exports;}
NAPI_MODULE(NODE_GYP_MODULE_NAME,init)
