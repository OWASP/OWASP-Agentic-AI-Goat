/* Native qualification only. No payload reaches logs or completion authority. */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
static int retain_private_failure(int enabled,int directory,const void *bytes,size_t size){
 if(!enabled)return 0;
 if(size>65536)return -1;
 int fd=openat(directory,"first-worker-failure.bin",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
 if(fd<0)return errno==EEXIST?0:-1;
 size_t done=0;int result=1;
 while(done<size){ssize_t n=write(fd,(const char *)bytes+done,size-done);if(n<0&&errno==EINTR)continue;if(n<=0){result=-1;break;}done+=(size_t)n;}
 if(fsync(fd))result=-1;
 if(close(fd))result=-1;
 return result;
}
