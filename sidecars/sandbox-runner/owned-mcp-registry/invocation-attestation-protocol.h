#include <stddef.h>
#include <string.h>
/* Kernel credentials are supplied by recvmsg, never parsed from worker bytes. */
static int peer_frame_valid(const unsigned char *bytes,size_t length,unsigned char kind,const unsigned char nonce[16],int truncated,int credential_count,long pid,unsigned long uid,unsigned long gid,unsigned long expected_uid,unsigned long expected_gid,long supervisor){
 return length==17&&bytes[0]==kind&&!memcmp(bytes+1,nonce,16)&&!truncated&&credential_count==1&&pid>0&&pid!=supervisor&&uid==expected_uid&&gid==expected_gid;
}
