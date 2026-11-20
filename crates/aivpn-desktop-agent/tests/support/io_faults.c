#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
__attribute__((constructor)) static void watchdog(void) {if(getenv("AIVPN_AGENT_IO_FAULT"))alarm(3);}
static _Thread_local unsigned sends,starts,receives;
static int mode(const char *name) {const char *value=getenv("AIVPN_AGENT_IO_FAULT");return value && !strcmp(value,name);}
ssize_t send(int fd,const void *buffer,size_t length,int flags)
{
    ssize_t (*real_send)(int,const void*,size_t,int)=dlsym(RTLD_NEXT,"send");sends++;
    if(mode("send_late") && sends==2)usleep(80000);
    if(mode("send_interrupted_forever")) {usleep(20000);errno=EINTR;return -1;}
    if(mode("send_zero") && sends==1) {errno=0;return 0;}
    if(mode("send_denied") && sends==1) {errno=EACCES;return -1;}
    if(mode("send_interrupted") && sends<7 && (sends&1)) {errno=EINTR;return -1;}
    if(mode("short_io") && length>1)length=1;
    return real_send(fd,buffer,length,flags);
}
ssize_t sendmsg(int fd,const struct msghdr *message,int flags)
{
    ssize_t (*real_sendmsg)(int,const struct msghdr*,int)=dlsym(RTLD_NEXT,"sendmsg");starts++;
    if(mode("start_interrupted_forever")) {usleep(20000);errno=EINTR;return -1;}
    if(mode("start_zero") && starts==1) {errno=0;return 0;}
    if(mode("start_denied") && starts==1) {errno=EACCES;return -1;}
    if(mode("start_interrupted") && starts==1) {errno=EINTR;return -1;}
    return real_sendmsg(fd,message,flags);
}
ssize_t recvmsg(int fd,struct msghdr *message,int flags)
{
    ssize_t (*real_recvmsg)(int,struct msghdr*,int)=dlsym(RTLD_NEXT,"recvmsg");receives++;
    if(mode("receive_late") && receives==3)usleep(80000);
    if(mode("receive_interrupted_forever") || (mode("body_interrupted_forever") && receives>1)) {usleep(20000);errno=EINTR;return -1;}
    if(mode("receive_eof") && receives==1) {message->msg_controllen=0;message->msg_flags=0;errno=0;return 0;}
    if(mode("receive_denied") && receives==1) {errno=EACCES;return -1;}
    if(mode("receive_interrupted") && receives<7 && (receives&1)) {errno=EINTR;return -1;}
    if(mode("short_io") && message->msg_iovlen==1 && message->msg_iov[0].iov_len>1) {
        struct msghdr limited=*message;struct iovec vector=message->msg_iov[0];vector.iov_len=1;limited.msg_iov=&vector;
        ssize_t result=real_recvmsg(fd,&limited,flags);
        message->msg_controllen=limited.msg_controllen;message->msg_flags=limited.msg_flags;return result;
    }
    ssize_t result=real_recvmsg(fd,message,flags);
    if(mode("receive_oversized") && result>0)return result+1;
    return result;
}
int getsockopt(int fd,int level,int option,void *value,socklen_t *length)
{
    int (*real_getsockopt)(int,int,int,void*,socklen_t*)=dlsym(RTLD_NEXT,"getsockopt");
    if(level==SOL_SOCKET && option==SO_PEERCRED && mode("peer_denied")) {errno=EACCES;return -1;}
    if(level==SOL_SOCKET && option==AIVPN_SO_PEERPIDFD) {
        if(mode("pidfd_denied")) {errno=EACCES;return -1;}
        if(mode("pidfd_unsupported")) {errno=ENOPROTOOPT;return -1;}
    }
    int result=real_getsockopt(fd,level,option,value,length);
    if(!result && level==SOL_SOCKET && option==AIVPN_SO_PEERPIDFD && *length==sizeof(int)) {
        int descriptor=*(int*)value;
        if(mode("pidfd_short"))*length=sizeof(int)-1;
        if(mode("pidfd_negative")) {close(descriptor);*(int*)value=-2;}
        if(mode("pidfd_no_cloexec"))fcntl(descriptor,F_SETFD,0);
        if(mode("pidfd_zero")) {
            if(descriptor) {if(dup3(descriptor,0,O_CLOEXEC)<0) {close(descriptor);return -1;}close(descriptor);}
            *(int*)value=0;
        }
    }
    if(!result && level==SOL_SOCKET && option==SO_PEERCRED && *length>=sizeof(struct ucred)) {
        struct ucred *credentials=value;
        if(mode("peer_zero"))credentials->pid=0;
        if(mode("peer_one"))credentials->pid=1;
        if(mode("peer_negative"))credentials->pid=-1;
        if(mode("peer_short"))*length=sizeof(struct ucred)-1;
    }
    return result;
}

int poll(struct pollfd *fds,nfds_t count,int timeout)
{
    int (*real)(struct pollfd*,nfds_t,int)=dlsym(RTLD_NEXT,"poll");
    if(count==1 && fds[0].events==POLLIN && timeout==0) {
        if(mode("pidfd_poll_error")) {errno=EINTR;return -1;}
        if(mode("pidfd_poll_invalid")) {fds[0].revents=POLLNVAL;return 1;}
        if(mode("pidfd_poll_unknown")) {fds[0].revents=0;return 1;}
        if(mode("pidfd_poll_hup")) {fds[0].revents=POLLHUP;return 1;}
    }
    return real(fds,count,timeout);
}
