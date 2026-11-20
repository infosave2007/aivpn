#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
static _Atomic int armed;
static _Atomic unsigned threads,accepts;
void aivpn_service_arm_fault(void) {atomic_store(&threads,0);atomic_store(&accepts,0);atomic_store(&armed,1);}
static int mode(const char *expected) {const char *value=getenv("AIVPN_SERVICE_FAULT");return atomic_load(&armed) && value && !strcmp(value,expected);}
int pthread_create(pthread_t *thread,const pthread_attr_t *attributes,void *(*start)(void*),void *argument)
{
    int (*real)(pthread_t*,const pthread_attr_t*,void*(*)(void*),void*)=dlsym(RTLD_NEXT,"pthread_create");
    if(atomic_load(&armed)) {
        unsigned index=atomic_fetch_add(&threads,1);
        if((mode("worker_spawn") && index>=2) || (mode("acceptor_spawn") && index>=32))return EAGAIN;
    }
    return real(thread,attributes,start,argument);
}
int accept4(int socket,struct sockaddr *address,socklen_t *length,int flags)
{
    int (*real)(int,struct sockaddr*,socklen_t*,int)=dlsym(RTLD_NEXT,"accept4");
    if(mode("accept_denied")) {errno=EACCES;return -1;}
    if(mode("accept_interrupted") && atomic_fetch_add(&accepts,1)==0) {errno=EINTR;return -1;}
    return real(socket,address,length,flags);
}
int setsockopt(int socket,int level,int option,const void *value,socklen_t length)
{
    int (*real)(int,int,int,const void*,socklen_t)=dlsym(RTLD_NEXT,"setsockopt");
    if(mode("reply_buffer") && level==SOL_SOCKET && option==SO_SNDBUF) {errno=EACCES;return -1;}
    return real(socket,level,option,value,length);
}
int getsockopt(int socket,int level,int option,void *value,socklen_t *length)
{
    int (*real)(int,int,int,void*,socklen_t*)=dlsym(RTLD_NEXT,"getsockopt");
    if(mode("peer_denied") && level==SOL_SOCKET && option==SO_PEERCRED) {errno=EACCES;return -1;}
    return real(socket,level,option,value,length);
}
