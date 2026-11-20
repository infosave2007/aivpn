#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static _Atomic unsigned armed, checks, failures, attaches;
void aivpn_kernel_arm_link_probe(void) {
    atomic_store(&checks, 0);
    atomic_store(&failures, 0);
    atomic_store(&attaches, 0);
    atomic_store(&armed, 1);
}
uint64_t aivpn_kernel_link_probe_result(void) {
    atomic_store(&armed, 0);
    return ((uint64_t)atomic_load(&checks) << 32) | atomic_load(&failures);
}
static void *ordinary_sockets(void *unused) {
    (void)unused;
    for (unsigned i = 0; i < 2; i++) {
        int fd = socket(i ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        atomic_fetch_add(&checks, 1);
        if (fd < 0)
            atomic_fetch_add(&failures, 1);
        else
            close(fd);
    }
    return NULL;
}
int bpf_link__destroy(void *link) {
    int (*real)(void *) = dlsym(RTLD_NEXT, "bpf_link__destroy");
    int result = real(link);
    if (atomic_load(&armed)) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, ordinary_sockets, NULL) || pthread_join(thread, NULL))
            atomic_fetch_add(&failures, 1);
    }
    return result;
}
void *bpf_program__attach_cgroup(const void *program, int group) {
    void *(*real)(const void *, int) = dlsym(RTLD_NEXT, "bpf_program__attach_cgroup");
    if (atomic_load(&armed) && getenv("AIVPN_KERNEL_FORCE_ATTACH_FAIL") &&
        atomic_fetch_add(&attaches, 1) == 2) {
        errno = EACCES;
        return NULL;
    }
    return real(program, group);
}
