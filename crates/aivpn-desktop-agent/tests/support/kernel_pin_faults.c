#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
int bpf_obj_pin(int descriptor, const char *path) {
    int (*real)(int, const char *) = dlsym(RTLD_NEXT, "bpf_obj_pin");
    const char *needle = getenv("AIVPN_KERNEL_PIN_FAIL");
    if (needle && strstr(path, needle)) {
        errno = EACCES;
        return -EACCES;
    }
    int result = real(descriptor, path);
    const char *cut = getenv("AIVPN_KERNEL_PIN_KILL");
    if (!result && cut && strstr(path, cut))
        kill(getpid(), SIGKILL);
    return result;
}
