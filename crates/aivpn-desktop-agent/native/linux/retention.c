#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Собственные малые структуры ABI; структуры ядра берутся только из headers. */
int ar_retention_inspect(int fd, uint32_t program, uint32_t link,
                         uint32_t original_pid, int creating, uint32_t *ids)
{
    uint64_t offset = UINT64_MAX, reference = UINT64_MAX, cookie = UINT64_MAX;
    struct bpf_link_info info = {0};
    uint32_t size = sizeof(info);
    info.uprobe_multi.count = 1;
    info.uprobe_multi.offsets = (uintptr_t)&offset;
    info.uprobe_multi.ref_ctr_offsets = (uintptr_t)&reference;
    info.uprobe_multi.cookies = (uintptr_t)&cookie;
    int status = bpf_obj_get_info_by_fd(fd, &info, &size);
    if (status) return status;
    if (info.type != BPF_LINK_TYPE_UPROBE_MULTI || !info.id ||
        info.prog_id != program || (link && info.id != link)) return -EINVAL;
    if (info.uprobe_multi.count != 1 || info.uprobe_multi.flags ||
        offset || reference || cookie) return -EINVAL;
    if (!original_pid || original_pid > INT32_MAX) return -EINVAL;
    if (info.uprobe_multi.pid != original_pid &&
        (creating || info.uprobe_multi.pid)) return -EINVAL;
    /* Нулевой PID допустим лишь после исчезновения прежнего процесса.
     * Повторное использование номера дает безопасный отказ восстановления. */
    if (!info.uprobe_multi.pid) {
        if (!kill((pid_t)original_pid, 0) || errno != ESRCH) return -EINVAL;
    }
    ids[0] = info.id;
    ids[1] = info.prog_id;
    ids[2] = info.uprobe_multi.pid;
    return 0;
}

int ar_retention_attach(int program, int file)
{
    char path[64];
    unsigned long offset = 0;
    pid_t pid = getpid();
    if (pid <= 0) return -EINVAL;
    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", file) >= (int)sizeof(path))
        return -EINVAL;
    struct bpf_link_create_opts options = {.sz = sizeof(options)};
    options.uprobe_multi.path = path;
    options.uprobe_multi.offsets = &offset;
    options.uprobe_multi.cnt = 1;
    options.uprobe_multi.pid = (uint32_t)pid;
    return bpf_link_create(program, 0, BPF_TRACE_UPROBE_MULTI, &options);
}

int ar_retention_record(const unsigned char *bytes, uint32_t length)
{
    if (length != 128 && length != 256) return -EINVAL;
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "app_retention", 4, length, 1, NULL);
    if (fd < 0) return fd;
    uint32_t zero = 0;
    int status = bpf_map_update_elem(fd, &zero, bytes, BPF_ANY);
    if (!status) status = bpf_map_freeze(fd);
    if (status) { close(fd); return status; }
    return fd;
}

int ar_allocate_file_cookie(int program)
{
    unsigned char packet[64] = {0};
    struct bpf_test_run_opts options = {
        .sz = sizeof(options), .data_in = packet,
        .data_size_in = sizeof(packet), .repeat = 1,
    };
    int status = bpf_prog_test_run_opts(program, &options);
    if (status) return status;
    return options.retval == 1 ? 0 : -ENOSPC;
}
