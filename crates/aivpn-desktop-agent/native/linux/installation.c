#include <bpf/bpf.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* Повторная установка использует проверенные program FD прежнего экземпляра. */
int ar_attach_capture(int program) {
    return bpf_raw_tracepoint_open(NULL, program);
}

/* Session сохраняет аргумент и результат одного фактического fdget_raw. */
int ar_attach_fd_session(int program) {
    const char *symbols[] = {"fdget_raw"};
    struct bpf_link_create_opts options = {
        .sz = sizeof(options),
        .kprobe_multi = { .cnt = 1, .syms = symbols },
    };
    return bpf_link_create(program, 0, BPF_TRACE_KPROBE_SESSION, &options);
}

static enum bpf_attach_type cgroup_type(unsigned role) {
    const enum bpf_attach_type types[] = {
        BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_INET4_CONNECT,
        BPF_CGROUP_INET6_CONNECT, BPF_CGROUP_UDP4_SENDMSG,
        BPF_CGROUP_UDP6_SENDMSG, BPF_CGROUP_INET_EGRESS,
        BPF_CGROUP_INET_INGRESS,
    };
    return types[role];
}

int ar_attach_cgroup(int program, int cgroup, unsigned role) {
    if (role >= 7) return -EINVAL;
    return bpf_link_create(program, cgroup, cgroup_type(role), NULL);
}

int ar_attach_netfilter(int program, unsigned family, unsigned hook, int priority) {
    struct bpf_link_create_opts options = {
        .sz = sizeof(options),
        .netfilter = { .pf = family, .hooknum = hook, .priority = priority },
    };
    return bpf_link_create(program, 0, BPF_NETFILTER, &options);
}

int ar_verify_root_link(int link, uint32_t program, int kind, unsigned arg,
                        unsigned family, unsigned hook, int priority, uint64_t cgroup) {
    struct bpf_link_info info = {0};
    uint32_t size = sizeof(info);
    int status = bpf_obj_get_info_by_fd(link, &info, &size);
    if (status) return status;
    if (!info.id || info.prog_id != program) return -EINVAL;
    if (kind == 0)
        return info.type == BPF_LINK_TYPE_TRACING ? 0 : -EINVAL;
    if (kind == 3)
        return info.type == BPF_LINK_TYPE_KPROBE_MULTI && info.kprobe_multi.count == 1 &&
               !info.kprobe_multi.flags ? 0 : -EINVAL;
    if (kind == 4) {
        if (info.type == BPF_LINK_TYPE_TRACING)
            return info.tracing.attach_type == BPF_TRACE_RAW_TP && info.tracing.target_btf_id ? 0 : -EINVAL;
        if (info.type != BPF_LINK_TYPE_RAW_TRACEPOINT)
            return -EINVAL;
        char name[16] = {0};
        info.raw_tracepoint.tp_name = (uint64_t)(uintptr_t)name;
        info.raw_tracepoint.tp_name_len = sizeof(name);
        size = sizeof(info);
        status = bpf_obj_get_info_by_fd(link, &info, &size);
        return !status && !strcmp(name, "sys_exit") ? 0 : -EINVAL;
    }
    if (kind == 1) {
        if (arg >= 7 || info.type != BPF_LINK_TYPE_CGROUP ||
            info.cgroup.attach_type != cgroup_type(arg) || info.cgroup.cgroup_id != cgroup)
            return -EINVAL;
        return 0;
    }
    if (kind != 2 || info.type != BPF_LINK_TYPE_NETFILTER || info.netfilter.pf != family ||
        info.netfilter.hooknum != hook || info.netfilter.priority != priority || info.netfilter.flags)
        return -EINVAL;
    return 0;
}

int ar_attach_tcx(int program, unsigned index) {
    return bpf_link_create(program, index, BPF_TCX_INGRESS, NULL);
}
int ar_verify_tcx(int link, uint32_t program, unsigned index) {
    struct bpf_link_info info = {0}; uint32_t size = sizeof(info);
    int status = bpf_obj_get_info_by_fd(link, &info, &size);
    if (status) return status;
    return info.id && info.type == BPF_LINK_TYPE_TCX && info.prog_id == program &&
           info.tcx.ifindex == index && info.tcx.attach_type == BPF_TCX_INGRESS ? 0 : -EINVAL;
}

#define AP_BINDING_SNAPSHOT 1
#include "routing.h"
#include <string.h>
/* Один writer передает только exact key/cookie/epoch штатной программе ядра. */
int ar_reap_cache(int map, int request, int program, unsigned kind,
                  unsigned char cursor[64], unsigned *pending, unsigned budget) {
    if (kind > 2 || !budget || budget > 32) return -EINVAL;
    unsigned size = kind == 2 ? sizeof(struct tcp_tuple) : sizeof(struct flow_key);
    struct bpf_map_info info = {0}; uint32_t length = sizeof(info);
    if (bpf_obj_get_info_by_fd(map, &info, &length)) return -errno;
    if (info.key_size != size || info.value_size != (kind == 2 ? sizeof(struct tcp_tuple_route) : sizeof(struct route_cache_value))) return -EINVAL;
    unsigned count = 0, zero = 0;
    while (count < budget) {
        if (!*pending) {
            if (bpf_map_get_next_key(map, NULL, cursor)) return errno == ENOENT ? (int)count : -errno;
            *pending = 1;
        }
        unsigned char key[64]; memcpy(key, cursor, size);
        if (bpf_map_get_next_key(map, key, cursor)) {
            if (errno != ENOENT) return -errno;
            *pending = 0;
        }
        int status;
        if (kind == 2) {
            struct tcp_tuple_route value; struct tcp_reap_request row = {0};
            memcpy(&row.tuple, key, size); status = bpf_map_lookup_elem(map, key, &value);
            if (!status) { row.cookie=value.cookie; row.epoch=value.epoch; row.expires=value.expires; status=bpf_map_update_elem(request,&zero,&row,0); }
        } else {
            struct route_cache_value value; struct cache_reap_request row = {0};
            memcpy(&row.key, key, size); status = bpf_map_lookup_elem(map, key, &value);
            if (!status) { row.cookie=value.cookie; row.epoch=value.epoch; row.system=kind; status=bpf_map_update_elem(request,&zero,&row,0); }
        }
        if (status && errno != ENOENT) return -errno;
        if (!status) {
            char packet[64]={0}; struct bpf_test_run_opts options={.sz=sizeof(options),.data_in=packet,.data_size_in=sizeof(packet),.repeat=1};
            if (bpf_prog_test_run_opts(program,&options)) return -errno;
        }
        count++;
        if (!*pending) break;
    }
    return count;
}
