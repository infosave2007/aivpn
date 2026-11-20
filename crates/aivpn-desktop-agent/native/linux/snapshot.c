#include <string.h>
#include "kernel-policy/validate.h"

int aivpn_snapshot_policy_valid(const unsigned char *bytes, size_t length) {
    if (length != sizeof(struct ap_policy))
        return 0;
    struct ap_policy policy;
    memcpy(&policy, bytes, sizeof(policy));
    return ap_policy_valid(&policy, 1);
}

#include <bpf/bpf.h>
int aivpn_snapshot_create(void) {
    const struct bpf_map_create_opts options = {
        .sz = sizeof(options),
        .map_flags = BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC,
    };
    return bpf_map_create(BPF_MAP_TYPE_HASH, "binding_bundle", 40, 64, 401408, &options);
}
