#pragma once
/* Писатель удерживает свой CAS. Версия не повторяется после замены снимка. */
static __always_inline __u64 route_version_read(__u64 *version) {
    return __sync_fetch_and_add(version, 0);
}
static __always_inline int route_version_begin(__u64 *version) {
    __u64 previous = route_version_read(version);
    if ((previous & 1) || previous >= ~1ULL)
        return -1;
    __sync_lock_test_and_set(version, previous + 1);
    return 0;
}
static __always_inline void route_version_end(__u64 *version) { __sync_fetch_and_add(version, 1); }
static __always_inline void route_version_retire(__u64 *version) {
    __sync_fetch_and_or(version, 1);
}
