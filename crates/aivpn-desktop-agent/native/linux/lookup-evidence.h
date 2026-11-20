#pragma once

#define AP_LOOKUP_VERSION 1U
#define AP_LOOKUP_LIMIT 256U
#define AP_LOOKUP_BLOCK_ENTRIES 64U
#define AP_LOOKUP_PHYSICAL 1U
#define AP_LOOKUP_LOGICAL 2U
#define AP_LOOKUP_COMPLETE (AP_LOOKUP_PHYSICAL | AP_LOOKUP_LOGICAL)
#define AP_LOOKUP_ORIGINAL 4U
#define AP_LOOKUP_EXPANSION 8U
#define AP_LOOKUP_OVERFLOW 16U
#define AP_LOOKUP_UNREADABLE 32U
#define AP_LOOKUP_DOTDOT 64U
#define AP_LOOKUP_RENAMED 128U
#define AP_LOOKUP_PREFIX_MISSING 256U
#define AP_LOOKUP_COMPOSED 512U

/* Ключи относятся к фактическому lookup, без номеров правил и поколений политики. */
struct ap_lookup_observation {
    struct ph_hash physical, logical;
    AP_U64 physical_device, logical_scope, flags;
};

struct ap_lookup_scope {
    AP_U64 mount_namespace, root_device, root_inode, root_mount;
};
struct ap_lookup_facts {
    AP_U32 version, count, complete, reasons;
    AP_U64 inode_address, operation, task_identity, exec_identity;
    struct ap_lookup_scope scope;
};

struct ap_lookup_candidate {
    struct ph_hash hash;
    struct ph_stream prefix;
};

struct lookup_fs_work {
    AP_U64 proof, fs, path, dentry, mount, nonce;
    AP_U32 sequence, active;
};

/* facts/entries неизменяемы. Cookie связывается с source один раз при exec. */
struct ap_lookup_proof {
    AP_U64 references, bound_cookie, prefix_count;
    struct ap_lookup_facts facts;
    struct ap_lookup_observation entries[AP_LOOKUP_LIMIT];
};
_Static_assert(sizeof(struct ap_lookup_observation) == 56, "lookup observation ABI");
_Static_assert(sizeof(struct ap_lookup_facts) == 80, "lookup facts ABI");
_Static_assert(sizeof(struct ap_lookup_proof) == 14440, "lookup proof map ABI");

static __inline int ap_lookup_location_equal(const struct ap_lookup_observation *left,
                                               const struct ap_lookup_observation *right) {
    return left->physical.low == right->physical.low && left->physical.high == right->physical.high &&
           left->logical.low == right->logical.low && left->logical.high == right->logical.high &&
           left->physical_device == right->physical_device &&
           left->logical_scope == right->logical_scope &&
           (left->flags & AP_LOOKUP_COMPLETE) == (right->flags & AP_LOOKUP_COMPLETE);
}

static __inline int ap_lookup_scope_equal(const struct ap_lookup_scope *left,
                                           const struct ap_lookup_scope *right) {
    return left->mount_namespace == right->mount_namespace && left->root_device == right->root_device &&
           left->root_inode == right->root_inode && left->root_mount == right->root_mount;
}
