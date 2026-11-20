#pragma once
#include "schema.h"

/* Временный view живет только в текущем evaluation, ABI policy не меняется. */
struct ap_policy_view {
    const struct ap_policy *policy;
    void *binding;
    AP_U64 owner;
#ifdef AP_BINDING_SNAPSHOT
    struct bs_key *lookup;
#endif
};
