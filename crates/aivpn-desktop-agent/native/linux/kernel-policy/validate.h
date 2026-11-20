#pragma once
#include "schema.h"
static __inline int ap_action_valid(AP_U32 action, AP_U32 profile) {
    return action <= 2 && (action == 2 ? profile != 0 : profile == 0);
}
static __inline int ap_rule_network_valid(const struct ap_rule *rule) {
    if (rule->family != 0 && rule->family != 4 && rule->family != 6)
        return 0;
    unsigned width = rule->family == 6 ? 16 : rule->family == 4 ? 4 : 0;
    int ended = 0;
    for (unsigned index = 0; index < 16; index++) {
        if (index >= width) {
            if (rule->address[index] || rule->mask[index])
                return 0;
            continue;
        }
        if (rule->address[index] & (~rule->mask[index]))
            return 0;
        for (unsigned bit = 0; bit < 8; bit++) {
            if (rule->mask[index] & (128U >> bit)) {
                if (ended)
                    return 0;
            } else
                ended = 1;
        }
    }
    return 1;
}
static __inline int ap_policy_valid(const struct ap_policy *policy, unsigned platform) {
    if ((platform != 1 && platform != 2) || policy->version != 1 || !policy->generation ||
        policy->count > AP_RULE_LIMIT || policy->owner_kind < 1 || policy->owner_kind > 3 ||
        policy->reserved || !policy->dns_profile ||
        !ap_action_valid(policy->default_action, policy->default_profile))
        return 0;
    if (policy->owner_kind != 3 && policy->owner_kind != platform)
        return 0;
    if ((policy->owner_kind == 3 && policy->owner) || (policy->owner_kind == 2 && !policy->owner))
        return 0;
    for (unsigned index = 0; index < AP_RULE_LIMIT; index++) {
        const struct ap_rule *rule = &policy->rules[index];
        if (index >= policy->count) {
            const AP_U8 *bytes = (const AP_U8 *)rule;
            for (unsigned byte = 0; byte < sizeof(*rule); byte++)
                if (bytes[byte])
                    return 0;
            continue;
        }
        if (rule->selector > 2 || (platform == 1 && rule->selector == 2) || rule->inherit > 1 ||
            (rule->selector == 0 ? rule->application != 0 : rule->application == 0) ||
            !ap_action_valid(rule->action, rule->profile) || !ap_rule_network_valid(rule))
            return 0;
    }
    return 1;
}
