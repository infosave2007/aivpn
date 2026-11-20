#pragma once
#include "../linux/kernel-policy/view.h"

#define AR_OWNER_LIMIT 256u
#define AR_GROUP_LIMIT 4096u
#define AR_MEMBERSHIP_LIMIT 16384u
#define AR_ALIAS_LIMIT 4096u

/* Selector относится к логическому пути, group - к удерживаемому stream.
 * Порядок entries фиксирован: owner_kind, owner, selector, group. */
typedef struct {
    AP_U32 owner_kind, owner, selector, group;
} AR_MEMBERSHIP;
typedef struct {
    const AR_MEMBERSHIP *entries;
    AP_U32 count;
} AR_MEMBERSHIP_VIEW;

static __inline int ar_membership_compare(const AR_MEMBERSHIP *left, const AR_MEMBERSHIP *right)
{
    if (left->owner_kind != right->owner_kind) return left->owner_kind < right->owner_kind ? -1 : 1;
    if (left->owner != right->owner) return left->owner < right->owner ? -1 : 1;
    if (left->selector != right->selector) return left->selector < right->selector ? -1 : 1;
    if (left->group != right->group) return left->group < right->group ? -1 : 1;
    return 0;
}

static __inline int ar_memberships_valid(const AR_MEMBERSHIP_VIEW *view)
{
    if (!view || view->count > AR_MEMBERSHIP_LIMIT || (view->count && !view->entries)) return 0;
    for (AP_U32 i = 0; i < view->count; i++) {
        const AR_MEMBERSHIP *entry = &view->entries[i];
        if ((entry->owner_kind != 2 && entry->owner_kind != 3) ||
            (entry->owner_kind == 2 ? !entry->owner : entry->owner != 0) ||
            !entry->selector || !entry->group ||
            (i && ar_membership_compare(&view->entries[i - 1], entry) >= 0)) return 0;
    }
    return 1;
}

static __inline int ar_membership_contains(const AR_MEMBERSHIP_VIEW *view, AP_U32 kind,
    AP_U32 owner, AP_U32 selector, AP_U32 group)
{
    if (!view || !group || !selector || view->count > AR_MEMBERSHIP_LIMIT || (view->count && !view->entries)) return 0;
    AR_MEMBERSHIP key = {kind, owner, selector, group};
    AP_U32 first = 0, end = view->count;
    while (first < end) {
        AP_U32 middle = first + (end - first) / 2;
        int order = ar_membership_compare(&view->entries[middle], &key);
        if (!order) return 1;
        if (order < 0) first = middle + 1; else end = middle;
    }
    return 0;
}

static __inline int ar_view_application(const struct ap_policy_view *view,
    const struct ap_rule *rule, const struct ap_origin *origin);
#define AP_VIEW_APPLICATION(view, rule, origin) ar_view_application(view, rule, origin)
#include "../linux/kernel-policy/evaluate.h"
#undef AP_VIEW_APPLICATION

static __inline int ar_view_application(const struct ap_policy_view *view,
    const struct ap_rule *rule, const struct ap_origin *origin)
{
    if (!view->binding || rule->selector != 1) return ap_application(rule, origin);
    return ar_membership_contains((const AR_MEMBERSHIP_VIEW *)view->binding,
        view->policy->owner_kind, view->policy->owner, rule->application, origin->application);
}

static __inline struct ap_decision ar_evaluate_memberships(const struct ap_policy *policy,
    const AR_MEMBERSHIP_VIEW *memberships, const struct ap_context *context, int truncated)
{
    struct ap_decision denied = {0};
    denied.action = 1; denied.unresolved = 1; denied.rule = AP_NO_RULE; denied.generation = policy->generation;
    // Полная проверка сортировки выполняется до публикации immutable snapshot.
    if (!memberships || memberships->count > AR_MEMBERSHIP_LIMIT ||
        (memberships->count && !memberships->entries)) return denied;
    struct ap_policy_view view = {policy, (void *)memberships, 0};
    struct ap_decision decision = ap_evaluate_view(&view, context);
    if (!truncated || decision.unresolved || !ap_view_requires_identity(&view, context, 1)) return decision;
    if (policy->owner_kind != 3 && (policy->owner_kind != context->process.owner_kind ||
        policy->owner != context->process.owner)) return decision;
    if (ap_view_origin_matches(&view, context, &context->process, 0)) return decision;
    for (AP_U32 i = 0; i < context->parent_count; i++) {
        if (!ap_same_owner(&context->parents[i], &context->process) ||
            ap_view_origin_matches(&view, context, &context->parents[i], i + 1)) return decision;
    }
    return denied;
}
