#pragma once
#include "view.h"
#ifdef AIVPN_BPF
#define AP_INLINE __always_inline
#else
#define AP_INLINE __inline
#endif
#ifndef AP_FOR
#define AP_FOR(index, limit) for (unsigned index = 0; index < (limit); index++)
#endif

static AP_INLINE int ap_network(const struct ap_rule *rule, const struct ap_context *context) {
    if (!rule->family)
        return 1;
    if (rule->family != context->family)
        return 0;
    AP_FOR(index, 16) {
        if ((context->destination[index] & rule->mask[index]) != rule->address[index])
            return 0;
    }
    return 1;
}
static AP_INLINE int ap_application(const struct ap_rule *rule, const struct ap_origin *origin) {
    if (rule->selector == 1)
        return rule->application == origin->application && origin->application != 0;
    if (rule->selector == 2)
        return rule->application == origin->package && origin->package != 0;
    return 0;
}
#ifndef AP_VIEW_RULE
#define AP_VIEW_RULE(view, index) (&(view)->policy->rules[index])
#endif
#ifndef AP_VIEW_APPLICATION
#define AP_VIEW_APPLICATION(view, rule, origin) ap_application(rule, origin)
#endif

static AP_INLINE int ap_same_owner(const struct ap_origin *a, const struct ap_origin *b) {
    return a->owner_kind == b->owner_kind && a->owner == b->owner;
}
static AP_INLINE int ap_view_origin_matches(const struct ap_policy_view *view,
                                      const struct ap_context *context,
                                      const struct ap_origin *origin, unsigned depth) {
    const struct ap_policy *policy = view->policy;
    AP_FOR(index, AP_RULE_LIMIT) {
        if ((unsigned)index >= policy->count)
            break;
        const struct ap_rule *rule = AP_VIEW_RULE(view, index);
        if (!rule) return 0;
        if ((!depth || rule->inherit) && AP_VIEW_APPLICATION(view, rule, origin) && ap_network(rule, context))
            return 1;
    }
    return 0;
}
static AP_INLINE int ap_view_requires_identity(const struct ap_policy_view *view,
                                         const struct ap_context *context, int inherited) {
    const struct ap_policy *policy = view->policy;
    AP_FOR(index, AP_RULE_LIMIT) {
        if ((unsigned)index >= policy->count)
            break;
        const struct ap_rule *rule = AP_VIEW_RULE(view, index);
        if (!rule) return 1;
        if (!ap_network(rule, context))
            continue;
        if (!rule->selector)
            return 0;
        if (!inherited || rule->inherit)
            return 1;
    }
    return 0;
}
static AP_INLINE int ap_loopback(const struct ap_context *context) {
    if (context->family == 4)
        return context->destination[0] == 127;
    if (context->family != 6 || context->destination[15] != 1)
        return 0;
    AP_FOR(index, 15) if (context->destination[index]) return 0;
    return 1;
}
static AP_INLINE struct ap_decision ap_evaluate_view(const struct ap_policy_view *view,
                                               const struct ap_context *context) {
    const struct ap_policy *policy = view->policy;
    struct ap_decision result = {0};
    result.rule = AP_NO_RULE;
    result.generation = policy->generation;
    if (policy->owner_kind != 3 && (policy->owner_kind != context->process.owner_kind ||
                                    policy->owner != context->process.owner))
        return result;
    result.action = 1;
    if (policy->version != 1 || policy->count > AP_RULE_LIMIT ||
        context->parent_count > AP_PARENT_LIMIT || (context->family != 4 && context->family != 6)) {
        result.unresolved = 1;
        return result;
    }
    /* Отсутствующее обязательное правило не может превратиться в default/SYSTEM. */
    AP_FOR(index, AP_RULE_LIMIT) {
        if ((unsigned)index >= policy->count) break;
        if (!AP_VIEW_RULE(view, index)) { result.unresolved = 1; return result; }
    }
    if (!context->process.resolved && ap_view_requires_identity(view, context, 0)) {
        result.unresolved = 1;
        return result;
    }
    int depth = -1;
    const struct ap_origin *selected = 0;
    if (ap_view_origin_matches(view, context, &context->process, 0)) {
        depth = 0;
        selected = &context->process;
    }
    if (depth < 0) {
        int inherited = ap_view_requires_identity(view, context, 1);
        AP_FOR(index, AP_PARENT_LIMIT) {
            if ((unsigned)index >= context->parent_count)
                break;
            const struct ap_origin *parent = &context->parents[index];
            if (!ap_same_owner(parent, &context->process))
                break;
            if (!parent->resolved && inherited) {
                result.unresolved = 1;
                return result;
            }
            if (ap_view_origin_matches(view, context, parent, index + 1)) {
                depth = (int)index + 1;
                selected = parent;
                break;
            }
        }
    }
    result.action = policy->default_action;
    result.profile = policy->default_profile;
    AP_FOR(index, AP_RULE_LIMIT) {
        if ((unsigned)index >= policy->count)
            break;
        const struct ap_rule *rule = AP_VIEW_RULE(view, index);
        if (!rule) { result.action = 1; result.profile = 0; result.unresolved = 1; return result; }
        if (!ap_network(rule, context))
            continue;
        if (!rule->selector ||
            (selected && (!depth || rule->inherit) && AP_VIEW_APPLICATION(view, rule, selected))) {
            result.action = rule->action;
            result.profile = rule->profile;
            result.rule = index;
            result.depth = (AP_U32)(depth < 0 ? 0 : depth);
            if (!rule->selector)
                result.depth = 0;
            break;
        }
    }
    if (result.action == 2 && ap_loopback(context)) {
        result.action = 0;
        result.profile = 0;
    }
    return result;
}

static AP_INLINE int ap_origin_matches(const struct ap_policy *policy,
                                      const struct ap_context *context,
                                      const struct ap_origin *origin, unsigned depth) {
    const struct ap_policy_view view = { .policy = policy };
    return ap_view_origin_matches(&view, context, origin, depth);
}
static AP_INLINE struct ap_decision ap_evaluate(const struct ap_policy *policy,
                                               const struct ap_context *context) {
    const struct ap_policy_view view = { .policy = policy };
    return ap_evaluate_view(&view, context);
}

static AP_INLINE int ap_requires_identity(const struct ap_policy *policy,
                                         const struct ap_context *context, int inherited) {
    const struct ap_policy_view view = { .policy = policy };
    return ap_view_requires_identity(&view, context, inherited);
}
