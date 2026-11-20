#include "membership.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct ap_policy policy;
static struct ap_context context;

static void reset(void)
{
    memset(&policy, 0, sizeof(policy)); memset(&context, 0, sizeof(context));
    policy.version = 1; policy.owner_kind = 2; policy.owner = 10;
    policy.generation = 7; policy.dns_profile = 50; policy.count = 2;
    policy.rules[0] = (struct ap_rule){.selector=1, .application=100, .action=2, .profile=50, .inherit=1};
    policy.rules[1] = (struct ap_rule){.selector=1, .application=200, .action=1, .inherit=1};
    context.process = (struct ap_origin){.owner_kind=2, .owner=10, .application=1, .resolved=1};
    context.family = 4; context.destination[0] = 8; context.destination[3] = 8;
}

int main(void)
{
    /* A->{G1,G2}, B->{G2}; U2 не получает историю U1. */
    const AR_MEMBERSHIP entries[] = {{2,10,100,1},{2,10,100,2},{2,10,200,2},{2,20,100,2}};
    AR_MEMBERSHIP_VIEW view = {entries, 4};
    assert(ar_memberships_valid(&view)); reset();
    struct ap_decision value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 2 && value.rule == 0 && value.generation == 7);
    context.process.application = 2;
    value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 2 && value.rule == 0);
    struct ap_rule first = policy.rules[0]; policy.rules[0] = policy.rules[1]; policy.rules[1] = first;
    value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 1 && value.rule == 0);
    context.process.application = 1;
    value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 2 && value.rule == 1);
    policy.owner = context.process.owner = 20;
    value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 0 && value.rule == AP_NO_RULE);

    reset(); context.process.application = 9; context.parent_count = 1;
    context.parents[0] = (struct ap_origin){.owner_kind=2, .owner=10, .application=1, .resolved=1};
    value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 2 && value.rule == 0 && value.depth == 1);
    context.process.application = 2; policy.rules[0].family = 4;
    policy.rules[0].address[0] = 9; policy.rules[0].mask[0] = 255;
    value = ar_evaluate_memberships(&policy, &view, &context, 0);
    assert(value.action == 1 && value.rule == 1 && value.depth == 0);

    reset(); context.process.application = 9;
    value = ar_evaluate_memberships(&policy, &view, &context, 1);
    assert(value.action == 1 && value.unresolved);
    context.process.application = 1;
    value = ar_evaluate_memberships(&policy, &view, &context, 1);
    assert(value.action == 2 && !value.unresolved);
    context.process.resolved = 0;
    assert(ar_evaluate_memberships(&policy, &view, &context, 0).unresolved);

    /* Single-membership сохраняет прежнее значение rule, depth и action. */
    reset(); context.process.application = 100;
    AR_MEMBERSHIP scalar[] = {{2,10,100,100},{2,10,200,200}};
    view = (AR_MEMBERSHIP_VIEW){scalar, 2};
    for (unsigned i = 0; i < 3; i++) {
        context.process.application = i ? i * 100 : 999;
        struct ap_decision a = ap_evaluate(&policy, &context);
        struct ap_decision b = ar_evaluate_memberships(&policy, &view, &context, 0);
        assert(a.action == b.action && a.profile == b.profile && a.rule == b.rule &&
            a.depth == b.depth && a.unresolved == b.unresolved && a.generation == b.generation);
    }
    scalar[1] = scalar[0]; assert(!ar_memberships_valid(&view));
    view.count = AR_MEMBERSHIP_LIMIT + 1; assert(!ar_memberships_valid(&view));
    puts("membership: ordered roles, owner isolation, ancestry, CIDR, incomplete and scalar parity OK");
    return 0;
}
