#include <assert.h>
#include <stdio.h>
#include "kernel-policy/view.h"

struct test_view {struct ap_rule rules[256];unsigned missing;unsigned selector;unsigned group;};
static const struct ap_rule *test_rule(const struct ap_policy_view *view, unsigned index) {
    const struct test_view *data=view->binding;
    if (!data) return &view->policy->rules[index];
    return index==data->missing ? 0 : &data->rules[index];
}
static int test_application(const struct ap_policy_view *view, const struct ap_rule *rule, const struct ap_origin *origin) {
    if (rule->selector==1) {
        const struct test_view *data=view->binding;
        return data ? rule->application==data->selector && origin->application==data->group :
            origin->application && rule->application==origin->application;
    }
    return rule->selector==2 && origin->package && rule->application==origin->package;
}
#define AP_VIEW_RULE(view,index) test_rule(view,index)
#define AP_VIEW_APPLICATION(view,rule,origin) test_application(view,rule,origin)
#include "kernel-policy/evaluate.h"
_Static_assert(sizeof(struct ap_rule)==56,"rule ABI");
_Static_assert(sizeof(struct ap_policy)==14376,"policy ABI");
static void equal(struct ap_decision a,struct ap_decision b) {
    assert(a.action==b.action && a.profile==b.profile && a.rule==b.rule && a.depth==b.depth &&
           a.unresolved==b.unresolved && a.generation==b.generation);
}
static void controls(unsigned owner_kind,unsigned selector) {
    struct ap_policy policy={.version=1,.owner_kind=owner_kind,.owner=5,.count=256,.generation=3,.dns_profile=1};
    struct ap_context context={.process={.owner_kind=owner_kind,.owner=5,.resolved=1},.family=4};
    context.destination[0]=198;
    if(selector==1) context.process.application=42;else context.process.package=42;
    struct test_view records={.missing=256,.selector=42,.group=99};
    for(unsigned index=0;index<256;index++) {
        policy.rules[index]=(struct ap_rule){.selector=selector,.application=100+index,.inherit=1,.action=1};
        records.rules[index]=policy.rules[index];
    }
    const unsigned positions[]={0,63,64,127,128,191,192,255};
    for(unsigned p=0;p<sizeof(positions)/sizeof(*positions);p++) {
        unsigned index=positions[p];
        policy.rules[index].application=42;policy.rules[index].action=2;policy.rules[index].profile=7;
        records.rules[index]=policy.rules[index];
        struct ap_decision expected=ap_evaluate(&policy,&context);
        assert(expected.action==2 && expected.rule==index && expected.profile==7);
        const struct ap_policy_view ordinary={.policy=&policy};equal(expected,ap_evaluate_view(&ordinary,&context));
        struct ap_context grouped=context;if(selector==1)grouped.process.application=99;
        const struct ap_policy_view split={.policy=&policy,.binding=&records};equal(expected,ap_evaluate_view(&split,&grouped));
        records.missing=255;assert(ap_evaluate_view(&split,&grouped).unresolved==1);records.missing=256;
        policy.rules[index].application=100+index;records.rules[index]=policy.rules[index];
    }
    policy.count=1;policy.rules[0]=(struct ap_rule){.selector=selector,.application=42,.inherit=1,.action=2,.profile=7};
    context.parents[0]=context.process;context.process.application=0;context.process.package=0;context.parent_count=1;
    assert(ap_evaluate(&policy,&context).depth==1);
    context.parents[0].owner=6;assert(ap_evaluate(&policy,&context).action==0);
    context.parents[0].owner=5;context.process.resolved=0;assert(ap_evaluate(&policy,&context).unresolved==1);
    context.process=context.parents[0];context.destination[0]=127;assert(ap_evaluate(&policy,&context).action==0);
}
static void early_any_unknown(void) {
    struct ap_policy policy={.version=1,.owner_kind=1,.owner=5,.count=2,.generation=1};
    struct ap_context context={.process={.owner_kind=1,.owner=5},.family=4};
    policy.rules[0]=(struct ap_rule){.family=4,.address={192,0,2},.mask={255,255,255}};
    policy.rules[1]=(struct ap_rule){.selector=1,.application=42,.inherit=1,.action=2,.profile=7};
    for(unsigned action=0;action<3;action++) {
        policy.rules[0].action=action;policy.rules[0].profile=action==2?7:0;
        for(unsigned parent=0;parent<2;parent++) {
            context.process.resolved=parent;
            context.parent_count=parent;
            context.parents[0]=(struct ap_origin){.owner_kind=1,.owner=5};
            context.destination[0]=192;context.destination[1]=0;context.destination[2]=2;context.destination[3]=1;
            struct ap_decision result=ap_evaluate(&policy,&context);
            assert(result.action==action && result.rule==0 && !result.unresolved);
            context.destination[0]=198;context.destination[1]=18;context.destination[2]=0;context.destination[3]=53;
            assert(ap_evaluate(&policy,&context).unresolved);
        }
    }
    struct test_view records={.missing=1};
    records.rules[0]=policy.rules[0];records.rules[1]=policy.rules[1];
    struct ap_policy_view view={.policy=&policy,.binding=&records};
    context.destination[0]=192;context.destination[1]=0;context.destination[2]=2;
    assert(ap_evaluate_view(&view,&context).unresolved);
}
int main(void) {
    controls(1,1);controls(2,1);controls(2,2);
    early_any_unknown();
    puts("DEFAULT_WINDOWS_EQUALITY_AND_VIEW_PASS");
}
