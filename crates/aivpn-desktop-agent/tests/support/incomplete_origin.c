/* Модель captured facts и map lookup. Root и proof artifacts здесь не создаются. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "routing.h"
#include "lookup-evidence.h"
#include "kernel-policy/view.h"
typedef AP_U32 __u32;
typedef AP_U64 __u64;
#define __noinline __attribute__((unused))
#define __arg_nonnull
struct bs_value { __u64 words[8]; };
struct bs_key { __u64 kind, owner, payload[3]; };
struct working_buffer { struct ap_context context; struct bs_key lookup_key; __u64 source_markers[4]; };
#define BS_RULE 2
#define BS_FILE 3
#define BS_MEMBERSHIP 4
#define BS_PHYSICAL 5
#define BS_LOGICAL 6
#define BS_SOURCE_PHYSICAL 9
#define BS_SOURCE_LOGICAL 10
#define BS_SOURCE_META 11
/* Эти проверки моделируют прежний image origin без lookup proof и composed prefix. */
struct lookup_prefix_value { struct ph_stream prefix; struct ap_lookup_scope scope; };
static const struct lookup_prefix_value *lookup_prefix_find(__u64 id, __u32 index, __u32 domain) {
    (void)id; (void)index; (void)domain;
    return NULL;
}
static int file_bindings, applications;
static __u32 known_group;
static const struct bs_value *bs_lookup(void *, __u64, __u64, __u64, __u64, __u64);
static void *bpf_map_lookup_elem(const void *map, const void *key) {
    static __u32 marker;
    if (map == &file_bindings) return &known_group;
    if (map == &applications) {
        marker=((const struct application_key *)key)->path.low;
        return marker ? &marker : NULL;
    }
    const struct bs_key *k=key;
    return (void *)bs_lookup((void *)map,k->kind,k->owner,k->payload[0],k->payload[1],k->payload[2]);
}
static const struct bs_value *bs_lookup(void *inner, __u64 kind, __u64 owner,
                                      __u64 a, __u64 b, __u64 c) {
    static struct bs_value values[12];
    assert(kind < 12);
    if (kind == BS_SOURCE_META) return NULL;
    struct bs_value *value=&values[kind];
    (void)owner;(void)c;
    memset(value,0,sizeof(*value));
    if (kind==BS_RULE) memcpy(value,&((struct ap_policy *)inner)->rules[a],sizeof(struct ap_rule));
    else if (kind==BS_MEMBERSHIP) value->words[0]=a && a==b;
    else if (kind==BS_FILE) value->words[0]=known_group;
    else value->words[0]=a==10 ? 1 : a==20 ? 2 : 0;
    return value;
}
static const struct ap_rule *bs_rule(const struct ap_policy_view *view,unsigned index) {
    return &view->policy->rules[index];
}
static int bs_member(const struct ap_policy_view *view,__u32 selector,__u32 group) {
    (void)view;
    return (selector==10 && group==10) || (selector==20 && group==20);
}
#define AP_VIEW_RULE(view,index) bs_rule(view,index)
#ifdef TEST_SNAPSHOT
#define AP_VIEW_APPLICATION(view,rule,origin) bs_member(view,(rule)->application,(origin)->application)
#endif
#include "kernel-policy/evaluate.h"
#include "production-origin.h"

static struct ap_policy policy(void) {
    struct ap_policy p={.version=1,.owner_kind=1,.owner=1000,.count=2,.generation=1,.dns_profile=1};
    for(unsigned i=0;i<2;i++) {
        p.rules[i]=(struct ap_rule){.selector=1,.application=10+10*i,.inherit=1,.action=2,.profile=1,.family=4};
        p.rules[i].address[0]=53+i;p.rules[i].mask[0]=255;
    }
    return p;
}
static struct ap_decision evaluate(struct ap_policy *p,struct origin_hash *source,unsigned depth,unsigned target) {
    struct working_buffer work={.context={.family=4,.process={.owner_kind=1,.owner=1000,.resolved=1}}};
    struct ap_context *context=&work.context;
    context->destination[0]=target;context->parent_count=depth;
    struct ap_origin *out=depth ? &context->parents[0] : &context->process;
#ifdef TEST_SNAPSHOT
    const struct ap_policy_view view={.policy=p,.binding=p,.owner=(1ULL<<32)|1000};
    bs_fill_origin(out,source,&view,context,depth);
    return ap_evaluate_view(&view,context);
#else
    fill_origin(out,source,p,context,depth);
    return ap_evaluate(p,context);
#endif
}
static unsigned failures,checks;
static void expect(struct ap_policy *p,struct origin_hash *source,unsigned depth,unsigned target,unsigned action,const char *case_name) {
    struct ap_decision result=evaluate(p,source,depth,target);checks++;
    if(result.action!=action) {failures++;printf("MODEL_FAIL %s flags=%u depth=%u group=%u expected=%u actual=%u\n",case_name,source->path_flags,depth,known_group,action,result.action);}
}
static void incomplete_cases(unsigned group) {
    struct ap_policy p=policy();known_group=group;
    for(unsigned flags=0;flags<3;flags++) {
        struct origin_hash origin={.uid=1000,.path_flags=flags,.file_cookie=1,.filesystem_device=2,.path={20,0},.logical_path={10,0}};
        if(flags==2) {origin.path.low=10;origin.logical_path.low=20;}
        for(unsigned depth=0;depth<2;depth++) {
            expect(&p,&origin,depth,53,1,"incomplete-applicable");
            expect(&p,&origin,depth,54,1,"incomplete-known-own-selector");
            expect(&p,&origin,depth,55,0,"incomplete-no-cidr");
        }
        p.rules[0].inherit=0;expect(&p,&origin,1,53,0,"incomplete-no-inherit");p.rules[0].inherit=1;
    }
}
static void candidate_controls(void) {
    struct ap_policy p=policy();known_group=20;
    struct origin_hash stored={.uid=1000,.file_cookie=1,.task_identity=9,.exec_identity=7,.owner_epoch=8,.path={20,0},.logical_path={20,0}};
    struct origin_hash candidate=stored;candidate.path_flags=AP_PATH_COMPLETE;
    for(unsigned flags=0;flags<3;flags++) {
        stored.path_flags=flags;
        assert(available_origin(&stored,&candidate)==&candidate);
        struct origin_hash chosen=*available_origin(&stored,&candidate);
        expect(&p,&chosen,0,53,0,"complete-candidate-other-selector");
        expect(&p,&chosen,0,54,2,"complete-candidate-own-selector");
        candidate.file_cookie=2;assert(available_origin(&stored,&candidate)==&stored);candidate.file_cookie=1;
        candidate.uid=1001;assert(available_origin(&stored,&candidate)==&stored);candidate.uid=1000;
        candidate.task_identity=10;assert(available_origin(&stored,&candidate)==&stored);candidate.task_identity=9;
        candidate.exec_identity=9;assert(available_origin(&stored,&candidate)==&stored);candidate.exec_identity=7;
        candidate.owner_epoch=9;assert(available_origin(&stored,&candidate)==&stored);candidate.owner_epoch=8;
        candidate.path_flags=flags;assert(available_origin(&stored,&candidate)==&stored);candidate.path_flags=AP_PATH_COMPLETE;
    }
    stored.path_flags=AP_PATH_COMPLETE;assert(available_origin(&stored,&candidate)==&stored);
    stored.path.low=10;expect(&p,&stored,0,53,1,"complete-physical-negative");
    stored.path.low=20;stored.logical_path.low=10;expect(&p,&stored,0,53,1,"complete-logical-negative");
}
static void renamed_candidate_keeps_negative(void) {
    struct ap_policy p=policy();known_group=20;
    struct origin_hash stored={.uid=1000,.path_flags=AP_PATH_PHYSICAL,.file_cookie=1,
        .task_identity=9,.exec_identity=7,.owner_epoch=8,.filesystem_device=2,.path={10,0}};
    struct origin_hash candidate=stored;
    candidate.path_flags=AP_PATH_COMPLETE;candidate.path.low=20;candidate.logical_path.low=20;
    struct origin_hash chosen=*available_origin(&stored,&candidate);
    expect(&p,&chosen,0,53,1,"renamed-candidate-preserves-original-negative");
}
int main(void) {
    incomplete_cases(20);incomplete_cases(30);candidate_controls();renamed_candidate_keeps_negative();
    printf("ORIGIN_MODEL checks=%u failures=%u\n",checks,failures);
    return failures ? 1 : 0;
}
