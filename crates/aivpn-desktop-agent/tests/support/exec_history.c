#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "routing.h"
#define AP_FOR(index,limit) for (unsigned index=0;index<(limit);index++)
#include "exec-history.h"
#include "kernel-policy/view.h"
static const struct ap_rule *model_rule(const struct ap_policy_view *view,unsigned index) {
    return &view->policy->rules[index];
}
#define AP_VIEW_RULE(view,index) model_rule(view,index)
#include "kernel-policy/evaluate.h"

static struct exec_frame frame(unsigned task,unsigned exec,unsigned owner,unsigned epoch) {
    struct exec_frame result={0};
    frame_owner(&result,owner,epoch,task);
    result.source.exec_identity=result.image.exec_identity=exec;
    result.source.file_cookie=100+exec;result.image.file_cookie=200+exec;
    result.source.path_flags=result.image.path_flags=AP_PATH_COMPLETE;
    return result;
}
static void chain(void) {
    struct task_capture parent={.committed.self=frame(1,1,1000,1)};
    struct process_companion parent_mate={0};
    for(unsigned depth=1;depth<=33;depth++) {
        struct task_capture child={0};
        struct process_companion child_mate=parent_mate;
        history_fork(&child,&parent.committed,&child_mate,depth+1,1000+depth,0);
        assert(witnessed_first_exec(&child));
        unsigned flags=child.committed.ancestry_flags;
        history_commit_exec(&child,&child_mate);
        assert(child.committed.parent_count==(depth<32?depth:32));
        assert(child.committed.ancestry_flags==flags);
        assert(child.committed.parents[0].has_carried);
        assert(child_mate.carried[0].source.task_identity==depth+1);
        assert(child.committed.parents[0].parent.source.task_identity==depth);
        assert(child_mate.carried[0].source.file_cookie==child.committed.parents[0].parent.source.file_cookie);
        assert(!child.witness.armed);
        child.committed.self=frame(depth+1,depth+1,1000,1);
        parent=child;parent_mate=child_mate;
    }
    assert(parent.committed.ancestry_flags==AP_ANCESTRY_OVERFLOW);
    assert(parent.committed.parents[31].parent.source.task_identity==2);
    history_commit_exec(&parent,&parent_mate);
    assert(parent.committed.ancestry_flags==(AP_ANCESTRY_OVERFLOW|AP_ANCESTRY_EXEC_OVERFLOW));
    assert(parent.committed.parents[0].kind==AP_HISTORY_EXEC);
}
static void lifetime(void) {
    struct task_capture parent={.committed.self=frame(1,5,1000,8)},child={0};
    struct process_companion child_mate={0},thread_mate={0};
    history_fork(&child,&parent.committed,&child_mate,2,17,0);
    /* Неудачная попытка меняет только pending, witness расходуется успешным exec. */
    child.pending.active=1;child.pending.attempt=40;child.pending.active=0;
    child.pending.active=1;child.pending.attempt=41;child.pending.active=0;
    assert(witnessed_first_exec(&child));
    child.committed.self.image.path_flags=AP_PATH_PHYSICAL;
    history_commit_exec(&child,&child_mate);
    assert(child_mate.carried[0].image.path_flags==AP_PATH_PHYSICAL);
    assert(child.committed.parents[0].parent.image.path_flags==AP_PATH_COMPLETE);
    parent.committed.self=frame(1,9,1000,8);
    assert(child.committed.parents[0].parent.source.exec_identity==5);
    struct task_capture thread={0};
    history_fork(&thread,&child.committed,&thread_mate,3,19,1);
    assert(thread.committed.parent_count==child.committed.parent_count && !thread.witness.armed);
    history_commit_exec(&thread,&thread_mate);
    assert(thread.committed.parent_count==2);
    for(unsigned mismatch=0;mismatch<7;mismatch++) {
        history_fork(&child,&parent.committed,&child_mate,2,20,0);
        switch(mismatch) {
        case 0:child.witness.edge_identity++;break;
        case 1:child.witness.parent_task++;break;
        case 2:child.witness.child_task++;break;
        case 3:child.witness.copied_exec++;break;
        case 4:child.witness.owner_epoch++;break;
        case 5:child.witness.owner++;break;
        case 6:child.witness.owner_epoch=0;break;
        }
        assert(!witnessed_first_exec(&child));
        history_commit_exec(&child,&child_mate);assert(child.committed.parent_count==2);
    }
}
static void owners(void) {
    struct task_capture capture={.committed.self=frame(1,2,1000,3)};
    struct process_companion mate={0};
    history_owner(&capture,&mate,0,4,0);history_owner(&capture,&mate,1000,5,0);
    assert(capture.committed.self.source.uid==1000 && capture.committed.self.source.owner_epoch==5);
    assert(capture.committed.parents[0].parent.source.uid==0);
    assert(capture.committed.parents[1].parent.source.uid==1000);
    assert(capture.committed.parents[1].parent.source.owner_epoch==3);
    capture.pending.active=1;capture.pending.source=frame(1,6,1000,5).source;
    unsigned count=capture.committed.parent_count;
    history_owner(&capture,&mate,1001,7,1);
    assert(capture.committed.parent_count==count);
    assert(capture.committed.self.source.uid==1000);
    assert(capture.pending.source.uid==1001 && capture.pending.source.owner_epoch==7);
    history_commit_exec(&capture,&mate);
    assert(capture.committed.parent_count==count+1);
    assert(capture.committed.parents[0].parent.source.uid==1000);
}
static void pending_return(void) {
    struct task_capture capture={.committed.self=frame(1,2,1000,3)};
    struct process_companion mate={0};
    capture.pending.active=1;capture.pending.source=frame(1,9,1000,3).source;
    history_owner(&capture,&mate,1001,4,1);
    history_owner(&capture,&mate,1000,5,1);
    assert(capture.pending.source.uid==1000 && capture.pending.source.owner_epoch==5);
    assert(capture.committed.parent_count==0 && capture.committed.self.source.owner_epoch==3);
    history_commit_exec(&capture,&mate);
    assert(capture.committed.parent_count==2);
    assert(capture.committed.parents[0].kind==AP_HISTORY_OWNER);
    assert(capture.committed.parents[0].parent.source.uid==1001);
    assert(capture.committed.parents[1].parent.source.uid==1000);
    assert(capture.committed.parents[1].parent.source.exec_identity==2);
    struct ap_policy policy={.version=1,.owner_kind=1,.owner=1000,.count=1,.generation=1,.dns_profile=1};
    policy.rules[0]=(struct ap_rule){.selector=1,.application=1,.inherit=1,.action=2,.profile=1};
    struct ap_context context={.family=4,.process={.owner_kind=1,.owner=1000,.resolved=1},.parent_count=2};
    context.parents[0]=(struct ap_origin){.owner_kind=1,.owner=capture.committed.parents[0].parent.source.uid};
    context.parents[1]=(struct ap_origin){.owner_kind=1,.owner=1000,.application=1,.resolved=1};
    assert(ap_evaluate(&policy,&context).action==0);
    context.process.application=1;
    assert(ap_evaluate(&policy,&context).action==2);
}
int main(void) {
    chain();lifetime();owners();pending_return();
    struct task_capture capture={.committed.self=frame(1,2,1000,3)};
    struct process_companion mate={.snapshot_identity=8,.available=1};
    capture.committed.snapshot_identity=8;
    assert(process_pair_valid(&capture.committed,&mate));
    mate.snapshot_identity=9;assert(!process_pair_valid(&capture.committed,&mate));
    assert(!process_pair_valid(&capture.committed,0));
    history_unknown_pair(&capture.committed,&mate);
    assert(!capture.committed.self.source.path_flags && !mate.available);
    capture.committed.snapshot_identity=mate.snapshot_identity=0;
    assert(!process_pair_valid(&capture.committed,&mate));
    printf("EXEC_HISTORY_PASS origin=%zu frame=%zu slot=%zu process=%zu task=%zu companion=%zu frames=65 slots=32\n",
           sizeof(struct origin_hash),sizeof(struct exec_frame),sizeof(struct history_slot),sizeof(struct process_state),sizeof(struct task_capture),sizeof(struct process_companion));
}
