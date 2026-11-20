#pragma once
#include "lookup-reference.h"

static __always_inline int process_pair_valid(const struct process_state *state,
                                              const struct process_companion *companion) {
    return state && companion && state->snapshot_identity &&
           state->snapshot_identity == companion->snapshot_identity;
}

/* Несогласованные части нельзя заново опубликовать как полную прежнюю историю. */
static __always_inline void history_unknown_pair(struct process_state *state,
                                                 struct process_companion *companion) {
    state->self.source.path_flags = state->self.image.path_flags = 0;
    AP_FOR(index, AP_PARENT_LIMIT) {
        state->parents[index].parent.source.path_flags = 0;
        state->parents[index].parent.image.path_flags = 0;
    }
    if (companion)
        companion->available = 0;
}

/* Frames копируются целиком. Родительские снимки после публикации не дополняются. */
static __always_inline void frame_owner(struct exec_frame *frame, AP_U32 owner,
                                        AP_U64 epoch, AP_U64 task) {
    frame->source.uid = frame->image.uid = owner;
    frame->source.owner_epoch = frame->image.owner_epoch = epoch;
    frame->source.task_identity = frame->image.task_identity = task;
}
static __always_inline void history_prepend(struct process_state *state,
                                            struct process_companion *companion,
                                            const struct exec_frame *frame, AP_U32 kind, AP_U64 edge) {
    if (state->parent_count == AP_PARENT_LIMIT) {
        state->ancestry_flags |= kind == AP_HISTORY_FORK ? AP_ANCESTRY_OVERFLOW :
            kind == AP_HISTORY_OWNER ? AP_ANCESTRY_OWNER_OVERFLOW : AP_ANCESTRY_EXEC_OVERFLOW;
    } else {
        state->parent_count++;
    }
    AP_FOR(offset, AP_PARENT_LIMIT - 1) {
        unsigned index = AP_PARENT_LIMIT - 1 - (unsigned)offset;
        if (index < state->parent_count)
            copy_history_slot(&state->parents[index], &state->parents[index - 1]);
    }
    if (companion) {
        AP_FOR(offset, AP_PARENT_LIMIT - 1) {
            unsigned index = AP_PARENT_LIMIT - 1 - (unsigned)offset;
            if (index < state->parent_count)
                copy_exec_frame(&companion->carried[index], &companion->carried[index - 1]);
        }
    }
    copy_exec_frame(&state->parents[0].parent, frame);
    state->parents[0].edge_identity = edge;
    state->parents[0].kind = kind;
    state->parents[0].has_carried = 0;
    if (companion)
        companion->available <<= 1;
}
static __always_inline int witnessed_first_exec(const struct task_capture *capture) {
    const struct fork_witness *witness = &capture->witness;
    const struct process_state *state = &capture->committed;
    const struct origin_hash *self = &state->self.source;
    const struct history_slot *slot = &state->parents[0];
    return witness->armed && state->parent_count && slot->kind == AP_HISTORY_FORK &&
           !slot->has_carried && witness->edge_identity &&
           witness->edge_identity == slot->edge_identity && witness->parent_task &&
           witness->parent_task == slot->parent.source.task_identity && witness->child_task &&
           witness->child_task == self->task_identity && witness->copied_exec &&
           witness->copied_exec == self->exec_identity &&
           witness->copied_exec == slot->parent.source.exec_identity && witness->owner_epoch &&
           witness->owner_epoch == self->owner_epoch && witness->owner == self->uid;
}
static __always_inline void history_commit_exec(struct task_capture *capture,
                                                  struct process_companion *companion) {
    struct process_state *state = &capture->committed;
    if (witnessed_first_exec(capture)) {
        if (companion)
            copy_exec_frame(&companion->carried[0], &state->self);
        if (companion)
            companion->available |= 1;
        state->parents[0].has_carried = 1;
    } else {
        history_prepend(state, companion, &state->self, AP_HISTORY_EXEC, 0);
    }
    if ((capture->pending.active & AP_EXEC_OWNER_CHANGED) &&
        capture->pending.source.uid == state->self.source.uid) {
        /* Возврат UID не стирает реально пройденную границу другого owner. */
        history_prepend(state, companion, &state->self, AP_HISTORY_OWNER,
                        capture->pending.source.owner_epoch);
        state->parents[0].parent.source = (struct origin_hash){ .uid = capture->pending.previous_owner };
        state->parents[0].parent.image = state->parents[0].parent.source;
        lookup_frame_clear(&state->parents[0].parent);
    }
    capture->witness.armed = 0;
}

static __always_inline void history_fork(struct task_capture *capture,
                                         const struct process_state *parent,
                                         struct process_companion *companion,
                                         AP_U64 child_identity, AP_U64 edge, int thread) {
    struct process_state *state = &capture->committed;
    copy_exec_frame(&state->self, &parent->self);
    state->parent_count = parent->parent_count;
    state->ancestry_flags = parent->ancestry_flags;
    AP_FOR(index, AP_PARENT_LIMIT) {
        copy_history_slot(&state->parents[index], &parent->parents[index]);
    }
    frame_owner(&state->self, parent->self.source.uid, parent->self.source.owner_epoch, child_identity);
    capture->pending.active = 0;
    lookup_pending_clear(&capture->pending);
    capture->witness.armed = 0;
    if (!thread) {
        history_prepend(state, companion, &parent->self, AP_HISTORY_FORK, edge);
        capture->witness = (struct fork_witness){
            .edge_identity = edge, .parent_task = parent->self.source.task_identity,
            .child_task = child_identity, .copied_exec = state->self.source.exec_identity,
            .owner_epoch = state->self.source.owner_epoch, .owner = state->self.source.uid,
            .armed = 1,
        };
    }
}

static __always_inline void history_owner(struct task_capture *capture, struct process_companion *companion, AP_U32 owner,
                                          AP_U64 epoch, int in_exec) {
    AP_U32 previous = capture->pending.active && in_exec ? capture->pending.source.uid :
                                                           capture->committed.self.source.uid;
    if (owner == previous)
        return;
    capture->witness.armed = 0;
    if (capture->pending.active && in_exec) {
        capture->pending.previous_owner = previous;
        capture->pending.source.uid = owner;
        capture->pending.source.owner_epoch = epoch;
        capture->pending.active |= AP_EXEC_OWNER_CHANGED;
        return;
    }
    capture->pending.active = 0;
    lookup_pending_clear(&capture->pending);
    history_prepend(&capture->committed, companion, &capture->committed.self, AP_HISTORY_OWNER, 0);
    frame_owner(&capture->committed.self, owner, epoch,
                capture->committed.self.source.task_identity);
}

static __always_inline void copy_process_companion(struct process_companion *target,
                                                   const struct process_companion *source) {
    target->snapshot_identity = 0;
    __asm__ __volatile__("" ::: "memory");
    target->available = source ? source->available : 0;
    AP_FOR(index, AP_PARENT_LIMIT) {
        if (source)
            copy_exec_frame(&target->carried[index], &source->carried[index]);
        else {
            target->carried[index].source = (struct origin_hash){0};
            target->carried[index].image = (struct origin_hash){0};
            lookup_frame_clear(&target->carried[index]);
        }
    }
    __asm__ __volatile__("" ::: "memory");
    target->snapshot_identity = source ? source->snapshot_identity : 0;
}
