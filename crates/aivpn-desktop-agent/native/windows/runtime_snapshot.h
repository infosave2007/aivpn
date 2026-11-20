#pragma once
#include "runtime_groups.h"

#define RS_SID_LIMIT (AR_OWNER_LIMIT + AR_GROUP_LIMIT)
typedef struct { UINT32 kind, slot, length; UCHAR sid[AR_SID_BYTES]; } RS_SID;
typedef struct {
    struct ap_policy policy;
    UCHAR document_digest[32];
    UINT32 verified[(AP_RULE_LIMIT + 31u) / 32u];
    BOOLEAN carried;
} RS_POLICY;
typedef struct {
    LONG references;
    UCHAR namespace_id[16];
    UINT64 epoch, serial, session;
    UINT32 expected, count, sid_count;
    BOOLEAN sealed;
    RG_REGISTRY *registry;
    RS_POLICY *policies;
    RS_SID sids[RS_SID_LIMIT];
} RS_SNAPSHOT;
static RS_SNAPSHOT *rs_current, *rs_pending;
static UINT64 rs_epoch;

static void rs_release(RS_SNAPSHOT *snapshot)
{
    if (!snapshot || InterlockedDecrement(&snapshot->references)) return;
    rg_release(snapshot->registry);
    if (snapshot->policies) ExFreePoolWithTag(snapshot->policies, AR_POOL_TAG);
    ExFreePoolWithTag(snapshot, AR_POOL_TAG);
}

static void rs_abort(void)
{
    rs_release(rs_pending);
    rs_pending = NULL;
}

static RS_POLICY *rs_find_policy(RS_SNAPSHOT *snapshot, UINT32 kind, UINT32 owner)
{
    if (snapshot) for (UINT32 i = 0; i < snapshot->count; i++)
        if (snapshot->policies[i].policy.owner_kind == kind && snapshot->policies[i].policy.owner == owner)
            return &snapshot->policies[i];
    return NULL;
}

static BOOLEAN rs_same_policy(const struct ap_policy *left, const struct ap_policy *right)
{
    /* Runtime epoch назначает драйвер. Он не меняет логическое содержание policy. */
    return RtlCompareMemory(left, right, 16) == 16 &&
        RtlCompareMemory((const UCHAR *)left + 24, (const UCHAR *)right + 24, sizeof(*left) - 24) == sizeof(*left) - 24;
}

static NTSTATUS rs_begin(const AR_RUNTIME_BEGIN *request)
{
    if (request->reserved || !request->serial || bytes_zero(request->namespace_id, 16) || request->policy_count > AR_OWNER_LIMIT)
        return STATUS_INVALID_PARAMETER;
    if (rs_current && RtlCompareMemory(rs_current->namespace_id, request->namespace_id, 16) != 16)
        return STATUS_OBJECT_NAME_COLLISION;
    if (rs_current && request->serial < rs_current->serial) return STATUS_REVISION_MISMATCH;
    if (rs_epoch == MAXUINT64) return STATUS_INTEGER_OVERFLOW;
    RS_SNAPSHOT *next = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*next), AR_POOL_TAG);
    if (!next) return STATUS_INSUFFICIENT_RESOURCES;
    next->references = 1;
    next->expected = request->policy_count;
    next->serial = request->serial; next->session = session_id;
    RtlCopyMemory(next->namespace_id, request->namespace_id, 16);
    NTSTATUS status = rg_clone(rs_current ? rs_current->registry : NULL, &next->registry);
    if (!NT_SUCCESS(status)) { rs_release(next); return status; }
    if (request->policy_count) {
        next->policies = ExAllocatePool2(POOL_FLAG_NON_PAGED, request->policy_count * sizeof(RS_POLICY), AR_POOL_TAG);
        if (!next->policies) { rs_release(next); return STATUS_INSUFFICIENT_RESOURCES; }
    }
    if (rs_current) {
        next->sid_count = rs_current->sid_count;
        RtlCopyMemory(next->sids, rs_current->sids, next->sid_count * sizeof(RS_SID));
    }
    next->epoch = ++rs_epoch;
    rs_abort(); rs_pending = next;
    return STATUS_SUCCESS;
}

static BOOLEAN rs_mutable(void)
{
    return rs_pending && rs_pending->session == session_id && !rs_pending->sealed;
}

static NTSTATUS rs_policy(const AR_RUNTIME_POLICY *request)
{
    if (!rs_mutable()) return STATUS_DEVICE_NOT_READY;
    const struct ap_policy *policy = &request->stage.policy;
    if (policy->generation != rs_pending->epoch) return STATUS_REVISION_MISMATCH;
    if (!ap_policy_valid(policy, 2) || bytes_zero(request->document_digest, 32)) return STATUS_INVALID_PARAMETER;
    if (rs_find_policy(rs_pending, policy->owner_kind, policy->owner)) return STATUS_OBJECT_NAME_COLLISION;
    if (rs_pending->count == rs_pending->expected) return STATUS_INSUFFICIENT_RESOURCES;
    RS_POLICY *next = &rs_pending->policies[rs_pending->count++];
    next->policy = *policy; next->policy.generation = rs_pending->epoch;
    RtlCopyMemory(next->document_digest, request->document_digest, 32);
    const RS_POLICY *current = rs_find_policy(rs_current, policy->owner_kind, policy->owner);
    next->carried = current && rs_same_policy(&current->policy, policy) &&
        RtlCompareMemory(current->document_digest, request->document_digest, 32) == 32;
    return STATUS_SUCCESS;
}

static NTSTATUS rs_sid(const AR_RUNTIME_SID *request)
{
    if (!rs_mutable()) return STATUS_DEVICE_NOT_READY;
    if (request->epoch != rs_pending->epoch) return STATUS_REVISION_MISMATCH;
    if ((request->kind != AR_BIND_OWNER && request->kind != AR_BIND_PACKAGE) || !request->slot ||
        request->reserved || request->tail_reserved || request->sid_length < 8 || request->sid_length > AR_SID_BYTES ||
        !bytes_zero(request->sid + request->sid_length, AR_SID_BYTES - request->sid_length) ||
        request->sid[1] > 15 || 8u + 4u * request->sid[1] != request->sid_length || !RtlValidSid((PSID)request->sid))
        return STATUS_INVALID_PARAMETER;
    UINT32 count = 0;
    for (UINT32 i = 0; i < rs_pending->sid_count; i++) {
        const RS_SID *value = &rs_pending->sids[i];
        if (value->kind != request->kind) continue;
        count++;
        BOOLEAN same = value->length == request->sid_length && RtlCompareMemory(value->sid, request->sid, value->length) == value->length;
        if (same || value->slot == request->slot) return same && value->slot == request->slot ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION;
    }
    if (rs_pending->sid_count == RS_SID_LIMIT || count == (request->kind == AR_BIND_OWNER ? AR_OWNER_LIMIT : AR_GROUP_LIMIT))
        return STATUS_INSUFFICIENT_RESOURCES;
    RS_SID *value = &rs_pending->sids[rs_pending->sid_count++];
    value->kind = request->kind; value->slot = request->slot; value->length = request->sid_length;
    RtlCopyMemory(value->sid, request->sid, request->sid_length);
    return STATUS_SUCCESS;
}

static BOOLEAN rs_sid_bound(const RS_SNAPSHOT *snapshot, UINT32 kind, UINT32 slot)
{
    for (UINT32 i = 0; i < snapshot->sid_count; i++)
        if (snapshot->sids[i].kind == kind && snapshot->sids[i].slot == slot) return TRUE;
    return FALSE;
}

static NTSTATUS rs_claim(const AR_RUNTIME_CLAIM *request, UINT32 *group, UINT64 *claim)
{
    if (!rs_mutable()) return STATUS_DEVICE_NOT_READY;
    if (request->epoch != rs_pending->epoch) return STATUS_REVISION_MISMATCH;
    RS_POLICY *owner = rs_find_policy(rs_pending, request->owner_kind, request->owner);
    if (!owner) return STATUS_NOT_FOUND;
    BOOLEAN selected = FALSE;
    for (UINT32 i = 0; i < owner->policy.count; i++)
        if (owner->policy.rules[i].selector == 1 && owner->policy.rules[i].application == request->binding.slot) selected = TRUE;
    if (!selected) return STATUS_INVALID_PARAMETER;
    NTSTATUS status = rg_verify(rs_pending->registry, request->owner_kind, request->owner, &request->binding, group, claim);
    if (NT_SUCCESS(status)) for (UINT32 i = 0; i < owner->policy.count; i++)
        if (owner->policy.rules[i].selector == 1 && owner->policy.rules[i].application == request->binding.slot)
            owner->verified[i / 32u] |= 1u << (i % 32u);
    return status;
}

static NTSTATUS rs_seal(const AR_RUNTIME_SEAL *request)
{
    if (!rs_pending || rs_pending->session != session_id) return STATUS_DEVICE_NOT_READY;
    if (request->epoch != rs_pending->epoch) return STATUS_REVISION_MISMATCH;
    if (rs_pending->sealed) return STATUS_SUCCESS;
    if (rs_pending->count != rs_pending->expected) return STATUS_INVALID_PARAMETER;
    AR_MEMBERSHIP_VIEW view = {rs_pending->registry->members, rs_pending->registry->member_count};
    if (!ar_memberships_valid(&view)) return STATUS_INVALID_PARAMETER;
    for (UINT32 i = 0; i < view.count; i++)
        if (!rg_group_by_id(rs_pending->registry, view.entries[i].group)) return STATUS_INVALID_PARAMETER;
    for (UINT32 i = 0; i < rs_pending->registry->alias_count; i++) {
        const RG_ALIAS *alias = rs_pending->registry->aliases[i];
        if (!rg_member(rs_pending->registry, alias->owner_kind, alias->owner, alias->selector, alias->group))
            return STATUS_INVALID_PARAMETER;
    }
    for (UINT32 i = 0; i < rs_pending->count; i++) {
        const RS_POLICY *record = &rs_pending->policies[i];
        const struct ap_policy *policy = &record->policy;
        if (policy->owner_kind == 3 && rs_pending->count != 1) return STATUS_OBJECT_NAME_COLLISION;
        if (policy->owner_kind == 2 && !rs_sid_bound(rs_pending, AR_BIND_OWNER, policy->owner)) return STATUS_INVALID_SID;
        for (UINT32 rule = 0; rule < policy->count; rule++) {
            const struct ap_rule *value = &policy->rules[rule];
            if (value->selector == 2 && !rs_sid_bound(rs_pending, AR_BIND_PACKAGE, value->application)) return STATUS_INVALID_SID;
            if (value->selector == 1 && !record->carried && !(record->verified[rule / 32u] & (1u << (rule % 32u))))
                return STATUS_DEVICE_NOT_READY;
        }
    }
    rs_pending->sealed = TRUE;
    return STATUS_SUCCESS;
}

static void rs_receipt(AR_RUNTIME_RECEIPT *output, UINT32 group, UINT64 claim, UINT32 flags)
{
    RtlZeroMemory(output, sizeof(*output));
    output->header.version = AR_ABI_VERSION; output->header.size = sizeof(*output); output->header.session = session_id;
    if (rs_pending) { output->epoch = rs_pending->epoch; output->serial = rs_pending->serial; }
    output->group = group; output->claim = claim; output->flags = flags;
}
