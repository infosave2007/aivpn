#pragma once

static UINT32 rs_sid_slot(const RS_SNAPSHOT *snapshot, UINT32 kind, const UCHAR *sid, UINT32 length)
{
    if (!length) return 0;
    for (UINT32 i = 0; i < snapshot->sid_count; i++) {
        const RS_SID *value = &snapshot->sids[i];
        if (value->kind == kind && value->length == length && RtlCompareMemory(value->sid, sid, length) == length) return value->slot;
    }
    return 0;
}

static UINT32 rs_policy_index(const RS_SNAPSHOT *snapshot, UINT32 owner)
{
    for (UINT32 i = 0; i < snapshot->count; i++) {
        const struct ap_policy *policy = &snapshot->policies[i].policy;
        if (policy->owner_kind == 3 || (policy->owner_kind == 2 && owner && policy->owner == owner)) return i;
    }
    return MAXULONG;
}

static BOOLEAN rs_negative(AR_ORIGIN *source, const AR_OPENED_NAME *name,
    const RS_SNAPSHOT *snapshot, const struct ap_policy *policy, UINT32 group)
{
    const RG_REGISTRY *registry = snapshot->registry;
    for (UINT32 i = 0; i < registry->alias_count; i++) {
        const RG_ALIAS *alias = registry->aliases[i];
        UINT32 bit = 1u << (i % 32u);
        if (source->runtime_negative[i / 32u] & bit) continue;
        /* Ранее проверенный G1 остается членом A после A->G2. Это не
         * очищает отрицательный факт, уже наблюденный этим origin. */
        if (rg_member(registry, alias->owner_kind, alias->owner, alias->selector, group)) continue;
        BOOLEAN changed = equal_path(name->path, name->units, alias->path, alias->units);
        if (!changed) {
            AR_FILE_VIEW target = {0};
            NTSTATUS status = file_view_open(alias->path, alias->units, &target);
            changed = NT_SUCCESS(status) && same_stream(source->image, target.file);
            file_view_close(&target);
        }
        if (changed) source->runtime_negative[i / 32u] |= bit;
    }
    for (UINT32 i = 0; i < registry->alias_count; i++) {
        const RG_ALIAS *alias = registry->aliases[i];
        if (alias->owner_kind == policy->owner_kind && alias->owner == policy->owner &&
            (source->runtime_negative[i / 32u] & (1u << (i % 32u))) && file_selected(policy, alias->selector)) return TRUE;
    }
    return FALSE;
}

static NTSTATUS rs_resolve_origin(AR_ORIGIN *source, struct ap_origin *origin, AR_DIAGNOSTIC *details,
    const RS_SNAPSHOT *snapshot, UINT32 policy_index)
{
    UCHAR user[AR_SID_BYTES] = {0}, package[AR_SID_BYTES] = {0};
    UINT32 user_length = 0, package_length = 0;
    NTSTATUS status = token_sid(source->token, TokenUser, user, &user_length);
    if (!NT_SUCCESS(status) || !user_length) return STATUS_INVALID_SID;
    status = token_sid(source->token, TokenAppContainerSid, package, &package_length);
    if (!NT_SUCCESS(status)) return status;
    origin->owner_kind = 2;
    origin->owner = rs_sid_slot(snapshot, AR_BIND_OWNER, user, user_length);
    origin->package = rs_sid_slot(snapshot, AR_BIND_PACKAGE, package, package_length);
    origin->resolved = source->process == PsInitialSystemProcess;
    if (details) {
        details->user_length = user_length; details->package_length = package_length;
        RtlCopyMemory(details->user, user, user_length); RtlCopyMemory(details->package, package, package_length);
    }
    if (policy_index == MAXULONG) return STATUS_SUCCESS;
    if (policy_index >= snapshot->count) return STATUS_INVALID_PARAMETER;
    BOOLEAN available = source->image && source->image->DeviceObject && source->image->SectionObjectPointer;
    if (available) {
        RG_GROUP *group = rg_group_for_image(snapshot->registry, source->image);
        origin->application = group ? group->id : 0;
        AR_OPENED_NAME *name = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*name), AR_POOL_TAG);
        if (name) {
            origin->resolved = opened_name(source, name) &&
                !rs_negative(source, name, snapshot, &snapshot->policies[policy_index].policy, origin->application);
            ExFreePoolWithTag(name, AR_POOL_TAG);
        }
    }
    return STATUS_SUCCESS;
}
