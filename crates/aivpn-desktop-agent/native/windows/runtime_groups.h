#pragma once

/* Только PASSIVE под session mutex. Числовой group не поступает от caller:
 * он выдается после сравнения удерживаемых device/SOP и не используется повторно. */
typedef struct {
    LONG references;
    UINT32 id;
    HANDLE file;
    PFILE_OBJECT image;
    PDEVICE_OBJECT device;
    FILE_ID_INFORMATION metadata;
} RG_GROUP;
typedef struct {
    LONG references;
    UINT64 claim;
    UINT32 owner_kind, owner, selector, group, units;
    WCHAR path[];
} RG_ALIAS;
typedef struct {
    UINT32 group_count, alias_count, member_count;
    RG_GROUP *groups[AR_GROUP_LIMIT];
    RG_ALIAS *aliases[AR_ALIAS_LIMIT];
    AR_MEMBERSHIP members[AR_MEMBERSHIP_LIMIT];
} RG_REGISTRY;
static UINT32 rg_next_group;
static UINT64 rg_next_claim;

static void rg_group_release(RG_GROUP *group)
{
    if (!group || InterlockedDecrement(&group->references)) return;
    if (group->file) ZwClose(group->file);
    if (group->image) ObDereferenceObject(group->image);
    if (group->device) ObDereferenceObject(group->device);
    ExFreePoolWithTag(group, AR_POOL_TAG);
}

static void rg_alias_release(RG_ALIAS *alias)
{
    if (alias && !InterlockedDecrement(&alias->references)) ExFreePoolWithTag(alias, AR_POOL_TAG);
}

static void rg_release(RG_REGISTRY *registry)
{
    if (!registry) return;
    for (UINT32 i = 0; i < registry->group_count; i++) rg_group_release(registry->groups[i]);
    for (UINT32 i = 0; i < registry->alias_count; i++) rg_alias_release(registry->aliases[i]);
    ExFreePoolWithTag(registry, AR_POOL_TAG);
}

static NTSTATUS rg_clone(const RG_REGISTRY *current, RG_REGISTRY **output)
{
    *output = NULL;
    RG_REGISTRY *copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*copy), AR_POOL_TAG);
    if (!copy) return STATUS_INSUFFICIENT_RESOURCES;
    if (current) {
        *copy = *current;
        for (UINT32 i = 0; i < copy->group_count; i++) InterlockedIncrement(&copy->groups[i]->references);
        for (UINT32 i = 0; i < copy->alias_count; i++) InterlockedIncrement(&copy->aliases[i]->references);
    }
    *output = copy;
    return STATUS_SUCCESS;
}

static RG_GROUP *rg_group_for_image(const RG_REGISTRY *registry, PFILE_OBJECT image)
{
    for (UINT32 i = 0; i < registry->group_count; i++)
        if (same_stream(registry->groups[i]->image, image)) return registry->groups[i];
    return NULL;
}

static RG_GROUP *rg_group_by_id(const RG_REGISTRY *registry, UINT32 id)
{
    for (UINT32 i = 0; i < registry->group_count; i++)
        if (registry->groups[i]->id == id) return registry->groups[i];
    return NULL;
}

static BOOLEAN rg_member(const RG_REGISTRY *registry, UINT32 kind, UINT32 owner, UINT32 selector, UINT32 group)
{
    AR_MEMBERSHIP_VIEW view = {registry->members, registry->member_count};
    return ar_membership_contains(&view, kind, owner, selector, group) != 0;
}

/* Новый membership вставляется отдельно. Совпавший G2 не объединяет историю
 * selectors A/B или разных владельцев. Отказ не усекает таблицу. */
static NTSTATUS rg_add_member(RG_REGISTRY *registry, UINT32 kind, UINT32 owner, UINT32 selector, UINT32 group)
{
    AR_MEMBERSHIP value = {kind, owner, selector, group};
    UINT32 position = 0;
    while (position < registry->member_count) {
        int order = ar_membership_compare(&registry->members[position], &value);
        if (!order) return STATUS_SUCCESS;
        if (order > 0) break;
        position++;
    }
    if (registry->member_count == AR_MEMBERSHIP_LIMIT) return STATUS_INSUFFICIENT_RESOURCES;
    RtlMoveMemory(registry->members + position + 1, registry->members + position,
        (registry->member_count - position) * sizeof(value));
    registry->members[position] = value;
    registry->member_count++;
    return STATUS_SUCCESS;
}

/* Вызывать только для еще не опубликованной копии. При любой ошибке caller
 * уничтожает всю копию, текущий snapshot и его refs остаются прежними. */
static NTSTATUS rg_verify(RG_REGISTRY *registry, UINT32 kind, UINT32 owner,
    const AR_BIND *request, UINT32 *verified_group, UINT64 *verified_claim)
{
    *verified_group = 0; *verified_claim = 0;
    if ((kind != 2 && kind != 3) || (kind == 2 ? !owner : owner != 0) ||
        request->kind != AR_BIND_FILE || !request->slot || !request->handle ||
        request->reserved || request->tail_reserved || request->path_reserved) return STATUS_INVALID_PARAMETER;
    AR_BINDING *binding = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*binding), AR_POOL_TAG);
    if (!binding) return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS status = bind_file(request, binding);
    if (!NT_SUCCESS(status)) goto done;
    for (UINT32 i = 0; i < registry->alias_count; i++) {
        const RG_ALIAS *alias = registry->aliases[i];
        if (alias->owner_kind == kind && alias->owner == owner && alias->selector == request->slot &&
            !equal_path(alias->path, alias->units, request->path, request->path_units)) {
            status = STATUS_OBJECT_NAME_COLLISION; goto done;
        }
    }
    RG_GROUP *group = rg_group_for_image(registry, binding->image);
    if (!group) {
        if (registry->group_count == AR_GROUP_LIMIT || rg_next_group == MAXULONG) {
            status = STATUS_INSUFFICIENT_RESOURCES; goto done;
        }
        group = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*group), AR_POOL_TAG);
        if (!group) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
        group->references = 1; group->id = ++rg_next_group;
        group->file = binding->file; binding->file = NULL;
        group->image = binding->image; binding->image = NULL;
        group->device = binding->volume_device; binding->volume_device = NULL;
        group->metadata = binding->identity;
        registry->groups[registry->group_count++] = group;
    }
    RG_ALIAS *claim = NULL;
    for (UINT32 i = 0; i < registry->alias_count; i++) {
        RG_ALIAS *alias = registry->aliases[i];
        if (alias->owner_kind == kind && alias->owner == owner && alias->selector == request->slot && alias->group == group->id) {
            claim = alias; break;
        }
    }
    if (!claim) {
        if (registry->alias_count == AR_ALIAS_LIMIT || rg_next_claim == MAXUINT64) {
            status = STATUS_INSUFFICIENT_RESOURCES; goto done;
        }
        claim = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*claim) + request->path_units * sizeof(WCHAR), AR_POOL_TAG);
        if (!claim) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
        claim->references = 1; claim->claim = ++rg_next_claim;
        claim->owner_kind = kind; claim->owner = owner; claim->selector = request->slot;
        claim->group = group->id; claim->units = request->path_units;
        RtlCopyMemory(claim->path, request->path, request->path_units * sizeof(WCHAR));
        registry->aliases[registry->alias_count++] = claim;
    }
    status = rg_add_member(registry, kind, owner, request->slot, group->id);
    if (NT_SUCCESS(status)) { *verified_group = group->id; *verified_claim = claim->claim; }
done:
    if (binding->file) ZwClose(binding->file);
    if (binding->image) ObDereferenceObject(binding->image);
    if (binding->volume_device) ObDereferenceObject(binding->volume_device);
    ExFreePoolWithTag(binding, AR_POOL_TAG);
    return status;
}
