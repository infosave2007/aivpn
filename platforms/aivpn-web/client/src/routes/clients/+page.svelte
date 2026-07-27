<script lang="ts">
  import { goto } from '$app/navigation';
  import { createQuery, createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { clients as clientsApi, type ClientRole } from '$lib/api';
  import ClientTable from '$lib/components/ClientTable.svelte';
  import QrModal from '$lib/components/QrModal.svelte';
  import ConnectionKeyModal from '$lib/components/ConnectionKeyModal.svelte';
  import { Plus, Search, ChevronLeft, ChevronRight } from 'lucide-svelte';

  const qc = useQueryClient();

  let search = $state('');
  let searchDebounced = $state('');
  let filterEnabled = $state<boolean | undefined>(undefined);
  let page = $state(0);
  const PAGE_SIZE = 25;

  let debounceTimer: ReturnType<typeof setTimeout>;
  $effect(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => { searchDebounced = search; page = 0; }, 300);
    return () => clearTimeout(debounceTimer);
  });

  const query = createQuery({
    queryKey: ['clients', searchDebounced, filterEnabled, page],
    queryFn: () => clientsApi.list({ search: searchDebounced || undefined, enabled: filterEnabled, page, limit: PAGE_SIZE }),
  });

  const createMut = createMutation({
    mutationFn: (data: { name: string; one_time: boolean; expires_at: string | null }) =>
      clientsApi.create({ name: data.name, one_time: data.one_time, expires_at: data.expires_at || null }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients'] }); showAddModal = false; newName = ''; newOneTime = false; newExpiresAt = ''; },
  });

  const deleteMut = createMutation({
    mutationFn: (id: string) => clientsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clients'] }),
    onError: (err: Error) => { alert(`Delete failed: ${err.message}`); },
  });

  const revokeMut = createMutation({
    mutationFn: (id: string) => clientsApi.revoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clients'] }),
    onError: (err: Error) => { alert(`Revoke failed: ${err.message}`); },
  });

  const roleMut = createMutation({
    mutationFn: (vars: { id: string; role: ClientRole }) => clientsApi.update(vars.id, { role: vars.role }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clients'] }),
    onError: (err: Error) => { alert(`Role change failed: ${err.message}`); qc.invalidateQueries({ queryKey: ['clients'] }); },
  });

  let showAddModal = $state(false);
  let newName = $state('');
  let newOneTime = $state(false);
  let newExpiresAt = $state('');

  let qrOpen = $state(false);
  let qrData = $state('');
  let connKeyOpen = $state(false);
  let connKey = $state('');

  async function handleViewKey(id: string) {
    try {
      const res = await clientsApi.connectionKey(id);
      connKey = res.connection_key;
      connKeyOpen = true;
    } catch { /* ignore */ }
  }

  async function handleViewQr(id: string) {
    try {
      const res = await clientsApi.connectionKey(id);
      qrData = res.connection_key;
      qrOpen = true;
    } catch { /* ignore */ }
  }

  function handleEdit(id: string) {
    goto(`/clients/${id}`);
  }

  async function handleDelete(id: string) {
    if (confirm('Delete this client? This cannot be undone.')) {
      $deleteMut.mutate(id);
    }
  }

  async function handleRevoke(id: string) {
    if (confirm('Permanently revoke and disconnect this client? This cannot be undone.')) {
      $revokeMut.mutate(id);
    }
  }

  function handleRoleChange(id: string, role: ClientRole) {
    $roleMut.mutate({ id, role });
  }

  const clientList = $derived($query.data?.items ?? []);
  const total = $derived($query.data?.total ?? 0);
  const totalPages = $derived(Math.ceil(total / PAGE_SIZE));
</script>

<div class="space-y-4">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Clients</h1>
    <button
      onclick={() => { showAddModal = true; }}
      class="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium transition-colors"
    >
      <Plus size={16} />
      Add Client
    </button>
  </div>

  <div class="flex items-center gap-3">
    <div class="relative flex-1 max-w-xs">
      <Search class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
      <input
        type="text"
        bind:value={search}
        placeholder="Search clients..."
        class="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
      />
    </div>
    <select
      bind:value={filterEnabled}
      class="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
    >
      <option value={undefined}>All Status</option>
      <option value={true}>Enabled</option>
      <option value={false}>Disabled</option>
    </select>
  </div>

  {#if $query.isLoading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
    </div>
  {:else if $query.error}
    <p class="text-red-500 text-sm">{($query.error as Error).message}</p>
  {:else}
    <ClientTable
      clients={clientList}
      onEdit={handleEdit}
      onDelete={handleDelete}
      onRevoke={handleRevoke}
      onRoleChange={handleRoleChange}
      onViewKey={handleViewKey}
      onViewQr={handleViewQr}
    />

    {#if totalPages > 1}
      <div class="flex items-center justify-between pt-2">
        <p class="text-sm text-gray-500">{total} total clients</p>
        <div class="flex items-center gap-2">
          <button
            onclick={() => { page = Math.max(0, page - 1); }}
            disabled={page === 0}
            class="p-1.5 rounded border border-gray-300 dark:border-gray-600 disabled:opacity-40 hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            <ChevronLeft size={16} />
          </button>
          <span class="text-sm text-gray-600 dark:text-gray-400">{page + 1} / {totalPages}</span>
          <button
            onclick={() => { page = Math.min(totalPages - 1, page + 1); }}
            disabled={page >= totalPages - 1}
            class="p-1.5 rounded border border-gray-300 dark:border-gray-600 disabled:opacity-40 hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    {/if}
  {/if}
</div>

{#if showAddModal}
  <div class="fixed inset-0 z-50 flex items-center justify-center">
    <button class="absolute inset-0 bg-black/60" onclick={() => { showAddModal = false; }}></button>
    <div class="relative bg-white dark:bg-gray-800 rounded-xl p-6 shadow-2xl w-full max-w-sm mx-4">
      <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Add Client</h2>
      <form onsubmit={(e) => { e.preventDefault(); $createMut.mutate({ name: newName, one_time: newOneTime, expires_at: newExpiresAt ? new Date(newExpiresAt).toISOString() : null }); }} class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="name">Name</label>
          <input
            id="name"
            type="text"
            bind:value={newName}
            required
            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            placeholder="Client name"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="expires">Expires at (optional)</label>
          <input
            id="expires"
            type="datetime-local"
            bind:value={newExpiresAt}
            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
          <input type="checkbox" bind:checked={newOneTime} class="rounded" />
          One-time enrollment (auto-bind first device)
        </label>
        <div class="flex gap-3">
          <button type="button" onclick={() => { showAddModal = false; }} class="flex-1 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700">
            Cancel
          </button>
          <button type="submit" disabled={$createMut.isPending} class="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">
            {$createMut.isPending ? 'Creating...' : 'Create'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<QrModal open={qrOpen} data={qrData} title="Client QR Code" onClose={() => { qrOpen = false; }} />
<ConnectionKeyModal open={connKeyOpen} connectionKey={connKey} onClose={() => { connKeyOpen = false; }} />
