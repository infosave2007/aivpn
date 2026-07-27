<script lang="ts">
  import type { Client, ClientRole } from '$lib/api';
  import { authStore } from '$lib/stores/auth.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import { Key, QrCode, Edit, Trash2, ShieldOff } from 'lucide-svelte';

  let {
    clients,
    onEdit,
    onDelete,
    onRevoke,
    onRoleChange,
    onViewKey,
    onViewQr,
  }: {
    clients: Client[];
    onEdit: (id: string) => void;
    onDelete: (id: string) => void;
    onRevoke: (id: string) => void;
    onRoleChange: (id: string, role: ClientRole) => void;
    onViewKey: (id: string) => void;
    onViewQr: (id: string) => void;
  } = $props();

  // Role assignment is a web-panel ADMIN-only action (never available over the
  // tunnel). The panel's own login role — not the VPN client's role field —
  // gates whether the editor is shown; the server independently enforces this
  // too (viewers can't reach PATCH at all, see proxy.ts requireReadAccess).
  const isAdmin = $derived(authStore.user?.role === 'admin');

  const ROLES: ClientRole[] = ['user', 'viewer', 'admin'];

  function formatBytes(b: number): string {
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
    return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }

  function handleRoleChange(id: string, e: Event) {
    const value = (e.target as HTMLSelectElement).value as ClientRole;
    onRoleChange(id, value);
  }
</script>

<div class="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-700">
  <table class="w-full text-sm">
    <thead class="bg-gray-50 dark:bg-gray-800 text-gray-500 dark:text-gray-400">
      <tr>
        <th class="px-4 py-3 text-left font-medium">Name</th>
        <th class="px-4 py-3 text-left font-medium">VPN IP</th>
        <th class="px-4 py-3 text-left font-medium">Status</th>
        <th class="px-4 py-3 text-left font-medium">Role</th>
        <th class="px-4 py-3 text-left font-medium">Traffic</th>
        <th class="px-4 py-3 text-left font-medium">Last Connected</th>
        <th class="px-4 py-3 text-right font-medium">Actions</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-gray-100 dark:divide-gray-700 bg-white dark:bg-gray-900">
      {#each clients as client (client.id)}
        <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
          <td class="px-4 py-3 font-medium text-gray-900 dark:text-white">
            {client.name}
            {#if client.one_time}
              <span class="ml-1 text-xs text-orange-500">(one-time)</span>
            {/if}
            {#if client.device_bound}
              <span class="ml-1 text-xs text-blue-500">(device)</span>
            {/if}
            {#if client.expires_at}
              <span class="ml-1 text-xs {new Date(client.expires_at) < new Date() ? 'text-red-500' : 'text-yellow-500'}">
                exp {new Date(client.expires_at).toLocaleDateString()}
              </span>
            {/if}
          </td>
          <td class="px-4 py-3 text-gray-600 dark:text-gray-400 font-mono text-xs">{client.vpn_ip}</td>
          <td class="px-4 py-3">
            <StatusBadge
              status={client.enabled ? 'enabled' : 'disabled'}
              variant={client.enabled ? 'success' : 'error'}
            />
          </td>
          <td class="px-4 py-3">
            {#if isAdmin}
              <select
                value={client.role ?? 'user'}
                onchange={(e) => handleRoleChange(client.id, e)}
                title="Change client role"
                class="px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-xs text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                {#each ROLES as r (r)}
                  <option value={r}>{r}</option>
                {/each}
              </select>
            {:else}
              <span class="capitalize text-gray-600 dark:text-gray-400 text-xs">{client.role ?? 'user'}</span>
            {/if}
          </td>
          <td class="px-4 py-3 text-gray-600 dark:text-gray-400 text-xs">
            ↑{formatBytes(client.stats?.bytes_out ?? 0)} ↓{formatBytes(client.stats?.bytes_in ?? 0)}
          </td>
          <td class="px-4 py-3 text-gray-600 dark:text-gray-400 text-xs">
            {client.stats?.last_connected ? new Date(client.stats.last_connected).toLocaleString() : '—'}
          </td>
          <td class="px-4 py-3">
            <div class="flex items-center justify-end gap-1">
              <button
                onclick={() => onViewKey(client.id)}
                class="p-1.5 text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 rounded"
                title="Connection Key"
              >
                <Key size={15} />
              </button>
              <button
                onclick={() => onViewQr(client.id)}
                class="p-1.5 text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 rounded"
                title="QR Code"
              >
                <QrCode size={15} />
              </button>
              <button
                onclick={() => onEdit(client.id)}
                class="p-1.5 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded"
                title="Edit"
              >
                <Edit size={15} />
              </button>
              <button
                onclick={() => onDelete(client.id)}
                class="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded"
                title="Delete"
              >
                <Trash2 size={15} />
              </button>
              {#if isAdmin}
                <button
                  onclick={() => onRevoke(client.id)}
                  class="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded"
                  title="Revoke (tombstone + force-disconnect)"
                >
                  <ShieldOff size={15} />
                </button>
              {/if}
            </div>
          </td>
        </tr>
      {/each}
      {#if clients.length === 0}
        <tr>
          <td colspan="7" class="px-4 py-8 text-center text-gray-400">No clients found</td>
        </tr>
      {/if}
    </tbody>
  </table>
</div>
